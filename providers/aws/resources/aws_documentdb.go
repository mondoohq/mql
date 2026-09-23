// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdb_types "github.com/aws/aws-sdk-go-v2/service/docdb/types"
	"github.com/aws/aws-sdk-go-v2/service/docdbelastic"
	docdbelastic_types "github.com/aws/aws-sdk-go-v2/service/docdbelastic/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

const (
	docdbClusterArnPattern   = "arn:aws:rds:%s:%s:cluster:%s"
	docdbInstanceArnPattern  = "arn:aws:rds:%s:%s:db:%s"
	docdbClusterPgArnPattern = "arn:aws:rds:%s:%s:cluster-pg:%s"
	docdbEngine              = "docdb"
	docdbAuditLogType        = "audit"
	docdbProfilerLogType     = "profiler"
)

func (a *mqlAwsDocumentdb) id() (string, error) {
	return "aws.documentdb", nil
}

type mqlAwsDocumentdbInternal struct {
	subnetGroupCache       sync.Map // region+name -> *docdbSubnetGroupResolved
	pendingActionsOnce     sync.Once
	pendingActions         []docdb_types.ResourcePendingMaintenanceActions
	pendingActionsErr      error
	globalClustersOnce     sync.Once
	globalClustersCached   []docdb_types.GlobalCluster
	globalClustersErrCache error
}

type docdbSubnetGroupResolved struct {
	once    sync.Once
	vpcId   string
	subnets []string
	err     error
}

// helpers

func docdbIsArn(s string) bool {
	return len(s) > 4 && s[:4] == "arn:"
}

func docdbResolveKmsKey(runtime *plugin.Runtime, arnPtr *string, field *plugin.TValue[*mqlAwsKmsKey]) (*mqlAwsKmsKey, error) {
	if arnPtr == nil || *arnPtr == "" {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(runtime, ResourceAwsKmsKey, map[string]*llx.RawData{
		"arn": llx.StringDataPtr(arnPtr),
	})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func docdbGetParent(runtime *plugin.Runtime) (*mqlAwsDocumentdb, error) {
	obj, err := CreateResource(runtime, "aws.documentdb", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlAwsDocumentdb), nil
}

// ---------- aws.documentdb.cluster ----------

func (a *mqlAwsDocumentdb) clusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	pool := jobpool.CreatePool(a.getDbClusters(conn), 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	for i := range pool.Jobs {
		if pool.Jobs[i].Result != nil {
			res = append(res, pool.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsDocumentdb) getDbClusters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := []*jobpool.Job{}
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("documentdb>getDbClusters>calling aws with region %s", region)
			svc := conn.DocumentDB(region)
			ctx := context.Background()
			res := []any{}
			// The docdb client's DescribeDBClusters returns clusters of all engines (RDS Aurora,
			// Postgres, DocumentDB) because it shares the underlying RDS service. The "engine"
			// API filter is rejected with "Unrecognized engine name: docdb", so we filter here.
			paginator := docdb.NewDescribeDBClustersPaginator(svc, &docdb.DescribeDBClustersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, cluster := range page.DBClusters {
					if cluster.Engine == nil || *cluster.Engine != docdbEngine {
						continue
					}
					mqlCluster, err := newMqlAwsDocumentdbCluster(a.MqlRuntime, region, conn.AccountId(), cluster)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCluster)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// docdbLogExportsEnabled scans EnabledCloudwatchLogsExports for the audit and
// profiler log types and reports which are present.
func docdbLogExportsEnabled(exports []string) (audit, profiler bool) {
	for _, l := range exports {
		switch l {
		case docdbAuditLogType:
			audit = true
		case docdbProfilerLogType:
			profiler = true
		}
	}
	return
}

func newMqlAwsDocumentdbCluster(runtime *plugin.Runtime, region, accountID string, cluster docdb_types.DBCluster) (*mqlAwsDocumentdbCluster, error) {
	auditEnabled, profilerEnabled := docdbLogExportsEnabled(cluster.EnabledCloudwatchLogsExports)

	memberIds := []string{}
	var writerId *string
	for _, m := range cluster.DBClusterMembers {
		if m.DBInstanceIdentifier != nil {
			memberIds = append(memberIds, *m.DBInstanceIdentifier)
			if m.IsClusterWriter != nil && *m.IsClusterWriter {
				w := *m.DBInstanceIdentifier
				writerId = &w
			}
		}
	}

	roleArns := []string{}
	for _, r := range cluster.AssociatedRoles {
		if r.RoleArn != nil {
			roleArns = append(roleArns, *r.RoleArn)
		}
	}

	resource, err := CreateResource(runtime, "aws.documentdb.cluster",
		map[string]*llx.RawData{
			"__id":                         llx.StringDataPtr(cluster.DBClusterArn),
			"arn":                          llx.StringDataPtr(cluster.DBClusterArn),
			"name":                         llx.StringDataPtr(cluster.DBClusterIdentifier),
			"clusterIdentifier":            llx.StringDataPtr(cluster.DBClusterIdentifier),
			"engine":                       llx.StringDataPtr(cluster.Engine),
			"engineVersion":                llx.StringDataPtr(cluster.EngineVersion),
			"region":                       llx.StringData(region),
			"availabilityZones":            llx.ArrayData(convert.SliceAnyToInterface(cluster.AvailabilityZones), types.String),
			"backupRetentionPeriod":        llx.IntDataPtr(cluster.BackupRetentionPeriod),
			"createdAt":                    llx.TimeDataPtr(cluster.ClusterCreateTime),
			"clusterParameterGroup":        llx.StringDataPtr(cluster.DBClusterParameterGroup),
			"subnetGroup":                  llx.StringDataPtr(cluster.DBSubnetGroup),
			"clusterResourceId":            llx.StringDataPtr(cluster.DbClusterResourceId),
			"deletionProtection":           llx.BoolDataPtr(cluster.DeletionProtection),
			"copyTagsToSnapshot":           llx.BoolDataPtr(cluster.CopyTagsToSnapshot),
			"earliestRestorableTime":       llx.TimeDataPtr(cluster.EarliestRestorableTime),
			"latestRestorableTime":         llx.TimeDataPtr(cluster.LatestRestorableTime),
			"enabledCloudwatchLogsExports": llx.ArrayData(convert.SliceAnyToInterface(cluster.EnabledCloudwatchLogsExports), types.String),
			"auditLogsEnabled":             llx.BoolData(auditEnabled),
			"profilerLogsEnabled":          llx.BoolData(profilerEnabled),
			"endpoint":                     llx.StringDataPtr(cluster.Endpoint),
			"readerEndpoint":               llx.StringDataPtr(cluster.ReaderEndpoint),
			"hostedZoneId":                 llx.StringDataPtr(cluster.HostedZoneId),
			"masterUsername":               llx.StringDataPtr(cluster.MasterUsername),
			"multiAZ":                      llx.BoolDataPtr(cluster.MultiAZ),
			"port":                         llx.IntDataPtr(cluster.Port),
			"preferredBackupWindow":        llx.StringDataPtr(cluster.PreferredBackupWindow),
			"preferredMaintenanceWindow":   llx.StringDataPtr(cluster.PreferredMaintenanceWindow),
			"cloneGroupId":                 llx.StringDataPtr(cluster.CloneGroupId),
			"status":                       llx.StringDataPtr(cluster.Status),
			"storageEncrypted":             llx.BoolDataPtr(cluster.StorageEncrypted),
			"storageType":                  llx.StringDataPtr(cluster.StorageType),
			"networkType":                  llx.StringDataPtr(cluster.NetworkType),
		})
	if err != nil {
		return nil, err
	}

	sgArns := []string{}
	for _, sg := range cluster.VpcSecurityGroups {
		if sg.VpcSecurityGroupId != nil {
			sgArns = append(sgArns, NewSecurityGroupArn(region, accountID, *sg.VpcSecurityGroupId))
		}
	}

	mqlCluster := resource.(*mqlAwsDocumentdbCluster)
	mqlCluster.region = region
	mqlCluster.accountID = accountID
	mqlCluster.cacheKmsKeyId = cluster.KmsKeyId
	mqlCluster.cacheReplicationSourceIdentifier = cluster.ReplicationSourceIdentifier
	mqlCluster.cacheReadReplicas = cluster.ReadReplicaIdentifiers
	mqlCluster.cacheMemberIdentifiers = memberIds
	mqlCluster.cacheWriterIdentifier = writerId
	mqlCluster.cacheRoleArns = roleArns
	mqlCluster.cacheParamGroupName = cluster.DBClusterParameterGroup
	mqlCluster.cacheSubnetGroupName = cluster.DBSubnetGroup
	mqlCluster.setSecurityGroupArns(sgArns)
	return mqlCluster, nil
}

type mqlAwsDocumentdbClusterInternal struct {
	securityGroupIdHandler
	region                           string
	accountID                        string
	cacheKmsKeyId                    *string
	cacheReplicationSourceIdentifier *string
	cacheReadReplicas                []string
	cacheMemberIdentifiers           []string
	cacheWriterIdentifier            *string
	cacheRoleArns                    []string
	cacheParamGroupName              *string
	cacheSubnetGroupName             *string
}

func initAwsDocumentdbCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformDocumentdbCluster); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch documentdb cluster")
	}
	d, err := docdbGetParent(runtime)
	if err != nil {
		return nil, nil, err
	}
	rawResources := d.GetClusters()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}
	arnVal := args["arn"].Value.(string)
	for _, raw := range rawResources.Data {
		c := raw.(*mqlAwsDocumentdbCluster)
		if c.Arn.Data == arnVal {
			return args, c, nil
		}
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.documentdb.cluster with arn %q not found", arnVal)
}

func (a *mqlAwsDocumentdbCluster) kmsKey() (*mqlAwsKmsKey, error) {
	return docdbResolveKmsKey(a.MqlRuntime, a.cacheKmsKeyId, &a.KmsKey)
}

func (a *mqlAwsDocumentdbCluster) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsDocumentdbCluster) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.DocumentDB(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data
	resp, err := svc.ListTagsForResource(ctx, &docdb.ListTagsForResourceInput{ResourceName: &arn})
	if err != nil {
		return nil, err
	}
	tags := map[string]any{}
	for _, t := range resp.TagList {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	return tags, nil
}

func (a *mqlAwsDocumentdbCluster) snapshots() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.DocumentDB(a.Region.Data)
	ctx := context.Background()
	res := []any{}
	id := a.ClusterIdentifier.Data
	paginator := docdb.NewDescribeDBClusterSnapshotsPaginator(svc, &docdb.DescribeDBClusterSnapshotsInput{
		DBClusterIdentifier: &id,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, snapshot := range page.DBClusterSnapshots {
			mqlSnap, err := newMqlAwsDocumentdbSnapshot(a.MqlRuntime, a.Region.Data, conn.AccountId(), snapshot)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSnap)
		}
	}
	return res, nil
}

func (a *mqlAwsDocumentdbCluster) parameterGroup() (*mqlAwsDocumentdbClusterParameterGroup, error) {
	if a.cacheParamGroupName == nil || *a.cacheParamGroupName == "" {
		a.ParameterGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	pgArn := fmt.Sprintf(docdbClusterPgArnPattern, a.region, a.accountID, *a.cacheParamGroupName)
	mqlPg, err := NewResource(a.MqlRuntime, "aws.documentdb.clusterParameterGroup", map[string]*llx.RawData{
		"arn": llx.StringData(pgArn),
	})
	if err != nil {
		return nil, err
	}
	return mqlPg.(*mqlAwsDocumentdbClusterParameterGroup), nil
}

func (a *mqlAwsDocumentdbCluster) vpc() (*mqlAwsVpc, error) {
	resolved, err := a.fetchSubnetGroup()
	if err != nil {
		return nil, err
	}
	if resolved == nil || resolved.vpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	mqlVpc, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{
		"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.region, conn.AccountId(), resolved.vpcId)),
	})
	if err != nil {
		return nil, err
	}
	return mqlVpc.(*mqlAwsVpc), nil
}

func (a *mqlAwsDocumentdbCluster) subnets() ([]any, error) {
	resolved, err := a.fetchSubnetGroup()
	if err != nil {
		return nil, err
	}
	if resolved == nil {
		return []any{}, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	for _, subnetId := range resolved.subnets {
		ref, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet, map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.region, conn.AccountId(), subnetId)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}

func (a *mqlAwsDocumentdbCluster) fetchSubnetGroup() (*docdbSubnetGroupResolved, error) {
	if a.cacheSubnetGroupName == nil || *a.cacheSubnetGroupName == "" {
		return nil, nil
	}
	parent, err := docdbGetParent(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	key := a.region + "/" + *a.cacheSubnetGroupName
	cacheAny, _ := parent.subnetGroupCache.LoadOrStore(key, &docdbSubnetGroupResolved{})
	cache := cacheAny.(*docdbSubnetGroupResolved)
	cache.once.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.DocumentDB(a.region)
		ctx := context.Background()
		resp, err := svc.DescribeDBSubnetGroups(ctx, &docdb.DescribeDBSubnetGroupsInput{
			DBSubnetGroupName: a.cacheSubnetGroupName,
		})
		if err != nil {
			cache.err = err
			return
		}
		if len(resp.DBSubnetGroups) > 0 {
			grp := resp.DBSubnetGroups[0]
			if grp.VpcId != nil {
				cache.vpcId = *grp.VpcId
			}
			for _, s := range grp.Subnets {
				if s.SubnetIdentifier != nil {
					cache.subnets = append(cache.subnets, *s.SubnetIdentifier)
				}
			}
		}
	})
	if cache.err != nil {
		return nil, cache.err
	}
	return cache, nil
}

func (a *mqlAwsDocumentdbCluster) members() ([]any, error) {
	res := []any{}
	for _, id := range a.cacheMemberIdentifiers {
		ref, err := NewResource(a.MqlRuntime, "aws.documentdb.instance", map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(docdbInstanceArnPattern, a.region, a.accountID, id)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}

func (a *mqlAwsDocumentdbCluster) writer() (*mqlAwsDocumentdbInstance, error) {
	if a.cacheWriterIdentifier == nil || *a.cacheWriterIdentifier == "" {
		a.Writer.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlInst, err := NewResource(a.MqlRuntime, "aws.documentdb.instance", map[string]*llx.RawData{
		"arn": llx.StringData(fmt.Sprintf(docdbInstanceArnPattern, a.region, a.accountID, *a.cacheWriterIdentifier)),
	})
	if err != nil {
		return nil, err
	}
	return mqlInst.(*mqlAwsDocumentdbInstance), nil
}

func (a *mqlAwsDocumentdbCluster) iamRoles() ([]any, error) {
	res := []any{}
	for _, roleArn := range a.cacheRoleArns {
		ref, err := NewResource(a.MqlRuntime, ResourceAwsIamRole, map[string]*llx.RawData{
			"arn": llx.StringData(roleArn),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}

func (a *mqlAwsDocumentdbCluster) replicationSource() (*mqlAwsDocumentdbCluster, error) {
	if a.cacheReplicationSourceIdentifier == nil || *a.cacheReplicationSourceIdentifier == "" {
		a.ReplicationSource.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	id := *a.cacheReplicationSourceIdentifier
	var arnStr string
	if docdbIsArn(id) {
		arnStr = id
	} else {
		arnStr = fmt.Sprintf(docdbClusterArnPattern, a.region, a.accountID, id)
	}
	mqlCluster, err := NewResource(a.MqlRuntime, "aws.documentdb.cluster", map[string]*llx.RawData{
		"arn": llx.StringData(arnStr),
	})
	if err != nil {
		return nil, err
	}
	return mqlCluster.(*mqlAwsDocumentdbCluster), nil
}

func (a *mqlAwsDocumentdbCluster) readReplicas() ([]any, error) {
	res := []any{}
	for _, id := range a.cacheReadReplicas {
		var arnStr string
		if docdbIsArn(id) {
			arnStr = id
		} else {
			arnStr = fmt.Sprintf(docdbClusterArnPattern, a.region, a.accountID, id)
		}
		ref, err := NewResource(a.MqlRuntime, "aws.documentdb.cluster", map[string]*llx.RawData{
			"arn": llx.StringData(arnStr),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}

func (a *mqlAwsDocumentdbCluster) globalClusterIdentifier() (string, error) {
	gc, err := a.findContainingGlobalCluster()
	if err != nil {
		return "", err
	}
	if gc == nil || gc.GlobalClusterIdentifier == nil {
		return "", nil
	}
	return *gc.GlobalClusterIdentifier, nil
}

func (a *mqlAwsDocumentdbCluster) globalCluster() (*mqlAwsDocumentdbGlobalCluster, error) {
	gc, err := a.findContainingGlobalCluster()
	if err != nil {
		return nil, err
	}
	if gc == nil {
		a.GlobalCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlGc, err := NewResource(a.MqlRuntime, "aws.documentdb.globalCluster", map[string]*llx.RawData{
		"arn": llx.StringDataPtr(gc.GlobalClusterArn),
	})
	if err != nil {
		return nil, err
	}
	return mqlGc.(*mqlAwsDocumentdbGlobalCluster), nil
}

func (a *mqlAwsDocumentdbCluster) findContainingGlobalCluster() (*docdb_types.GlobalCluster, error) {
	parent, err := docdbGetParent(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	gcs, err := parent.fetchGlobalClusters()
	if err != nil {
		return nil, err
	}
	for i := range gcs {
		for _, m := range gcs[i].GlobalClusterMembers {
			if m.DBClusterArn != nil && *m.DBClusterArn == a.Arn.Data {
				return &gcs[i], nil
			}
		}
	}
	return nil, nil
}

func (a *mqlAwsDocumentdbCluster) pendingMaintenanceActions() ([]any, error) {
	parent, err := docdbGetParent(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	all, err := parent.fetchPendingMaintenanceActions()
	if err != nil {
		return nil, err
	}
	return docdbPendingActionsForArn(a.MqlRuntime, all, a.Arn.Data)
}

// ---------- aws.documentdb.instance ----------

func (a *mqlAwsDocumentdb) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	pool := jobpool.CreatePool(a.getDbInstances(conn), 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	for i := range pool.Jobs {
		if pool.Jobs[i].Result != nil {
			res = append(res, pool.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsDocumentdb) getDbInstances(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := []*jobpool.Job{}
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("documentdb>getDbInstances>calling aws with region %s", region)
			svc := conn.DocumentDB(region)
			ctx := context.Background()
			res := []any{}
			// The docdb client's DescribeDBInstances returns instances of all engines (RDS Aurora,
			// Postgres, DocumentDB) because it shares the underlying RDS service. The "engine"
			// API filter is rejected with "Unrecognized engine name: docdb", so we filter here.
			paginator := docdb.NewDescribeDBInstancesPaginator(svc, &docdb.DescribeDBInstancesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, instance := range page.DBInstances {
					if instance.Engine == nil || *instance.Engine != docdbEngine {
						continue
					}
					mqlInstance, err := newMqlAwsDocumentdbInstance(a.MqlRuntime, region, conn.AccountId(), instance)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlInstance)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsDocumentdbInstance(runtime *plugin.Runtime, region, accountID string, instance docdb_types.DBInstance) (*mqlAwsDocumentdbInstance, error) {
	endpointAddress := ""
	endpointHostedZone := ""
	endpointPort := int64(0)
	if instance.Endpoint != nil {
		if instance.Endpoint.Address != nil {
			endpointAddress = *instance.Endpoint.Address
		}
		if instance.Endpoint.HostedZoneId != nil {
			endpointHostedZone = *instance.Endpoint.HostedZoneId
		}
		if instance.Endpoint.Port != nil {
			endpointPort = int64(*instance.Endpoint.Port)
		}
	}

	caIdentifier := ""
	caValidTill := llx.NilData
	if instance.CertificateDetails != nil {
		if instance.CertificateDetails.CAIdentifier != nil {
			caIdentifier = *instance.CertificateDetails.CAIdentifier
		}
		if instance.CertificateDetails.ValidTill != nil {
			caValidTill = llx.TimeDataPtr(instance.CertificateDetails.ValidTill)
		}
	}

	pendingMods := docdbInstancePendingModifiedValues(instance.PendingModifiedValues)

	sgArns := []string{}
	for _, sg := range instance.VpcSecurityGroups {
		if sg.VpcSecurityGroupId != nil {
			sgArns = append(sgArns, NewSecurityGroupArn(region, accountID, *sg.VpcSecurityGroupId))
		}
	}

	resource, err := CreateResource(runtime, "aws.documentdb.instance",
		map[string]*llx.RawData{
			"__id":                             llx.StringDataPtr(instance.DBInstanceArn),
			"arn":                              llx.StringDataPtr(instance.DBInstanceArn),
			"name":                             llx.StringDataPtr(instance.DBInstanceIdentifier),
			"dbiResourceId":                    llx.StringDataPtr(instance.DbiResourceId),
			"clusterIdentifier":                llx.StringDataPtr(instance.DBClusterIdentifier),
			"engine":                           llx.StringDataPtr(instance.Engine),
			"engineVersion":                    llx.StringDataPtr(instance.EngineVersion),
			"createdAt":                        llx.TimeDataPtr(instance.InstanceCreateTime),
			"region":                           llx.StringData(region),
			"autoMinorVersionUpgrade":          llx.BoolDataPtr(instance.AutoMinorVersionUpgrade),
			"availabilityZone":                 llx.StringDataPtr(instance.AvailabilityZone),
			"backupRetentionPeriod":            llx.IntDataPtr(instance.BackupRetentionPeriod),
			"instanceClass":                    llx.StringDataPtr(instance.DBInstanceClass),
			"enabledCloudwatchLogsExports":     llx.ArrayData(convert.SliceAnyToInterface(instance.EnabledCloudwatchLogsExports), types.String),
			"endpointAddress":                  llx.StringData(endpointAddress),
			"endpointPort":                     llx.IntData(endpointPort),
			"endpointHostedZoneId":             llx.StringData(endpointHostedZone),
			"preferredBackupWindow":            llx.StringDataPtr(instance.PreferredBackupWindow),
			"preferredMaintenanceWindow":       llx.StringDataPtr(instance.PreferredMaintenanceWindow),
			"promotionTier":                    llx.IntDataPtr(instance.PromotionTier),
			"status":                           llx.StringDataPtr(instance.DBInstanceStatus),
			"storageEncrypted":                 llx.BoolDataPtr(instance.StorageEncrypted),
			"certificateAuthority":             llx.StringDataPtr(instance.CACertificateIdentifier),
			"caCertificateDetailsCAIdentifier": llx.StringData(caIdentifier),
			"caCertificateValidTill":           caValidTill,
			"publiclyAccessible":               llx.BoolDataPtr(instance.PubliclyAccessible),
			"copyTagsToSnapshot":               llx.BoolDataPtr(instance.CopyTagsToSnapshot),
			"latestRestorableTime":             llx.TimeDataPtr(instance.LatestRestorableTime),
			"performanceInsightsEnabled":       llx.BoolDataPtr(instance.PerformanceInsightsEnabled),
			"pendingModifiedValues":            llx.MapData(pendingMods, types.String),
		})
	if err != nil {
		return nil, err
	}
	mqlInstance := resource.(*mqlAwsDocumentdbInstance)
	mqlInstance.region = region
	mqlInstance.accountID = accountID
	mqlInstance.cacheKmsKeyId = instance.KmsKeyId
	mqlInstance.cachePerformanceInsightsKmsKeyId = instance.PerformanceInsightsKMSKeyId
	mqlInstance.cacheClusterIdentifier = instance.DBClusterIdentifier
	mqlInstance.setSecurityGroupArns(sgArns)
	return mqlInstance, nil
}

type mqlAwsDocumentdbInstanceInternal struct {
	securityGroupIdHandler
	region                           string
	accountID                        string
	cacheKmsKeyId                    *string
	cachePerformanceInsightsKmsKeyId *string
	cacheClusterIdentifier           *string
}

func initAwsDocumentdbInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformDocumentdbInstance); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch documentdb instance")
	}
	d, err := docdbGetParent(runtime)
	if err != nil {
		return nil, nil, err
	}
	rawResources := d.GetInstances()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}
	arnVal := args["arn"].Value.(string)
	for _, raw := range rawResources.Data {
		i := raw.(*mqlAwsDocumentdbInstance)
		if i.Arn.Data == arnVal {
			return args, i, nil
		}
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.documentdb.instance with arn %q not found", arnVal)
}

func docdbInstancePendingModifiedValues(p *docdb_types.PendingModifiedValues) map[string]any {
	out := map[string]any{}
	if p == nil {
		return out
	}
	if p.AllocatedStorage != nil {
		out["allocatedStorage"] = fmt.Sprintf("%d", *p.AllocatedStorage)
	}
	if p.BackupRetentionPeriod != nil {
		out["backupRetentionPeriod"] = fmt.Sprintf("%d", *p.BackupRetentionPeriod)
	}
	if p.CACertificateIdentifier != nil {
		out["caCertificateIdentifier"] = *p.CACertificateIdentifier
	}
	if p.DBInstanceClass != nil {
		out["dbInstanceClass"] = *p.DBInstanceClass
	}
	if p.DBInstanceIdentifier != nil {
		out["dbInstanceIdentifier"] = *p.DBInstanceIdentifier
	}
	if p.DBSubnetGroupName != nil {
		out["dbSubnetGroupName"] = *p.DBSubnetGroupName
	}
	if p.EngineVersion != nil {
		out["engineVersion"] = *p.EngineVersion
	}
	if p.Iops != nil {
		out["iops"] = fmt.Sprintf("%d", *p.Iops)
	}
	if p.LicenseModel != nil {
		out["licenseModel"] = *p.LicenseModel
	}
	if p.MasterUserPassword != nil {
		out["masterUserPassword"] = "<redacted>"
	}
	if p.MultiAZ != nil {
		out["multiAZ"] = fmt.Sprintf("%t", *p.MultiAZ)
	}
	if p.Port != nil {
		out["port"] = fmt.Sprintf("%d", *p.Port)
	}
	if p.StorageType != nil {
		out["storageType"] = *p.StorageType
	}
	if p.PendingCloudwatchLogsExports != nil {
		if len(p.PendingCloudwatchLogsExports.LogTypesToEnable) > 0 {
			out["logTypesToEnable"] = fmt.Sprintf("%v", p.PendingCloudwatchLogsExports.LogTypesToEnable)
		}
		if len(p.PendingCloudwatchLogsExports.LogTypesToDisable) > 0 {
			out["logTypesToDisable"] = fmt.Sprintf("%v", p.PendingCloudwatchLogsExports.LogTypesToDisable)
		}
	}
	return out
}

func (a *mqlAwsDocumentdbInstance) kmsKey() (*mqlAwsKmsKey, error) {
	return docdbResolveKmsKey(a.MqlRuntime, a.cacheKmsKeyId, &a.KmsKey)
}

func (a *mqlAwsDocumentdbInstance) performanceInsightsKmsKey() (*mqlAwsKmsKey, error) {
	return docdbResolveKmsKey(a.MqlRuntime, a.cachePerformanceInsightsKmsKeyId, &a.PerformanceInsightsKmsKey)
}

func (a *mqlAwsDocumentdbInstance) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsDocumentdbInstance) cluster() (*mqlAwsDocumentdbCluster, error) {
	if a.cacheClusterIdentifier == nil || *a.cacheClusterIdentifier == "" {
		a.Cluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	clusterArn := fmt.Sprintf(docdbClusterArnPattern, a.region, a.accountID, *a.cacheClusterIdentifier)
	mqlCluster, err := NewResource(a.MqlRuntime, "aws.documentdb.cluster", map[string]*llx.RawData{
		"arn": llx.StringData(clusterArn),
	})
	if err != nil {
		return nil, err
	}
	return mqlCluster.(*mqlAwsDocumentdbCluster), nil
}

func (a *mqlAwsDocumentdbInstance) isClusterWriter() (bool, error) {
	// Look up the parent cluster directly through the global cluster list rather than
	// going through a.cluster()/NewResource — this avoids a recursive resource lookup
	// that the MQL runtime cannot serialize when iterating cluster.members.
	if a.cacheClusterIdentifier == nil || *a.cacheClusterIdentifier == "" {
		return false, nil
	}
	parent, err := docdbGetParent(a.MqlRuntime)
	if err != nil {
		return false, err
	}
	clusters := parent.GetClusters()
	if clusters.Error != nil {
		return false, clusters.Error
	}
	for _, raw := range clusters.Data {
		c, ok := raw.(*mqlAwsDocumentdbCluster)
		if !ok {
			continue
		}
		if c.ClusterIdentifier.Data != *a.cacheClusterIdentifier {
			continue
		}
		if c.cacheWriterIdentifier == nil {
			return false, nil
		}
		return *c.cacheWriterIdentifier == a.Name.Data, nil
	}
	return false, nil
}

func (a *mqlAwsDocumentdbInstance) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.DocumentDB(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data
	resp, err := svc.ListTagsForResource(ctx, &docdb.ListTagsForResourceInput{ResourceName: &arn})
	if err != nil {
		return nil, err
	}
	tags := map[string]any{}
	for _, t := range resp.TagList {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	return tags, nil
}

func (a *mqlAwsDocumentdbInstance) pendingMaintenanceActions() ([]any, error) {
	parent, err := docdbGetParent(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	all, err := parent.fetchPendingMaintenanceActions()
	if err != nil {
		return nil, err
	}
	return docdbPendingActionsForArn(a.MqlRuntime, all, a.Arn.Data)
}

// ---------- aws.documentdb.snapshot ----------

func (a *mqlAwsDocumentdbSnapshot) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsDocumentdb) snapshots() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	pool := jobpool.CreatePool(a.getSnapshots(conn), 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	for i := range pool.Jobs {
		if pool.Jobs[i].Result != nil {
			res = append(res, pool.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsDocumentdb) getSnapshots(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := []*jobpool.Job{}
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("documentdb>getSnapshots>calling aws with region %s", region)
			svc := conn.DocumentDB(region)
			ctx := context.Background()
			res := []any{}
			paginator := docdb.NewDescribeDBClusterSnapshotsPaginator(svc, &docdb.DescribeDBClusterSnapshotsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, snapshot := range page.DBClusterSnapshots {
					if snapshot.Engine == nil || *snapshot.Engine != docdbEngine {
						continue
					}
					mqlSnapshot, err := newMqlAwsDocumentdbSnapshot(a.MqlRuntime, region, conn.AccountId(), snapshot)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSnapshot)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsDocumentdbSnapshot(runtime *plugin.Runtime, region, accountID string, snapshot docdb_types.DBClusterSnapshot) (*mqlAwsDocumentdbSnapshot, error) {
	resource, err := CreateResource(runtime, "aws.documentdb.snapshot",
		map[string]*llx.RawData{
			"__id":              llx.StringDataPtr(snapshot.DBClusterSnapshotArn),
			"arn":               llx.StringDataPtr(snapshot.DBClusterSnapshotArn),
			"id":                llx.StringDataPtr(snapshot.DBClusterSnapshotIdentifier),
			"clusterIdentifier": llx.StringDataPtr(snapshot.DBClusterIdentifier),
			"engine":            llx.StringDataPtr(snapshot.Engine),
			"engineVersion":     llx.StringDataPtr(snapshot.EngineVersion),
			"status":            llx.StringDataPtr(snapshot.Status),
			"snapshotType":      llx.StringDataPtr(snapshot.SnapshotType),
			"sourceSnapshot":    llx.StringDataPtr(snapshot.SourceDBClusterSnapshotArn),
			"port":              llx.IntDataDefault(snapshot.Port, 0),
			"storageEncrypted":  llx.BoolDataPtr(snapshot.StorageEncrypted),
			"storageType":       llx.StringDataPtr(snapshot.StorageType),
			"masterUsername":    llx.StringDataPtr(snapshot.MasterUsername),
			"availabilityZones": llx.ArrayData(convert.SliceAnyToInterface(snapshot.AvailabilityZones), types.String),
			"percentProgress":   llx.IntDataDefault(snapshot.PercentProgress, 0),
			"createdAt":         llx.TimeDataPtr(snapshot.SnapshotCreateTime),
			"clusterCreatedAt":  llx.TimeDataPtr(snapshot.ClusterCreateTime),
			"region":            llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mqlSnapshot := resource.(*mqlAwsDocumentdbSnapshot)
	mqlSnapshot.cacheKmsKeyId = snapshot.KmsKeyId
	mqlSnapshot.cacheVpcId = snapshot.VpcId
	mqlSnapshot.cacheClusterIdentifier = snapshot.DBClusterIdentifier
	mqlSnapshot.region = region
	mqlSnapshot.accountID = accountID
	return mqlSnapshot, nil
}

type mqlAwsDocumentdbSnapshotInternal struct {
	region                 string
	accountID              string
	cacheKmsKeyId          *string
	cacheVpcId             *string
	cacheClusterIdentifier *string
	attributesOnce         sync.Once
	attributes             []docdb_types.DBClusterSnapshotAttribute
	attributesErr          error
}

func (a *mqlAwsDocumentdbSnapshot) kmsKey() (*mqlAwsKmsKey, error) {
	return docdbResolveKmsKey(a.MqlRuntime, a.cacheKmsKeyId, &a.KmsKey)
}

func (a *mqlAwsDocumentdbSnapshot) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	mqlVpc, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{
		"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.Region.Data, conn.AccountId(), *a.cacheVpcId)),
	})
	if err != nil {
		return nil, err
	}
	return mqlVpc.(*mqlAwsVpc), nil
}

func (a *mqlAwsDocumentdbSnapshot) cluster() (*mqlAwsDocumentdbCluster, error) {
	if a.cacheClusterIdentifier == nil || *a.cacheClusterIdentifier == "" {
		a.Cluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlCluster, err := NewResource(a.MqlRuntime, "aws.documentdb.cluster", map[string]*llx.RawData{
		"arn": llx.StringData(fmt.Sprintf(docdbClusterArnPattern, a.region, a.accountID, *a.cacheClusterIdentifier)),
	})
	if err != nil {
		return nil, err
	}
	return mqlCluster.(*mqlAwsDocumentdbCluster), nil
}

func (a *mqlAwsDocumentdbSnapshot) sharedWith() ([]any, error) {
	attrs, err := a.fetchSnapshotAttributes()
	if err != nil {
		return nil, err
	}
	for _, attr := range attrs {
		if attr.AttributeName != nil && *attr.AttributeName == "restore" {
			out := make([]any, 0, len(attr.AttributeValues))
			for _, v := range attr.AttributeValues {
				out = append(out, v)
			}
			return out, nil
		}
	}
	return []any{}, nil
}

func (a *mqlAwsDocumentdbSnapshot) isPublic() (bool, error) {
	shared, err := a.sharedWith()
	if err != nil {
		return false, err
	}
	for _, v := range shared {
		if s, ok := v.(string); ok && s == "all" {
			return true, nil
		}
	}
	return false, nil
}

func (a *mqlAwsDocumentdbSnapshot) fetchSnapshotAttributes() ([]docdb_types.DBClusterSnapshotAttribute, error) {
	a.attributesOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.DocumentDB(a.Region.Data)
		ctx := context.Background()
		id := a.Id.Data
		resp, err := svc.DescribeDBClusterSnapshotAttributes(ctx, &docdb.DescribeDBClusterSnapshotAttributesInput{
			DBClusterSnapshotIdentifier: &id,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return
			}
			a.attributesErr = err
			return
		}
		if resp.DBClusterSnapshotAttributesResult != nil {
			a.attributes = resp.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes
		}
	})
	return a.attributes, a.attributesErr
}

// ---------- aws.documentdb.clusterParameterGroup ----------

func (a *mqlAwsDocumentdb) clusterParameterGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	pool := jobpool.CreatePool(a.getClusterParameterGroups(conn), 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	for i := range pool.Jobs {
		if pool.Jobs[i].Result != nil {
			res = append(res, pool.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsDocumentdb) getClusterParameterGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := []*jobpool.Job{}
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.DocumentDB(region)
			ctx := context.Background()
			res := []any{}
			paginator := docdb.NewDescribeDBClusterParameterGroupsPaginator(svc, &docdb.DescribeDBClusterParameterGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						return res, nil
					}
					return nil, err
				}
				for _, pg := range page.DBClusterParameterGroups {
					mqlPg, err := newMqlAwsDocumentdbClusterParameterGroup(a.MqlRuntime, region, pg)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsDocumentdbClusterParameterGroup(runtime *plugin.Runtime, region string, pg docdb_types.DBClusterParameterGroup) (*mqlAwsDocumentdbClusterParameterGroup, error) {
	res, err := CreateResource(runtime, "aws.documentdb.clusterParameterGroup", map[string]*llx.RawData{
		"__id":        llx.StringDataPtr(pg.DBClusterParameterGroupArn),
		"arn":         llx.StringDataPtr(pg.DBClusterParameterGroupArn),
		"name":        llx.StringDataPtr(pg.DBClusterParameterGroupName),
		"family":      llx.StringDataPtr(pg.DBParameterGroupFamily),
		"description": llx.StringDataPtr(pg.Description),
		"region":      llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsDocumentdbClusterParameterGroup), nil
}

func initAwsDocumentdbClusterParameterGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch documentdb cluster parameter group")
	}
	d, err := docdbGetParent(runtime)
	if err != nil {
		return nil, nil, err
	}
	pgs := d.GetClusterParameterGroups()
	if pgs.Error != nil {
		return nil, nil, pgs.Error
	}
	arnVal := args["arn"].Value.(string)
	for _, raw := range pgs.Data {
		pg := raw.(*mqlAwsDocumentdbClusterParameterGroup)
		if pg.Arn.Data == arnVal {
			return args, pg, nil
		}
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.documentdb.clusterParameterGroup with arn %q not found", arnVal)
}

func (a *mqlAwsDocumentdbClusterParameterGroup) parameters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.DocumentDB(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	res := []any{}
	paginator := docdb.NewDescribeDBClusterParametersPaginator(svc, &docdb.DescribeDBClusterParametersInput{
		DBClusterParameterGroupName: &name,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range page.Parameters {
			paramName := convert.ToValue(p.ParameterName)
			paramId := a.Arn.Data + "/param/" + paramName
			r, err := CreateResource(a.MqlRuntime, "aws.documentdb.clusterParameter", map[string]*llx.RawData{
				"__id":                 llx.StringData(paramId),
				"name":                 llx.StringDataPtr(p.ParameterName),
				"value":                llx.StringDataPtr(p.ParameterValue),
				"allowedValues":        llx.StringDataPtr(p.AllowedValues),
				"applyMethod":          llx.StringData(string(p.ApplyMethod)),
				"applyType":            llx.StringDataPtr(p.ApplyType),
				"dataType":             llx.StringDataPtr(p.DataType),
				"description":          llx.StringDataPtr(p.Description),
				"isModifiable":         llx.BoolDataPtr(p.IsModifiable),
				"minimumEngineVersion": llx.StringDataPtr(p.MinimumEngineVersion),
				"source":               llx.StringDataPtr(p.Source),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
	}
	return res, nil
}

// ---------- aws.documentdb.globalCluster ----------

func (a *mqlAwsDocumentdb) globalClusters() ([]any, error) {
	gcs, err := a.fetchGlobalClusters()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, gc := range gcs {
		mqlGc, err := newMqlAwsDocumentdbGlobalCluster(a.MqlRuntime, gc)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGc)
	}
	return res, nil
}

func (a *mqlAwsDocumentdb) fetchGlobalClusters() ([]docdb_types.GlobalCluster, error) {
	a.globalClustersOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		regions, err := conn.Regions()
		if err != nil {
			a.globalClustersErrCache = err
			return
		}
		out := []docdb_types.GlobalCluster{}
		seen := map[string]bool{}
		for _, region := range regions {
			svc := conn.DocumentDB(region)
			ctx := context.Background()
			paginator := docdb.NewDescribeGlobalClustersPaginator(svc, &docdb.DescribeGlobalClustersInput{})
		regionLoop:
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied describing global clusters")
						break regionLoop
					}
					a.globalClustersErrCache = err
					return
				}
				for _, gc := range page.GlobalClusters {
					if gc.GlobalClusterArn == nil || seen[*gc.GlobalClusterArn] {
						continue
					}
					seen[*gc.GlobalClusterArn] = true
					out = append(out, gc)
				}
			}
		}
		a.globalClustersCached = out
	})
	return a.globalClustersCached, a.globalClustersErrCache
}

func newMqlAwsDocumentdbGlobalCluster(runtime *plugin.Runtime, gc docdb_types.GlobalCluster) (*mqlAwsDocumentdbGlobalCluster, error) {
	res, err := CreateResource(runtime, "aws.documentdb.globalCluster", map[string]*llx.RawData{
		"__id":                    llx.StringDataPtr(gc.GlobalClusterArn),
		"arn":                     llx.StringDataPtr(gc.GlobalClusterArn),
		"globalClusterIdentifier": llx.StringDataPtr(gc.GlobalClusterIdentifier),
		"status":                  llx.StringDataPtr(gc.Status),
		"engine":                  llx.StringDataPtr(gc.Engine),
		"engineVersion":           llx.StringDataPtr(gc.EngineVersion),
		"deletionProtection":      llx.BoolDataPtr(gc.DeletionProtection),
		"databaseName":            llx.StringDataPtr(gc.DatabaseName),
		"storageEncrypted":        llx.BoolDataPtr(gc.StorageEncrypted),
		"globalClusterResourceId": llx.StringDataPtr(gc.GlobalClusterResourceId),
	})
	if err != nil {
		return nil, err
	}
	mqlGc := res.(*mqlAwsDocumentdbGlobalCluster)
	mqlGc.cacheMembers = gc.GlobalClusterMembers
	return mqlGc, nil
}

func initAwsDocumentdbGlobalCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch documentdb global cluster")
	}
	d, err := docdbGetParent(runtime)
	if err != nil {
		return nil, nil, err
	}
	gcs := d.GetGlobalClusters()
	if gcs.Error != nil {
		return nil, nil, gcs.Error
	}
	arnVal := args["arn"].Value.(string)
	for _, raw := range gcs.Data {
		gc := raw.(*mqlAwsDocumentdbGlobalCluster)
		if gc.Arn.Data == arnVal {
			return args, gc, nil
		}
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.documentdb.globalCluster with arn %q not found", arnVal)
}

type mqlAwsDocumentdbGlobalClusterInternal struct {
	cacheMembers []docdb_types.GlobalClusterMember
}

func (a *mqlAwsDocumentdbGlobalCluster) members() ([]any, error) {
	res := []any{}
	for _, m := range a.cacheMembers {
		writerArn := ""
		if m.DBClusterArn != nil {
			writerArn = *m.DBClusterArn
		}
		memberId := a.Arn.Data + "/member/" + writerArn
		isWriter := false
		if m.IsWriter != nil {
			isWriter = *m.IsWriter
		}
		r, err := CreateResource(a.MqlRuntime, "aws.documentdb.globalCluster.member", map[string]*llx.RawData{
			"__id":     llx.StringData(memberId),
			"isWriter": llx.BoolData(isWriter),
		})
		if err != nil {
			return nil, err
		}
		mqlMember := r.(*mqlAwsDocumentdbGlobalClusterMember)
		mqlMember.cacheClusterArn = writerArn
		mqlMember.cacheReaderArns = m.Readers
		res = append(res, mqlMember)
	}
	return res, nil
}

type mqlAwsDocumentdbGlobalClusterMemberInternal struct {
	cacheClusterArn string
	cacheReaderArns []string
}

func (a *mqlAwsDocumentdbGlobalClusterMember) cluster() (*mqlAwsDocumentdbCluster, error) {
	if a.cacheClusterArn == "" {
		a.Cluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlCluster, err := NewResource(a.MqlRuntime, "aws.documentdb.cluster", map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheClusterArn),
	})
	if err != nil {
		return nil, err
	}
	return mqlCluster.(*mqlAwsDocumentdbCluster), nil
}

func (a *mqlAwsDocumentdbGlobalClusterMember) readers() ([]any, error) {
	res := []any{}
	for _, arn := range a.cacheReaderArns {
		ref, err := NewResource(a.MqlRuntime, "aws.documentdb.cluster", map[string]*llx.RawData{
			"arn": llx.StringData(arn),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}

// ---------- aws.documentdb.pendingMaintenanceAction ----------

func (a *mqlAwsDocumentdb) pendingMaintenanceActions() ([]any, error) {
	all, err := a.fetchPendingMaintenanceActions()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, ra := range all {
		expanded, err := docdbBuildPendingActions(a.MqlRuntime, ra)
		if err != nil {
			return nil, err
		}
		res = append(res, expanded...)
	}
	return res, nil
}

func (a *mqlAwsDocumentdb) fetchPendingMaintenanceActions() ([]docdb_types.ResourcePendingMaintenanceActions, error) {
	a.pendingActionsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		regions, err := conn.Regions()
		if err != nil {
			a.pendingActionsErr = err
			return
		}
		out := []docdb_types.ResourcePendingMaintenanceActions{}
		for _, region := range regions {
			svc := conn.DocumentDB(region)
			ctx := context.Background()
			paginator := docdb.NewDescribePendingMaintenanceActionsPaginator(svc, &docdb.DescribePendingMaintenanceActionsInput{})
		regionLoop:
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied describing pending maintenance actions")
						break regionLoop
					}
					a.pendingActionsErr = err
					return
				}
				out = append(out, page.PendingMaintenanceActions...)
			}
		}
		a.pendingActions = out
	})
	return a.pendingActions, a.pendingActionsErr
}

func docdbBuildPendingActions(runtime *plugin.Runtime, ra docdb_types.ResourcePendingMaintenanceActions) ([]any, error) {
	res := []any{}
	resourceArn := ""
	if ra.ResourceIdentifier != nil {
		resourceArn = *ra.ResourceIdentifier
	}
	for _, pa := range ra.PendingMaintenanceActionDetails {
		action := convert.ToValue(pa.Action)
		paId := resourceArn + "/" + action
		r, err := CreateResource(runtime, "aws.documentdb.pendingMaintenanceAction", map[string]*llx.RawData{
			"__id":                 llx.StringData(paId),
			"resourceArn":          llx.StringData(resourceArn),
			"action":               llx.StringData(action),
			"description":          llx.StringDataPtr(pa.Description),
			"autoAppliedAfterDate": llx.TimeDataPtr(pa.AutoAppliedAfterDate),
			"currentApplyDate":     llx.TimeDataPtr(pa.CurrentApplyDate),
			"forcedApplyDate":      llx.TimeDataPtr(pa.ForcedApplyDate),
			"optInStatus":          llx.StringDataPtr(pa.OptInStatus),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func docdbPendingActionsForArn(runtime *plugin.Runtime, all []docdb_types.ResourcePendingMaintenanceActions, target string) ([]any, error) {
	res := []any{}
	for _, ra := range all {
		if ra.ResourceIdentifier == nil || *ra.ResourceIdentifier != target {
			continue
		}
		expanded, err := docdbBuildPendingActions(runtime, ra)
		if err != nil {
			return nil, err
		}
		res = append(res, expanded...)
	}
	return res, nil
}

// ---------- aws.documentdb.elasticCluster ----------

func (a *mqlAwsDocumentdb) elasticClusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	pool := jobpool.CreatePool(a.getElasticClusters(conn), 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	for i := range pool.Jobs {
		if pool.Jobs[i].Result != nil {
			res = append(res, pool.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsDocumentdb) getElasticClusters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := []*jobpool.Job{}
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.DocumentDBElastic(region)
			ctx := context.Background()
			res := []any{}
			paginator := docdbelastic.NewListClustersPaginator(svc, &docdbelastic.ListClustersInput{})
			var arns []string
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing elastic clusters")
						return res, nil
					}
					return nil, err
				}
				for _, summary := range page.Clusters {
					if summary.ClusterArn != nil {
						arns = append(arns, *summary.ClusterArn)
					}
				}
			}

			details := make([]*docdbelastic_types.Cluster, len(arns))
			g, gctx := errgroup.WithContext(ctx)
			g.SetLimit(10)
			for i, arn := range arns {
				g.Go(func() error {
					resp, err := svc.GetCluster(gctx, &docdbelastic.GetClusterInput{ClusterArn: &arn})
					if err != nil {
						log.Warn().Str("region", region).Str("clusterArn", arn).Err(err).Msg("get elastic cluster failed; skipping")
						return nil
					}
					if resp != nil {
						details[i] = resp.Cluster
					}
					return nil
				})
			}
			_ = g.Wait()

			for _, detail := range details {
				if detail == nil {
					continue
				}
				mqlEc, err := newMqlAwsDocumentdbElasticCluster(a.MqlRuntime, region, conn.AccountId(), *detail)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlEc)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsDocumentdbElasticCluster(runtime *plugin.Runtime, region, accountID string, c docdbelastic_types.Cluster) (*mqlAwsDocumentdbElasticCluster, error) {
	res, err := CreateResource(runtime, "aws.documentdb.elasticCluster", map[string]*llx.RawData{
		"__id":                       llx.StringDataPtr(c.ClusterArn),
		"arn":                        llx.StringDataPtr(c.ClusterArn),
		"name":                       llx.StringDataPtr(c.ClusterName),
		"status":                     llx.StringData(string(c.Status)),
		"adminUserName":              llx.StringDataPtr(c.AdminUserName),
		"authType":                   llx.StringData(string(c.AuthType)),
		"shardCapacity":              llx.IntDataDefault(c.ShardCapacity, 0),
		"shardCount":                 llx.IntDataDefault(c.ShardCount, 0),
		"shardInstanceCount":         llx.IntDataDefault(c.ShardInstanceCount, 0),
		"backupRetentionPeriod":      llx.IntDataDefault(c.BackupRetentionPeriod, 0),
		"preferredBackupWindow":      llx.StringDataPtr(c.PreferredBackupWindow),
		"preferredMaintenanceWindow": llx.StringDataPtr(c.PreferredMaintenanceWindow),
		"createdAt":                  llx.StringDataPtr(c.CreateTime),
		"endpoint":                   llx.StringDataPtr(c.ClusterEndpoint),
		"region":                     llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	mqlEc := res.(*mqlAwsDocumentdbElasticCluster)
	mqlEc.region = region
	mqlEc.accountID = accountID
	mqlEc.cacheKmsKeyId = c.KmsKeyId
	mqlEc.cacheSubnetIds = c.SubnetIds
	sgArns := []string{}
	for _, sg := range c.VpcSecurityGroupIds {
		sgArns = append(sgArns, NewSecurityGroupArn(region, accountID, sg))
	}
	mqlEc.setSecurityGroupArns(sgArns)
	return mqlEc, nil
}

func initAwsDocumentdbElasticCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch documentdb elastic cluster")
	}
	d, err := docdbGetParent(runtime)
	if err != nil {
		return nil, nil, err
	}
	clusters := d.GetElasticClusters()
	if clusters.Error != nil {
		return nil, nil, clusters.Error
	}
	arnVal := args["arn"].Value.(string)
	for _, raw := range clusters.Data {
		c := raw.(*mqlAwsDocumentdbElasticCluster)
		if c.Arn.Data == arnVal {
			return args, c, nil
		}
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.documentdb.elasticCluster with arn %q not found", arnVal)
}

type mqlAwsDocumentdbElasticClusterInternal struct {
	securityGroupIdHandler
	region         string
	accountID      string
	cacheKmsKeyId  *string
	cacheSubnetIds []string
}

func (a *mqlAwsDocumentdbElasticCluster) kmsKey() (*mqlAwsKmsKey, error) {
	return docdbResolveKmsKey(a.MqlRuntime, a.cacheKmsKeyId, &a.KmsKey)
}

func (a *mqlAwsDocumentdbElasticCluster) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsDocumentdbElasticCluster) subnets() ([]any, error) {
	return docdbResolveSubnets(a.MqlRuntime, a.region, a.accountID, a.cacheSubnetIds)
}

func docdbResolveSubnets(runtime *plugin.Runtime, region, accountID string, ids []string) ([]any, error) {
	if accountID == "" {
		conn := runtime.Connection.(*connection.AwsConnection)
		accountID = conn.AccountId()
	}
	res := []any{}
	for _, id := range ids {
		ref, err := NewResource(runtime, ResourceAwsVpcSubnet, map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, region, accountID, id)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}

func (a *mqlAwsDocumentdbElasticCluster) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.DocumentDBElastic(a.Region.Data)
	ctx := context.Background()
	resp, err := svc.ListTagsForResource(ctx, &docdbelastic.ListTagsForResourceInput{ResourceArn: &a.Arn.Data})
	if err != nil {
		return nil, err
	}
	tags := map[string]any{}
	for k, v := range resp.Tags {
		tags[k] = v
	}
	return tags, nil
}

func (a *mqlAwsDocumentdbElasticCluster) snapshots() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.DocumentDBElastic(a.Region.Data)
	ctx := context.Background()
	res := []any{}
	paginator := docdbelastic.NewListClusterSnapshotsPaginator(svc, &docdbelastic.ListClusterSnapshotsInput{
		ClusterArn: &a.Arn.Data,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, summary := range page.Snapshots {
			if summary.SnapshotArn == nil {
				continue
			}
			detail, err := svc.GetClusterSnapshot(ctx, &docdbelastic.GetClusterSnapshotInput{
				SnapshotArn: summary.SnapshotArn,
			})
			if err != nil {
				log.Warn().Str("region", a.Region.Data).Str("snapshotArn", *summary.SnapshotArn).Err(err).Msg("get elastic snapshot failed; skipping")
				continue
			}
			if detail.Snapshot == nil {
				continue
			}
			mqlSnap, err := newMqlAwsDocumentdbElasticSnapshot(a.MqlRuntime, a.Region.Data, conn.AccountId(), *detail.Snapshot)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSnap)
		}
	}
	return res, nil
}

// ---------- aws.documentdb.elasticSnapshot ----------

func (a *mqlAwsDocumentdb) elasticSnapshots() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	pool := jobpool.CreatePool(a.getElasticSnapshots(conn), 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}
	for i := range pool.Jobs {
		if pool.Jobs[i].Result != nil {
			res = append(res, pool.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsDocumentdb) getElasticSnapshots(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := []*jobpool.Job{}
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.DocumentDBElastic(region)
			ctx := context.Background()
			res := []any{}
			paginator := docdbelastic.NewListClusterSnapshotsPaginator(svc, &docdbelastic.ListClusterSnapshotsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing elastic snapshots")
						return res, nil
					}
					return nil, err
				}
				for _, summary := range page.Snapshots {
					if summary.SnapshotArn == nil {
						continue
					}
					detail, err := svc.GetClusterSnapshot(ctx, &docdbelastic.GetClusterSnapshotInput{
						SnapshotArn: summary.SnapshotArn,
					})
					if err != nil {
						log.Warn().Str("region", region).Str("snapshotArn", *summary.SnapshotArn).Err(err).Msg("get elastic snapshot failed; skipping")
						continue
					}
					if detail.Snapshot == nil {
						continue
					}
					mqlSnap, err := newMqlAwsDocumentdbElasticSnapshot(a.MqlRuntime, region, conn.AccountId(), *detail.Snapshot)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSnap)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsDocumentdbElasticSnapshot(runtime *plugin.Runtime, region, accountID string, s docdbelastic_types.ClusterSnapshot) (*mqlAwsDocumentdbElasticSnapshot, error) {
	res, err := CreateResource(runtime, "aws.documentdb.elasticSnapshot", map[string]*llx.RawData{
		"__id":                 llx.StringDataPtr(s.SnapshotArn),
		"arn":                  llx.StringDataPtr(s.SnapshotArn),
		"name":                 llx.StringDataPtr(s.SnapshotName),
		"status":               llx.StringData(string(s.Status)),
		"snapshotType":         llx.StringData(string(s.SnapshotType)),
		"snapshotCreationTime": llx.StringDataPtr(s.SnapshotCreationTime),
		"adminUserName":        llx.StringDataPtr(s.AdminUserName),
		"region":               llx.StringData(region),
	})
	if err != nil {
		return nil, err
	}
	mqlSnap := res.(*mqlAwsDocumentdbElasticSnapshot)
	mqlSnap.region = region
	mqlSnap.accountID = accountID
	mqlSnap.cacheKmsKeyId = s.KmsKeyId
	mqlSnap.cacheSubnetIds = s.SubnetIds
	mqlSnap.cacheClusterArn = convert.ToValue(s.ClusterArn)
	sgArns := []string{}
	for _, sg := range s.VpcSecurityGroupIds {
		sgArns = append(sgArns, NewSecurityGroupArn(region, accountID, sg))
	}
	mqlSnap.setSecurityGroupArns(sgArns)
	return mqlSnap, nil
}

type mqlAwsDocumentdbElasticSnapshotInternal struct {
	securityGroupIdHandler
	region          string
	accountID       string
	cacheKmsKeyId   *string
	cacheSubnetIds  []string
	cacheClusterArn string
}

func (a *mqlAwsDocumentdbElasticSnapshot) kmsKey() (*mqlAwsKmsKey, error) {
	return docdbResolveKmsKey(a.MqlRuntime, a.cacheKmsKeyId, &a.KmsKey)
}

func (a *mqlAwsDocumentdbElasticSnapshot) cluster() (*mqlAwsDocumentdbElasticCluster, error) {
	if a.cacheClusterArn == "" {
		a.Cluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlCluster, err := NewResource(a.MqlRuntime, "aws.documentdb.elasticCluster", map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheClusterArn),
	})
	if err != nil {
		return nil, err
	}
	return mqlCluster.(*mqlAwsDocumentdbElasticCluster), nil
}

func (a *mqlAwsDocumentdbElasticSnapshot) subnets() ([]any, error) {
	return docdbResolveSubnets(a.MqlRuntime, a.region, a.accountID, a.cacheSubnetIds)
}

func (a *mqlAwsDocumentdbElasticSnapshot) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsDocumentdbElasticSnapshot) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.DocumentDBElastic(a.Region.Data)
	ctx := context.Background()
	resp, err := svc.ListTagsForResource(ctx, &docdbelastic.ListTagsForResourceInput{ResourceArn: &a.Arn.Data})
	if err != nil {
		return nil, err
	}
	tags := map[string]any{}
	for k, v := range resp.Tags {
		tags[k] = v
	}
	return tags, nil
}

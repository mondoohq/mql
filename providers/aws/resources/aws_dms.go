// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// ===== Internal struct layouts =====

type mqlAwsDmsReplicationInstanceInternal struct {
	lazyTags
	securityGroupIdHandler
	region                        string
	accountID                     string
	cacheKmsKeyId                 *string
	cacheReplicationSubnetGroupId *string
}

type mqlAwsDmsEndpointInternal struct {
	lazyTags
	region                    string
	accountID                 string
	cacheKmsKeyId             *string
	cacheCertificate          *string
	cacheServiceAccessRoleArn *string
}

type mqlAwsDmsReplicationTaskInternal struct {
	lazyTags
	region                      string
	accountID                   string
	cacheSourceEndpointArn      *string
	cacheTargetEndpointArn      *string
	cacheReplicationInstanceArn *string
}

type mqlAwsDmsReplicationSubnetGroupInternal struct {
	region         string
	accountID      string
	cacheVpcId     *string
	cacheSubnetIds []string
}

// ===== aws.dms namespace =====

func (a *mqlAwsDms) id() (string, error) {
	return "aws.dms", nil
}

// ===== aws.dms.replicationInstance =====

func (a *mqlAwsDmsReplicationInstance) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsDms) replicationInstances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getReplicationInstances(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	var errs []error
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Err != nil {
			errs = append(errs, poolOfJobs.Jobs[i].Err)
		}
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, errors.Join(errs...)
}

func (a *mqlAwsDms) getReplicationInstances(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("dms>getReplicationInstances>calling aws with region %s", region)

			svc := conn.Dms(region)
			ctx := context.Background()
			res := []any{}

			paginator := databasemigrationservice.NewDescribeReplicationInstancesPaginator(svc, &databasemigrationservice.DescribeReplicationInstancesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for i := range page.ReplicationInstances {
					mqlInst, err := newMqlAwsDmsReplicationInstance(a.MqlRuntime, region, conn.AccountId(), page.ReplicationInstances[i])
					if err != nil {
						return nil, err
					}
					res = append(res, mqlInst)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsDmsReplicationInstance(runtime *plugin.Runtime, region, accountID string, inst dmstypes.ReplicationInstance) (*mqlAwsDmsReplicationInstance, error) {
	var pendingDict any
	if inst.PendingModifiedValues != nil {
		dict, err := convert.JsonToDict(inst.PendingModifiedValues)
		if err != nil {
			return nil, err
		}
		// Every unset pointer marshals as a null-valued key, so an instance
		// with nothing pending would otherwise report a dict full of nulls.
		for k, v := range dict {
			if v == nil {
				delete(dict, k)
			}
		}
		if len(dict) > 0 {
			pendingDict = dict
		}
	}

	args := map[string]*llx.RawData{
		"arn":                                   llx.StringDataPtr(inst.ReplicationInstanceArn),
		"replicationInstanceIdentifier":         llx.StringDataPtr(inst.ReplicationInstanceIdentifier),
		"replicationInstanceClass":              llx.StringDataPtr(inst.ReplicationInstanceClass),
		"replicationInstanceStatus":             llx.StringDataPtr(inst.ReplicationInstanceStatus),
		"engineVersion":                         llx.StringDataPtr(inst.EngineVersion),
		"autoMinorVersionUpgrade":               llx.BoolData(inst.AutoMinorVersionUpgrade),
		"multiAZ":                               llx.BoolData(inst.MultiAZ),
		"publiclyAccessible":                    llx.BoolData(inst.PubliclyAccessible),
		"allocatedStorage":                      llx.IntData(int64(inst.AllocatedStorage)),
		"availabilityZone":                      llx.StringDataPtr(inst.AvailabilityZone),
		"secondaryAvailabilityZone":             llx.StringDataPtr(inst.SecondaryAvailabilityZone),
		"instanceCreateTime":                    llx.TimeDataPtr(inst.InstanceCreateTime),
		"preferredMaintenanceWindow":            llx.StringDataPtr(inst.PreferredMaintenanceWindow),
		"networkType":                           llx.StringDataPtr(inst.NetworkType),
		"replicationInstancePrivateIpAddresses": llx.ArrayData(convert.SliceAnyToInterface(inst.ReplicationInstancePrivateIpAddresses), types.String),
		"replicationInstancePublicIpAddresses":  llx.ArrayData(convert.SliceAnyToInterface(inst.ReplicationInstancePublicIpAddresses), types.String),
		"replicationInstanceIpv6Addresses":      llx.ArrayData(convert.SliceAnyToInterface(inst.ReplicationInstanceIpv6Addresses), types.String),
		"dnsNameServers":                        llx.StringDataPtr(inst.DnsNameServers),
		"region":                                llx.StringData(region),
		"pendingModifiedValues":                 llx.DictData(pendingDict),
	}

	resource, err := CreateResource(runtime, "aws.dms.replicationInstance", args)
	if err != nil {
		return nil, err
	}

	mqlInst := resource.(*mqlAwsDmsReplicationInstance)
	mqlInst.region = region
	mqlInst.accountID = accountID
	mqlInst.cacheKmsKeyId = inst.KmsKeyId
	if inst.ReplicationSubnetGroup != nil {
		mqlInst.cacheReplicationSubnetGroupId = inst.ReplicationSubnetGroup.ReplicationSubnetGroupIdentifier
	}

	sgArns := []string{}
	for _, sg := range inst.VpcSecurityGroups {
		if sg.VpcSecurityGroupId != nil {
			sgArns = append(sgArns, NewSecurityGroupArn(region, accountID, *sg.VpcSecurityGroupId))
		}
	}
	mqlInst.setSecurityGroupArns(sgArns)
	return mqlInst, nil
}

func (a *mqlAwsDmsReplicationInstance) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey, map[string]*llx.RawData{
		"arn": llx.StringDataPtr(a.cacheKmsKeyId),
	})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsDmsReplicationInstance) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsDmsReplicationInstance) subnetGroup() (*mqlAwsDmsReplicationSubnetGroup, error) {
	if a.cacheReplicationSubnetGroupId == nil || *a.cacheReplicationSubnetGroupId == "" {
		a.SubnetGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlSg, err := NewResource(a.MqlRuntime, "aws.dms.replicationSubnetGroup", map[string]*llx.RawData{
		"replicationSubnetGroupIdentifier": llx.StringDataPtr(a.cacheReplicationSubnetGroupId),
		"region":                           llx.StringData(a.region),
	})
	if err != nil {
		return nil, err
	}
	return mqlSg.(*mqlAwsDmsReplicationSubnetGroup), nil
}

func initAwsDmsReplicationInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch DMS replication instance")
	}
	arnVal, ok := args["arn"].Value.(string)
	if !ok || arnVal == "" {
		return nil, nil, errors.New("arn required to fetch DMS replication instance")
	}

	dms, err := dmsGetParent(runtime)
	if err != nil {
		return nil, nil, err
	}
	all := dms.GetReplicationInstances()
	if all.Error != nil {
		return nil, nil, all.Error
	}
	for _, raw := range all.Data {
		inst := raw.(*mqlAwsDmsReplicationInstance)
		if inst.Arn.Data == arnVal {
			return args, inst, nil
		}
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.dms.replicationInstance with arn %q not found", arnVal)
}

// ===== aws.dms.endpoint =====

func (a *mqlAwsDmsEndpoint) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsDms) endpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getEndpoints(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	var errs []error
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Err != nil {
			errs = append(errs, poolOfJobs.Jobs[i].Err)
		}
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, errors.Join(errs...)
}

func (a *mqlAwsDms) getEndpoints(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("dms>getEndpoints>calling aws with region %s", region)

			svc := conn.Dms(region)
			ctx := context.Background()
			res := []any{}

			paginator := databasemigrationservice.NewDescribeEndpointsPaginator(svc, &databasemigrationservice.DescribeEndpointsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for i := range page.Endpoints {
					mqlEp, err := newMqlAwsDmsEndpoint(a.MqlRuntime, region, conn.AccountId(), page.Endpoints[i])
					if err != nil {
						return nil, err
					}
					res = append(res, mqlEp)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsDmsEndpoint(runtime *plugin.Runtime, region, accountID string, ep dmstypes.Endpoint) (*mqlAwsDmsEndpoint, error) {
	args := map[string]*llx.RawData{
		"arn":                       llx.StringDataPtr(ep.EndpointArn),
		"endpointIdentifier":        llx.StringDataPtr(ep.EndpointIdentifier),
		"endpointType":              llx.StringData(string(ep.EndpointType)),
		"engineName":                llx.StringDataPtr(ep.EngineName),
		"engineDisplayName":         llx.StringDataPtr(ep.EngineDisplayName),
		"username":                  llx.StringDataPtr(ep.Username),
		"serverName":                llx.StringDataPtr(ep.ServerName),
		"port":                      llx.IntDataPtr(ep.Port),
		"databaseName":              llx.StringDataPtr(ep.DatabaseName),
		"status":                    llx.StringDataPtr(ep.Status),
		"sslMode":                   llx.StringData(string(ep.SslMode)),
		"isReadOnly":                llx.BoolDataPtr(ep.IsReadOnly),
		"extraConnectionAttributes": llx.StringDataPtr(ep.ExtraConnectionAttributes),
		"region":                    llx.StringData(region),
	}

	resource, err := CreateResource(runtime, "aws.dms.endpoint", args)
	if err != nil {
		return nil, err
	}

	mqlEp := resource.(*mqlAwsDmsEndpoint)
	mqlEp.region = region
	mqlEp.accountID = accountID
	mqlEp.cacheKmsKeyId = ep.KmsKeyId
	mqlEp.cacheCertificate = ep.CertificateArn
	mqlEp.cacheServiceAccessRoleArn = ep.ServiceAccessRoleArn
	return mqlEp, nil
}

func (a *mqlAwsDmsEndpoint) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey, map[string]*llx.RawData{
		"arn": llx.StringDataPtr(a.cacheKmsKeyId),
	})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsDmsEndpoint) certificate() (*mqlAwsAcmCertificate, error) {
	if a.cacheCertificate == nil || *a.cacheCertificate == "" {
		a.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlCert, err := NewResource(a.MqlRuntime, ResourceAwsAcmCertificate, map[string]*llx.RawData{
		"arn": llx.StringDataPtr(a.cacheCertificate),
	})
	if err != nil {
		return nil, err
	}
	return mqlCert.(*mqlAwsAcmCertificate), nil
}

func (a *mqlAwsDmsEndpoint) serviceAccessIamRole() (*mqlAwsIamRole, error) {
	if a.cacheServiceAccessRoleArn == nil || *a.cacheServiceAccessRoleArn == "" {
		a.ServiceAccessIamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, "aws.iam.role", map[string]*llx.RawData{
		"arn": llx.StringDataPtr(a.cacheServiceAccessRoleArn),
	})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func initAwsDmsEndpoint(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch DMS endpoint")
	}
	arnVal, ok := args["arn"].Value.(string)
	if !ok || arnVal == "" {
		return nil, nil, errors.New("arn required to fetch DMS endpoint")
	}

	dms, err := dmsGetParent(runtime)
	if err != nil {
		return nil, nil, err
	}
	all := dms.GetEndpoints()
	if all.Error != nil {
		return nil, nil, all.Error
	}
	for _, raw := range all.Data {
		ep := raw.(*mqlAwsDmsEndpoint)
		if ep.Arn.Data == arnVal {
			return args, ep, nil
		}
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.dms.endpoint with arn %q not found", arnVal)
}

// ===== aws.dms.replicationTask =====

func (a *mqlAwsDmsReplicationTask) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsDms) replicationTasks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getReplicationTasks(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	var errs []error
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Err != nil {
			errs = append(errs, poolOfJobs.Jobs[i].Err)
		}
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, errors.Join(errs...)
}

func (a *mqlAwsDms) getReplicationTasks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("dms>getReplicationTasks>calling aws with region %s", region)

			svc := conn.Dms(region)
			ctx := context.Background()
			res := []any{}

			paginator := databasemigrationservice.NewDescribeReplicationTasksPaginator(svc, &databasemigrationservice.DescribeReplicationTasksInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for i := range page.ReplicationTasks {
					mqlTask, err := newMqlAwsDmsReplicationTask(a.MqlRuntime, region, conn.AccountId(), page.ReplicationTasks[i])
					if err != nil {
						return nil, err
					}
					res = append(res, mqlTask)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsDmsReplicationTask(runtime *plugin.Runtime, region, accountID string, task dmstypes.ReplicationTask) (*mqlAwsDmsReplicationTask, error) {
	args := map[string]*llx.RawData{
		"arn":                         llx.StringDataPtr(task.ReplicationTaskArn),
		"replicationTaskIdentifier":   llx.StringDataPtr(task.ReplicationTaskIdentifier),
		"migrationType":               llx.StringData(string(task.MigrationType)),
		"status":                      llx.StringDataPtr(task.Status),
		"lastFailureMessage":          llx.StringDataPtr(task.LastFailureMessage),
		"stopReason":                  llx.StringDataPtr(task.StopReason),
		"replicationTaskCreationDate": llx.TimeDataPtr(task.ReplicationTaskCreationDate),
		"replicationTaskStartDate":    llx.TimeDataPtr(task.ReplicationTaskStartDate),
		"cdcStartPosition":            llx.StringDataPtr(task.CdcStartPosition),
		"cdcStopPosition":             llx.StringDataPtr(task.CdcStopPosition),
		"recoveryCheckpoint":          llx.StringDataPtr(task.RecoveryCheckpoint),
		"region":                      llx.StringData(region),
	}

	if task.ReplicationTaskStats != nil {
		stats := task.ReplicationTaskStats
		args["fullLoadProgressPercent"] = llx.IntData(int64(stats.FullLoadProgressPercent))
		args["elapsedTimeMillis"] = llx.IntData(stats.ElapsedTimeMillis)
		args["tablesLoaded"] = llx.IntData(int64(stats.TablesLoaded))
		args["tablesLoading"] = llx.IntData(int64(stats.TablesLoading))
		args["tablesQueued"] = llx.IntData(int64(stats.TablesQueued))
		args["tablesErrored"] = llx.IntData(int64(stats.TablesErrored))
	} else {
		args["fullLoadProgressPercent"] = llx.IntData(0)
		args["elapsedTimeMillis"] = llx.IntData(0)
		args["tablesLoaded"] = llx.IntData(0)
		args["tablesLoading"] = llx.IntData(0)
		args["tablesQueued"] = llx.IntData(0)
		args["tablesErrored"] = llx.IntData(0)
	}

	resource, err := CreateResource(runtime, "aws.dms.replicationTask", args)
	if err != nil {
		return nil, err
	}

	mqlTask := resource.(*mqlAwsDmsReplicationTask)
	mqlTask.region = region
	mqlTask.accountID = accountID
	mqlTask.cacheSourceEndpointArn = task.SourceEndpointArn
	mqlTask.cacheTargetEndpointArn = task.TargetEndpointArn
	mqlTask.cacheReplicationInstanceArn = task.ReplicationInstanceArn
	return mqlTask, nil
}

func (a *mqlAwsDmsReplicationTask) sourceEndpoint() (*mqlAwsDmsEndpoint, error) {
	if a.cacheSourceEndpointArn == nil || *a.cacheSourceEndpointArn == "" {
		a.SourceEndpoint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlEp, err := NewResource(a.MqlRuntime, "aws.dms.endpoint", map[string]*llx.RawData{
		"arn": llx.StringDataPtr(a.cacheSourceEndpointArn),
	})
	if err != nil {
		return nil, err
	}
	return mqlEp.(*mqlAwsDmsEndpoint), nil
}

func (a *mqlAwsDmsReplicationTask) targetEndpoint() (*mqlAwsDmsEndpoint, error) {
	if a.cacheTargetEndpointArn == nil || *a.cacheTargetEndpointArn == "" {
		a.TargetEndpoint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlEp, err := NewResource(a.MqlRuntime, "aws.dms.endpoint", map[string]*llx.RawData{
		"arn": llx.StringDataPtr(a.cacheTargetEndpointArn),
	})
	if err != nil {
		return nil, err
	}
	return mqlEp.(*mqlAwsDmsEndpoint), nil
}

func (a *mqlAwsDmsReplicationTask) replicationInstance() (*mqlAwsDmsReplicationInstance, error) {
	if a.cacheReplicationInstanceArn == nil || *a.cacheReplicationInstanceArn == "" {
		a.ReplicationInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlInst, err := NewResource(a.MqlRuntime, "aws.dms.replicationInstance", map[string]*llx.RawData{
		"arn": llx.StringDataPtr(a.cacheReplicationInstanceArn),
	})
	if err != nil {
		return nil, err
	}
	return mqlInst.(*mqlAwsDmsReplicationInstance), nil
}

// ===== aws.dms.replicationSubnetGroup =====

func (a *mqlAwsDmsReplicationSubnetGroup) id() (string, error) {
	return "aws.dms.replicationSubnetGroup/" + a.Region.Data + "/" + a.ReplicationSubnetGroupIdentifier.Data, nil
}

func (a *mqlAwsDms) replicationSubnetGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getReplicationSubnetGroups(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	var errs []error
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Err != nil {
			errs = append(errs, poolOfJobs.Jobs[i].Err)
		}
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, errors.Join(errs...)
}

func (a *mqlAwsDms) getReplicationSubnetGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("dms>getReplicationSubnetGroups>calling aws with region %s", region)

			svc := conn.Dms(region)
			ctx := context.Background()
			res := []any{}

			paginator := databasemigrationservice.NewDescribeReplicationSubnetGroupsPaginator(svc, &databasemigrationservice.DescribeReplicationSubnetGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for i := range page.ReplicationSubnetGroups {
					mqlSg, err := newMqlAwsDmsReplicationSubnetGroup(a.MqlRuntime, region, conn.AccountId(), page.ReplicationSubnetGroups[i])
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsDmsReplicationSubnetGroup(runtime *plugin.Runtime, region, accountID string, sg dmstypes.ReplicationSubnetGroup) (*mqlAwsDmsReplicationSubnetGroup, error) {
	args := map[string]*llx.RawData{
		"replicationSubnetGroupIdentifier":  llx.StringDataPtr(sg.ReplicationSubnetGroupIdentifier),
		"replicationSubnetGroupDescription": llx.StringDataPtr(sg.ReplicationSubnetGroupDescription),
		"subnetGroupStatus":                 llx.StringDataPtr(sg.SubnetGroupStatus),
		"supportedNetworkTypes":             llx.ArrayData(convert.SliceAnyToInterface(sg.SupportedNetworkTypes), types.String),
		"isReadOnly":                        llx.BoolDataPtr(sg.IsReadOnly),
		"region":                            llx.StringData(region),
	}

	resource, err := CreateResource(runtime, "aws.dms.replicationSubnetGroup", args)
	if err != nil {
		return nil, err
	}

	mqlSg := resource.(*mqlAwsDmsReplicationSubnetGroup)
	mqlSg.region = region
	mqlSg.accountID = accountID
	mqlSg.cacheVpcId = sg.VpcId

	subnetIds := []string{}
	for _, s := range sg.Subnets {
		if s.SubnetIdentifier != nil {
			subnetIds = append(subnetIds, *s.SubnetIdentifier)
		}
	}
	mqlSg.cacheSubnetIds = subnetIds
	return mqlSg, nil
}

func (a *mqlAwsDmsReplicationSubnetGroup) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlVpc, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{
		"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.region, a.accountID, *a.cacheVpcId)),
	})
	if err != nil {
		return nil, err
	}
	return mqlVpc.(*mqlAwsVpc), nil
}

func (a *mqlAwsDmsReplicationSubnetGroup) subnets() ([]any, error) {
	res := []any{}
	for _, subnetId := range a.cacheSubnetIds {
		ref, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet, map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.region, a.accountID, subnetId)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}

func initAwsDmsReplicationSubnetGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["replicationSubnetGroupIdentifier"] == nil {
		return nil, nil, errors.New("replicationSubnetGroupIdentifier required to fetch DMS replication subnet group")
	}
	idVal, ok := args["replicationSubnetGroupIdentifier"].Value.(string)
	if !ok || idVal == "" {
		return nil, nil, errors.New("replicationSubnetGroupIdentifier required to fetch DMS replication subnet group")
	}
	regionVal := ""
	if args["region"] != nil {
		if v, ok := args["region"].Value.(string); ok {
			regionVal = v
		}
	}

	dms, err := dmsGetParent(runtime)
	if err != nil {
		return nil, nil, err
	}
	all := dms.GetReplicationSubnetGroups()
	if all.Error != nil {
		return nil, nil, all.Error
	}
	for _, raw := range all.Data {
		sg := raw.(*mqlAwsDmsReplicationSubnetGroup)
		if sg.ReplicationSubnetGroupIdentifier.Data != idVal {
			continue
		}
		if regionVal != "" && sg.Region.Data != regionVal {
			continue
		}
		return args, sg, nil
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.dms.replicationSubnetGroup with identifier %q not found", idVal)
}

// ===== shared helpers =====

func dmsGetParent(runtime *plugin.Runtime) (*mqlAwsDms, error) {
	res, err := NewResource(runtime, "aws.dms", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsDms), nil
}

func (a *mqlAwsDmsReplicationInstance) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Dms(a.Region.Data)
		arn := a.Arn.Data
		resp, err := svc.ListTagsForResource(context.Background(), &databasemigrationservice.ListTagsForResourceInput{ResourceArn: &arn})
		if err != nil {
			if Is400AccessDeniedError(err) {
				if plugin.StructuredErrors() {
					return nil, llx.Forbidden(err, llx.WithPermissions("dms:ListTagsForResource"))
				}
				return nil, errTagsUnreadable
			}
			return nil, err
		}
		return tagsToMap(resp.TagList, func(t dmstypes.Tag) *string { return t.Key }, func(t dmstypes.Tag) *string { return t.Value }), nil
	})
}

func (a *mqlAwsDmsEndpoint) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Dms(a.Region.Data)
		arn := a.Arn.Data
		resp, err := svc.ListTagsForResource(context.Background(), &databasemigrationservice.ListTagsForResourceInput{ResourceArn: &arn})
		if err != nil {
			if Is400AccessDeniedError(err) {
				if plugin.StructuredErrors() {
					return nil, llx.Forbidden(err, llx.WithPermissions("dms:ListTagsForResource"))
				}
				return nil, errTagsUnreadable
			}
			return nil, err
		}
		return tagsToMap(resp.TagList, func(t dmstypes.Tag) *string { return t.Key }, func(t dmstypes.Tag) *string { return t.Value }), nil
	})
}

func (a *mqlAwsDmsReplicationTask) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Dms(a.Region.Data)
		arn := a.Arn.Data
		resp, err := svc.ListTagsForResource(context.Background(), &databasemigrationservice.ListTagsForResourceInput{ResourceArn: &arn})
		if err != nil {
			if Is400AccessDeniedError(err) {
				if plugin.StructuredErrors() {
					return nil, llx.Forbidden(err, llx.WithPermissions("dms:ListTagsForResource"))
				}
				return nil, errTagsUnreadable
			}
			return nil, err
		}
		return tagsToMap(resp.TagList, func(t dmstypes.Tag) *string { return t.Key }, func(t dmstypes.Tag) *string { return t.Value }), nil
	})
}

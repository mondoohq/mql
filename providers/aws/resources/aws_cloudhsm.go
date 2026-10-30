// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudhsmv2"
	cloudhsmv2_types "github.com/aws/aws-sdk-go-v2/service/cloudhsmv2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsCloudhsm) id() (string, error) {
	return "aws.cloudhsm", nil
}

func cloudHsmTagsToMap(tags []cloudhsmv2_types.Tag) map[string]any {
	return tagsToMap(tags, func(t cloudhsmv2_types.Tag) *string { return t.Key }, func(t cloudhsmv2_types.Tag) *string { return t.Value })
}

// ---- aws.cloudhsm.cluster ----

func (a *mqlAwsCloudhsm) clusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getClusters(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsCloudhsm) getClusters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("cloudhsm>getClusters>calling aws with region %s", region)

			svc := conn.CloudHsmV2(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				page, err := svc.DescribeClusters(ctx, &cloudhsmv2.DescribeClustersInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("CloudHSM service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, cluster := range page.Clusters {
					mqlCluster, err := newMqlAwsCloudhsmCluster(a.MqlRuntime, region, conn.AccountId(), cluster)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCluster)
				}
				if page.NextToken == nil {
					break
				}
				nextToken = page.NextToken
			}
			return res, nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsCloudhsmCluster(runtime *plugin.Runtime, region string, accountID string, cluster cloudhsmv2_types.Cluster) (*mqlAwsCloudhsmCluster, error) {
	clusterId := convert.ToValue(cluster.ClusterId)

	var createTimestamp *llx.RawData
	if cluster.CreateTimestamp != nil {
		createTimestamp = llx.TimeData(*cluster.CreateTimestamp)
	} else {
		createTimestamp = llx.NilData
	}

	backupRetentionDays := 0
	if cluster.BackupRetentionPolicy != nil &&
		cluster.BackupRetentionPolicy.Type == cloudhsmv2_types.BackupRetentionTypeDays &&
		cluster.BackupRetentionPolicy.Value != nil {
		if v, err := strconv.Atoi(*cluster.BackupRetentionPolicy.Value); err == nil {
			backupRetentionDays = v
		}
	}

	certificates := map[string]any{}
	if cluster.Certificates != nil {
		certificates["clusterCsr"] = convert.ToValue(cluster.Certificates.ClusterCsr)
		certificates["clusterCertificate"] = convert.ToValue(cluster.Certificates.ClusterCertificate)
		certificates["hsmCertificate"] = convert.ToValue(cluster.Certificates.HsmCertificate)
		certificates["awsHardwareCertificate"] = convert.ToValue(cluster.Certificates.AwsHardwareCertificate)
		certificates["manufacturerHardwareCertificate"] = convert.ToValue(cluster.Certificates.ManufacturerHardwareCertificate)
	}

	resource, err := CreateResource(runtime, "aws.cloudhsm.cluster",
		map[string]*llx.RawData{
			"__id":                llx.StringData(clusterId),
			"clusterId":           llx.StringData(clusterId),
			"region":              llx.StringData(region),
			"state":               llx.StringData(string(cluster.State)),
			"stateMessage":        llx.StringData(convert.ToValue(cluster.StateMessage)),
			"mode":                llx.StringData(string(cluster.Mode)),
			"hsmType":             llx.StringData(convert.ToValue(cluster.HsmType)),
			"backupPolicy":        llx.StringData(string(cluster.BackupPolicy)),
			"backupRetentionDays": llx.IntData(int64(backupRetentionDays)),
			"sourceBackupId":      llx.StringData(convert.ToValue(cluster.SourceBackupId)),
			"certificates":        llx.DictData(certificates),
			"createTimestamp":     createTimestamp,
			"tags":                llx.MapData(cloudHsmTagsToMap(cluster.TagList), types.String),
		})
	if err != nil {
		return nil, err
	}

	mqlCluster := resource.(*mqlAwsCloudhsmCluster)
	mqlCluster.region = region
	mqlCluster.accountID = accountID
	mqlCluster.cacheVpcId = cluster.VpcId
	mqlCluster.cacheSecurityGroupId = cluster.SecurityGroup
	for _, subnetId := range cluster.SubnetMapping {
		mqlCluster.cacheSubnetIds = append(mqlCluster.cacheSubnetIds, subnetId)
	}
	mqlCluster.cacheHsms = cluster.Hsms
	return mqlCluster, nil
}

type mqlAwsCloudhsmClusterInternal struct {
	region               string
	accountID            string
	cacheVpcId           *string
	cacheSecurityGroupId *string
	cacheSubnetIds       []string
	cacheHsms            []cloudhsmv2_types.Hsm
}

const cloudhsmClusterArnPattern = "arn:aws:cloudhsm:%s:%s:cluster/%s"

func (a *mqlAwsCloudhsmCluster) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(cloudhsmClusterArnPattern, a.Region.Data, conn.AccountId(), a.ClusterId.Data), nil
}

func (a *mqlAwsCloudhsmCluster) vpc() (*mqlAwsVpc, error) {
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

func (a *mqlAwsCloudhsmCluster) securityGroup() (*mqlAwsEc2Securitygroup, error) {
	if a.cacheSecurityGroupId == nil || *a.cacheSecurityGroupId == "" {
		a.SecurityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlSg, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup", map[string]*llx.RawData{
		"arn": llx.StringData(NewSecurityGroupArn(a.region, a.accountID, *a.cacheSecurityGroupId)),
	})
	if err != nil {
		return nil, err
	}
	return mqlSg.(*mqlAwsEc2Securitygroup), nil
}

func (a *mqlAwsCloudhsmCluster) subnets() ([]any, error) {
	res := []any{}
	for _, subnetId := range a.cacheSubnetIds {
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet", map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.region, a.accountID, subnetId)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsCloudhsmCluster) hsms() ([]any, error) {
	res := []any{}
	for _, hsm := range a.cacheHsms {
		mqlHsm, err := newMqlAwsCloudhsmHsm(a.MqlRuntime, a.region, a.accountID, hsm)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlHsm)
	}
	return res, nil
}

func initAwsCloudhsmCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["clusterId"] == nil {
		return nil, nil, errors.New("clusterId required to fetch aws cloudhsm cluster")
	}

	obj, err := CreateResource(runtime, "aws.cloudhsm", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	cloudhsm := obj.(*mqlAwsCloudhsm)
	clusters := cloudhsm.GetClusters()
	if clusters != nil && clusters.Error == nil {
		clusterIdVal, _ := args["clusterId"].Value.(string)
		for _, raw := range clusters.Data {
			c := raw.(*mqlAwsCloudhsmCluster)
			if c.ClusterId.Data == clusterIdVal {
				return args, c, nil
			}
		}
	}

	return nil, nil, errors.New("aws cloudhsm cluster not found")
}

// ---- aws.cloudhsm.hsm ----

func newMqlAwsCloudhsmHsm(runtime *plugin.Runtime, region string, accountID string, hsm cloudhsmv2_types.Hsm) (*mqlAwsCloudhsmHsm, error) {
	resource, err := CreateResource(runtime, "aws.cloudhsm.hsm",
		map[string]*llx.RawData{
			"__id":             llx.StringData(convert.ToValue(hsm.HsmId)),
			"hsmId":            llx.StringData(convert.ToValue(hsm.HsmId)),
			"clusterId":        llx.StringData(convert.ToValue(hsm.ClusterId)),
			"state":            llx.StringData(string(hsm.State)),
			"stateMessage":     llx.StringData(convert.ToValue(hsm.StateMessage)),
			"availabilityZone": llx.StringData(convert.ToValue(hsm.AvailabilityZone)),
			"hsmType":          llx.StringData(convert.ToValue(hsm.HsmType)),
			"eniIp":            llx.StringData(convert.ToValue(hsm.EniIp)),
		})
	if err != nil {
		return nil, err
	}
	resource.(*mqlAwsCloudhsmHsm).cacheEniId = convert.ToValue(hsm.EniId)

	mqlHsm := resource.(*mqlAwsCloudhsmHsm)
	mqlHsm.region = region
	mqlHsm.accountID = accountID
	mqlHsm.cacheSubnetId = hsm.SubnetId
	return mqlHsm, nil
}

type mqlAwsCloudhsmHsmInternal struct {
	cacheEniId    string
	region        string
	accountID     string
	cacheSubnetId *string
}

func (a *mqlAwsCloudhsmHsm) subnet() (*mqlAwsVpcSubnet, error) {
	if a.cacheSubnetId == nil || *a.cacheSubnetId == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet", map[string]*llx.RawData{
		"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.region, a.accountID, *a.cacheSubnetId)),
	})
	if err != nil {
		return nil, err
	}
	return mqlSubnet.(*mqlAwsVpcSubnet), nil
}

func (a *mqlAwsCloudhsmHsm) networkInterface() (*mqlAwsEc2Networkinterface, error) {
	eniId := a.cacheEniId
	if eniId == "" {
		a.NetworkInterface.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2Networkinterface,
		map[string]*llx.RawData{"id": llx.StringData(eniId), "region": llx.StringData(a.region)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Networkinterface), nil
}

// ---- aws.cloudhsm.backup ----

func (a *mqlAwsCloudhsm) backups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getBackups(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsCloudhsm) getBackups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("cloudhsm>getBackups>calling aws with region %s", region)

			svc := conn.CloudHsmV2(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				page, err := svc.DescribeBackups(ctx, &cloudhsmv2.DescribeBackupsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("CloudHSM service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, backup := range page.Backups {
					mqlBackup, err := newMqlAwsCloudhsmBackup(a.MqlRuntime, region, backup)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlBackup)
				}
				if page.NextToken == nil {
					break
				}
				nextToken = page.NextToken
			}
			return res, nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsCloudhsmBackup(runtime *plugin.Runtime, region string, backup cloudhsmv2_types.Backup) (*mqlAwsCloudhsmBackup, error) {
	arn := convert.ToValue(backup.BackupArn)

	timeData := func(t *time.Time) *llx.RawData {
		if t != nil {
			return llx.TimeData(*t)
		}
		return llx.NilData
	}

	resource, err := CreateResource(runtime, "aws.cloudhsm.backup",
		map[string]*llx.RawData{
			"__id":            llx.StringData(arn),
			"arn":             llx.StringData(arn),
			"backupId":        llx.StringData(convert.ToValue(backup.BackupId)),
			"region":          llx.StringData(region),
			"clusterId":       llx.StringData(convert.ToValue(backup.ClusterId)),
			"state":           llx.StringData(string(backup.BackupState)),
			"mode":            llx.StringData(string(backup.Mode)),
			"hsmType":         llx.StringData(convert.ToValue(backup.HsmType)),
			"neverExpires":    llx.BoolDataPtr(backup.NeverExpires),
			"createTimestamp": timeData(backup.CreateTimestamp),
			"copyTimestamp":   timeData(backup.CopyTimestamp),
			"deleteTimestamp": timeData(backup.DeleteTimestamp),
			"sourceRegion":    llx.StringData(convert.ToValue(backup.SourceRegion)),
			"sourceBackupId":  llx.StringData(convert.ToValue(backup.SourceBackup)),
			"sourceClusterId": llx.StringData(convert.ToValue(backup.SourceCluster)),
			"tags":            llx.MapData(cloudHsmTagsToMap(backup.TagList), types.String),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsCloudhsmBackup), nil
}

func initAwsCloudhsmBackup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws cloudhsm backup")
	}

	obj, err := CreateResource(runtime, "aws.cloudhsm", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	cloudhsm := obj.(*mqlAwsCloudhsm)
	backups := cloudhsm.GetBackups()
	if backups != nil && backups.Error == nil {
		arnVal, _ := args["arn"].Value.(string)
		for _, raw := range backups.Data {
			b := raw.(*mqlAwsCloudhsmBackup)
			if b.Arn.Data == arnVal {
				return args, b, nil
			}
		}
	}

	// All backup fields come from DescribeBackups at list time; there is no
	// detail API to populate a bare backup, so a not-found arn cannot be turned
	// into a usable resource — error rather than return an empty husk.
	return nil, nil, errors.New("aws cloudhsm backup not found")
}

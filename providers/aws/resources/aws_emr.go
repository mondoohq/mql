// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/emr"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"

	"go.mondoo.com/mql/types"
)

func (a *mqlAwsEmr) id() (string, error) {
	return "aws.emr", nil
}

func (a *mqlAwsEmr) clusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getClusters(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsEmrCluster) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEmr) getClusters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Emr(region)
			ctx := context.Background()

			res := []any{}

			params := &emr.ListClustersInput{}
			paginator := emr.NewListClustersPaginator(svc, params)
			for paginator.HasMorePages() {
				clusters, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, cluster := range clusters.Clusters {
					jsonStatus, err := convert.JsonToDict(cluster.Status)
					if err != nil {
						return nil, err
					}
					var createdAt *time.Time
					if cluster.Status != nil && cluster.Status.Timeline != nil {
						createdAt = cluster.Status.Timeline.CreationDateTime
					}
					mqlCluster, err := CreateResource(a.MqlRuntime, "aws.emr.cluster",
						map[string]*llx.RawData{
							"arn":                     llx.StringDataPtr(cluster.ClusterArn),
							"region":                  llx.StringData(region),
							"name":                    llx.StringDataPtr(cluster.Name),
							"normalizedInstanceHours": llx.IntDataDefault(cluster.NormalizedInstanceHours, 0),
							"outpostArn":              llx.StringDataPtr(cluster.OutpostArn),
							"status":                  llx.MapData(jsonStatus, types.String),
							"createdAt":               llx.TimeDataPtr(createdAt),
							"id":                      llx.StringDataPtr(cluster.Id),
						})
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

func initAwsEmrCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformEmrCluster); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch emr cluster")
	}

	obj, err := CreateResource(runtime, "aws.emr", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	e := obj.(*mqlAwsEmr)

	rawResources := e.GetClusters()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal, ok := args["arn"].Value.(string)
	if !ok {
		return nil, nil, errors.New("arn must be a string")
	}
	for _, rawResource := range rawResources.Data {
		cluster := rawResource.(*mqlAwsEmrCluster)
		if cluster.Arn.Data == arnVal {
			return args, cluster, nil
		}
	}
	return nil, nil, errors.New("emr cluster does not exist")
}

type mqlAwsEmrClusterInternal struct {
	clusterDetailsFetched           bool
	clusterDetailsLock              sync.Mutex
	cacheSecurityConfig             string
	cacheLogUri                     string
	cacheTags                       map[string]any
	cacheTerminationProtected       bool
	cacheMasterPublicDnsName        string
	cacheLogEncryptionKmsKeyId      *string
	cacheReleaseLabel               string
	cacheApplications               []any
	cacheConfigurations             []any
	cacheEbsRootVolumeSize          int64
	cacheEbsRootVolumeIops          int64
	cacheEbsRootVolumeThroughput    int64
	cacheRepoUpgradeOnBoot          string
	cacheKerberosAttributes         any
	cacheStepConcurrencyLevel       int64
	cachePlacementGroups            []any
	cacheAutoTerminate              bool
	cacheInstanceCollectionType     string
	cacheScaleDownBehavior          string
	cacheVisibleToAllUsers          bool
	cacheAutoScalingRoleArn         string
	cacheServiceRoleArn             string
	cacheSessionEnabled             bool
	autoTerminationFetched          bool
	autoTerminationLock             sync.Mutex
	cacheAutoTerminationIdleTimeout int64
	cacheEc2SubnetIds               []string
	cacheEc2SecurityGroupIds        []string
	cacheEc2KeyName                 string
	cacheEc2InstanceProfile         string
}

func (a *mqlAwsEmrCluster) fetchClusterDetails() error {
	if a.clusterDetailsFetched {
		return nil
	}
	a.clusterDetailsLock.Lock()
	defer a.clusterDetailsLock.Unlock()
	if a.clusterDetailsFetched {
		return nil
	}

	region, err := GetRegionFromArn(a.Arn.Data)
	if err != nil {
		return err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Emr(region)
	ctx := context.Background()

	id := a.Id.Data
	resp, err := svc.DescribeCluster(ctx, &emr.DescribeClusterInput{ClusterId: &id})
	if err != nil {
		return err
	}
	if resp.Cluster == nil {
		a.clusterDetailsFetched = true
		return nil
	}

	if resp.Cluster.SecurityConfiguration != nil {
		a.cacheSecurityConfig = *resp.Cluster.SecurityConfiguration
	}
	if resp.Cluster.LogUri != nil {
		a.cacheLogUri = *resp.Cluster.LogUri
	}
	tags := make(map[string]any)
	for _, t := range resp.Cluster.Tags {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	a.cacheTags = tags
	if resp.Cluster.TerminationProtected != nil {
		a.cacheTerminationProtected = *resp.Cluster.TerminationProtected
	}
	if resp.Cluster.MasterPublicDnsName != nil {
		a.cacheMasterPublicDnsName = *resp.Cluster.MasterPublicDnsName
	}
	a.cacheLogEncryptionKmsKeyId = resp.Cluster.LogEncryptionKmsKeyId

	if resp.Cluster.ReleaseLabel != nil {
		a.cacheReleaseLabel = *resp.Cluster.ReleaseLabel
	}
	if apps, err := convert.JsonToDictSlice(resp.Cluster.Applications); err == nil {
		a.cacheApplications = apps
	}
	if cfgs, err := convert.JsonToDictSlice(resp.Cluster.Configurations); err == nil {
		a.cacheConfigurations = cfgs
	}
	if resp.Cluster.EbsRootVolumeSize != nil {
		a.cacheEbsRootVolumeSize = int64(*resp.Cluster.EbsRootVolumeSize)
	}
	if resp.Cluster.EbsRootVolumeIops != nil {
		a.cacheEbsRootVolumeIops = int64(*resp.Cluster.EbsRootVolumeIops)
	}
	if resp.Cluster.EbsRootVolumeThroughput != nil {
		a.cacheEbsRootVolumeThroughput = int64(*resp.Cluster.EbsRootVolumeThroughput)
	}
	a.cacheRepoUpgradeOnBoot = string(resp.Cluster.RepoUpgradeOnBoot)
	a.cacheKerberosAttributes = redactedKerberosAttributes(resp.Cluster.KerberosAttributes)
	if resp.Cluster.StepConcurrencyLevel != nil {
		a.cacheStepConcurrencyLevel = int64(*resp.Cluster.StepConcurrencyLevel)
	}
	if pgs, err := convert.JsonToDictSlice(resp.Cluster.PlacementGroups); err == nil {
		a.cachePlacementGroups = pgs
	}
	if resp.Cluster.AutoTerminate != nil {
		a.cacheAutoTerminate = *resp.Cluster.AutoTerminate
	}
	a.cacheInstanceCollectionType = string(resp.Cluster.InstanceCollectionType)
	a.cacheScaleDownBehavior = string(resp.Cluster.ScaleDownBehavior)
	if resp.Cluster.VisibleToAllUsers != nil {
		a.cacheVisibleToAllUsers = *resp.Cluster.VisibleToAllUsers
	}
	if resp.Cluster.AutoScalingRole != nil {
		a.cacheAutoScalingRoleArn = *resp.Cluster.AutoScalingRole
	}
	if resp.Cluster.ServiceRole != nil {
		a.cacheServiceRoleArn = *resp.Cluster.ServiceRole
	}
	if resp.Cluster.SessionEnabled != nil {
		a.cacheSessionEnabled = *resp.Cluster.SessionEnabled
	}

	if attr := resp.Cluster.Ec2InstanceAttributes; attr != nil {
		// RequestedEc2SubnetIds covers all configured subnets; fall back to the
		// single launched subnet when the requested list is empty.
		if len(attr.RequestedEc2SubnetIds) > 0 {
			a.cacheEc2SubnetIds = attr.RequestedEc2SubnetIds
		} else if attr.Ec2SubnetId != nil && *attr.Ec2SubnetId != "" {
			a.cacheEc2SubnetIds = []string{*attr.Ec2SubnetId}
		}
		sgIds := []string{}
		seen := map[string]struct{}{}
		addSG := func(id string) {
			if id == "" {
				return
			}
			if _, ok := seen[id]; ok {
				return
			}
			seen[id] = struct{}{}
			sgIds = append(sgIds, id)
		}
		addSG(convert.ToValue(attr.EmrManagedMasterSecurityGroup))
		addSG(convert.ToValue(attr.EmrManagedSlaveSecurityGroup))
		addSG(convert.ToValue(attr.ServiceAccessSecurityGroup))
		for _, id := range attr.AdditionalMasterSecurityGroups {
			addSG(id)
		}
		for _, id := range attr.AdditionalSlaveSecurityGroups {
			addSG(id)
		}
		a.cacheEc2SecurityGroupIds = sgIds
		a.cacheEc2KeyName = convert.ToValue(attr.Ec2KeyName)
		a.cacheEc2InstanceProfile = convert.ToValue(attr.IamInstanceProfile)
	}

	a.clusterDetailsFetched = true
	return nil
}

func (a *mqlAwsEmrCluster) subnets() ([]any, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region, err := GetRegionFromArn(a.Arn.Data)
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, id := range a.cacheEc2SubnetIds {
		ref, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet,
			map[string]*llx.RawData{"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, region, conn.AccountId(), id))})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}

func (a *mqlAwsEmrCluster) securityGroups() ([]any, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region, err := GetRegionFromArn(a.Arn.Data)
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, id := range a.cacheEc2SecurityGroupIds {
		ref, err := NewResource(a.MqlRuntime, ResourceAwsEc2Securitygroup,
			map[string]*llx.RawData{"arn": llx.StringData(fmt.Sprintf(securityGroupArnPattern, region, conn.AccountId(), id))})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}

func (a *mqlAwsEmrCluster) ec2KeyName() (string, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return "", err
	}
	return a.cacheEc2KeyName, nil
}

func (a *mqlAwsEmrCluster) ec2InstanceProfile() (*mqlAwsIamInstanceProfile, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return nil, err
	}
	profile := a.cacheEc2InstanceProfile
	if profile == "" {
		a.Ec2InstanceProfile.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// EMR returns the instance profile as a name or an ARN; build the ARN when
	// only a name is present (IAM is global, so no region in the ARN).
	arnVal := profile
	if !strings.HasPrefix(arnVal, "arn:") {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		arnVal = fmt.Sprintf("arn:aws:iam::%s:instance-profile/%s", conn.AccountId(), profile)
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.instanceProfile",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		a.Ec2InstanceProfile.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsIamInstanceProfile), nil
}

// redactedKerberosAttributes returns a sanitized view of KerberosAttributes
// with password fields removed; the realm and AD domain join user are
// retained because they are not sensitive on their own.
func redactedKerberosAttributes(k *emrtypes.KerberosAttributes) any {
	if k == nil {
		return nil
	}
	out := map[string]any{}
	if k.Realm != nil {
		out["realm"] = *k.Realm
	}
	if k.ADDomainJoinUser != nil {
		out["adDomainJoinUser"] = *k.ADDomainJoinUser
	}
	return out
}

func (a *mqlAwsEmrCluster) tags() (map[string]any, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return nil, err
	}
	return a.cacheTags, nil
}

func (a *mqlAwsEmrCluster) securityConfiguration() (string, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return "", err
	}
	return a.cacheSecurityConfig, nil
}

func (a *mqlAwsEmrCluster) logUri() (string, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return "", err
	}
	return a.cacheLogUri, nil
}

func (a *mqlAwsEmrCluster) terminationProtected() (bool, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return false, err
	}
	return a.cacheTerminationProtected, nil
}

func (a *mqlAwsEmrCluster) masterPublicDnsName() (string, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return "", err
	}
	return a.cacheMasterPublicDnsName, nil
}

func (a *mqlAwsEmrCluster) releaseLabel() (string, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return "", err
	}
	return a.cacheReleaseLabel, nil
}

func (a *mqlAwsEmrCluster) applications() ([]any, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return nil, err
	}
	return a.cacheApplications, nil
}

func (a *mqlAwsEmrCluster) configurations() ([]any, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return nil, err
	}
	return a.cacheConfigurations, nil
}

func (a *mqlAwsEmrCluster) ebsRootVolumeSize() (int64, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return 0, err
	}
	return a.cacheEbsRootVolumeSize, nil
}

func (a *mqlAwsEmrCluster) ebsRootVolumeIops() (int64, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return 0, err
	}
	return a.cacheEbsRootVolumeIops, nil
}

func (a *mqlAwsEmrCluster) ebsRootVolumeThroughput() (int64, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return 0, err
	}
	return a.cacheEbsRootVolumeThroughput, nil
}

func (a *mqlAwsEmrCluster) repoUpgradeOnBoot() (string, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return "", err
	}
	return a.cacheRepoUpgradeOnBoot, nil
}

func (a *mqlAwsEmrCluster) kerberosAttributes() (any, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return nil, err
	}
	return a.cacheKerberosAttributes, nil
}

func (a *mqlAwsEmrCluster) stepConcurrencyLevel() (int64, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return 0, err
	}
	return a.cacheStepConcurrencyLevel, nil
}

func (a *mqlAwsEmrCluster) placementGroups() ([]any, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return nil, err
	}
	return a.cachePlacementGroups, nil
}

func (a *mqlAwsEmrCluster) autoTerminate() (bool, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return false, err
	}
	return a.cacheAutoTerminate, nil
}

func (a *mqlAwsEmrCluster) instanceCollectionType() (string, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return "", err
	}
	return a.cacheInstanceCollectionType, nil
}

func (a *mqlAwsEmrCluster) scaleDownBehavior() (string, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return "", err
	}
	return a.cacheScaleDownBehavior, nil
}

func (a *mqlAwsEmrCluster) visibleToAllUsers() (bool, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return false, err
	}
	return a.cacheVisibleToAllUsers, nil
}

func (a *mqlAwsEmrCluster) autoScalingRole() (*mqlAwsIamRole, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return nil, err
	}
	if a.cacheAutoScalingRoleArn == "" {
		a.AutoScalingRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := iamRoleByArnOrName(a.MqlRuntime, a.cacheAutoScalingRoleArn)
	if err != nil {
		return nil, err
	}
	return mqlRole, nil
}

func (a *mqlAwsEmrCluster) serviceRole() (*mqlAwsIamRole, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return nil, err
	}
	if a.cacheServiceRoleArn == "" {
		a.ServiceRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := iamRoleByArnOrName(a.MqlRuntime, a.cacheServiceRoleArn)
	if err != nil {
		return nil, err
	}
	return mqlRole, nil
}

func (a *mqlAwsEmrCluster) sessionEnabled() (bool, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return false, err
	}
	return a.cacheSessionEnabled, nil
}

// iamRoleByArnOrName resolves an iam.role reference where the input string may
// be either an ARN (arn:aws:iam::...) or a bare role name. EMR (and a few
// other services) return the role name in some places and the ARN in others.
func iamRoleByArnOrName(runtime *plugin.Runtime, arnOrName string) (*mqlAwsIamRole, error) {
	if arnOrName == "" {
		return nil, nil
	}
	args := map[string]*llx.RawData{}
	if len(arnOrName) >= 4 && arnOrName[:4] == "arn:" {
		args["arn"] = llx.StringData(arnOrName)
	} else {
		args["name"] = llx.StringData(arnOrName)
	}
	res, err := NewResource(runtime, ResourceAwsIamRole, args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsEmrCluster) autoTerminationIdleTimeout() (int64, error) {
	if a.autoTerminationFetched {
		return a.cacheAutoTerminationIdleTimeout, nil
	}
	a.autoTerminationLock.Lock()
	defer a.autoTerminationLock.Unlock()
	if a.autoTerminationFetched {
		return a.cacheAutoTerminationIdleTimeout, nil
	}

	region, err := GetRegionFromArn(a.Arn.Data)
	if err != nil {
		return 0, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Emr(region)
	ctx := context.Background()

	id := a.Id.Data
	resp, err := svc.GetAutoTerminationPolicy(ctx, &emr.GetAutoTerminationPolicyInput{ClusterId: &id})
	if err != nil {
		return 0, classifyAwsError(err, "elasticmapreduce:GetAutoTerminationPolicy")
	}
	if resp.AutoTerminationPolicy != nil && resp.AutoTerminationPolicy.IdleTimeout != nil {
		a.cacheAutoTerminationIdleTimeout = *resp.AutoTerminationPolicy.IdleTimeout
	}
	a.autoTerminationFetched = true
	return a.cacheAutoTerminationIdleTimeout, nil
}

// securityConfig returns the typed security configuration linked by name
// to the cluster. Security configurations are regional, so we resolve via
// the region-qualified __id used by securityConfigurations() to avoid
// matching a same-named config in a different region.
func (a *mqlAwsEmrCluster) securityConfig() (*mqlAwsEmrSecurityConfiguration, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return nil, err
	}
	if a.cacheSecurityConfig == "" {
		a.SecurityConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	region, err := GetRegionFromArn(a.Arn.Data)
	if err != nil {
		return nil, err
	}
	id := emrSecurityConfigurationID(region, a.cacheSecurityConfig)
	res, err := NewResource(a.MqlRuntime, "aws.emr.securityConfiguration",
		map[string]*llx.RawData{
			"__id": llx.StringData(id),
			"name": llx.StringData(a.cacheSecurityConfig),
		})
	if err != nil {
		return nil, err
	}
	sc := res.(*mqlAwsEmrSecurityConfiguration)
	if sc.cacheRegion == "" {
		sc.cacheRegion = region
	}
	return sc, nil
}

func (a *mqlAwsEmrCluster) logEncryptionKmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return nil, err
	}
	if a.cacheLogEncryptionKmsKeyId == nil || *a.cacheLogEncryptionKmsKeyId == "" {
		a.LogEncryptionKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheLogEncryptionKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

// initAwsEmrClusterEncryptionConfiguration resolves the encryption
// configuration through the scanned EMR cluster asset. Without this init, the
// static path `aws.emr.cluster.encryptionConfiguration` used by policy checks
// instantiates the sub-resource standalone (empty id, no fields set), so
// per-asset encryption checks scored fail even on correctly configured
// clusters.
func initAwsEmrClusterEncryptionConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Fully-built resources (from the accessor) always carry an __id.
	if args["__id"] != nil {
		return args, nil, nil
	}
	if len(args) > 0 {
		return nil, nil, errors.New("aws.emr.cluster.encryptionConfiguration cannot be initialized from partial arguments; query it without arguments or through aws.emr.cluster")
	}
	clusterRes, err := NewResource(runtime, "aws.emr.cluster", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	cluster := clusterRes.(*mqlAwsEmrCluster)
	cfg := cluster.GetEncryptionConfiguration()
	if cfg.Error != nil {
		return nil, nil, cfg.Error
	}
	if cfg.Data != nil {
		return args, cfg.Data, nil
	}
	// The cluster has no security configuration: encryption is off.
	res, err := CreateResource(runtime, "aws.emr.cluster.encryptionConfiguration",
		map[string]*llx.RawData{
			"__id":                   llx.StringData(cluster.Arn.Data + "/encryptionConfiguration"),
			"atRestEnabled":          llx.BoolData(false),
			"inTransitEnabled":       llx.BoolData(false),
			"atRestConfiguration":    llx.NilData,
			"inTransitConfiguration": llx.NilData,
		})
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (a *mqlAwsEmrCluster) encryptionConfiguration() (*mqlAwsEmrClusterEncryptionConfiguration, error) {
	if err := a.fetchClusterDetails(); err != nil {
		return nil, err
	}
	if a.cacheSecurityConfig == "" {
		a.EncryptionConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	region, err := GetRegionFromArn(a.Arn.Data)
	if err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Emr(region)
	ctx := context.Background()

	resp, err := svc.DescribeSecurityConfiguration(ctx, &emr.DescribeSecurityConfigurationInput{
		Name: &a.cacheSecurityConfig,
	})
	if err != nil {
		return nil, err
	}
	if resp.SecurityConfiguration == nil {
		a.EncryptionConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var configJSON map[string]any
	if err := json.Unmarshal([]byte(*resp.SecurityConfiguration), &configJSON); err != nil {
		return nil, err
	}

	encConfigRaw, ok := configJSON["EncryptionConfiguration"]
	if !ok {
		a.EncryptionConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	encConfig, ok := encConfigRaw.(map[string]any)
	if !ok {
		a.EncryptionConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	atRestEnabled, ok := encConfig["EnableAtRestEncryption"].(bool)
	if !ok {
		if _, exists := encConfig["EnableAtRestEncryption"]; exists {
			log.Warn().Str("cluster", a.Arn.Data).Msg("unexpected type for EnableAtRestEncryption in security configuration")
		}
	}
	inTransitEnabled, ok := encConfig["EnableInTransitEncryption"].(bool)
	if !ok {
		if _, exists := encConfig["EnableInTransitEncryption"]; exists {
			log.Warn().Str("cluster", a.Arn.Data).Msg("unexpected type for EnableInTransitEncryption in security configuration")
		}
	}

	var atRestConfig any
	if v, exists := encConfig["AtRestEncryptionConfiguration"]; exists {
		atRestConfig, err = convert.JsonToDict(v)
		if err != nil {
			return nil, err
		}
	}
	var inTransitConfig any
	if v, exists := encConfig["InTransitEncryptionConfiguration"]; exists {
		inTransitConfig, err = convert.JsonToDict(v)
		if err != nil {
			return nil, err
		}
	}

	res, err := CreateResource(a.MqlRuntime, "aws.emr.cluster.encryptionConfiguration",
		map[string]*llx.RawData{
			"__id":                   llx.StringData(a.Arn.Data + "/encryptionConfiguration"),
			"atRestEnabled":          llx.BoolData(atRestEnabled),
			"inTransitEnabled":       llx.BoolData(inTransitEnabled),
			"atRestConfiguration":    llx.DictData(atRestConfig),
			"inTransitConfiguration": llx.DictData(inTransitConfig),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEmrClusterEncryptionConfiguration), nil
}

func (a *mqlAwsEmrCluster) masterInstances() ([]any, error) {
	arn := a.Arn.Data
	id := a.Id.Data
	region, err := GetRegionFromArn(arn)
	if err != nil {
		return nil, err
	}
	res := []emrtypes.Instance{}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Emr(region)
	ctx := context.Background()

	params := &emr.ListInstancesInput{
		ClusterId:          &id,
		InstanceGroupTypes: []emrtypes.InstanceGroupType{"MASTER"},
	}
	paginator := emr.NewListInstancesPaginator(svc, params)
	for paginator.HasMorePages() {
		instances, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		res = append(res, instances.Instances...)
	}
	return convert.JsonToDictSlice(res)
}

// ── Block Public Access Configuration ───────────────────────────────────────

func (a *mqlAwsEmr) blockPublicAccessConfiguration() (any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regions, err := conn.Regions()
	if err != nil {
		return nil, err
	}
	if len(regions) == 0 {
		return nil, nil
	}
	// Account-level config: fetch from the first available region
	svc := conn.Emr(regions[0])
	ctx := context.Background()
	resp, err := svc.GetBlockPublicAccessConfiguration(ctx, &emr.GetBlockPublicAccessConfigurationInput{})
	if err != nil {
		return nil, classifyAwsError(err, "elasticmapreduce:GetBlockPublicAccessConfiguration")
	}
	return convert.JsonToDict(resp.BlockPublicAccessConfiguration)
}

// ── Steps ───────────────────────────────────────────────────────────────────

type mqlAwsEmrClusterStepInternal struct {
	cacheClusterId        string
	cacheRegion           string
	executionRoleFetched  bool
	executionRoleLock     sync.Mutex
	cacheExecutionRoleArn string
}

func (a *mqlAwsEmrCluster) steps() ([]any, error) {
	arn := a.Arn.Data
	clusterId := a.Id.Data
	region, err := GetRegionFromArn(arn)
	if err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Emr(region)
	ctx := context.Background()

	res := []any{}
	paginator := emr.NewListStepsPaginator(svc, &emr.ListStepsInput{ClusterId: &clusterId})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "elasticmapreduce:ListSteps")
		}
		for _, step := range page.Steps {
			var status, stateChangeReason string
			var failureDetails any
			var createdAt, startedAt, endedAt *llx.RawData
			if step.Status != nil {
				status = string(step.Status.State)
				if step.Status.Timeline != nil {
					createdAt = llx.TimeDataPtr(step.Status.Timeline.CreationDateTime)
					startedAt = llx.TimeDataPtr(step.Status.Timeline.StartDateTime)
					endedAt = llx.TimeDataPtr(step.Status.Timeline.EndDateTime)
				}
				if step.Status.StateChangeReason != nil && step.Status.StateChangeReason.Message != nil {
					stateChangeReason = *step.Status.StateChangeReason.Message
				}
				if step.Status.FailureDetails != nil {
					fd, ferr := convert.JsonToDict(step.Status.FailureDetails)
					if ferr == nil {
						failureDetails = fd
					}
				}
			}
			if createdAt == nil {
				createdAt = llx.TimeDataPtr(nil)
			}
			if startedAt == nil {
				startedAt = llx.TimeDataPtr(nil)
			}
			if endedAt == nil {
				endedAt = llx.TimeDataPtr(nil)
			}

			var jar, mainClass string
			var args []any
			properties := map[string]any{}
			if step.Config != nil {
				jar = convert.ToValue(step.Config.Jar)
				mainClass = convert.ToValue(step.Config.MainClass)
				args = make([]any, len(step.Config.Args))
				for i, a := range step.Config.Args {
					args[i] = a
				}
				for k, v := range step.Config.Properties {
					properties[k] = v
				}
			}

			mqlStep, err := CreateResource(a.MqlRuntime, "aws.emr.cluster.step",
				map[string]*llx.RawData{
					"__id":              llx.StringData(fmt.Sprintf("%s/step/%s", arn, convert.ToValue(step.Id))),
					"id":                llx.StringDataPtr(step.Id),
					"name":              llx.StringDataPtr(step.Name),
					"actionOnFailure":   llx.StringData(string(step.ActionOnFailure)),
					"status":            llx.StringData(status),
					"jar":               llx.StringData(jar),
					"mainClass":         llx.StringData(mainClass),
					"properties":        llx.MapData(properties, types.String),
					"args":              llx.ArrayData(args, types.String),
					"createdAt":         createdAt,
					"startedAt":         startedAt,
					"endedAt":           endedAt,
					"stateChangeReason": llx.StringData(stateChangeReason),
					"failureDetails":    llx.DictData(failureDetails),
					"logUri":            llx.StringDataPtr(step.LogUri),
				})
			if err != nil {
				return nil, err
			}
			s := mqlStep.(*mqlAwsEmrClusterStep)
			s.cacheClusterId = clusterId
			s.cacheRegion = region
			res = append(res, mqlStep)
		}
	}
	return res, nil
}

func (a *mqlAwsEmrClusterStep) id() (string, error) {
	return a.__id, nil
}

// executionRole returns the IAM runtime role used by the step. Resolved
// lazily because StepSummary returned by ListSteps does not include the
// ExecutionRoleArn — DescribeStep is required.
func (a *mqlAwsEmrClusterStep) executionRole() (*mqlAwsIamRole, error) {
	if !a.executionRoleFetched {
		a.executionRoleLock.Lock()
		if !a.executionRoleFetched {
			if err := a.fetchExecutionRoleArn(); err != nil {
				a.executionRoleLock.Unlock()
				return nil, err
			}
		}
		a.executionRoleLock.Unlock()
	}
	if a.cacheExecutionRoleArn == "" {
		a.ExecutionRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return iamRoleByArnOrName(a.MqlRuntime, a.cacheExecutionRoleArn)
}

func (a *mqlAwsEmrClusterStep) fetchExecutionRoleArn() error {
	if a.cacheClusterId == "" || a.cacheRegion == "" || a.Id.Data == "" {
		a.executionRoleFetched = true
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Emr(a.cacheRegion)
	ctx := context.Background()

	stepId := a.Id.Data
	clusterId := a.cacheClusterId
	resp, err := svc.DescribeStep(ctx, &emr.DescribeStepInput{ClusterId: &clusterId, StepId: &stepId})
	if err != nil {
		return classifyAwsError(err, "elasticmapreduce:DescribeStep")
	}
	if resp.Step != nil && resp.Step.ExecutionRoleArn != nil {
		a.cacheExecutionRoleArn = *resp.Step.ExecutionRoleArn
	}
	a.executionRoleFetched = true
	return nil
}

// ── Instance Groups ─────────────────────────────────────────────────────────

func (a *mqlAwsEmrCluster) instanceGroups() ([]any, error) {
	arn := a.Arn.Data
	clusterId := a.Id.Data
	region, err := GetRegionFromArn(arn)
	if err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Emr(region)
	ctx := context.Background()

	res := []any{}
	paginator := emr.NewListInstanceGroupsPaginator(svc, &emr.ListInstanceGroupsInput{ClusterId: &clusterId})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "elasticmapreduce:ListInstanceGroups")
		}
		for _, ig := range page.InstanceGroups {
			var status string
			var createdAt *time.Time
			if ig.Status != nil {
				status = string(ig.Status.State)
				if ig.Status.Timeline != nil {
					createdAt = ig.Status.Timeline.CreationDateTime
				}
			}
			var ebsBlockDevices []any
			if devices, derr := convert.JsonToDictSlice(ig.EbsBlockDevices); derr == nil {
				ebsBlockDevices = devices
			}
			var configurations []any
			if cfgs, cerr := convert.JsonToDictSlice(ig.Configurations); cerr == nil {
				configurations = cfgs
			}
			mqlIg, err := CreateResource(a.MqlRuntime, "aws.emr.cluster.instanceGroup",
				map[string]*llx.RawData{
					"__id":                   llx.StringData(fmt.Sprintf("%s/instanceGroup/%s", arn, convert.ToValue(ig.Id))),
					"id":                     llx.StringDataPtr(ig.Id),
					"name":                   llx.StringDataPtr(ig.Name),
					"instanceGroupType":      llx.StringData(string(ig.InstanceGroupType)),
					"instanceType":           llx.StringDataPtr(ig.InstanceType),
					"market":                 llx.StringData(string(ig.Market)),
					"requestedInstanceCount": llx.IntDataDefault(ig.RequestedInstanceCount, 0),
					"runningInstanceCount":   llx.IntDataDefault(ig.RunningInstanceCount, 0),
					"status":                 llx.StringData(status),
					"createdAt":              llx.TimeDataPtr(createdAt),
					"bidPrice":               llx.StringDataPtr(ig.BidPrice),
					"ebsOptimized":           llx.BoolDataPtr(ig.EbsOptimized),
					"customAmiId":            llx.StringDataPtr(ig.CustomAmiId),
					"ebsBlockDevices":        llx.ArrayData(ebsBlockDevices, types.Dict),
					"configurations":         llx.ArrayData(configurations, types.Dict),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlIg)
		}
	}
	return res, nil
}

func (a *mqlAwsEmrClusterInstanceGroup) id() (string, error) {
	return a.__id, nil
}

// ── Bootstrap Actions ───────────────────────────────────────────────────────

func (a *mqlAwsEmrCluster) bootstrapActions() ([]any, error) {
	arn := a.Arn.Data
	clusterId := a.Id.Data
	region, err := GetRegionFromArn(arn)
	if err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Emr(region)
	ctx := context.Background()

	res := []any{}
	idx := 0
	paginator := emr.NewListBootstrapActionsPaginator(svc, &emr.ListBootstrapActionsInput{ClusterId: &clusterId})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "elasticmapreduce:ListBootstrapActions")
		}
		for _, cmd := range page.BootstrapActions {
			args := make([]any, len(cmd.Args))
			for i, a := range cmd.Args {
				args[i] = a
			}
			mqlBa, err := CreateResource(a.MqlRuntime, "aws.emr.cluster.bootstrapAction",
				map[string]*llx.RawData{
					"__id":       llx.StringData(fmt.Sprintf("%s/bootstrapAction/%d", arn, idx)),
					"name":       llx.StringDataPtr(cmd.Name),
					"scriptPath": llx.StringDataPtr(cmd.ScriptPath),
					"args":       llx.ArrayData(args, types.String),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlBa)
			idx++
		}
	}
	return res, nil
}

func (a *mqlAwsEmrClusterBootstrapAction) id() (string, error) {
	return a.__id, nil
}

// ── Security Configurations ─────────────────────────────────────────────────

type mqlAwsEmrSecurityConfigurationInternal struct {
	cacheRegion         string
	configurationLock   sync.Mutex
	configurationLoaded bool
	cacheConfiguration  string
}

// emrSecurityConfigurationID returns the canonical __id for an EMR
// security configuration. Security configurations are regional, so the
// cache key includes the region to keep regional namespaces distinct.
func emrSecurityConfigurationID(region, name string) string {
	return fmt.Sprintf("aws.emr.securityConfiguration/%s/%s", region, name)
}

func (a *mqlAwsEmrSecurityConfiguration) id() (string, error) {
	return emrSecurityConfigurationID(a.cacheRegion, a.Name.Data), nil
}

func (a *mqlAwsEmr) securityConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSecurityConfigurations(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsEmr) getSecurityConfigurations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			svc := conn.Emr(region)
			ctx := context.Background()
			res := []any{}

			var marker *string
			for {
				resp, err := svc.ListSecurityConfigurations(ctx, &emr.ListSecurityConfigurationsInput{Marker: marker})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, sc := range resp.SecurityConfigurations {
					mqlSc, err := CreateResource(a.MqlRuntime, "aws.emr.securityConfiguration",
						map[string]*llx.RawData{
							"__id":             llx.StringData(emrSecurityConfigurationID(region, convert.ToValue(sc.Name))),
							"name":             llx.StringDataPtr(sc.Name),
							"creationDateTime": llx.TimeDataPtr(sc.CreationDateTime),
						})
					if err != nil {
						return nil, err
					}
					mqlSc.(*mqlAwsEmrSecurityConfiguration).cacheRegion = region
					res = append(res, mqlSc)
				}
				if resp.Marker == nil {
					break
				}
				marker = resp.Marker
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsEmrSecurityConfiguration) configuration() (string, error) {
	if a.configurationLoaded {
		return a.cacheConfiguration, nil
	}
	a.configurationLock.Lock()
	defer a.configurationLock.Unlock()
	if a.configurationLoaded {
		return a.cacheConfiguration, nil
	}

	region := a.cacheRegion
	if region == "" {
		// fall back: try the first available region
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		regions, err := conn.Regions()
		if err != nil || len(regions) == 0 {
			a.configurationLoaded = true
			return "", nil
		}
		region = regions[0]
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Emr(region)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeSecurityConfiguration(ctx, &emr.DescribeSecurityConfigurationInput{Name: &name})
	if err != nil {
		return "", classifyAwsError(err, "elasticmapreduce:DescribeSecurityConfiguration")
	}
	if resp.SecurityConfiguration != nil {
		a.cacheConfiguration = *resp.SecurityConfiguration
	}
	a.configurationLoaded = true
	return a.cacheConfiguration, nil
}

func initAwsEmrSecurityConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["name"] == nil {
		return nil, nil, errors.New("name required to fetch emr security configuration")
	}
	nameVal, ok := args["name"].Value.(string)
	if !ok {
		return nil, nil, errors.New("name must be a string")
	}

	obj, err := CreateResource(runtime, "aws.emr", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	e := obj.(*mqlAwsEmr)

	rawResources := e.GetSecurityConfigurations()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	// If __id was provided (e.g., from securityConfig() on a cluster),
	// match by the region-qualified __id to disambiguate same-named
	// configurations across regions.
	var wantID string
	if args["__id"] != nil {
		if s, ok := args["__id"].Value.(string); ok {
			wantID = s
		}
	}

	var nameMatch *mqlAwsEmrSecurityConfiguration
	for _, rawResource := range rawResources.Data {
		sc := rawResource.(*mqlAwsEmrSecurityConfiguration)
		scID := emrSecurityConfigurationID(sc.cacheRegion, sc.Name.Data)
		if wantID != "" && scID == wantID {
			return args, sc, nil
		}
		if sc.Name.Data == nameVal && nameMatch == nil {
			nameMatch = sc
		}
	}
	if wantID == "" && nameMatch != nil {
		return args, nameMatch, nil
	}
	return nil, nil, errors.New("emr security configuration does not exist")
}

type mqlAwsEmrStudioInternal struct {
	cacheVpcId                  string
	cacheSubnetIds              []string
	cacheServiceRoleArn         string
	cacheUserRoleArn            string
	cacheWorkspaceSecurityGroup string
	cacheEngineSecurityGroup    string
	cacheEncryptionKeyArn       string
}

func (a *mqlAwsEmrStudio) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEmr) studios() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getStudios(conn), 5)
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

func (a *mqlAwsEmr) getStudios(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			svc := conn.Emr(region)
			ctx := context.Background()
			res := []any{}

			paginator := emr.NewListStudiosPaginator(svc, &emr.ListStudiosInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, summary := range page.Studios {
					if summary.StudioId == nil {
						continue
					}
					details, err := svc.DescribeStudio(ctx, &emr.DescribeStudioInput{StudioId: summary.StudioId})
					if err != nil {
						if Is400AccessDeniedError(err) {
							continue
						}
						return nil, err
					}
					mqlStudio, err := newMqlAwsEmrStudio(a.MqlRuntime, region, details.Studio)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlStudio)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsEmrStudio(runtime *plugin.Runtime, region string, studio *emrtypes.Studio) (*mqlAwsEmrStudio, error) {
	if studio == nil {
		return nil, errors.New("studio is nil")
	}
	res, err := CreateResource(runtime, "aws.emr.studio",
		map[string]*llx.RawData{
			"studioId":                   llx.StringDataPtr(studio.StudioId),
			"arn":                        llx.StringDataPtr(studio.StudioArn),
			"region":                     llx.StringData(region),
			"name":                       llx.StringDataPtr(studio.Name),
			"description":                llx.StringDataPtr(studio.Description),
			"authMode":                   llx.StringData(string(studio.AuthMode)),
			"defaultS3Location":          llx.StringDataPtr(studio.DefaultS3Location),
			"encryptionKeyArn":           llx.StringDataPtr(studio.EncryptionKeyArn),
			"idpAuthUrl":                 llx.StringDataPtr(studio.IdpAuthUrl),
			"idpRelayStateParameterName": llx.StringDataPtr(studio.IdpRelayStateParameterName),
			"url":                        llx.StringDataPtr(studio.Url),
			"createdAt":                  llx.TimeDataPtr(studio.CreationTime),
			"tags":                       llx.MapData(toInterfaceMap(emrTagsToMap(studio.Tags)), types.String),
		})
	if err != nil {
		return nil, err
	}
	mqlStudio := res.(*mqlAwsEmrStudio)
	mqlStudio.cacheVpcId = convert.ToValue(studio.VpcId)
	mqlStudio.cacheSubnetIds = studio.SubnetIds
	mqlStudio.cacheServiceRoleArn = convert.ToValue(studio.ServiceRole)
	mqlStudio.cacheUserRoleArn = convert.ToValue(studio.UserRole)
	mqlStudio.cacheWorkspaceSecurityGroup = convert.ToValue(studio.WorkspaceSecurityGroupId)
	mqlStudio.cacheEngineSecurityGroup = convert.ToValue(studio.EngineSecurityGroupId)
	mqlStudio.cacheEncryptionKeyArn = convert.ToValue(studio.EncryptionKeyArn)
	return mqlStudio, nil
}

func emrTagsToMap(tags []emrtypes.Tag) map[string]string {
	return tagsToStringMap(tags, func(t emrtypes.Tag) *string { return t.Key }, func(t emrtypes.Tag) *string { return t.Value })
}

func (a *mqlAwsEmrStudio) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res, err := NewResource(a.MqlRuntime, "aws.vpc",
		map[string]*llx.RawData{"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.Region.Data, conn.AccountId(), a.cacheVpcId))})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

func (a *mqlAwsEmrStudio) subnets() ([]any, error) {
	if len(a.cacheSubnetIds) == 0 {
		return []any{}, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := make([]any, 0, len(a.cacheSubnetIds))
	for _, sid := range a.cacheSubnetIds {
		s, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.Region.Data, conn.AccountId(), sid))})
		if err != nil {
			return nil, err
		}
		res = append(res, s)
	}
	return res, nil
}

func (a *mqlAwsEmrStudio) serviceIamRole() (*mqlAwsIamRole, error) {
	if a.cacheServiceRoleArn == "" {
		a.ServiceIamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheServiceRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsEmrStudio) userIamRole() (*mqlAwsIamRole, error) {
	if a.cacheUserRoleArn == "" {
		a.UserIamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheUserRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsEmrStudio) workspaceSecurityGroup() (*mqlAwsEc2Securitygroup, error) {
	if a.cacheWorkspaceSecurityGroup == "" {
		a.WorkspaceSecurityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup",
		map[string]*llx.RawData{"arn": llx.StringData(fmt.Sprintf(securityGroupArnPattern, a.Region.Data, conn.AccountId(), a.cacheWorkspaceSecurityGroup))})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Securitygroup), nil
}

func (a *mqlAwsEmrStudio) engineSecurityGroup() (*mqlAwsEc2Securitygroup, error) {
	if a.cacheEngineSecurityGroup == "" {
		a.EngineSecurityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup",
		map[string]*llx.RawData{"arn": llx.StringData(fmt.Sprintf(securityGroupArnPattern, a.Region.Data, conn.AccountId(), a.cacheEngineSecurityGroup))})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Securitygroup), nil
}

func (a *mqlAwsEmrStudio) encryptionKey() (*mqlAwsKmsKey, error) {
	if a.cacheEncryptionKeyArn == "" {
		a.EncryptionKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheEncryptionKeyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

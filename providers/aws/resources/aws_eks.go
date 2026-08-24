// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
)

func (a *mqlAwsEks) id() (string, error) {
	return ResourceAwsEks, nil
}

func (a *mqlAwsEks) clusters() ([]any, error) {
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

func (a *mqlAwsEks) getClusters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}} // return the error
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("eks>getClusters>calling aws with region %s", region)

			svc := conn.Eks(region)
			ctx := context.Background()
			res := []any{}

			paginator := eks.NewListClustersPaginator(svc, &eks.ListClustersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, clusterName := range page.Clusters {
					clusterArn := fmt.Sprintf("arn:aws:eks:%s:%s:cluster/%s", region, conn.AccountId(), clusterName)

					// If tag filters are active, we need to describe the cluster to check tags.
					// Cache the response to avoid a redundant call in fetchDetail().
					var cachedDescribe *ekstypes.Cluster
					if conn.Filters.General.HasTags() {
						descResp, err := svc.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: aws.String(clusterName)})
						if err != nil {
							return nil, err
						}
						if descResp == nil || descResp.Cluster == nil {
							continue
						}
						if conn.Filters.General.IsFilteredOutByTags(descResp.Cluster.Tags) {
							log.Debug().Str("cluster", clusterName).Msg("skipping eks cluster due to filters")
							continue
						}
						cachedDescribe = descResp.Cluster
						// Use the real ARN from the API (handles partitions correctly)
						if descResp.Cluster.Arn != nil {
							clusterArn = *descResp.Cluster.Arn
						}
					}

					args := map[string]*llx.RawData{
						"name":   llx.StringData(clusterName),
						"arn":    llx.StringData(clusterArn),
						"region": llx.StringData(region),
					}

					mqlCluster, err := CreateResource(a.MqlRuntime, ResourceAwsEksCluster, args)
					if err != nil {
						return nil, err
					}
					cast := mqlCluster.(*mqlAwsEksCluster)
					cast.accountID = conn.AccountId()
					cast.region = region
					// If we already described the cluster for tag filtering, cache it
					// to avoid a redundant DescribeCluster call in fetchDetail()
					if cachedDescribe != nil {
						if err := cast.populateFromDescribe(cachedDescribe); err != nil {
							return nil, err
						}
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

type mqlAwsEksClusterInternal struct {
	securityGroupIdHandler
	fetched          bool
	fetchErr         error
	lock             sync.Mutex
	cacheVpcId       *string
	cacheSubnetIds   []string
	cacheClusterSgId *string
	region           string
	accountID        string
}

func (a *mqlAwsEksCluster) fetchDetail() error {
	if a.fetched {
		return a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.fetchErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Eks(a.Region.Data)

	a.accountID = conn.AccountId()
	a.region = a.Region.Data

	descResp, err := svc.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: aws.String(a.Name.Data),
	})
	if err != nil {
		a.fetched = true
		a.fetchErr = err
		return err
	}
	if descResp.Cluster == nil {
		a.fetched = true
		a.fetchErr = fmt.Errorf("eks DescribeCluster returned no cluster for %q in %q", a.Name.Data, a.Region.Data)
		return a.fetchErr
	}
	if err := a.populateFromDescribe(descResp.Cluster); err != nil {
		a.fetched = true
		a.fetchErr = err
		return err
	}
	return nil
}

// populateFromDescribe sets all computed fields from a DescribeCluster response.
// Called from fetchDetail() and also from getClusters() when tag filtering is active
// (to avoid a redundant DescribeCluster call).
func (a *mqlAwsEksCluster) populateFromDescribe(cluster *ekstypes.Cluster) error {
	a.Tags = plugin.TValue[map[string]any]{Data: toInterfaceMap(cluster.Tags), State: plugin.StateIsSet}
	a.Endpoint = plugin.TValue[string]{Data: convert.ToValue(cluster.Endpoint), State: plugin.StateIsSet}
	a.Version = plugin.TValue[string]{Data: convert.ToValue(cluster.Version), State: plugin.StateIsSet}
	a.PlatformVersion = plugin.TValue[string]{Data: convert.ToValue(cluster.PlatformVersion), State: plugin.StateIsSet}
	a.Status = plugin.TValue[string]{Data: string(cluster.Status), State: plugin.StateIsSet}

	encryptionConfig, _ := convert.JsonToDictSlice(cluster.EncryptionConfig)
	a.EncryptionConfig = plugin.TValue[[]any]{Data: encryptionConfig, State: plugin.StateIsSet}

	logging, _ := convert.JsonToDict(cluster.Logging)
	a.Logging = plugin.TValue[any]{Data: logging, State: plugin.StateIsSet}

	kubernetesNetworkConfig, _ := convert.JsonToDict(cluster.KubernetesNetworkConfig)
	a.NetworkConfig = plugin.TValue[any]{Data: kubernetesNetworkConfig, State: plugin.StateIsSet}

	controlPlaneEgressMode := ""
	if cluster.ResourcesVpcConfig != nil {
		controlPlaneEgressMode = string(cluster.ResourcesVpcConfig.ControlPlaneEgressMode)
	}
	a.ControlPlaneEgressMode = plugin.TValue[string]{Data: controlPlaneEgressMode, State: plugin.StateIsSet}

	vpcConfig, _ := convert.JsonToDict(cluster.ResourcesVpcConfig)
	a.ResourcesVpcConfig = plugin.TValue[any]{Data: vpcConfig, State: plugin.StateIsSet}

	if cluster.ResourcesVpcConfig != nil {
		a.cacheVpcId = cluster.ResourcesVpcConfig.VpcId
		a.cacheSubnetIds = cluster.ResourcesVpcConfig.SubnetIds
		a.cacheClusterSgId = cluster.ResourcesVpcConfig.ClusterSecurityGroupId
		sgArns := make([]string, 0, len(cluster.ResourcesVpcConfig.SecurityGroupIds))
		for _, sgId := range cluster.ResourcesVpcConfig.SecurityGroupIds {
			sgArns = append(sgArns, NewSecurityGroupArn(a.region, a.accountID, sgId))
		}
		a.setSecurityGroupArns(sgArns)
	}

	a.CreatedAt = plugin.TValue[*time.Time]{Data: cluster.CreatedAt, State: plugin.StateIsSet}

	supportType := ""
	if cluster.UpgradePolicy != nil {
		supportType = string(cluster.UpgradePolicy.SupportType)
	}
	a.SupportType = plugin.TValue[string]{Data: supportType, State: plugin.StateIsSet}

	authMode := ""
	var bootstrapClusterCreatorAdmin bool
	if cluster.AccessConfig != nil {
		authMode = string(cluster.AccessConfig.AuthenticationMode)
		bootstrapClusterCreatorAdmin = convert.ToValue(cluster.AccessConfig.BootstrapClusterCreatorAdminPermissions)
	}
	a.AuthenticationMode = plugin.TValue[string]{Data: authMode, State: plugin.StateIsSet}
	a.BootstrapClusterCreatorAdminPermissions = plugin.TValue[bool]{Data: bootstrapClusterCreatorAdmin, State: plugin.StateIsSet}

	var deletionProtection bool
	if cluster.DeletionProtection != nil {
		deletionProtection = *cluster.DeletionProtection
	}
	a.DeletionProtection = plugin.TValue[bool]{Data: deletionProtection, State: plugin.StateIsSet}

	var endpointPublicAccess, endpointPrivateAccess bool
	publicAccessCidrs := []any{}
	if cluster.ResourcesVpcConfig != nil {
		endpointPublicAccess = cluster.ResourcesVpcConfig.EndpointPublicAccess
		endpointPrivateAccess = cluster.ResourcesVpcConfig.EndpointPrivateAccess
		for _, cidr := range cluster.ResourcesVpcConfig.PublicAccessCidrs {
			publicAccessCidrs = append(publicAccessCidrs, cidr)
		}
	}
	a.EndpointPublicAccess = plugin.TValue[bool]{Data: endpointPublicAccess, State: plugin.StateIsSet}
	a.EndpointPrivateAccess = plugin.TValue[bool]{Data: endpointPrivateAccess, State: plugin.StateIsSet}
	a.PublicAccessCidrs = plugin.TValue[[]any]{Data: publicAccessCidrs, State: plugin.StateIsSet}

	if cluster.RoleArn != nil {
		mqlIam, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
			map[string]*llx.RawData{"arn": llx.StringDataPtr(cluster.RoleArn)},
		)
		if err != nil {
			return err
		}
		a.IamRole = plugin.TValue[*mqlAwsIamRole]{Data: mqlIam.(*mqlAwsIamRole), State: plugin.StateIsSet}
	} else {
		a.IamRole = plugin.TValue[*mqlAwsIamRole]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	healthDict, _ := convert.JsonToDict(cluster.Health)
	a.Health = plugin.TValue[any]{Data: healthDict, State: plugin.StateIsSet}

	certAuth := ""
	if cluster.CertificateAuthority != nil && cluster.CertificateAuthority.Data != nil {
		certAuth = *cluster.CertificateAuthority.Data
	}
	a.CertificateAuthority = plugin.TValue[string]{Data: certAuth, State: plugin.StateIsSet}

	// EKS reports a distinct active certificate authority only once a cluster
	// has been through a rotation. Leaving these null rather than empty keeps
	// "never rotated" distinguishable from "rotated to an authority with a
	// blank id".
	if cluster.CertificateAuthority != nil && cluster.CertificateAuthority.Active != nil {
		active := cluster.CertificateAuthority.Active
		activeID := ""
		if active.Id != nil {
			activeID = *active.Id
		}
		a.ActiveCertificateAuthorityId = plugin.TValue[string]{Data: activeID, State: plugin.StateIsSet}
		a.ActiveCertificateAuthorityActivatedBy = plugin.TValue[string]{
			Data: string(active.ActivatedBy), State: plugin.StateIsSet,
		}
	} else {
		a.ActiveCertificateAuthorityId = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		a.ActiveCertificateAuthorityActivatedBy = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	}

	// Typed encryption config fields
	var encryptionResources []any
	if len(cluster.EncryptionConfig) > 0 && cluster.EncryptionConfig[0].Provider != nil && cluster.EncryptionConfig[0].Provider.KeyArn != nil {
		keyArn := *cluster.EncryptionConfig[0].Provider.KeyArn
		mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
			map[string]*llx.RawData{"arn": llx.StringData(keyArn)})
		if err != nil {
			return err
		}
		a.EncryptionKmsKey = plugin.TValue[*mqlAwsKmsKey]{Data: mqlKey.(*mqlAwsKmsKey), State: plugin.StateIsSet}
		for _, r := range cluster.EncryptionConfig[0].Resources {
			encryptionResources = append(encryptionResources, r)
		}
	} else {
		a.EncryptionKmsKey = plugin.TValue[*mqlAwsKmsKey]{State: plugin.StateIsSet | plugin.StateIsNull}
	}
	a.EncryptionResources = plugin.TValue[[]any]{Data: encryptionResources, State: plugin.StateIsSet}

	upgradePolicy, _ := convert.JsonToDict(cluster.UpgradePolicy)
	a.UpgradePolicy = plugin.TValue[any]{Data: upgradePolicy, State: plugin.StateIsSet}

	zonalShiftConfig, _ := convert.JsonToDict(cluster.ZonalShiftConfig)
	a.ZonalShiftConfig = plugin.TValue[any]{Data: zonalShiftConfig, State: plugin.StateIsSet}

	computeConfig, _ := convert.JsonToDict(cluster.ComputeConfig)
	a.ComputeConfig = plugin.TValue[any]{Data: computeConfig, State: plugin.StateIsSet}

	storageConfig, _ := convert.JsonToDict(cluster.StorageConfig)
	a.StorageConfig = plugin.TValue[any]{Data: storageConfig, State: plugin.StateIsSet}

	remoteNetworkConfig, _ := convert.JsonToDict(cluster.RemoteNetworkConfig)
	a.RemoteNetworkConfig = plugin.TValue[any]{Data: remoteNetworkConfig, State: plugin.StateIsSet}

	a.fetched = true
	return nil
}

func (a *mqlAwsEksCluster) tags() (map[string]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) endpoint() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsEksCluster) version() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsEksCluster) platformVersion() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsEksCluster) status() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsEksCluster) encryptionConfig() ([]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) encryptionKmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return a.EncryptionKmsKey.Data, nil
}

func (a *mqlAwsEksCluster) encryptionResources() ([]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) upgradePolicy() (map[string]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) zonalShiftConfig() (map[string]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) computeConfig() (map[string]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) storageConfig() (map[string]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) remoteNetworkConfig() (map[string]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) logging() (map[string]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) networkConfig() (map[string]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) controlPlaneEgressMode() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsEksCluster) resourcesVpcConfig() (map[string]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) createdAt() (*time.Time, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) iamRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return a.IamRole.Data, nil
}

func (a *mqlAwsEksCluster) supportType() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsEksCluster) authenticationMode() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsEksCluster) bootstrapClusterCreatorAdminPermissions() (bool, error) {
	return false, a.fetchDetail()
}

func (a *mqlAwsEksCluster) deletionProtection() (bool, error) {
	return false, a.fetchDetail()
}

func (a *mqlAwsEksCluster) endpointPublicAccess() (bool, error) {
	return false, a.fetchDetail()
}

func (a *mqlAwsEksCluster) endpointPrivateAccess() (bool, error) {
	return false, a.fetchDetail()
}

func (a *mqlAwsEksCluster) publicAccessCidrs() ([]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) vpc() (*mqlAwsVpc, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	vpcArn := fmt.Sprintf(vpcArnPattern, a.region, a.accountID, *a.cacheVpcId)
	res, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{"arn": llx.StringData(vpcArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

func (a *mqlAwsEksCluster) clusterSubnets() ([]any, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	if len(a.cacheSubnetIds) == 0 {
		return nil, nil
	}
	res := []any{}
	for _, subnetId := range a.cacheSubnetIds {
		subnetArn := fmt.Sprintf(subnetArnPattern, a.region, a.accountID, subnetId)
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{"arn": llx.StringData(subnetArn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsEksCluster) clusterSecurityGroups() ([]any, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	return a.securityGroupIdHandler.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsEksCluster) clusterSecurityGroup() (*mqlAwsEc2Securitygroup, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	if a.cacheClusterSgId == nil || *a.cacheClusterSgId == "" {
		a.ClusterSecurityGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	sgArn := NewSecurityGroupArn(a.region, a.accountID, *a.cacheClusterSgId)
	mqlSg, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup",
		map[string]*llx.RawData{"arn": llx.StringData(sgArn)})
	if err != nil {
		return nil, err
	}
	return mqlSg.(*mqlAwsEc2Securitygroup), nil
}

func (a *mqlAwsEksCluster) health() (map[string]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsEksCluster) certificateAuthority() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsEksCluster) activeCertificateAuthorityId() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsEksCluster) activeCertificateAuthorityActivatedBy() (string, error) {
	return "", a.fetchDetail()
}

func initAwsEksCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformEksCluster); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch eks cluster")
	}

	// load all eks clusters
	obj, err := CreateResource(runtime, ResourceAwsEks, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}

	eks := obj.(*mqlAwsEks)
	rawResources := eks.GetClusters()

	arnVal := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		cluster := rawResource.(*mqlAwsEksCluster)
		if cluster.Arn.Data == arnVal {
			return args, cluster, nil
		}
	}
	return nil, nil, errors.New("eks cluster does not exist")
}

func (a *mqlAwsEksCluster) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEksCluster) nodeGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regionVal := a.Region.Data
	log.Debug().Msgf("eks>getNodegroups>calling aws with region %s", regionVal)

	svc := conn.Eks(regionVal)
	ctx := context.Background()
	res := []any{}

	paginator := eks.NewListNodegroupsPaginator(svc, &eks.ListNodegroupsInput{ClusterName: aws.String(a.Name.Data)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("region", regionVal).Msg("error accessing region for AWS API")
				return res, nil
			}
			return nil, err
		}

		for i := range page.Nodegroups {
			nodegroup := page.Nodegroups[i]
			args := map[string]*llx.RawData{
				"__id":   llx.StringData(fmt.Sprintf("aws.eks.nodegroup/%s/%s/%s", regionVal, a.Name.Data, nodegroup)),
				"name":   llx.StringData(nodegroup),
				"region": llx.StringData(regionVal),
			}

			mqlNg, err := CreateResource(a.MqlRuntime, ResourceAwsEksNodegroup, args)
			if err != nil {
				return nil, err
			}
			mqlNg.(*mqlAwsEksNodegroup).clusterName = a.Name.Data
			mqlNg.(*mqlAwsEksNodegroup).region = regionVal
			res = append(res, mqlNg)
		}
	}
	return res, nil
}

type mqlAwsEksNodegroupInternal struct {
	details     *ekstypes.Nodegroup
	fetchErr    error
	fetched     bool
	region      string
	lock        sync.Mutex
	clusterName string
}

func (a *mqlAwsEksNodegroup) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEksNodegroup) autoscalingGroups() ([]any, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if ng.Resources == nil || ng.Resources.AutoScalingGroups == nil {
		return nil, nil
	}
	res := []any{}
	for i := range ng.Resources.AutoScalingGroups {
		ag := ng.Resources.AutoScalingGroups[i]
		mqlAg, err := NewResource(a.MqlRuntime, ResourceAwsAutoscalingGroup,
			map[string]*llx.RawData{
				"name":   llx.StringDataPtr(ag.Name),
				"region": llx.StringData(a.region),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAg)
	}

	return res, nil
}

func (a *mqlAwsEksNodegroup) fetchDetails() (*ekstypes.Nodegroup, error) {
	if a.fetched {
		return a.details, a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.details, a.fetchErr
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Eks(a.region)
	desc, err := svc.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{NodegroupName: aws.String(a.Name.Data), ClusterName: aws.String(a.clusterName)})
	if err != nil {
		a.fetchErr = err
		a.fetched = true
		return nil, err
	}
	if desc.Nodegroup == nil {
		a.fetchErr = errors.New("DescribeNodegroup returned no nodegroup for " + a.Name.Data)
		a.fetched = true
		return nil, a.fetchErr
	}
	a.details = desc.Nodegroup
	a.fetched = true
	return desc.Nodegroup, nil
}

func (a *mqlAwsEksNodegroup) arn() (string, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(ng.NodegroupArn), nil
}

func (a *mqlAwsEksNodegroup) capacityType() (string, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return string(ng.CapacityType), nil
}

func (a *mqlAwsEksNodegroup) launchTemplate() (*mqlAwsEc2Launchtemplate, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if ng.LaunchTemplate == nil || (ng.LaunchTemplate.Id == nil && ng.LaunchTemplate.Name == nil) {
		a.LaunchTemplate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	args := map[string]*llx.RawData{"region": llx.StringData(a.region)}
	if ng.LaunchTemplate.Id != nil && *ng.LaunchTemplate.Id != "" {
		args["id"] = llx.StringDataPtr(ng.LaunchTemplate.Id)
	} else {
		args["name"] = llx.StringDataPtr(ng.LaunchTemplate.Name)
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2Launchtemplate, args)
	if err != nil {
		a.LaunchTemplate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsEc2Launchtemplate), nil
}

func (a *mqlAwsEksNodegroup) launchTemplateVersion() (string, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if ng.LaunchTemplate == nil {
		a.LaunchTemplateVersion.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return convert.ToValue(ng.LaunchTemplate.Version), nil
}

func (a *mqlAwsEksNodegroup) status() (string, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return string(ng.Status), nil
}

func (a *mqlAwsEksNodegroup) amiType() (string, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return string(ng.AmiType), nil
}

func (a *mqlAwsEksNodegroup) diskSize() (int64, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return 0, err
	}
	if ng.DiskSize == nil {
		a.DiskSize.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	return int64(*ng.DiskSize), nil
}

func (a *mqlAwsEksNodegroup) createdAt() (*time.Time, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return ng.CreatedAt, nil
}

func (a *mqlAwsEksNodegroup) modifiedAt() (*time.Time, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return ng.ModifiedAt, nil
}

func (a *mqlAwsEksNodegroup) scalingConfig() (map[string]any, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(ng.ScalingConfig)
}

func (a *mqlAwsEksNodegroup) warmPoolConfig() (map[string]any, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if ng.WarmPoolConfig == nil {
		return nil, nil
	}
	return convert.JsonToDict(ng.WarmPoolConfig)
}

func (a *mqlAwsEksNodegroup) instanceTypes() ([]any, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	s := []any{}
	for i := range ng.InstanceTypes {
		s = append(s, ng.InstanceTypes[i])
	}
	return s, nil
}

func (a *mqlAwsEksNodegroup) labels() (map[string]any, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	new := make(map[string]any)
	for k, v := range ng.Labels {
		new[k] = v
	}
	return new, nil
}

func (a *mqlAwsEksNodegroup) tags() (map[string]any, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	new := make(map[string]any)
	for k, v := range ng.Tags {
		new[k] = v
	}
	return new, nil
}

func (a *mqlAwsEksNodegroup) nodeRole() (*mqlAwsIamRole, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if ng.NodeRole == nil {
		a.NodeRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlIam, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(ng.NodeRole),
		})
	if err != nil {
		return nil, err
	}
	return mqlIam.(*mqlAwsIamRole), nil
}

func (a *mqlAwsEksNodegroup) health() (map[string]any, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(ng.Health)
}

func (a *mqlAwsEksNodegroup) taints() ([]any, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(ng.Taints)
}

func (a *mqlAwsEksNodegroup) releaseVersion() (string, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(ng.ReleaseVersion), nil
}

func (a *mqlAwsEksNodegroup) remoteAccess() (map[string]any, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if ng.RemoteAccess == nil {
		return nil, nil
	}
	return convert.JsonToDict(ng.RemoteAccess)
}

func (a *mqlAwsEksNodegroup) updateConfig() (map[string]any, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if ng.UpdateConfig == nil {
		return nil, nil
	}
	return convert.JsonToDict(ng.UpdateConfig)
}

func (a *mqlAwsEksNodegroup) nodeVersion() (string, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(ng.Version), nil
}

func (a *mqlAwsEksNodegroup) nodeRepairEnabled() (bool, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return false, err
	}
	if ng.NodeRepairConfig != nil && ng.NodeRepairConfig.Enabled != nil {
		return *ng.NodeRepairConfig.Enabled, nil
	}
	return false, nil
}

func (a *mqlAwsEksNodegroup) nodegroupSubnets() ([]any, error) {
	ng, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if len(ng.Subnets) == 0 {
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	accountID := conn.AccountId()
	res := []any{}
	for _, subnetId := range ng.Subnets {
		subnetArn := fmt.Sprintf(subnetArnPattern, a.region, accountID, subnetId)
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{"arn": llx.StringData(subnetArn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

// AwsEksAddons
func (a *mqlAwsEksCluster) addons() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regionVal := a.Region.Data
	log.Debug().Msgf("eks>getAddons>calling aws with region %s", regionVal)

	svc := conn.Eks(regionVal)
	ctx := context.Background()
	res := []any{}

	paginator := eks.NewListAddonsPaginator(svc, &eks.ListAddonsInput{ClusterName: aws.String(a.Name.Data)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("region", regionVal).Msg("error accessing region for AWS API")
				return res, nil
			}
			return nil, err
		}

		for i := range page.Addons {
			addon := page.Addons[i]
			args := map[string]*llx.RawData{
				// region-qualified: cluster names are unique per region, so two
				// same-named clusters in different regions would otherwise share a
				// key and cross-contaminate. Every sibling collection in this file
				// (nodeGroups, accessEntries, fargateProfiles, ...) includes it.
				"__id":   llx.StringData(fmt.Sprintf("%s/%s/%s/%s", ResourceAwsEksAddon, regionVal, a.Name.Data, addon)),
				"name":   llx.StringData(addon),
				"region": llx.StringData(regionVal),
			}

			mqlNg, err := CreateResource(a.MqlRuntime, ResourceAwsEksAddon, args)
			if err != nil {
				return nil, err
			}
			mqlNg.(*mqlAwsEksAddon).clusterName = a.Name.Data
			mqlNg.(*mqlAwsEksAddon).region = regionVal
			res = append(res, mqlNg)
		}
	}
	return res, nil
}

type mqlAwsEksAddonInternal struct {
	details     *ekstypes.Addon
	fetchErr    error
	fetched     bool
	region      string
	lock        sync.Mutex
	clusterName string
}

func (a *mqlAwsEksAddon) fetchDetails() (*ekstypes.Addon, error) {
	if a.fetched {
		return a.details, a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.details, a.fetchErr
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Eks(a.region)
	desc, err := svc.DescribeAddon(ctx, &eks.DescribeAddonInput{AddonName: aws.String(a.Name.Data), ClusterName: aws.String(a.clusterName)})
	if err != nil {
		a.fetchErr = err
		a.fetched = true
		return nil, err
	}
	if desc.Addon == nil {
		a.fetchErr = errors.New("DescribeAddon returned no addon for " + a.Name.Data)
		a.fetched = true
		return nil, a.fetchErr
	}
	a.details = desc.Addon
	a.fetched = true
	return desc.Addon, nil
}

func (a *mqlAwsEksAddon) arn() (string, error) {
	ao, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if ao.AddonArn == nil {
		return "", nil
	}
	return *ao.AddonArn, nil
}

func (a *mqlAwsEksAddon) status() (string, error) {
	ao, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return string(ao.Status), nil
}

func (a *mqlAwsEksAddon) createdAt() (*time.Time, error) {
	ao, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return ao.CreatedAt, nil
}

func (a *mqlAwsEksAddon) modifiedAt() (*time.Time, error) {
	ao, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return ao.ModifiedAt, nil
}

func (a *mqlAwsEksAddon) tags() (map[string]any, error) {
	ao, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	new := make(map[string]any)
	for k, v := range ao.Tags {
		new[k] = v
	}
	return new, nil
}

func (a *mqlAwsEksAddon) addonVersion() (string, error) {
	ao, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if ao.AddonVersion == nil {
		return "", nil
	}
	return *ao.AddonVersion, nil
}

func (a *mqlAwsEksAddon) publisher() (string, error) {
	ao, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if ao.Publisher == nil {
		return "", nil
	}
	return *ao.Publisher, nil
}

func (a *mqlAwsEksAddon) owner() (string, error) {
	ao, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if ao.Owner == nil {
		return "", nil
	}
	return *ao.Owner, nil
}

func (a *mqlAwsEksAddon) configurationValues() (string, error) {
	ao, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if ao.ConfigurationValues == nil {
		return "", nil
	}
	return *ao.ConfigurationValues, nil
}

func (a *mqlAwsEksAddon) health() (map[string]any, error) {
	ao, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(ao.Health)
}

// Access Entries

func (a *mqlAwsEksCluster) accessEntries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regionVal := a.Region.Data
	svc := conn.Eks(regionVal)
	ctx := context.Background()
	res := []any{}

	paginator := eks.NewListAccessEntriesPaginator(svc, &eks.ListAccessEntriesInput{ClusterName: aws.String(a.Name.Data)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}

		for _, principalArn := range page.AccessEntries {
			mqlEntry, err := CreateResource(a.MqlRuntime, "aws.eks.accessEntry",
				map[string]*llx.RawData{
					"__id":         llx.StringData(fmt.Sprintf("aws.eks.accessEntry/%s/%s/%s", regionVal, a.Name.Data, principalArn)),
					"clusterName":  llx.StringData(a.Name.Data),
					"principalArn": llx.StringData(principalArn),
					"region":       llx.StringData(regionVal),
				})
			if err != nil {
				return nil, err
			}
			mqlEntry.(*mqlAwsEksAccessEntry).clusterName = a.Name.Data
			mqlEntry.(*mqlAwsEksAccessEntry).region = regionVal
			res = append(res, mqlEntry)
		}
	}
	return res, nil
}

type mqlAwsEksAccessEntryInternal struct {
	details     *ekstypes.AccessEntry
	fetchErr    error
	fetched     bool
	region      string
	lock        sync.Mutex
	clusterName string
}

func (a *mqlAwsEksAccessEntry) id() (string, error) {
	return fmt.Sprintf("aws.eks.accessEntry/%s/%s", a.ClusterName.Data, a.PrincipalArn.Data), nil
}

func (a *mqlAwsEksAccessEntry) arn() (string, error) {
	entry, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(entry.AccessEntryArn), nil
}

func (a *mqlAwsEksAccessEntry) compute_type() (string, error) {
	entry, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(entry.Type), nil
}

func (a *mqlAwsEksAccessEntry) fetchDetails() (*ekstypes.AccessEntry, error) {
	if a.fetched {
		return a.details, a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.details, a.fetchErr
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Eks(a.region)
	principalArn := a.PrincipalArn.Data
	desc, err := svc.DescribeAccessEntry(ctx, &eks.DescribeAccessEntryInput{
		ClusterName:  aws.String(a.clusterName),
		PrincipalArn: &principalArn,
	})
	if err != nil {
		a.fetchErr = err
		a.fetched = true
		return nil, err
	}
	if desc.AccessEntry == nil {
		a.fetchErr = errors.New("DescribeAccessEntry returned no access entry for " + principalArn)
		a.fetched = true
		return nil, a.fetchErr
	}
	a.details = desc.AccessEntry
	a.fetched = true
	return desc.AccessEntry, nil
}

func (a *mqlAwsEksAccessEntry) kubernetesGroups() ([]any, error) {
	entry, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(entry.KubernetesGroups))
	for _, g := range entry.KubernetesGroups {
		res = append(res, g)
	}
	return res, nil
}

func (a *mqlAwsEksAccessEntry) tags() (map[string]any, error) {
	entry, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	tags := make(map[string]any)
	for k, v := range entry.Tags {
		tags[k] = v
	}
	return tags, nil
}

func (a *mqlAwsEksAccessEntry) createdAt() (*time.Time, error) {
	entry, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return entry.CreatedAt, nil
}

func (a *mqlAwsEksAccessEntry) accessPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Eks(a.region)

	res := []any{}
	paginator := eks.NewListAssociatedAccessPoliciesPaginator(svc, &eks.ListAssociatedAccessPoliciesInput{
		ClusterName:  aws.String(a.clusterName),
		PrincipalArn: aws.String(a.PrincipalArn.Data),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, policy := range page.AssociatedAccessPolicies {
			scopeType := ""
			var namespaces []any
			if policy.AccessScope != nil {
				scopeType = string(policy.AccessScope.Type)
				for _, ns := range policy.AccessScope.Namespaces {
					namespaces = append(namespaces, ns)
				}
			}
			mqlPolicy, err := CreateResource(a.MqlRuntime, "aws.eks.accessPolicy",
				map[string]*llx.RawData{
					"__id":         llx.StringData(fmt.Sprintf("aws.eks.accessPolicy/%s/%s/%s/%s", a.region, a.clusterName, a.PrincipalArn.Data, convert.ToValue(policy.PolicyArn))),
					"policyArn":    llx.StringDataPtr(policy.PolicyArn),
					"scopeType":    llx.StringData(scopeType),
					"namespaces":   llx.ArrayData(namespaces, "\x02"),
					"associatedAt": llx.TimeDataPtr(policy.AssociatedAt),
					"modifiedAt":   llx.TimeDataPtr(policy.ModifiedAt),
					"clusterName":  llx.StringData(a.clusterName),
					"principalArn": llx.StringData(a.PrincipalArn.Data),
					"region":       llx.StringData(a.region),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPolicy)
		}
	}
	return res, nil
}

func (a *mqlAwsEksAccessPolicy) id() (string, error) {
	return fmt.Sprintf("aws.eks.accessPolicy/%s/%s/%s/%s", a.Region.Data, a.ClusterName.Data, a.PrincipalArn.Data, a.PolicyArn.Data), nil
}

// Fargate Profiles

func (a *mqlAwsEksCluster) fargateProfiles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regionVal := a.Region.Data
	svc := conn.Eks(regionVal)
	ctx := context.Background()
	res := []any{}

	paginator := eks.NewListFargateProfilesPaginator(svc, &eks.ListFargateProfilesInput{ClusterName: aws.String(a.Name.Data)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}

		for _, profileName := range page.FargateProfileNames {
			mqlProfile, err := CreateResource(a.MqlRuntime, "aws.eks.fargateProfile",
				map[string]*llx.RawData{
					"__id":        llx.StringData(fmt.Sprintf("aws.eks.fargateProfile/%s/%s/%s", regionVal, a.Name.Data, profileName)),
					"name":        llx.StringData(profileName),
					"clusterName": llx.StringData(a.Name.Data),
					"region":      llx.StringData(regionVal),
				})
			if err != nil {
				return nil, err
			}
			mqlProfile.(*mqlAwsEksFargateProfile).clusterName = a.Name.Data
			mqlProfile.(*mqlAwsEksFargateProfile).region = regionVal
			mqlProfile.(*mqlAwsEksFargateProfile).accountID = conn.AccountId()
			res = append(res, mqlProfile)
		}
	}
	return res, nil
}

type mqlAwsEksFargateProfileInternal struct {
	details     *ekstypes.FargateProfile
	fetchErr    error
	fetched     bool
	region      string
	lock        sync.Mutex
	clusterName string
	accountID   string
}

func (a *mqlAwsEksFargateProfile) id() (string, error) {
	return fmt.Sprintf("aws.eks.fargateProfile/%s/%s/%s", a.region, a.ClusterName.Data, a.Name.Data), nil
}

func (a *mqlAwsEksFargateProfile) arn() (string, error) {
	fp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(fp.FargateProfileArn), nil
}

func (a *mqlAwsEksFargateProfile) fetchDetails() (*ekstypes.FargateProfile, error) {
	if a.fetched {
		return a.details, a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.details, a.fetchErr
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Eks(a.region)
	name := a.Name.Data
	desc, err := svc.DescribeFargateProfile(ctx, &eks.DescribeFargateProfileInput{
		ClusterName:        aws.String(a.clusterName),
		FargateProfileName: &name,
	})
	if err != nil {
		a.fetchErr = err
		a.fetched = true
		return nil, err
	}
	if desc.FargateProfile == nil {
		a.fetchErr = errors.New("DescribeFargateProfile returned no profile for " + name)
		a.fetched = true
		return nil, a.fetchErr
	}
	a.details = desc.FargateProfile
	a.fetched = true
	return desc.FargateProfile, nil
}

func (a *mqlAwsEksFargateProfile) podExecutionRoleArn() (string, error) {
	fp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(fp.PodExecutionRoleArn), nil
}

func (a *mqlAwsEksFargateProfile) selectors() ([]any, error) {
	fp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, s := range fp.Selectors {
		d, err := convert.JsonToDict(s)
		if err != nil {
			return nil, err
		}
		res = append(res, d)
	}
	return res, nil
}

func (a *mqlAwsEksFargateProfile) subnets() ([]any, error) {
	fp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(fp.Subnets))
	for _, s := range fp.Subnets {
		res = append(res, s)
	}
	return res, nil
}

func (a *mqlAwsEksFargateProfile) status() (string, error) {
	fp, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return string(fp.Status), nil
}

func (a *mqlAwsEksFargateProfile) tags() (map[string]any, error) {
	fp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	tags := make(map[string]any)
	for k, v := range fp.Tags {
		tags[k] = v
	}
	return tags, nil
}

func (a *mqlAwsEksFargateProfile) createdAt() (*time.Time, error) {
	fp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return fp.CreatedAt, nil
}

func (a *mqlAwsEksFargateProfile) podExecutionRole() (*mqlAwsIamRole, error) {
	fp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if fp.PodExecutionRoleArn == nil || *fp.PodExecutionRoleArn == "" {
		a.PodExecutionRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{"arn": llx.StringDataPtr(fp.PodExecutionRoleArn)})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsEksFargateProfile) fargateSubnets() ([]any, error) {
	fp, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if len(fp.Subnets) == 0 {
		return nil, nil
	}
	res := []any{}
	for _, subnetId := range fp.Subnets {
		subnetArn := fmt.Sprintf(subnetArnPattern, a.region, a.accountID, subnetId)
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{"arn": llx.StringData(subnetArn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

// Pod Identity Associations

func (a *mqlAwsEksCluster) podIdentityAssociations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regionVal := a.Region.Data
	svc := conn.Eks(regionVal)
	ctx := context.Background()
	res := []any{}

	paginator := eks.NewListPodIdentityAssociationsPaginator(svc, &eks.ListPodIdentityAssociationsInput{ClusterName: aws.String(a.Name.Data)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}

		for _, assoc := range page.Associations {
			mqlAssoc, err := CreateResource(a.MqlRuntime, "aws.eks.podIdentityAssociation",
				map[string]*llx.RawData{
					"__id":           llx.StringDataPtr(assoc.AssociationArn),
					"associationArn": llx.StringDataPtr(assoc.AssociationArn),
					"associationId":  llx.StringDataPtr(assoc.AssociationId),
					"clusterName":    llx.StringDataPtr(assoc.ClusterName),
					"region":         llx.StringData(regionVal),
				})
			if err != nil {
				return nil, err
			}
			mqlAssoc.(*mqlAwsEksPodIdentityAssociation).clusterName = a.Name.Data
			mqlAssoc.(*mqlAwsEksPodIdentityAssociation).region = regionVal
			res = append(res, mqlAssoc)
		}
	}
	return res, nil
}

type mqlAwsEksPodIdentityAssociationInternal struct {
	details     *ekstypes.PodIdentityAssociation
	fetchErr    error
	fetched     bool
	region      string
	lock        sync.Mutex
	clusterName string
}

func (a *mqlAwsEksPodIdentityAssociation) id() (string, error) {
	return a.AssociationArn.Data, nil
}

func (a *mqlAwsEksPodIdentityAssociation) fetchDetails() (*ekstypes.PodIdentityAssociation, error) {
	if a.fetched {
		return a.details, a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.details, a.fetchErr
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Eks(a.region)
	assocId := a.AssociationId.Data
	desc, err := svc.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{
		ClusterName:   aws.String(a.clusterName),
		AssociationId: &assocId,
	})
	if err != nil {
		a.fetchErr = err
		a.fetched = true
		return nil, err
	}
	if desc.Association == nil {
		a.fetchErr = errors.New("DescribePodIdentityAssociation returned no association for " + assocId)
		a.fetched = true
		return nil, a.fetchErr
	}
	a.details = desc.Association
	a.fetched = true
	return desc.Association, nil
}

func (a *mqlAwsEksPodIdentityAssociation) namespace() (string, error) {
	assoc, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(assoc.Namespace), nil
}

func (a *mqlAwsEksPodIdentityAssociation) serviceAccount() (string, error) {
	assoc, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(assoc.ServiceAccount), nil
}

func (a *mqlAwsEksPodIdentityAssociation) roleArn() (string, error) {
	assoc, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(assoc.RoleArn), nil
}

func (a *mqlAwsEksPodIdentityAssociation) createdAt() (*time.Time, error) {
	assoc, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return assoc.CreatedAt, nil
}

func (a *mqlAwsEksPodIdentityAssociation) iamRole() (*mqlAwsIamRole, error) {
	assoc, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if assoc.RoleArn == nil || *assoc.RoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{"arn": llx.StringDataPtr(assoc.RoleArn)})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsEksPodIdentityAssociation) modifiedAt() (*time.Time, error) {
	assoc, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return assoc.ModifiedAt, nil
}

func (a *mqlAwsEksPodIdentityAssociation) ownerArn() (string, error) {
	assoc, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(assoc.OwnerArn), nil
}

// OIDC Identity Provider Configs

func (a *mqlAwsEksCluster) identityProviderConfigs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regionVal := a.Region.Data
	svc := conn.Eks(regionVal)
	ctx := context.Background()
	res := []any{}

	paginator := eks.NewListIdentityProviderConfigsPaginator(svc, &eks.ListIdentityProviderConfigsInput{ClusterName: aws.String(a.Name.Data)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}

		for _, config := range page.IdentityProviderConfigs {
			mqlConfig, err := CreateResource(a.MqlRuntime, "aws.eks.identityProviderConfig",
				map[string]*llx.RawData{
					"__id":        llx.StringData(fmt.Sprintf("aws.eks.identityProviderConfig/%s/%s/%s/%s", regionVal, a.Name.Data, convert.ToValue(config.Type), convert.ToValue(config.Name))),
					"name":        llx.StringDataPtr(config.Name),
					"type":        llx.StringDataPtr(config.Type),
					"clusterName": llx.StringData(a.Name.Data),
					"region":      llx.StringData(regionVal),
				})
			if err != nil {
				return nil, err
			}
			mqlConfig.(*mqlAwsEksIdentityProviderConfig).clusterName = a.Name.Data
			mqlConfig.(*mqlAwsEksIdentityProviderConfig).region = regionVal
			res = append(res, mqlConfig)
		}
	}
	return res, nil
}

type mqlAwsEksIdentityProviderConfigInternal struct {
	details     *ekstypes.OidcIdentityProviderConfig
	fetchErr    error
	fetched     bool
	region      string
	lock        sync.Mutex
	clusterName string
}

func (a *mqlAwsEksIdentityProviderConfig) id() (string, error) {
	return fmt.Sprintf("aws.eks.identityProviderConfig/%s/%s/%s/%s", a.region, a.ClusterName.Data, a.Type.Data, a.Name.Data), nil
}

func (a *mqlAwsEksIdentityProviderConfig) fetchDetails() (*ekstypes.OidcIdentityProviderConfig, error) {
	if a.fetched {
		return a.details, a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.details, a.fetchErr
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Eks(a.region)
	name := a.Name.Data
	configType := a.Type.Data
	desc, err := svc.DescribeIdentityProviderConfig(ctx, &eks.DescribeIdentityProviderConfigInput{
		ClusterName: aws.String(a.clusterName),
		IdentityProviderConfig: &ekstypes.IdentityProviderConfig{
			Name: &name,
			Type: &configType,
		},
	})
	if err != nil {
		a.fetchErr = err
		a.fetched = true
		return nil, err
	}
	if desc.IdentityProviderConfig == nil {
		a.fetched = true
		return nil, nil
	}
	a.details = desc.IdentityProviderConfig.Oidc
	a.fetched = true
	return a.details, nil
}

func (a *mqlAwsEksIdentityProviderConfig) status() (string, error) {
	cfg, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", nil
	}
	return string(cfg.Status), nil
}

func (a *mqlAwsEksIdentityProviderConfig) issuerUrl() (string, error) {
	cfg, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", nil
	}
	return convert.ToValue(cfg.IssuerUrl), nil
}

func (a *mqlAwsEksIdentityProviderConfig) clientId() (string, error) {
	cfg, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", nil
	}
	return convert.ToValue(cfg.ClientId), nil
}

func (a *mqlAwsEksIdentityProviderConfig) usernamePrefix() (string, error) {
	cfg, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", nil
	}
	return convert.ToValue(cfg.UsernamePrefix), nil
}

func (a *mqlAwsEksIdentityProviderConfig) usernameClaim() (string, error) {
	cfg, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", nil
	}
	return convert.ToValue(cfg.UsernameClaim), nil
}

func (a *mqlAwsEksIdentityProviderConfig) groupsPrefix() (string, error) {
	cfg, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", nil
	}
	return convert.ToValue(cfg.GroupsPrefix), nil
}

func (a *mqlAwsEksIdentityProviderConfig) groupsClaim() (string, error) {
	cfg, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", nil
	}
	return convert.ToValue(cfg.GroupsClaim), nil
}

func (a *mqlAwsEksIdentityProviderConfig) requiredClaims() (map[string]any, error) {
	cfg, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return map[string]any{}, nil
	}
	result := make(map[string]any)
	for k, v := range cfg.RequiredClaims {
		result[k] = v
	}
	return result, nil
}

func (a *mqlAwsEksIdentityProviderConfig) tags() (map[string]any, error) {
	cfg, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return map[string]any{}, nil
	}
	result := make(map[string]any)
	for k, v := range cfg.Tags {
		result[k] = v
	}
	return result, nil
}

// EKS Insights

func (a *mqlAwsEksCluster) insights() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regionVal := a.Region.Data
	svc := conn.Eks(regionVal)
	ctx := context.Background()
	res := []any{}

	paginator := eks.NewListInsightsPaginator(svc, &eks.ListInsightsInput{ClusterName: aws.String(a.Name.Data)})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, summary := range page.Insights {
			insightId := convert.ToValue(summary.Id)
			mqlInsight, err := CreateResource(a.MqlRuntime, "aws.eks.insight",
				map[string]*llx.RawData{
					"__id":        llx.StringData(fmt.Sprintf("aws.eks.insight/%s/%s/%s", regionVal, a.Name.Data, insightId)),
					"id":          llx.StringData(insightId),
					"clusterName": llx.StringData(a.Name.Data),
					"region":      llx.StringData(regionVal),
				})
			if err != nil {
				return nil, err
			}
			cast := mqlInsight.(*mqlAwsEksInsight)
			cast.clusterName = a.Name.Data
			cast.region = regionVal

			// Eagerly populate fields available from the list summary to avoid
			// N+1 DescribeInsight calls (especially for @defaults fields).
			cast.Name = plugin.TValue[string]{Data: convert.ToValue(summary.Name), State: plugin.StateIsSet}
			cast.Category = plugin.TValue[string]{Data: string(summary.Category), State: plugin.StateIsSet}
			statusDict, _ := convert.JsonToDict(summary.InsightStatus)
			cast.InsightStatus = plugin.TValue[any]{Data: statusDict, State: plugin.StateIsSet}
			cast.KubernetesVersion = plugin.TValue[string]{Data: convert.ToValue(summary.KubernetesVersion), State: plugin.StateIsSet}
			cast.Description = plugin.TValue[string]{Data: convert.ToValue(summary.Description), State: plugin.StateIsSet}
			cast.LastRefreshTime = plugin.TValue[*time.Time]{Data: summary.LastRefreshTime, State: plugin.StateIsSet}
			cast.LastTransitionTime = plugin.TValue[*time.Time]{Data: summary.LastTransitionTime, State: plugin.StateIsSet}

			res = append(res, mqlInsight)
		}
	}
	return res, nil
}

type mqlAwsEksInsightInternal struct {
	details     *ekstypes.Insight
	fetchErr    error
	fetched     bool
	region      string
	lock        sync.Mutex
	clusterName string
}

func (a *mqlAwsEksInsight) id() (string, error) {
	return fmt.Sprintf("aws.eks.insight/%s/%s/%s", a.region, a.ClusterName.Data, a.Id.Data), nil
}

func (a *mqlAwsEksInsight) fetchDetails() (*ekstypes.Insight, error) {
	if a.fetched {
		return a.details, a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.details, a.fetchErr
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Eks(a.region)
	desc, err := svc.DescribeInsight(ctx, &eks.DescribeInsightInput{
		ClusterName: aws.String(a.clusterName),
		Id:          aws.String(a.Id.Data),
	})
	if err != nil {
		a.fetchErr = err
		a.fetched = true
		return nil, err
	}
	if desc.Insight == nil {
		a.fetchErr = errors.New("DescribeInsight returned nil insight for " + a.Id.Data)
		a.fetched = true
		return nil, a.fetchErr
	}
	a.details = desc.Insight
	a.fetched = true
	return desc.Insight, nil
}

func (a *mqlAwsEksInsight) name() (string, error) {
	insight, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(insight.Name), nil
}

func (a *mqlAwsEksInsight) category() (string, error) {
	insight, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return string(insight.Category), nil
}

func (a *mqlAwsEksInsight) description() (string, error) {
	insight, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(insight.Description), nil
}

func (a *mqlAwsEksInsight) insightStatus() (map[string]any, error) {
	insight, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(insight.InsightStatus)
}

func (a *mqlAwsEksInsight) kubernetesVersion() (string, error) {
	insight, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(insight.KubernetesVersion), nil
}

func (a *mqlAwsEksInsight) recommendation() (string, error) {
	insight, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	return convert.ToValue(insight.Recommendation), nil
}

func (a *mqlAwsEksInsight) additionalInfo() (map[string]any, error) {
	insight, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return toInterfaceMap(insight.AdditionalInfo), nil
}

func (a *mqlAwsEksInsight) categorySpecificSummary() (map[string]any, error) {
	insight, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(insight.CategorySpecificSummary)
}

func (a *mqlAwsEksInsight) resources() ([]any, error) {
	insight, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(insight.Resources)
}

func (a *mqlAwsEksInsight) lastRefreshTime() (*time.Time, error) {
	insight, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return insight.LastRefreshTime, nil
}

func (a *mqlAwsEksInsight) lastTransitionTime() (*time.Time, error) {
	insight, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	return insight.LastTransitionTime, nil
}

// EKS Addon Versions

func (a *mqlAwsEksCluster) availableAddonVersions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	regionVal := a.Region.Data
	svc := conn.Eks(regionVal)
	ctx := context.Background()
	res := []any{}

	// Get cluster version for filtering
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	clusterVersion := a.Version.Data

	paginator := eks.NewDescribeAddonVersionsPaginator(svc, &eks.DescribeAddonVersionsInput{
		KubernetesVersion: aws.String(clusterVersion),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, addonInfo := range page.Addons {
			addonName := convert.ToValue(addonInfo.AddonName)
			for _, versionInfo := range addonInfo.AddonVersions {
				version := convert.ToValue(versionInfo.AddonVersion)

				compats, _ := convert.JsonToDictSlice(versionInfo.Compatibilities)
				archs := make([]any, 0, len(versionInfo.Architecture))
				for _, arch := range versionInfo.Architecture {
					archs = append(archs, arch)
				}
				computeTypes := make([]any, 0, len(versionInfo.ComputeTypes))
				for _, ct := range versionInfo.ComputeTypes {
					computeTypes = append(computeTypes, ct)
				}

				mqlAddonVersion, err := CreateResource(a.MqlRuntime, "aws.eks.addonVersion",
					map[string]*llx.RawData{
						"__id":                   llx.StringData(fmt.Sprintf("aws.eks.addonVersion/%s/%s/%s", regionVal, addonName, version)),
						"addonName":              llx.StringData(addonName),
						"addonVersion":           llx.StringData(version),
						"architectures":          llx.ArrayData(archs, "\x02"),
						"computeTypes":           llx.ArrayData(computeTypes, "\x02"),
						"requiresConfiguration":  llx.BoolData(versionInfo.RequiresConfiguration),
						"requiresIamPermissions": llx.BoolData(versionInfo.RequiresIamPermissions),
					})
				if err != nil {
					return nil, err
				}
				// Set compatibilities eagerly since we already have the data
				cast := mqlAddonVersion.(*mqlAwsEksAddonVersion)
				cast.region = regionVal
				cast.Compatibilities = plugin.TValue[[]any]{Data: compats, State: plugin.StateIsSet}
				res = append(res, mqlAddonVersion)
			}
		}
	}
	return res, nil
}

type mqlAwsEksAddonVersionInternal struct {
	region string
}

func (a *mqlAwsEksAddonVersion) id() (string, error) {
	return fmt.Sprintf("aws.eks.addonVersion/%s/%s/%s", a.region, a.AddonName.Data, a.AddonVersion.Data), nil
}

func (a *mqlAwsEksAddonVersion) compatibilities() ([]any, error) {
	// Compatibilities are set eagerly during creation
	return nil, nil
}

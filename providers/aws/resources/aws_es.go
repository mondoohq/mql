// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	es_types "github.com/aws/aws-sdk-go-v2/service/elasticsearchservice/types"
	"github.com/aws/smithy-go/transport/http"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// esDescribeBatchSize is the maximum number of domain names accepted by a single
// DescribeElasticsearchDomains call.
const esDescribeBatchSize = 5

// chunkStrings splits s into successive slices of at most size elements.
// A non-positive size returns a single chunk containing all of s.
func chunkStrings(s []string, size int) [][]string {
	if len(s) == 0 {
		return nil
	}
	if size <= 0 {
		return [][]string{s}
	}
	out := make([][]string, 0, (len(s)+size-1)/size)
	for i := 0; i < len(s); i += size {
		end := i + size
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}

type mqlAwsEsDomainInternal struct {
	cacheCustomEndpointCertificateArn string
	cacheCognitoRoleArn               string
	securityGroupIdHandler
	region    string
	accountID string

	cacheVpcId                  *string
	cacheSubnetIds              []string
	cacheKmsKeyId               *string
	cacheAuditLogGroupArn       *string
	cacheIndexSlowLogGroupArn   *string
	cacheSearchSlowLogGroupArn  *string
	cacheApplicationLogGroupArn *string
}

func (a *mqlAwsEs) id() (string, error) {
	return ResourceAwsEs, nil
}

func (a *mqlAwsEs) domains() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDomains(conn), 5)
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

func (a *mqlAwsEs) getDomains(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Es(region)
			ctx := context.Background()
			res := []any{}

			domains, err := svc.ListDomainNames(ctx, &elasticsearchservice.ListDomainNamesInput{})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				return nil, err
			}

			names := make([]string, 0, len(domains.DomainNames))
			for _, domain := range domains.DomainNames {
				if n := convert.ToValue(domain.DomainName); n != "" {
					names = append(names, n)
				}
			}

			// DescribeElasticsearchDomains accepts up to 5 domain names per call.
			for _, batch := range chunkStrings(names, esDescribeBatchSize) {
				resp, err := svc.DescribeElasticsearchDomains(ctx, &elasticsearchservice.DescribeElasticsearchDomainsInput{DomainNames: batch})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Strs("domains", batch).Msg("access denied describing es domains")
						continue
					}
					return nil, err
				}
				for j := range resp.DomainStatusList {
					mqlDomain, err := newMqlAwsEsDomain(a.MqlRuntime, region, conn.AccountId(), svc, resp.DomainStatusList[j])
					if err != nil {
						return nil, err
					}
					res = append(res, mqlDomain)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// newMqlAwsEsDomain builds an aws.es.domain resource from a fully described DomainStatus.
func newMqlAwsEsDomain(runtime *plugin.Runtime, region, accountID string, svc *elasticsearchservice.Client, status es_types.ElasticsearchDomainStatus) (*mqlAwsEsDomain, error) {
	tags, err := getESTags(context.Background(), svc, status.ARN)
	if err != nil {
		return nil, err
	}

	// encryption at rest
	var encAtRestEnabled bool
	var encAtRestKmsKeyId *string
	if status.EncryptionAtRestOptions != nil {
		encAtRestEnabled = convert.ToValue(status.EncryptionAtRestOptions.Enabled)
		encAtRestKmsKeyId = status.EncryptionAtRestOptions.KmsKeyId
	}

	// node-to-node encryption
	var nodeToNodeEncryptionEnabled bool
	if status.NodeToNodeEncryptionOptions != nil {
		nodeToNodeEncryptionEnabled = convert.ToValue(status.NodeToNodeEncryptionOptions.Enabled)
	}

	// domain endpoint options
	var enforceHTTPS bool
	var tlsSecurityPolicy string
	var customEndpointEnabled bool
	var customEndpoint string
	var customEndpointCertificateArn string
	if status.DomainEndpointOptions != nil {
		enforceHTTPS = convert.ToValue(status.DomainEndpointOptions.EnforceHTTPS)
		tlsSecurityPolicy = string(status.DomainEndpointOptions.TLSSecurityPolicy)
		customEndpointEnabled = convert.ToValue(status.DomainEndpointOptions.CustomEndpointEnabled)
		customEndpoint = convert.ToValue(status.DomainEndpointOptions.CustomEndpoint)
		customEndpointCertificateArn = convert.ToValue(status.DomainEndpointOptions.CustomEndpointCertificateArn)
	}

	// log publishing
	var auditLogEnabled, indexSlowLogEnabled, searchSlowLogEnabled, applicationLogEnabled bool
	var auditLogArn, indexSlowLogArn, searchSlowLogArn, applicationLogArn *string
	if status.LogPublishingOptions != nil {
		if opt, ok := status.LogPublishingOptions["AUDIT_LOGS"]; ok {
			auditLogEnabled = convert.ToValue(opt.Enabled)
			auditLogArn = opt.CloudWatchLogsLogGroupArn
		}
		if opt, ok := status.LogPublishingOptions["INDEX_SLOW_LOGS"]; ok {
			indexSlowLogEnabled = convert.ToValue(opt.Enabled)
			indexSlowLogArn = opt.CloudWatchLogsLogGroupArn
		}
		if opt, ok := status.LogPublishingOptions["SEARCH_SLOW_LOGS"]; ok {
			searchSlowLogEnabled = convert.ToValue(opt.Enabled)
			searchSlowLogArn = opt.CloudWatchLogsLogGroupArn
		}
		if opt, ok := status.LogPublishingOptions["ES_APPLICATION_LOGS"]; ok {
			applicationLogEnabled = convert.ToValue(opt.Enabled)
			applicationLogArn = opt.CloudWatchLogsLogGroupArn
		}
	}

	// VPC options
	var vpcId string
	var subnetIds []string
	var securityGroupIds []string
	var availabilityZones []string
	if status.VPCOptions != nil {
		vpcId = convert.ToValue(status.VPCOptions.VPCId)
		subnetIds = status.VPCOptions.SubnetIds
		securityGroupIds = status.VPCOptions.SecurityGroupIds
		availabilityZones = status.VPCOptions.AvailabilityZones
	}

	// cluster config
	var instanceType, dedicatedMasterType, warmType string
	var instanceCount, dedicatedMasterCount, warmCount, zoneAwarenessAZCount int64
	var dedicatedMasterEnabled, zoneAwarenessEnabled, warmEnabled, coldStorageEnabled bool
	if status.ElasticsearchClusterConfig != nil {
		c := status.ElasticsearchClusterConfig
		instanceType = string(c.InstanceType)
		instanceCount = int64(convert.ToValue(c.InstanceCount))
		dedicatedMasterEnabled = convert.ToValue(c.DedicatedMasterEnabled)
		dedicatedMasterType = string(c.DedicatedMasterType)
		dedicatedMasterCount = int64(convert.ToValue(c.DedicatedMasterCount))
		zoneAwarenessEnabled = convert.ToValue(c.ZoneAwarenessEnabled)
		if c.ZoneAwarenessConfig != nil {
			zoneAwarenessAZCount = int64(convert.ToValue(c.ZoneAwarenessConfig.AvailabilityZoneCount))
		}
		warmEnabled = convert.ToValue(c.WarmEnabled)
		warmType = string(c.WarmType)
		warmCount = int64(convert.ToValue(c.WarmCount))
		if c.ColdStorageOptions != nil {
			coldStorageEnabled = convert.ToValue(c.ColdStorageOptions.Enabled)
		}
	}

	// EBS
	var ebsEnabled bool
	var ebsVolumeType string
	var ebsVolumeSize, ebsIops, ebsThroughput int64
	if status.EBSOptions != nil {
		ebsEnabled = convert.ToValue(status.EBSOptions.EBSEnabled)
		ebsVolumeType = string(status.EBSOptions.VolumeType)
		ebsVolumeSize = int64(convert.ToValue(status.EBSOptions.VolumeSize))
		ebsIops = int64(convert.ToValue(status.EBSOptions.Iops))
		ebsThroughput = int64(convert.ToValue(status.EBSOptions.Throughput))
	}

	// advanced security
	var advancedSecurityEnabled, internalUserDatabaseEnabled, anonymousAuthEnabled bool
	if status.AdvancedSecurityOptions != nil {
		advancedSecurityEnabled = convert.ToValue(status.AdvancedSecurityOptions.Enabled)
		internalUserDatabaseEnabled = convert.ToValue(status.AdvancedSecurityOptions.InternalUserDatabaseEnabled)
		anonymousAuthEnabled = convert.ToValue(status.AdvancedSecurityOptions.AnonymousAuthEnabled)
	}

	// snapshot
	var automatedSnapshotStartHour int64
	if status.SnapshotOptions != nil {
		automatedSnapshotStartHour = int64(convert.ToValue(status.SnapshotOptions.AutomatedSnapshotStartHour))
	}

	// automated snapshot pause
	var automatedSnapshotPauseEnabled bool
	var automatedSnapshotPauseState string
	automatedSnapshotPauseStartTime := llx.NilData
	automatedSnapshotPauseEndTime := llx.NilData
	if status.AutomatedSnapshotPauseOptions != nil {
		automatedSnapshotPauseEnabled = convert.ToValue(status.AutomatedSnapshotPauseOptions.Enabled)
		automatedSnapshotPauseState = string(status.AutomatedSnapshotPauseOptions.State)
		automatedSnapshotPauseStartTime = llx.TimeDataPtr(status.AutomatedSnapshotPauseOptions.StartTime)
		automatedSnapshotPauseEndTime = llx.TimeDataPtr(status.AutomatedSnapshotPauseOptions.EndTime)
	}

	// Cognito
	var cognitoEnabled bool
	var cognitoUserPoolId, cognitoIdentityPoolId, cognitoRoleArn string
	if status.CognitoOptions != nil {
		cognitoEnabled = convert.ToValue(status.CognitoOptions.Enabled)
		cognitoUserPoolId = convert.ToValue(status.CognitoOptions.UserPoolId)
		cognitoIdentityPoolId = convert.ToValue(status.CognitoOptions.IdentityPoolId)
		cognitoRoleArn = convert.ToValue(status.CognitoOptions.RoleArn)
	}

	// AutoTune
	var autoTuneState string
	if status.AutoTuneOptions != nil {
		autoTuneState = string(status.AutoTuneOptions.State)
	}

	// service software options
	var serviceSoftwareCurrentVersion, serviceSoftwareNewVersion, serviceSoftwareUpdateStatus string
	var serviceSoftwareUpdateAvailable, serviceSoftwareCancellable bool
	var serviceSoftwareAutomatedUpdateDate *llx.RawData
	if status.ServiceSoftwareOptions != nil {
		s := status.ServiceSoftwareOptions
		serviceSoftwareCurrentVersion = convert.ToValue(s.CurrentVersion)
		serviceSoftwareNewVersion = convert.ToValue(s.NewVersion)
		serviceSoftwareUpdateAvailable = convert.ToValue(s.UpdateAvailable)
		serviceSoftwareCancellable = convert.ToValue(s.Cancellable)
		serviceSoftwareUpdateStatus = string(s.UpdateStatus)
		// AWS returns the Unix epoch when no automated update is scheduled;
		// surface that sentinel as null rather than a 1970 timestamp.
		if d := s.AutomatedUpdateDate; d != nil && d.Unix() > 0 {
			serviceSoftwareAutomatedUpdateDate = llx.TimeDataPtr(d)
		} else {
			serviceSoftwareAutomatedUpdateDate = llx.NilData
		}
	} else {
		serviceSoftwareAutomatedUpdateDate = llx.NilData
	}

	// Last configuration change progress (change provenance: who initiated the
	// most recent change and when).
	var lastConfigChangeId, lastConfigChangeInitiatedBy, lastConfigChangeStatus string
	lastConfigChangeStartedAt := llx.NilData
	lastConfigChangeUpdatedAt := llx.NilData
	if cpd := status.ChangeProgressDetails; cpd != nil {
		lastConfigChangeId = convert.ToValue(cpd.ChangeId)
		lastConfigChangeInitiatedBy = string(cpd.InitiatedBy)
		lastConfigChangeStatus = string(cpd.ConfigChangeStatus)
		lastConfigChangeStartedAt = llx.TimeDataPtr(cpd.StartTime)
		lastConfigChangeUpdatedAt = llx.TimeDataPtr(cpd.LastUpdatedTime)
	}

	// endpoints map
	endpointsMap := make(map[string]any)
	for k, v := range status.Endpoints {
		endpointsMap[k] = v
	}

	args := map[string]*llx.RawData{
		"arn":                                llx.StringDataPtr(status.ARN),
		"name":                               llx.StringDataPtr(status.DomainName),
		"region":                             llx.StringData(region),
		"domainId":                           llx.StringDataPtr(status.DomainId),
		"domainName":                         llx.StringDataPtr(status.DomainName),
		"elasticsearchVersion":               llx.StringDataPtr(status.ElasticsearchVersion),
		"engineMode":                         llx.StringData(string(status.EngineMode)),
		"useCase":                            llx.StringData(string(status.UseCase)),
		"endpoint":                           llx.StringDataPtr(status.Endpoint),
		"endpoints":                          llx.MapData(endpointsMap, types.String),
		"tags":                               llx.MapData(tags, types.String),
		"accessPolicies":                     llx.StringDataPtr(status.AccessPolicies),
		"created":                            llx.BoolData(convert.ToValue(status.Created)),
		"deleted":                            llx.BoolData(convert.ToValue(status.Deleted)),
		"processing":                         llx.BoolData(convert.ToValue(status.Processing)),
		"upgradeProcessing":                  llx.BoolData(convert.ToValue(status.UpgradeProcessing)),
		"domainProcessingStatus":             llx.StringData(string(status.DomainProcessingStatus)),
		"encryptionAtRestEnabled":            llx.BoolData(encAtRestEnabled),
		"nodeToNodeEncryptionEnabled":        llx.BoolData(nodeToNodeEncryptionEnabled),
		"enforceHTTPS":                       llx.BoolData(enforceHTTPS),
		"tlsSecurityPolicy":                  llx.StringData(tlsSecurityPolicy),
		"customEndpointEnabled":              llx.BoolData(customEndpointEnabled),
		"customEndpoint":                     llx.StringData(customEndpoint),
		"availabilityZones":                  llx.ArrayData(toInterfaceArr(availabilityZones), types.String),
		"instanceType":                       llx.StringData(instanceType),
		"instanceCount":                      llx.IntData(instanceCount),
		"dedicatedMasterEnabled":             llx.BoolData(dedicatedMasterEnabled),
		"dedicatedMasterType":                llx.StringData(dedicatedMasterType),
		"dedicatedMasterCount":               llx.IntData(dedicatedMasterCount),
		"zoneAwarenessEnabled":               llx.BoolData(zoneAwarenessEnabled),
		"zoneAwarenessAvailabilityZoneCount": llx.IntData(zoneAwarenessAZCount),
		"warmEnabled":                        llx.BoolData(warmEnabled),
		"warmType":                           llx.StringData(warmType),
		"warmCount":                          llx.IntData(warmCount),
		"coldStorageEnabled":                 llx.BoolData(coldStorageEnabled),
		"ebsEnabled":                         llx.BoolData(ebsEnabled),
		"ebsVolumeType":                      llx.StringData(ebsVolumeType),
		"ebsVolumeSize":                      llx.IntData(ebsVolumeSize),
		"ebsIops":                            llx.IntData(ebsIops),
		"ebsThroughput":                      llx.IntData(ebsThroughput),
		"advancedSecurityEnabled":            llx.BoolData(advancedSecurityEnabled),
		"internalUserDatabaseEnabled":        llx.BoolData(internalUserDatabaseEnabled),
		"anonymousAuthEnabled":               llx.BoolData(anonymousAuthEnabled),
		"automatedSnapshotStartHour":         llx.IntData(automatedSnapshotStartHour),
		"automatedSnapshotPauseEnabled":      llx.BoolData(automatedSnapshotPauseEnabled),
		"automatedSnapshotPauseState":        llx.StringData(automatedSnapshotPauseState),
		"automatedSnapshotPauseStartTime":    automatedSnapshotPauseStartTime,
		"automatedSnapshotPauseEndTime":      automatedSnapshotPauseEndTime,
		"cognitoEnabled":                     llx.BoolData(cognitoEnabled),
		"cognitoUserPoolId":                  llx.StringData(cognitoUserPoolId),
		"cognitoIdentityPoolId":              llx.StringData(cognitoIdentityPoolId),
		"autoTuneState":                      llx.StringData(autoTuneState),
		"serviceSoftwareCurrentVersion":      llx.StringData(serviceSoftwareCurrentVersion),
		"serviceSoftwareNewVersion":          llx.StringData(serviceSoftwareNewVersion),
		"serviceSoftwareUpdateAvailable":     llx.BoolData(serviceSoftwareUpdateAvailable),
		"serviceSoftwareCancellable":         llx.BoolData(serviceSoftwareCancellable),
		"serviceSoftwareUpdateStatus":        llx.StringData(serviceSoftwareUpdateStatus),
		"serviceSoftwareAutomatedUpdateDate": serviceSoftwareAutomatedUpdateDate,
		"lastConfigChangeId":                 llx.StringData(lastConfigChangeId),
		"lastConfigChangeInitiatedBy":        llx.StringData(lastConfigChangeInitiatedBy),
		"lastConfigChangeStatus":             llx.StringData(lastConfigChangeStatus),
		"lastConfigChangeStartedAt":          lastConfigChangeStartedAt,
		"lastConfigChangeUpdatedAt":          lastConfigChangeUpdatedAt,
		"auditLogEnabled":                    llx.BoolData(auditLogEnabled),
		"indexSlowLogEnabled":                llx.BoolData(indexSlowLogEnabled),
		"searchSlowLogEnabled":               llx.BoolData(searchSlowLogEnabled),
		"applicationLogEnabled":              llx.BoolData(applicationLogEnabled),
	}

	resource, err := CreateResource(runtime, ResourceAwsEsDomain, args)
	if err != nil {
		return nil, err
	}
	resource.(*mqlAwsEsDomain).cacheCustomEndpointCertificateArn = customEndpointCertificateArn
	resource.(*mqlAwsEsDomain).cacheCognitoRoleArn = cognitoRoleArn
	mqlDomain := resource.(*mqlAwsEsDomain)
	mqlDomain.region = region
	mqlDomain.accountID = accountID
	if vpcId != "" {
		v := vpcId
		mqlDomain.cacheVpcId = &v
	}
	mqlDomain.cacheSubnetIds = subnetIds
	if len(securityGroupIds) > 0 {
		sgArns := make([]string, 0, len(securityGroupIds))
		for _, sg := range securityGroupIds {
			sgArns = append(sgArns, NewSecurityGroupArn(region, accountID, sg))
		}
		mqlDomain.setSecurityGroupArns(sgArns)
	}
	mqlDomain.cacheKmsKeyId = encAtRestKmsKeyId
	mqlDomain.cacheAuditLogGroupArn = auditLogArn
	mqlDomain.cacheIndexSlowLogGroupArn = indexSlowLogArn
	mqlDomain.cacheSearchSlowLogGroupArn = searchSlowLogArn
	mqlDomain.cacheApplicationLogGroupArn = applicationLogArn
	return mqlDomain, nil
}

func initAwsEsDomain(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformEsDomain); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil && args["name"] == nil {
		return nil, nil, errors.New("arn or name required to fetch es domain")
	}

	if cached := cachedArgByArn(runtime, ResourceAwsEsDomain, args); cached != nil {
		return args, cached, nil
	}

	// If we have an ARN but missing region or name, extract from ARN
	// ARN format: arn:aws:es:REGION:ACCOUNT:domain/DOMAIN_NAME
	if args["arn"] != nil && (args["region"] == nil || args["name"] == nil) {
		arnVal := args["arn"].Value.(string)
		parsedArn, err := arn.Parse(arnVal)
		if err != nil {
			return nil, nil, errors.New("invalid arn for es domain")
		}
		if args["region"] == nil {
			args["region"] = llx.StringData(parsedArn.Region)
		}
		if args["name"] == nil {
			args["name"] = llx.StringData(strings.TrimPrefix(parsedArn.Resource, "domain/"))
		}
	}

	if args["name"] == nil || args["region"] == nil {
		return nil, nil, errors.New("arn, or name and region required to fetch es domain")
	}

	name := args["name"].Value.(string)
	region := args["region"].Value.(string)

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Es(region)
	ctx := context.Background()
	domainDetails, err := svc.DescribeElasticsearchDomain(ctx, &elasticsearchservice.DescribeElasticsearchDomainInput{DomainName: &name})
	if err != nil {
		return nil, nil, err
	}
	if domainDetails == nil || domainDetails.DomainStatus == nil {
		return args, nil, nil
	}
	mqlDomain, err := newMqlAwsEsDomain(runtime, region, conn.AccountId(), svc, *domainDetails.DomainStatus)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlDomain, nil
}

func (a *mqlAwsEsDomain) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEsDomain) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
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

func (a *mqlAwsEsDomain) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlVpc, err := NewResource(a.MqlRuntime, "aws.vpc",
		map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.region, a.accountID, *a.cacheVpcId)),
		})
	if err != nil {
		return nil, err
	}
	return mqlVpc.(*mqlAwsVpc), nil
}

func (a *mqlAwsEsDomain) customEndpointCertificate() (*mqlAwsAcmCertificate, error) {
	arnVal := a.cacheCustomEndpointCertificateArn
	if arnVal == "" {
		a.CustomEndpointCertificate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsAcmCertificate,
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsAcmCertificate), nil
}

func (a *mqlAwsEsDomain) cognitoRole() (*mqlAwsIamRole, error) {
	arnVal := a.cacheCognitoRoleArn
	if arnVal == "" {
		a.CognitoRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsEsDomain) subnets() ([]any, error) {
	res := []any{}
	for _, subnetId := range a.cacheSubnetIds {
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.region, a.accountID, subnetId)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsEsDomain) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsEsDomain) auditLogGroup() (*mqlAwsCloudwatchLoggroup, error) {
	return esResolveLogGroup(a.MqlRuntime, a.cacheAuditLogGroupArn, &a.AuditLogGroup)
}

func (a *mqlAwsEsDomain) indexSlowLogGroup() (*mqlAwsCloudwatchLoggroup, error) {
	return esResolveLogGroup(a.MqlRuntime, a.cacheIndexSlowLogGroupArn, &a.IndexSlowLogGroup)
}

func (a *mqlAwsEsDomain) searchSlowLogGroup() (*mqlAwsCloudwatchLoggroup, error) {
	return esResolveLogGroup(a.MqlRuntime, a.cacheSearchSlowLogGroupArn, &a.SearchSlowLogGroup)
}

func (a *mqlAwsEsDomain) applicationLogGroup() (*mqlAwsCloudwatchLoggroup, error) {
	return esResolveLogGroup(a.MqlRuntime, a.cacheApplicationLogGroupArn, &a.ApplicationLogGroup)
}

func esResolveLogGroup(runtime *plugin.Runtime, arnPtr *string, field *plugin.TValue[*mqlAwsCloudwatchLoggroup]) (*mqlAwsCloudwatchLoggroup, error) {
	if arnPtr == nil || *arnPtr == "" {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, "aws.cloudwatch.loggroup",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(arnPtr)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCloudwatchLoggroup), nil
}

func getESTags(ctx context.Context, svc *elasticsearchservice.Client, arn *string) (map[string]any, error) {
	resp, err := svc.ListTags(ctx, &elasticsearchservice.ListTagsInput{ARN: arn})
	var respErr *http.ResponseError
	if err != nil {
		if errors.As(err, &respErr) {
			if respErr.HTTPStatusCode() == 404 {
				return nil, nil
			}
		}
		return nil, err
	}
	tags := make(map[string]any)
	for _, t := range resp.TagList {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	return tags, nil
}

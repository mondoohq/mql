// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/providers/aws/connection/awsec2ebsconn"
	awsec2ebstypes "go.mondoo.com/mql/providers/aws/connection/awsec2ebsconn/types"
	"go.mondoo.com/mql/providers/os/id/awsec2"
	"go.mondoo.com/mql/providers/os/id/containerid"
	"go.mondoo.com/mql/providers/os/id/ids"
)

const (
	MondooRegionLabelKey        = "mondoo.com/region"
	MondooInstanceLabelKey      = "mondoo.com/instance-id"
	MondooPlatformLabelKey      = "mondoo.com/platform"
	MondooLaunchTimeLabelKey    = "mondoo.com/launch-time"
	MondooInstanceTypeLabelKey  = "mondoo.com/instance-type"
	MondooParentIdLabelKey      = "mondoo.com/parent-id"
	MondooImageLabelKey         = "mondoo.com/image"
	MondooContainerNameLabelKey = "mondoo.com/container-name"
	MondooClusterNameLabelKey   = "mondoo.com/cluster-name"
	MondooTaskArnLabelKey       = "mondoo.com/task-arn"
	MondooSsmConnection         = "mondoo.com/ssm-connection"
)

type mqlObject struct {
	name        string
	labels      map[string]string
	awsObject   awsObject
	platformIds []string
}

type awsObject struct {
	account    string
	region     string
	id         string
	service    string
	objectType string
	arn        string
}

func MondooObjectID(awsObject awsObject) string {
	accountId := trimAwsAccountIdToJustId(awsObject.account)
	return "//platformid.api.mondoo.app/runtime/aws/" + awsObject.service + "/v1/accounts/" + accountId + "/regions/" + awsObject.region + "/" + awsObject.objectType + "/" + awsObject.id
}

func MqlObjectToAsset(account string, mqlObject mqlObject, conn *connection.AwsConnection) *inventory.Asset {
	if name := mqlObject.labels["Name"]; name != "" {
		mqlObject.name = name
	}
	if mqlObject.name == "" {
		mqlObject.name = mqlObject.awsObject.id
	}
	if err := validate(mqlObject); err != nil {
		log.Error().Err(err).Msg("missing values in mql object to asset translation")
		return nil
	}
	platformName := getPlatformName(mqlObject.awsObject)
	if platformName == "" {
		log.Error().Err(errors.New("could not fetch platform info for object")).Msg("missing runtime info")
		return nil
	}
	platformid := MondooObjectID(mqlObject.awsObject)
	// Clone first to avoid mutating the parent connection's config (race condition)
	clonedConfig := conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id), inventory.WithFilters())
	clonedConfig.PlatformId = platformid
	platformIds := []string{platformid, mqlObject.awsObject.arn}
	platformIds = append(platformIds, mqlObject.platformIds...)
	return &inventory.Asset{
		PlatformIds: platformIds,
		Name:        mqlObject.name,
		Platform:    connection.GetPlatformForObject(platformName, account),
		Labels:      mqlObject.labels,
		Connections: []*inventory.Config{clonedConfig},
		Options:     conn.ConnectionOptions(),
	}
}

func validate(m mqlObject) error {
	if m.name == "" {
		return errors.New("name required for mql aws object to asset translation")
	}
	if m.awsObject.id == "" {
		return errors.New("id required for mql aws object to asset translation")
	}
	if m.awsObject.region == "" {
		return errors.New("region required for mql aws object to asset translation")
	}
	if m.awsObject.account == "" {
		return errors.New("account required for mql aws object to asset translation")
	}
	if m.awsObject.arn == "" {
		return errors.New("arn required for mql aws object to asset translation")
	}
	return nil
}

func getPlatformName(awsObject awsObject) string {
	switch awsObject.service {
	case "s3":
		if awsObject.objectType == "bucket" {
			return "aws-s3-bucket"
		}
	case "cloudtrail":
		if awsObject.objectType == "trail" {
			return "aws-cloudtrail-trail"
		}
	case "rds":
		if awsObject.objectType == "dbinstance" {
			return "aws-rds-dbinstance"
		}
		if awsObject.objectType == "dbcluster" {
			return "aws-rds-dbcluster"
		}
		if awsObject.objectType == "snapshot" {
			return "aws-rds-snapshot"
		}
	case "dynamodb":
		switch awsObject.objectType {
		case "table":
			return "aws-dynamodb-table"
		case "globaltable":
			// Split out from "table" so a global table and its us-east-1 replica
			// stop sharing a platform id. Without a case here getPlatformName
			// returns "" and MqlObjectToAsset drops the asset entirely, so every
			// global table silently disappeared from discovery.
			return "aws-dynamodb-globaltable"
		}
	case "redshift":
		if awsObject.objectType == "cluster" {
			return "aws-redshift-cluster"
		}
	case "vpc":
		if awsObject.objectType == "vpc" {
			return "aws-vpc"
		}
	case "ec2":
		switch awsObject.objectType {
		case "securitygroup":
			return "aws-security-group"
		case "volume":
			return "aws-ebs-volume"
		case "snapshot":
			return "aws-ebs-snapshot"
		case "instance":
			return "aws-ec2-instance"
		}
	case "iam":
		switch awsObject.objectType {
		case "user":
			return "aws-iam-user"

		case "group":
			return "aws-iam-group"
		}
	case "cloudwatch":
		if awsObject.objectType == "loggroup" {
			return "aws-cloudwatch-loggroup"
		}
	case "lambda":
		if awsObject.objectType == "function" {
			return "aws-lambda-function"
		}
	case "ecs":
		switch awsObject.objectType {
		case "container":
			return "aws-ecs-container"
		case "instance":
			return "aws-ecs-instance"
		case "taskdefinition":
			return "aws-ecs-taskdefinition"
		}
	case "efs":
		if awsObject.objectType == "filesystem" {
			return "aws-efs-filesystem"
		}
	case "gateway":
		if awsObject.objectType == "restapi" {
			return "aws-gateway-restapi"
		}
	case "elb":
		if awsObject.objectType == "loadbalancer" {
			return "aws-elb-loadbalancer"
		}
	case "es":
		if awsObject.objectType == "domain" {
			return "aws-es-domain"
		}
	case "kms":
		if awsObject.objectType == "key" {
			return "aws-kms-key"
		}
	case "sagemaker":
		switch awsObject.objectType {
		case "notebookinstance":
			return "aws-sagemaker-notebookinstance"
		case "processingjob":
			return "aws-sagemaker-processingjob"
		case "trainingjob":
			return "aws-sagemaker-trainingjob"
		case "domain":
			return "aws-sagemaker-domain"
		case "model":
			return "aws-sagemaker-model"
		}
	case "secretsmanager":
		if awsObject.objectType == "secret" {
			return "aws-secretsmanager-secret"
		}
	case "ssm":
		if awsObject.objectType == "instance" {
			return "aws-ssm-instance"
		}
	case "ecr":
		switch awsObject.objectType {
		case "image":
			return "aws-ecr-image"
		case "repository":
			return "aws-ecr-repository"
		}
	case "eks":
		if awsObject.objectType == "cluster" {
			return "aws-eks-cluster"
		}
	case "opensearch":
		if awsObject.objectType == "domain" {
			return "aws-opensearch-domain"
		}
	case "elasticache":
		if awsObject.objectType == "cluster" {
			return "aws-elasticache-cluster"
		}
	case "cloudfront":
		if awsObject.objectType == "distribution" {
			return "aws-cloudfront-distribution"
		}
	case "neptune":
		if awsObject.objectType == "cluster" {
			return "aws-neptune-cluster"
		}
	case "emr":
		if awsObject.objectType == "cluster" {
			return "aws-emr-cluster"
		}
	case "documentdb":
		switch awsObject.objectType {
		case "cluster":
			return "aws-documentdb-cluster"
		case "instance":
			return "aws-documentdb-instance"
		}
	case "msk":
		if awsObject.objectType == "cluster" {
			return "aws-msk-cluster"
		}
	case "mq":
		if awsObject.objectType == "broker" {
			return "aws-mq-broker"
		}
	case "route53":
		if awsObject.objectType == "hostedzone" {
			return "aws-route53-hostedzone"
		}
	case "memorydb":
		if awsObject.objectType == "cluster" {
			return "aws-memorydb-cluster"
		}
	case "codebuild":
		if awsObject.objectType == "project" {
			return "aws-codebuild-project"
		}
	case "cognito":
		if awsObject.objectType == "userpool" {
			return "aws-cognito-userpool"
		}
	case "transfer":
		if awsObject.objectType == "server" {
			return "aws-transfer-server"
		}
	case "apigatewayv2":
		if awsObject.objectType == "api" {
			return "aws-apigatewayv2-api"
		}
	case "athena":
		if awsObject.objectType == "workgroup" {
			return "aws-athena-workgroup"
		}
	case "appstream":
		if awsObject.objectType == "fleet" {
			return "aws-appstream-fleet"
		}
	case "batch":
		if awsObject.objectType == "jobdefinition" {
			return "aws-batch-jobdefinition"
		}
	case "ds":
		if awsObject.objectType == "directory" {
			return "aws-directoryservice-directory"
		}
	case "sns":
		if awsObject.objectType == "topic" {
			return "aws-sns-topic"
		}
	case "sqs":
		if awsObject.objectType == "queue" {
			return "aws-sqs-queue"
		}
	}
	return ""
}

func accountAsset(conn *connection.AwsConnection, awsAccount *mqlAwsAccount) *inventory.Asset {
	var alias string
	aliases := awsAccount.GetAliases()
	if len(aliases.Data) > 0 {
		alias = aliases.Data[0].(string)
	}
	accountId := trimAwsAccountIdToJustId(awsAccount.Id.Data)
	name := AssembleIntegrationName(alias, accountId)

	id := "//platformid.api.mondoo.app/runtime/aws/accounts/" + accountId
	accountArn := "arn:aws:sts::" + accountId
	// Clone first to avoid mutating the parent connection's config
	clonedConfig := conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id), inventory.WithFilters())
	clonedConfig.PlatformId = id
	return &inventory.Asset{
		PlatformIds: []string{id, accountArn},
		Name:        name,
		Platform:    connection.GetPlatformForObject("", accountId),
		Labels:      map[string]string{},
		Connections: []*inventory.Config{clonedConfig},
		Options:     conn.ConnectionOptions(),
	}
}

func trimAwsAccountIdToJustId(id string) string {
	return strings.TrimPrefix(id, "aws.account/")
}

func AssembleIntegrationName(alias string, id string) string {
	accountId := trimAwsAccountIdToJustId(id)
	if alias == "" {
		return fmt.Sprintf("AWS Account %s", accountId)
	}
	return fmt.Sprintf("AWS Account %s (%s)", alias, accountId)
}

func getPlatformFamily(pf string) []string {
	if strings.Contains(strings.ToLower(pf), "linux") {
		return []string{"unix"}
	}
	if strings.Contains(strings.ToLower(pf), "windows") {
		return []string{"windows"}
	}
	return []string{}
}

// mergeAccountTagsIntoLabels merges account-level tags into an asset's labels.
// The asset's existing labels always win on key collisions — account tags only
// fill gaps. A nil labels map is initialized. An empty or nil accountTags map
// is a no-op.
func mergeAccountTagsIntoLabels(labels, accountTags map[string]string) map[string]string {
	if len(accountTags) == 0 {
		return labels
	}
	if labels == nil {
		labels = map[string]string{}
	}
	for k, v := range accountTags {
		if _, exists := labels[k]; !exists {
			labels[k] = v
		}
	}
	return labels
}

// isSiblingOrgAccountAsset returns true when the asset represents an AWS
// account other than the primary account (i.e. a sibling discovered via the
// organization target). These assets must not inherit the primary account's
// tags. Primary and sibling account assets both have Platform.Name == "aws"
// (set by GetPlatformForObject with an empty name), so the discriminator is
// whether the asset's platform id references the primary account id.
func isSiblingOrgAccountAsset(a *inventory.Asset, primaryAccountId string) bool {
	if a == nil || a.Platform == nil || a.Platform.Name != "aws" {
		return false
	}
	suffix := "/accounts/" + primaryAccountId
	for _, pid := range a.PlatformIds {
		if strings.HasSuffix(pid, suffix) {
			return false
		}
	}
	return true
}

// applyAccountTagsToAssets merges the primary account's tags into every asset
// in the list, except sibling org account assets which are skipped. The merge
// follows mergeAccountTagsIntoLabels semantics: asset labels win on collision.
func applyAccountTagsToAssets(assets []*inventory.Asset, accountTags map[string]string, primaryAccountId string) {
	if len(accountTags) == 0 {
		return
	}
	for _, a := range assets {
		if a == nil {
			continue
		}
		if isSiblingOrgAccountAsset(a, primaryAccountId) {
			continue
		}
		a.Labels = mergeAccountTagsIntoLabels(a.Labels, accountTags)
	}
}

type instanceInfo struct {
	region          string
	platformDetails string
	instanceType    string
	accountId       string
	instanceId      string
	launchTime      *time.Time
	image           *string
	instanceTags    map[string]string
}

func addMondooLabels(instance instanceInfo, asset *inventory.Asset) {
	if asset.Labels == nil {
		asset.Labels = make(map[string]string)
	}
	if instance.instanceTags != nil {
		asset.Labels = instance.instanceTags
	}
	asset.Labels[MondooRegionLabelKey] = instance.region
	asset.Labels[MondooPlatformLabelKey] = instance.platformDetails
	asset.Labels[MondooInstanceTypeLabelKey] = instance.instanceType
	asset.Labels[MondooParentIdLabelKey] = instance.accountId
	asset.Labels[MondooInstanceLabelKey] = instance.instanceId
	if instance.launchTime != nil {
		asset.Labels[MondooLaunchTimeLabelKey] = instance.launchTime.String()
	}
	if instance.image != nil {
		asset.Labels[MondooImageLabelKey] = *instance.image
	}
}

// isSsmOnline safely checks whether the SSM data for an EC2 instance indicates
// that the SSM agent is online, using safe type assertions to avoid panics.
func isSsmOnline(instance *mqlAwsEc2Instance) bool {
	ssm := instance.GetSsm()
	if ssm == nil || ssm.Data == nil {
		return false
	}
	ssmMap, ok := ssm.Data.(map[string]any)
	if !ok {
		return false
	}
	infoList, ok := ssmMap["InstanceInformationList"].([]any)
	if !ok || len(infoList) == 0 {
		return false
	}
	firstEntry, ok := infoList[0].(map[string]any)
	if !ok {
		return false
	}
	return firstEntry["PingStatus"] == "Online"
}

func addConnectionInfoToEc2Asset(instance *mqlAwsEc2Instance, accountId string, conn *connection.AwsConnection) *inventory.Asset {
	asset := &inventory.Asset{}
	asset.PlatformIds = []string{awsec2.MondooInstanceID(accountId, instance.Region.Data, instance.InstanceId.Data)}
	asset.IdDetector = []string{ids.IdDetector_Hostname, ids.IdDetector_CloudDetect}
	asset.Platform = &inventory.Platform{
		Kind:    inventory.AssetKindCloudVM,
		Runtime: "aws-ec2-instance",
		Family:  getPlatformFamily(instance.PlatformDetails.Data),
	}
	asset.State = mapEc2InstanceStateCode(instance.State.Data)
	instanceTags := mapStringInterfaceToStringString(instance.Tags.Data)
	asset.Name = getInstanceName(instance.InstanceId.Data, instanceTags)
	asset.Options = conn.ConnectionOptions()
	info := instanceInfo{
		instanceTags:    instanceTags,
		region:          instance.Region.Data,
		platformDetails: instance.PlatformDetails.Data,
		instanceType:    instance.InstanceType.Data,
		accountId:       accountId,
		instanceId:      instance.InstanceId.Data,
		launchTime:      instance.cacheLaunchTime,
	}
	if instance.GetImage().Data != nil {
		info.image = &instance.GetImage().Data.Id.Data
	}
	addMondooLabels(info, asset)
	imageName := ""
	if instance.GetImage().Data != nil {
		imageName = instance.GetImage().Data.Name.Data
	}
	probableUsername := getProbableUsernameFromImageName(imageName)

	// if there is a public ip & it is running, we assume ssh is an option
	if instance.PublicIp.Data != "" && instance.State.Data == string(types.InstanceStateNameRunning) {
		asset.Connections = []*inventory.Config{{
			Type:     "ssh",
			Host:     instance.PublicIp.Data,
			Insecure: true,
			Runtime:  "ssh",
			Credentials: []*vault.Credential{
				{
					Type: vault.CredentialType_aws_ec2_instance_connect,
					User: probableUsername,
				},
			},
			Options: map[string]string{
				"region":   instance.Region.Data,
				"profile":  conn.Profile(),
				"instance": instance.InstanceId.Data,
			},
		}}
	}
	// if the ssm agent indicates it is online, we assume ssm is an option
	if isSsmOnline(instance) {
		asset.Labels[MondooSsmConnection] = "Online"
		if len(asset.Connections) > 0 {
			asset.Connections[0].Credentials = append(asset.Connections[0].Credentials, &vault.Credential{
				User: probableUsername,
				Type: vault.CredentialType_aws_ec2_ssm_session,
			})
		} else {
			// if we don't have a connection already, we need to add one
			creds := []*vault.Credential{
				{
					User: probableUsername,
					Type: vault.CredentialType_aws_ec2_ssm_session,
				},
			}

			// try the public ip first, the private ip last.
			host := instance.InstanceId.Data
			if instance.PublicIp.Data != "" {
				host = instance.PublicIp.Data
			} else if instance.PrivateIp.Data != "" {
				host = instance.PrivateIp.Data
			}
			asset.Connections = []*inventory.Config{{
				Host:        host,
				Insecure:    true,
				Runtime:     "aws_ec2",
				Credentials: creds,
				Options: map[string]string{
					"region":   instance.Region.Data,
					"profile":  conn.Profile(),
					"instance": instance.InstanceId.Data,
				},
			}}
		}
	}
	return asset
}

// ec2InstanceIsDiscoverable reports whether an EC2 instance in this state can
// still be reached by any connection this provider knows how to build.
//
// EC2 keeps a terminated instance visible to DescribeInstances for roughly an
// hour after it goes away. Such an instance has no network interfaces, no
// volumes and no SSM agent, so addConnectionInfoToEc2Asset attaches no
// connections to it and every scan reports it as an asset that could not be
// connected to. It can never transition back, so there is nothing to wait for.
// An instance shutting down is on its way to the same place.
//
// Stopped instances deliberately stay discoverable: they keep their volumes,
// can be started again, and are still reachable through EBS scanning.
func ec2InstanceIsDiscoverable(state string) bool {
	switch state {
	case string(types.InstanceStateNameTerminated), string(types.InstanceStateNameShuttingDown):
		return false
	default:
		return true
	}
}

func mapEc2InstanceStateCode(state string) inventory.State {
	switch state {
	case string(types.InstanceStateNameRunning):
		return inventory.State_STATE_RUNNING
	case string(types.InstanceStateNamePending):
		return inventory.State_STATE_PENDING
	case string(types.InstanceStateNameShuttingDown): // 32 is shutting down, which is the step before terminated, assume terminated if we get shutting down
		return inventory.State_STATE_TERMINATED
	case string(types.InstanceStateNameStopping):
		return inventory.State_STATE_STOPPING
	case string(types.InstanceStateNameStopped):
		return inventory.State_STATE_STOPPED
	case string(types.InstanceStateNameTerminated):
		return inventory.State_STATE_TERMINATED
	default:
		log.Warn().Str("state", string(state)).Msg("unknown ec2 state")
		return inventory.State_STATE_UNKNOWN
	}
}

func getProbableUsernameFromImageName(name string) string {
	if strings.Contains(name, "centos") {
		return "centos"
	}
	if strings.Contains(name, "ubuntu") {
		return "ubuntu"
	}
	return "ec2-user"
}

func getInstanceName(id string, labels map[string]string) string {
	name := id
	if labelName := labels["Name"]; labelName != "" {
		name = labelName
	}
	return name
}

func addConnectionInfoToSSMAsset(instance *mqlAwsSsmInstance, accountId string, conn *connection.AwsConnection) *inventory.Asset {
	asset := &inventory.Asset{}
	asset.Labels = mapStringInterfaceToStringString(instance.GetTags().Data)
	asset.Labels["mondoo.com/platform"] = instance.PlatformName.Data
	asset.Labels["mondoo.com/region"] = instance.Region.Data

	asset.Name = getInstanceName(instance.InstanceId.Data, asset.Labels)
	creds := []*vault.Credential{
		{
			User: getProbableUsernameFromSSMPlatformName(strings.ToLower(instance.PlatformName.Data)),
		},
	}

	host := instance.InstanceId.Data
	if instance.IpAddress.Data != "" {
		host = instance.IpAddress.Data
	}
	asset.Options = conn.ConnectionOptions()
	asset.PlatformIds = []string{awsec2.MondooInstanceID(accountId, instance.Region.Data, instance.InstanceId.Data)}
	asset.Platform = &inventory.Platform{
		Kind:    inventory.AssetKindCloudVM,
		Runtime: "aws-ssm-instance",
		Family:  getPlatformFamily(instance.PlatformName.Data),
	}
	asset.State = mapSmmManagedPingStateCode(instance.PingStatus.Data)
	if strings.HasPrefix(instance.InstanceId.Data, "i-") && instance.PingStatus.Data == string(ssmtypes.PingStatusOnline) {
		creds[0].Type = vault.CredentialType_aws_ec2_ssm_session // this will only work for ec2 instances
		asset.Connections = []*inventory.Config{{
			Host:        host,
			Insecure:    true,
			Runtime:     "aws_ec2",
			Credentials: creds,
			Options: map[string]string{
				"region":   instance.Region.Data,
				"profile":  conn.Profile(),
				"instance": instance.InstanceId.Data,
			},
		}}
	}
	return asset
}

func getProbableUsernameFromSSMPlatformName(name string) string {
	if strings.HasPrefix(name, "centos") {
		return "centos"
	}
	if strings.HasPrefix(name, "ubuntu") {
		return "ubuntu"
	}
	return "ec2-user"
}

func mapSmmManagedPingStateCode(pingStatus string) inventory.State {
	switch pingStatus {
	case string(ssmtypes.PingStatusOnline):
		return inventory.State_STATE_RUNNING
	case string(ssmtypes.PingStatusConnectionLost):
		return inventory.State_STATE_PENDING
	case string(ssmtypes.PingStatusInactive):
		return inventory.State_STATE_STOPPED
	default:
		return inventory.State_STATE_UNKNOWN
	}
}

func MondooImageRegistryID(id string) string {
	return "//platformid.api.mondoo.app/runtime/docker/registry/" + id
}

func addConnectionInfoToEcrAsset(image *mqlAwsEcrImage, conn *connection.AwsConnection) *inventory.Asset {
	a := &inventory.Asset{}
	// NOTE: do not include platform id here, it will get filled in when we actually discover the images
	a.Platform = &inventory.Platform{
		Kind:    "container_image",
		Runtime: "aws-ecr",
	}
	a.Options = conn.ConnectionOptions()
	a.Name = ecrImageName(image.RepoName.Data, image.Digest.Data)
	a.State = inventory.State_STATE_ONLINE
	imageTags := []string{}
	for i := range image.Tags.Data {
		tag := image.Tags.Data[i].(string)
		imageTags = append(imageTags, tag)
	}

	a.Connections = append(a.Connections, &inventory.Config{
		Type: "registry-image",
		Host: image.Uri.Data + "@" + image.Digest.Data,
		Options: map[string]string{
			"region":  image.Region.Data,
			"profile": conn.Profile(),
		},
		Runtime:        "aws-ecr",
		DelayDiscovery: true,
	})

	a.Labels = make(map[string]string)
	// store digest
	a.Labels[fmt.Sprintf("ecr.%s.amazonaws.com/digest", image.Region.Data)] = image.Digest.Data
	a.Labels[fmt.Sprintf("ecr.%s.amazonaws.com/tags", image.Region.Data)] = strings.Join(imageTags, ",")

	// store repo digest
	repoDigests := []string{image.Uri.Data + "@" + image.Digest.Data}
	a.Labels[fmt.Sprintf("ecr.%s.amazonaws.com/repo-digests", image.Region.Data)] = strings.Join(repoDigests, ",")

	return a
}

func ecrImageName(repoName string, digest string) string {
	return repoName + "@" + digest
}

func mapContainerInstanceState(status *string) inventory.State {
	if status == nil {
		return inventory.State_STATE_UNKNOWN
	}
	switch *status {
	case "REGISTERING":
		return inventory.State_STATE_PENDING
	case "REGISTRATION_FAILED":
		return inventory.State_STATE_ERROR
	case "ACTIVE":
		return inventory.State_STATE_ONLINE
	case "INACTIVE":
		return inventory.State_STATE_OFFLINE
	case "DEREGISTERING":
		return inventory.State_STATE_STOPPING
	case "DRAINING":
		return inventory.State_STATE_STOPPING
	default:
		return inventory.State_STATE_UNKNOWN
	}
}

func addConnectionInfoToECSContainerAsset(container *mqlAwsEcsContainer, accountId string, conn *connection.AwsConnection) *inventory.Asset {
	a := &inventory.Asset{}

	runtimeId := container.RuntimeId.Data
	if runtimeId == "" {
		return nil
	}
	state := container.Status.Data
	containerArn := container.Arn.Data
	taskArn := container.cacheTaskArn
	publicIp := container.GetPublicIp().Data
	region := container.Region.Data

	a.Name = container.Name.Data
	a.Options = conn.ConnectionOptions()
	a.PlatformIds = []string{containerid.MondooContainerID(runtimeId), MondooECSContainerID(containerArn)}
	a.Platform = &inventory.Platform{
		Kind:    "container",
		Runtime: "aws-ecs",
	}
	a.State = mapContainerState(state)
	taskId := ""
	if arn.IsARN(taskArn) {
		if parsed, err := arn.Parse(taskArn); err == nil {
			if taskIds := strings.Split(parsed.Resource, "/"); len(taskIds) > 1 {
				taskId = taskIds[len(taskIds)-1]
			}
		}
	}

	if publicIp != "" {
		a.Connections = []*inventory.Config{{
			Host: publicIp,
			Type: "ssh",
			Options: map[string]string{
				"region":         region,
				"container_name": container.Name.Data,
				"task_id":        taskId,
			},
		}}
	} else {
		log.Warn().Str("asset", a.Name).Msg("no public ip address found")
		a = MqlObjectToAsset(accountId,
			mqlObject{
				name:   container.Name.Data,
				labels: make(map[string]string),
				awsObject: awsObject{
					account: accountId, region: container.Region.Data, arn: container.Arn.Data,
					id: container.Arn.Data, service: "ecs", objectType: "container",
				},
			}, conn)
	}

	a.Labels = map[string]string{
		MondooClusterNameLabelKey:   container.ClusterName.Data,
		MondooTaskArnLabelKey:       taskArn,
		MondooContainerNameLabelKey: container.ContainerName.Data,
		MondooRegionLabelKey:        container.Region.Data,
		MondooPlatformLabelKey:      container.PlatformFamily.Data,
	}

	return a
}

func addConnectionInfoToECSContainerInstanceAsset(inst *mqlAwsEcsInstance, accountId string, conn *connection.AwsConnection) *inventory.Asset {
	m := mqlObject{
		name: inst.Id.Data, labels: map[string]string{},
		awsObject: awsObject{
			account: accountId, region: inst.Region.Data, arn: inst.Arn.Data,
			id: inst.Id.Data, service: "ecs", objectType: "instance",
		},
	}
	a := MqlObjectToAsset(accountId, m, conn)
	a.Connections = append(a.Connections, &inventory.Config{
		Type: "ssh", // fallback to ssh
		Options: map[string]string{
			"region": inst.Region.Data,
		},
	})
	return a
}

func mapContainerState(state string) inventory.State {
	switch strings.ToLower(state) {
	case "running":
		return inventory.State_STATE_RUNNING
	case "created":
		return inventory.State_STATE_PENDING
	case "paused":
		return inventory.State_STATE_STOPPED
	case "exited":
		return inventory.State_STATE_TERMINATED
	case "restarting":
		return inventory.State_STATE_PENDING
	case "dead":
		return inventory.State_STATE_ERROR
	default:
		log.Warn().Str("state", state).Msg("unknown container state")
		return inventory.State_STATE_UNKNOWN
	}
}

func MondooECSContainerID(containerArn string) string {
	var account, region, id string
	if arn.IsARN(containerArn) {
		if p, err := arn.Parse(containerArn); err == nil {
			account = p.AccountID
			region = p.Region
			id = p.Resource
		}
	}
	return "//platformid.api.mondoo.app/runtime/aws/ecs/v1/accounts/" + account + "/regions/" + region + "/" + id
}

func SSMConnectAsset(args []string, opts map[string]string) (*inventory.Asset, error) {
	var user, id string
	if len(args) == 3 {
		if args[0] == "ec2" && args[1] == "ssm" {
			if targets := strings.Split(args[2], "@"); len(targets) == 2 {
				user = targets[0]
				id = targets[1]
			}
		}
	}
	asset := &inventory.Asset{}
	opts["instance"] = id
	asset.IdDetector = []string{ids.IdDetector_Hostname, ids.IdDetector_CloudDetect}
	asset.Connections = []*inventory.Config{{
		Type:     "ssh",
		Host:     id,
		Insecure: true,
		Runtime:  "ssh",
		Credentials: []*vault.Credential{
			{
				Type: vault.CredentialType_aws_ec2_ssm_session,
				User: user,
			},
		},
		Options: opts,
	}}
	return asset, nil
}

func InstanceConnectAsset(args []string, opts map[string]string) (*inventory.Asset, error) {
	var user, id string
	if len(args) == 3 {
		if args[0] == "ec2" && args[1] == "instance-connect" {
			if targets := strings.Split(args[2], "@"); len(targets) == 2 {
				user = targets[0]
				id = targets[1]
			}
		}
	}
	asset := &inventory.Asset{}
	asset.IdDetector = []string{ids.IdDetector_Hostname, ids.IdDetector_CloudDetect}
	opts["instance"] = id
	asset.Connections = []*inventory.Config{{
		Type:     "ssh",
		Host:     id,
		Insecure: true,
		Runtime:  "ssh",
		Credentials: []*vault.Credential{
			{
				Type: vault.CredentialType_aws_ec2_instance_connect,
				User: user,
			},
		},
		Options: opts,
	}}
	return asset, nil
}

func EbsConnectAsset(args []string, opts map[string]string) (*inventory.Asset, error) {
	var target, targetType string
	if len(args) >= 3 {
		if args[0] == "ec2" && args[1] == "ebs" {
			// parse for target type: instance, volume, snapshot
			switch args[2] {
			case awsec2ebstypes.EBSTargetVolume:
				if len(args) != 4 {
					return nil, errors.New("missing target volume")
				}
				target = args[3]
				targetType = awsec2ebstypes.EBSTargetVolume
			case awsec2ebstypes.EBSTargetSnapshot:
				if len(args) != 4 {
					return nil, errors.New("missing snapshot-id")
				}
				target = args[3]
				targetType = awsec2ebstypes.EBSTargetSnapshot
			default:
				// in the case of an instance target, this is the instance id
				target = args[2]
				targetType = awsec2ebstypes.EBSTargetInstance
			}
		}
	}
	asset := &inventory.Asset{}
	opts["type"] = targetType
	opts["id"] = target
	asset.Name = target
	asset.IdDetector = []string{ids.IdDetector_Hostname} // do not use cloud detect or host key here
	asset.Connections = []*inventory.Config{{
		Type:     string(awsec2ebsconn.EBSConnectionType),
		Host:     target,
		Insecure: true,
		Runtime:  "aws-ebs",
		Options:  opts,
	}}
	return asset, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/appflow"
	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	"github.com/aws/aws-sdk-go-v2/service/appmesh"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	"github.com/aws/aws-sdk-go-v2/service/appstream"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	"github.com/aws/aws-sdk-go-v2/service/budgets"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudhsmv2"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/codeartifact"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/controltower"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	"github.com/aws/aws-sdk-go-v2/service/dax"
	"github.com/aws/aws-sdk-go-v2/service/detective"
	"github.com/aws/aws-sdk-go-v2/service/directconnect"
	"github.com/aws/aws-sdk-go-v2/service/directoryservice"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	"github.com/aws/aws-sdk-go-v2/service/docdbelastic"
	"github.com/aws/aws-sdk-go-v2/service/drs"
	"github.com/aws/aws-sdk-go-v2/service/dsql"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticsearchservice"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/fms"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/aws-sdk-go-v2/service/keyspaces"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesisvideo"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lakeformation"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/memorydb"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/mwaa"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	"github.com/aws/aws-sdk-go-v2/service/neptunegraph"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/opensearchserverless"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/personalize"
	"github.com/aws/aws-sdk-go-v2/service/pipes"
	"github.com/aws/aws-sdk-go-v2/service/qbusiness"
	"github.com/aws/aws-sdk-go-v2/service/ram"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53domains"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/scheduler"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securitylake"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/shield"
	"github.com/aws/aws-sdk-go-v2/service/signer"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/aws/aws-sdk-go-v2/service/storagegateway"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/timestreaminfluxdb"
	"github.com/aws/aws-sdk-go-v2/service/timestreamwrite"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	"github.com/aws/aws-sdk-go-v2/service/vpclattice"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/workdocs"
	"github.com/aws/aws-sdk-go-v2/service/workspaces"
	"github.com/aws/aws-sdk-go-v2/service/workspacesweb"
	"github.com/rs/zerolog/log"
)

// CacheEntry contains cached clients
type CacheEntry struct {
	Timestamp int64
	Valid     bool
	Data      any
	Error     error
}

// Cache is a map containing CacheEntry values
type ClientsCache struct{ sync.Map }

// Store a Cache Entry
func (c *ClientsCache) Store(key string, v *CacheEntry) { c.Map.Store(key, v) }

// Load a Cache Entry
func (c *ClientsCache) Load(key string) (*CacheEntry, bool) {
	res, ok := c.Map.Load(key)
	if res == nil {
		return nil, ok
	}
	return res.(*CacheEntry), ok
}

// Delete a Cache Entry
func (c *ClientsCache) Delete(key string) { c.Map.Delete(key) }

// newClient returns the cached client stored under cacheKey, or constructs one
// for the given region and caches it. NewFromConfig builds SDK clients lazily,
// so this performs no network I/O.
func newClient[T any, O any](t *AwsConnection, cacheKey, region string, newFromConfig func(aws.Config, ...func(*O)) T) T {
	if c, ok := t.clientcache.Load(cacheKey); ok {
		log.Debug().Str("cache_key", cacheKey).Msg("using cached aws client")
		return c.Data.(T)
	}

	cfg := t.cfg.Copy()
	cfg.Region = region
	entry := &CacheEntry{Data: newFromConfig(cfg)}

	// LoadOrStore closes the check-then-act gap: if another goroutine cached a
	// client for this key between the Load above and here, we keep theirs and
	// discard our redundant construction, so every caller sees one instance.
	actual, _ := t.clientcache.Map.LoadOrStore(cacheKey, entry)
	return actual.(*CacheEntry).Data.(T)
}

// regionalClient returns a per-region client for a regional service. An empty
// region falls back to the connection's configured region.
func regionalClient[T any, O any](t *AwsConnection, service, region string, newFromConfig func(aws.Config, ...func(*O)) T) T {
	if len(region) == 0 {
		region = t.cfg.Region
	}
	return newClient(t, "_"+service+"_"+region, region, newFromConfig)
}

// globalClient returns a client for a global service whose endpoint is pinned
// to a single region. Its cache key is region-independent.
func globalClient[T any, O any](t *AwsConnection, service, region string, newFromConfig func(aws.Config, ...func(*O)) T) T {
	return newClient(t, "_"+service+"_", region, newFromConfig)
}

func (t *AwsConnection) Organizations(region string) *organizations.Client {
	return regionalClient(t, "organizations", region, organizations.NewFromConfig)
}

func (t *AwsConnection) Ec2(region string) *ec2.Client {
	return regionalClient(t, "ec2", region, ec2.NewFromConfig)
}

func (t *AwsConnection) Wafv2(region string) *wafv2.Client {
	return regionalClient(t, "wafv2", region, wafv2.NewFromConfig)
}

func (t *AwsConnection) VpcLattice(region string) *vpclattice.Client {
	return regionalClient(t, "vpclattice", region, vpclattice.NewFromConfig)
}

func (t *AwsConnection) Ecs(region string) *ecs.Client {
	return regionalClient(t, "ecs", region, ecs.NewFromConfig)
}

func (t *AwsConnection) Iam(region string) *iam.Client {
	return regionalClient(t, "iam", region, iam.NewFromConfig)
}

func (t *AwsConnection) Ecr(region string) *ecr.Client {
	return regionalClient(t, "ecr", region, ecr.NewFromConfig)
}

func (t *AwsConnection) Signer(region string) *signer.Client {
	return regionalClient(t, "signer", region, signer.NewFromConfig)
}

func (t *AwsConnection) EcrPublic(region string) *ecrpublic.Client {
	return regionalClient(t, "ecrpublic", region, ecrpublic.NewFromConfig)
}

func (t *AwsConnection) S3(region string) *s3.Client {
	return regionalClient(t, "s3", region, s3.NewFromConfig)
}

func (t *AwsConnection) S3Control(region string) *s3control.Client {
	return regionalClient(t, "s3control", region, s3control.NewFromConfig)
}

func (t *AwsConnection) CloudHsmV2(region string) *cloudhsmv2.Client {
	return regionalClient(t, "cloudhsmv2", region, cloudhsmv2.NewFromConfig)
}

func (t *AwsConnection) Cloudtrail(region string) *cloudtrail.Client {
	return regionalClient(t, "cloudtrail", region, cloudtrail.NewFromConfig)
}

func (t *AwsConnection) Cloudfront(region string) *cloudfront.Client {
	return regionalClient(t, "cloudfront", region, cloudfront.NewFromConfig)
}

func (t *AwsConnection) ConfigService(region string) *configservice.Client {
	return regionalClient(t, "config", region, configservice.NewFromConfig)
}

func (t *AwsConnection) Kms(region string) *kms.Client {
	return regionalClient(t, "kms", region, kms.NewFromConfig)
}

func (t *AwsConnection) CloudwatchLogs(region string) *cloudwatchlogs.Client {
	return regionalClient(t, "cloudwatchlogs", region, cloudwatchlogs.NewFromConfig)
}

func (t *AwsConnection) Cloudwatch(region string) *cloudwatch.Client {
	return regionalClient(t, "cloudwatch", region, cloudwatch.NewFromConfig)
}

func (t *AwsConnection) Inspector(region string) *inspector2.Client {
	return regionalClient(t, "inspector", region, inspector2.NewFromConfig)
}

func (t *AwsConnection) Sns(region string) *sns.Client {
	return regionalClient(t, "sns", region, sns.NewFromConfig)
}

func (t *AwsConnection) Sqs(region string) *sqs.Client {
	return regionalClient(t, "sqs", region, sqs.NewFromConfig)
}

func (t *AwsConnection) Ssm(region string) *ssm.Client {
	return regionalClient(t, "ssm", region, ssm.NewFromConfig)
}

func (t *AwsConnection) Efs(region string) *efs.Client {
	return regionalClient(t, "efs", region, efs.NewFromConfig)
}

func (t *AwsConnection) EventBridge(region string) *eventbridge.Client {
	return regionalClient(t, "eventbridge", region, eventbridge.NewFromConfig)
}

func (t *AwsConnection) Fsx(region string) *fsx.Client {
	return regionalClient(t, "fsx", region, fsx.NewFromConfig)
}

func (t *AwsConnection) StorageGateway(region string) *storagegateway.Client {
	return regionalClient(t, "storagegateway", region, storagegateway.NewFromConfig)
}

func (t *AwsConnection) Firehose(region string) *firehose.Client {
	return regionalClient(t, "firehose", region, firehose.NewFromConfig)
}

func (t *AwsConnection) Personalize(region string) *personalize.Client {
	return regionalClient(t, "personalize", region, personalize.NewFromConfig)
}

func (t *AwsConnection) Kinesis(region string) *kinesis.Client {
	return regionalClient(t, "kinesis", region, kinesis.NewFromConfig)
}

func (t *AwsConnection) Kinesisvideo(region string) *kinesisvideo.Client {
	return regionalClient(t, "kinesisvideo", region, kinesisvideo.NewFromConfig)
}

func (t *AwsConnection) Apigateway(region string) *apigateway.Client {
	return regionalClient(t, "apigateway", region, apigateway.NewFromConfig)
}

func (t *AwsConnection) Apigatewayv2(region string) *apigatewayv2.Client {
	return regionalClient(t, "apigatewayv2", region, apigatewayv2.NewFromConfig)
}

func (t *AwsConnection) Appsync(region string) *appsync.Client {
	return regionalClient(t, "appsync", region, appsync.NewFromConfig)
}

func (t *AwsConnection) AppRunner(region string) *apprunner.Client {
	return regionalClient(t, "apprunner", region, apprunner.NewFromConfig)
}

func (t *AwsConnection) Appstream(region string) *appstream.Client {
	return regionalClient(t, "appstream", region, appstream.NewFromConfig)
}

func (t *AwsConnection) ApplicationAutoscaling(region string) *applicationautoscaling.Client {
	return regionalClient(t, "applicationautoscaling", region, applicationautoscaling.NewFromConfig)
}

func (t *AwsConnection) Lakeformation(region string) *lakeformation.Client {
	return regionalClient(t, "lakeformation", region, lakeformation.NewFromConfig)
}

func (t *AwsConnection) Lambda(region string) *lambda.Client {
	return regionalClient(t, "lambda", region, lambda.NewFromConfig)
}

func (t *AwsConnection) Macie2(region string) *macie2.Client {
	return regionalClient(t, "macie2", region, macie2.NewFromConfig)
}

func (t *AwsConnection) Memorydb(region string) *memorydb.Client {
	return regionalClient(t, "memorydb", region, memorydb.NewFromConfig)
}

func (t *AwsConnection) Kafka(region string) *kafka.Client {
	return regionalClient(t, "kafka", region, kafka.NewFromConfig)
}

func (t *AwsConnection) Mq(region string) *mq.Client {
	return regionalClient(t, "mq", region, mq.NewFromConfig)
}

func (t *AwsConnection) Sesv2(region string) *sesv2.Client {
	return regionalClient(t, "sesv2", region, sesv2.NewFromConfig)
}

func (t *AwsConnection) Dynamodb(region string) *dynamodb.Client {
	return regionalClient(t, "dynamodb", region, dynamodb.NewFromConfig)
}

func (t *AwsConnection) Dax(region string) *dax.Client {
	return regionalClient(t, "dax", region, dax.NewFromConfig)
}

func (t *AwsConnection) Dms(region string) *databasemigrationservice.Client {
	return regionalClient(t, "dms", region, databasemigrationservice.NewFromConfig)
}

func (t *AwsConnection) Rds(region string) *rds.Client {
	return regionalClient(t, "rds", region, rds.NewFromConfig)
}

func (t *AwsConnection) Elasticache(region string) *elasticache.Client {
	return regionalClient(t, "elasticache", region, elasticache.NewFromConfig)
}

func (t *AwsConnection) Redshift(region string) *redshift.Client {
	return regionalClient(t, "redshift", region, redshift.NewFromConfig)
}

func (t *AwsConnection) Route53(region string) *route53.Client {
	return regionalClient(t, "route53", region, route53.NewFromConfig)
}

func (t *AwsConnection) Neptune(region string) *neptune.Client {
	return regionalClient(t, "neptune", region, neptune.NewFromConfig)
}

func (t *AwsConnection) OpenSearch(region string) *opensearch.Client {
	return regionalClient(t, "opensearch", region, opensearch.NewFromConfig)
}

func (t *AwsConnection) TimestreamLiveAnalytics(region string) *timestreamwrite.Client {
	return regionalClient(t, "timestream", region, timestreamwrite.NewFromConfig)
}

func (t *AwsConnection) Dsql(region string) *dsql.Client {
	return regionalClient(t, "dsql", region, dsql.NewFromConfig)
}

func (t *AwsConnection) OpenSearchServerless(region string) *opensearchserverless.Client {
	return regionalClient(t, "opensearchserverless", region, opensearchserverless.NewFromConfig)
}

func (t *AwsConnection) RedshiftServerless(region string) *redshiftserverless.Client {
	return regionalClient(t, "redshiftserverless", region, redshiftserverless.NewFromConfig)
}

func (t *AwsConnection) Mwaa(region string) *mwaa.Client {
	return regionalClient(t, "mwaa", region, mwaa.NewFromConfig)
}

func (t *AwsConnection) NeptuneGraph(region string) *neptunegraph.Client {
	return regionalClient(t, "neptunegraph", region, neptunegraph.NewFromConfig)
}

func (t *AwsConnection) TimestreamInfluxDB(region string) *timestreaminfluxdb.Client {
	return regionalClient(t, "timestream_influxdb", region, timestreaminfluxdb.NewFromConfig)
}

func (t *AwsConnection) AccessAnalyzer(region string) *accessanalyzer.Client {
	return regionalClient(t, "accessanalyzer", region, accessanalyzer.NewFromConfig)
}

func (t *AwsConnection) Acm(region string) *acm.Client {
	return regionalClient(t, "acm", region, acm.NewFromConfig)
}

func (t *AwsConnection) Athena(region string) *athena.Client {
	return regionalClient(t, "athena", region, athena.NewFromConfig)
}

func (t *AwsConnection) Elb(region string) *elasticloadbalancing.Client {
	return regionalClient(t, "elb", region, elasticloadbalancing.NewFromConfig)
}

func (t *AwsConnection) Elbv2(region string) *elasticloadbalancingv2.Client {
	return regionalClient(t, "elbv2", region, elasticloadbalancingv2.NewFromConfig)
}

func (t *AwsConnection) Es(region string) *elasticsearchservice.Client {
	return regionalClient(t, "es", region, elasticsearchservice.NewFromConfig)
}

func (t *AwsConnection) Sagemaker(region string) *sagemaker.Client {
	return regionalClient(t, "sagemaker", region, sagemaker.NewFromConfig)
}

func (t *AwsConnection) Autoscaling(region string) *autoscaling.Client {
	return regionalClient(t, "autoscaling", region, autoscaling.NewFromConfig)
}

func (t *AwsConnection) Backup(region string) *backup.Client {
	return regionalClient(t, "backup", region, backup.NewFromConfig)
}

func (t *AwsConnection) Drs(region string) *drs.Client {
	return regionalClient(t, "drs", region, drs.NewFromConfig)
}

func (t *AwsConnection) DirectConnect(region string) *directconnect.Client {
	return regionalClient(t, "directconnect", region, directconnect.NewFromConfig)
}

// globalAcceleratorControlPlaneRegion is the only region the Global Accelerator
// control plane answers in, regardless of where the accelerator sends traffic.
const globalAcceleratorControlPlaneRegion = "us-west-2"

// GlobalAccelerator returns a Global Accelerator client. The service is global
// but its control plane only answers in us-west-2, so the region is pinned here
// rather than taken from the caller.
func (t *AwsConnection) GlobalAccelerator() *globalaccelerator.Client {
	return regionalClient(t, "globalaccelerator", globalAcceleratorControlPlaneRegion, globalaccelerator.NewFromConfig)
}

func (t *AwsConnection) DirectoryService(region string) *directoryservice.Client {
	return regionalClient(t, "directoryservice", region, directoryservice.NewFromConfig)
}

func (t *AwsConnection) Codebuild(region string) *codebuild.Client {
	return regionalClient(t, "codebuild", region, codebuild.NewFromConfig)
}

func (t *AwsConnection) CodeDeploy(region string) *codedeploy.Client {
	return regionalClient(t, "codedeploy", region, codedeploy.NewFromConfig)
}

func (t *AwsConnection) Codepipeline(region string) *codepipeline.Client {
	return regionalClient(t, "codepipeline", region, codepipeline.NewFromConfig)
}

func (t *AwsConnection) Codeartifact(region string) *codeartifact.Client {
	return regionalClient(t, "codeartifact", region, codeartifact.NewFromConfig)
}

func (t *AwsConnection) Emr(region string) *emr.Client {
	return regionalClient(t, "emr", region, emr.NewFromConfig)
}

func (t *AwsConnection) Guardduty(region string) *guardduty.Client {
	return regionalClient(t, "guardduty", region, guardduty.NewFromConfig)
}

func (t *AwsConnection) Detective(region string) *detective.Client {
	return regionalClient(t, "detective", region, detective.NewFromConfig)
}

func (t *AwsConnection) Secretsmanager(region string) *secretsmanager.Client {
	return regionalClient(t, "secretsmanager", region, secretsmanager.NewFromConfig)
}

func (t *AwsConnection) Securityhub(region string) *securityhub.Client {
	return regionalClient(t, "securityhub", region, securityhub.NewFromConfig)
}

func (t *AwsConnection) Shield(region string) *shield.Client {
	return regionalClient(t, "shield", region, shield.NewFromConfig)
}

func (t *AwsConnection) Fms(region string) *fms.Client {
	return regionalClient(t, "fms", region, fms.NewFromConfig)
}

func (t *AwsConnection) NetworkFirewall(region string) *networkfirewall.Client {
	return regionalClient(t, "networkfirewall", region, networkfirewall.NewFromConfig)
}

func (t *AwsConnection) Eks(region string) *eks.Client {
	return regionalClient(t, "eks", region, eks.NewFromConfig)
}

func (t *AwsConnection) Account(region string) *account.Client {
	return regionalClient(t, "account", region, account.NewFromConfig)
}

func (t *AwsConnection) WorkDocs(region string) *workdocs.Client {
	return regionalClient(t, "workdocs", region, workdocs.NewFromConfig)
}

func (t *AwsConnection) Workspaces(region string) *workspaces.Client {
	return regionalClient(t, "workspaces", region, workspaces.NewFromConfig)
}

func (t *AwsConnection) WorkspacesWeb(region string) *workspacesweb.Client {
	return regionalClient(t, "workspacesweb", region, workspacesweb.NewFromConfig)
}

func (t *AwsConnection) STS(region string) *sts.Client {
	return regionalClient(t, "sts", region, sts.NewFromConfig)
}

func (t *AwsConnection) Glue(region string) *glue.Client {
	return regionalClient(t, "glue", region, glue.NewFromConfig)
}

func (t *AwsConnection) Route53Domains(region string) *route53domains.Client {
	return regionalClient(t, "route53domains", region, route53domains.NewFromConfig)
}

func (t *AwsConnection) Route53Resolver(region string) *route53resolver.Client {
	return regionalClient(t, "route53resolver", region, route53resolver.NewFromConfig)
}

func (t *AwsConnection) CognitoIdentity(region string) *cognitoidentity.Client {
	return regionalClient(t, "cognitoidentity", region, cognitoidentity.NewFromConfig)
}

func (t *AwsConnection) CognitoIdentityProvider(region string) *cognitoidentityprovider.Client {
	return regionalClient(t, "cognitoidentityprovider", region, cognitoidentityprovider.NewFromConfig)
}

func (t *AwsConnection) DocumentDB(region string) *docdb.Client {
	return regionalClient(t, "docdb", region, docdb.NewFromConfig)
}

func (t *AwsConnection) DocumentDBElastic(region string) *docdbelastic.Client {
	return regionalClient(t, "docdbelastic", region, docdbelastic.NewFromConfig)
}

func (t *AwsConnection) ElasticBeanstalk(region string) *elasticbeanstalk.Client {
	return regionalClient(t, "elasticbeanstalk", region, elasticbeanstalk.NewFromConfig)
}

func (t *AwsConnection) Batch(region string) *batch.Client {
	return regionalClient(t, "batch", region, batch.NewFromConfig)
}

func (t *AwsConnection) CloudFormation(region string) *cloudformation.Client {
	return regionalClient(t, "cloudformation", region, cloudformation.NewFromConfig)
}

func (t *AwsConnection) Lightsail(region string) *lightsail.Client {
	return regionalClient(t, "lightsail", region, lightsail.NewFromConfig)
}

func (t *AwsConnection) Pipes(region string) *pipes.Client {
	return regionalClient(t, "pipes", region, pipes.NewFromConfig)
}

func (t *AwsConnection) Scheduler(region string) *scheduler.Client {
	return regionalClient(t, "scheduler", region, scheduler.NewFromConfig)
}

func (t *AwsConnection) Keyspaces(region string) *keyspaces.Client {
	return regionalClient(t, "keyspaces", region, keyspaces.NewFromConfig)
}

func (t *AwsConnection) Sfn(region string) *sfn.Client {
	return regionalClient(t, "sfn", region, sfn.NewFromConfig)
}

func (t *AwsConnection) Ram(region string) *ram.Client {
	return regionalClient(t, "ram", region, ram.NewFromConfig)
}

func (t *AwsConnection) Transfer(region string) *transfer.Client {
	return regionalClient(t, "transfer", region, transfer.NewFromConfig)
}

func (t *AwsConnection) DataSync(region string) *datasync.Client {
	return regionalClient(t, "datasync", region, datasync.NewFromConfig)
}

func (t *AwsConnection) AppFlow(region string) *appflow.Client {
	return regionalClient(t, "appflow", region, appflow.NewFromConfig)
}

func (t *AwsConnection) AppMesh(region string) *appmesh.Client {
	return regionalClient(t, "appmesh", region, appmesh.NewFromConfig)
}

func (t *AwsConnection) SsoAdmin(region string) *ssoadmin.Client {
	return regionalClient(t, "ssoadmin", region, ssoadmin.NewFromConfig)
}

func (t *AwsConnection) IdentityStore(region string) *identitystore.Client {
	return regionalClient(t, "identitystore", region, identitystore.NewFromConfig)
}

func (t *AwsConnection) Acmpca(region string) *acmpca.Client {
	return regionalClient(t, "acmpca", region, acmpca.NewFromConfig)
}

func (t *AwsConnection) Bedrock(region string) *bedrock.Client {
	return regionalClient(t, "bedrock", region, bedrock.NewFromConfig)
}

func (t *AwsConnection) BedrockAgent(region string) *bedrockagent.Client {
	return regionalClient(t, "bedrockagent", region, bedrockagent.NewFromConfig)
}

func (t *AwsConnection) QBusiness(region string) *qbusiness.Client {
	return regionalClient(t, "qbusiness", region, qbusiness.NewFromConfig)
}

func (t *AwsConnection) BedrockAgentCoreControl(region string) *bedrockagentcorecontrol.Client {
	return regionalClient(t, "bedrockagentcorecontrol", region, bedrockagentcorecontrol.NewFromConfig)
}

func (t *AwsConnection) Controltower(region string) *controltower.Client {
	return regionalClient(t, "controltower", region, controltower.NewFromConfig)
}

func (t *AwsConnection) Securitylake(region string) *securitylake.Client {
	return regionalClient(t, "securitylake", region, securitylake.NewFromConfig)
}

func (t *AwsConnection) CostExplorer() *costexplorer.Client {
	return globalClient(t, "costexplorer", "us-east-1", costexplorer.NewFromConfig)
}

func (t *AwsConnection) Budgets() *budgets.Client {
	return globalClient(t, "budgets", "us-east-1", budgets.NewFromConfig)
}

module go.mondoo.com/mql/providers/aws

replace go.mondoo.com/mql => ../..

// AppStream DescribeImages fails with "deserialization failed, expected string,
// got major type 7" from service/appstream v1.64.0 on, the release that moved
// AppStream to the CBOR protocol. AWS's own public image
// Amazon-AppStream2-Sample-Image-06-17-2024 returns
// Applications[].Metadata.WORKING_DIRECTORY as null, the SDK models Metadata as
// map[string]string, and the whole call fails, so aws.appstream.images errors
// in every account. Upstream: aws/aws-sdk-go-v2#3501 (an API modeling issue,
// open). v1.63.0 decodes the null as an empty string. This replace holds the
// build there, and the `// pin v1.63.0` in the require block keeps the weekly
// `version mod-update` job from advancing it. Drop both once #3501 is fixed.
replace github.com/aws/aws-sdk-go-v2/service/appstream => github.com/aws/aws-sdk-go-v2/service/appstream v1.63.0

go 1.26.8

require (
	github.com/aws/aws-sdk-go-v2 v1.47.0
	github.com/aws/aws-sdk-go-v2/config v1.33.5
	github.com/aws/aws-sdk-go-v2/credentials v1.20.5
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.0
	github.com/aws/aws-sdk-go-v2/service/accessanalyzer v1.56.0
	github.com/aws/aws-sdk-go-v2/service/account v1.41.0
	github.com/aws/aws-sdk-go-v2/service/acm v1.50.0
	github.com/aws/aws-sdk-go-v2/service/acmpca v1.56.0
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.47.0
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.42.0
	github.com/aws/aws-sdk-go-v2/service/appflow v1.61.0
	github.com/aws/aws-sdk-go-v2/service/applicationautoscaling v1.50.0
	github.com/aws/aws-sdk-go-v2/service/appmesh v1.44.0
	github.com/aws/aws-sdk-go-v2/service/apprunner v1.48.0
	// pin v1.63.0
	github.com/aws/aws-sdk-go-v2/service/appstream v1.63.0
	github.com/aws/aws-sdk-go-v2/service/appsync v1.61.0
	github.com/aws/aws-sdk-go-v2/service/athena v1.66.0
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.78.0
	github.com/aws/aws-sdk-go-v2/service/backup v1.65.0
	github.com/aws/aws-sdk-go-v2/service/batch v1.76.0
	github.com/aws/aws-sdk-go-v2/service/bedrock v1.72.0
	github.com/aws/aws-sdk-go-v2/service/bedrockagent v1.65.0
	github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol v1.66.0
	github.com/aws/aws-sdk-go-v2/service/budgets v1.51.0
	github.com/aws/aws-sdk-go-v2/service/cloudformation v1.81.0
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.73.0
	github.com/aws/aws-sdk-go-v2/service/cloudhsmv2 v1.43.0
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.65.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.72.0
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.87.0
	github.com/aws/aws-sdk-go-v2/service/codeartifact v1.46.0
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.78.0
	github.com/aws/aws-sdk-go-v2/service/codedeploy v1.45.0
	github.com/aws/aws-sdk-go-v2/service/codepipeline v1.55.0
	github.com/aws/aws-sdk-go-v2/service/cognitoidentity v1.42.0
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.74.0
	github.com/aws/aws-sdk-go-v2/service/configservice v1.74.0
	github.com/aws/aws-sdk-go-v2/service/controltower v1.37.0
	github.com/aws/aws-sdk-go-v2/service/costexplorer v1.72.0
	github.com/aws/aws-sdk-go-v2/service/databasemigrationservice v1.71.0
	github.com/aws/aws-sdk-go-v2/service/datasync v1.67.0
	github.com/aws/aws-sdk-go-v2/service/dax v1.38.2
	github.com/aws/aws-sdk-go-v2/service/detective v1.47.0
	github.com/aws/aws-sdk-go-v2/service/directconnect v1.50.0
	github.com/aws/aws-sdk-go-v2/service/directoryservice v1.47.0
	github.com/aws/aws-sdk-go-v2/service/docdb v1.56.0
	github.com/aws/aws-sdk-go-v2/service/docdbelastic v1.28.0
	github.com/aws/aws-sdk-go-v2/service/drs v1.50.0
	github.com/aws/aws-sdk-go-v2/service/dsql v1.22.0
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.68.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.332.0
	github.com/aws/aws-sdk-go-v2/service/ecr v1.65.0
	github.com/aws/aws-sdk-go-v2/service/ecrpublic v1.47.0
	github.com/aws/aws-sdk-go-v2/service/ecs v1.98.0
	github.com/aws/aws-sdk-go-v2/service/efs v1.49.0
	github.com/aws/aws-sdk-go-v2/service/eks v1.99.0
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.61.0
	github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk v1.42.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.41.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.63.0
	github.com/aws/aws-sdk-go-v2/service/elasticsearchservice v1.50.0
	github.com/aws/aws-sdk-go-v2/service/emr v1.70.0
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.54.0
	github.com/aws/aws-sdk-go-v2/service/firehose v1.51.0
	github.com/aws/aws-sdk-go-v2/service/fms v1.53.0
	github.com/aws/aws-sdk-go-v2/service/fsx v1.74.0
	github.com/aws/aws-sdk-go-v2/service/globalaccelerator v1.44.0
	github.com/aws/aws-sdk-go-v2/service/glue v1.159.0
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.92.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.64.0
	github.com/aws/aws-sdk-go-v2/service/identitystore v1.44.0
	github.com/aws/aws-sdk-go-v2/service/inspector2 v1.59.0
	github.com/aws/aws-sdk-go-v2/service/kafka v1.64.0
	github.com/aws/aws-sdk-go-v2/service/keyspaces v1.33.1
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.54.0
	github.com/aws/aws-sdk-go-v2/service/kinesisvideo v1.41.0
	github.com/aws/aws-sdk-go-v2/service/kms v1.60.0
	github.com/aws/aws-sdk-go-v2/service/lakeformation v1.55.0
	github.com/aws/aws-sdk-go-v2/service/lambda v1.108.0
	github.com/aws/aws-sdk-go-v2/service/lightsail v1.66.0
	github.com/aws/aws-sdk-go-v2/service/macie2 v1.59.0
	github.com/aws/aws-sdk-go-v2/service/memorydb v1.42.0
	github.com/aws/aws-sdk-go-v2/service/mq v1.44.0
	github.com/aws/aws-sdk-go-v2/service/neptune v1.53.0
	github.com/aws/aws-sdk-go-v2/service/neptunegraph v1.30.0
	github.com/aws/aws-sdk-go-v2/service/networkfirewall v1.72.0
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.80.0
	github.com/aws/aws-sdk-go-v2/service/organizations v1.60.0
	github.com/aws/aws-sdk-go-v2/service/personalize v1.56.0
	github.com/aws/aws-sdk-go-v2/service/pipes v1.32.0
	github.com/aws/aws-sdk-go-v2/service/qbusiness v1.42.0
	github.com/aws/aws-sdk-go-v2/service/ram v1.44.0
	github.com/aws/aws-sdk-go-v2/service/rds v1.129.0
	github.com/aws/aws-sdk-go-v2/service/redshift v1.71.0
	github.com/aws/aws-sdk-go-v2/service/route53 v1.70.0
	github.com/aws/aws-sdk-go-v2/service/route53domains v1.44.0
	github.com/aws/aws-sdk-go-v2/service/route53resolver v1.54.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.113.1
	github.com/aws/aws-sdk-go-v2/service/s3control v1.79.0
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.277.0
	github.com/aws/aws-sdk-go-v2/service/scheduler v1.25.0
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.49.0
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.81.0
	github.com/aws/aws-sdk-go-v2/service/securitylake v1.34.0
	github.com/aws/aws-sdk-go-v2/service/sesv2 v1.73.0
	github.com/aws/aws-sdk-go-v2/service/sfn v1.50.0
	github.com/aws/aws-sdk-go-v2/service/shield v1.43.0
	github.com/aws/aws-sdk-go-v2/service/signer v1.41.0
	github.com/aws/aws-sdk-go-v2/service/sns v1.47.0
	github.com/aws/aws-sdk-go-v2/service/sqs v1.52.0
	github.com/aws/aws-sdk-go-v2/service/ssm v1.78.0
	github.com/aws/aws-sdk-go-v2/service/ssoadmin v1.48.0
	github.com/aws/aws-sdk-go-v2/service/storagegateway v1.52.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.0
	github.com/aws/aws-sdk-go-v2/service/timestreaminfluxdb v1.29.0
	github.com/aws/aws-sdk-go-v2/service/timestreamwrite v1.43.0
	github.com/aws/aws-sdk-go-v2/service/transfer v1.82.0
	github.com/aws/aws-sdk-go-v2/service/vpclattice v1.32.0
	github.com/aws/aws-sdk-go-v2/service/wafv2 v1.83.0
	github.com/aws/aws-sdk-go-v2/service/workdocs v1.38.0
	github.com/aws/aws-sdk-go-v2/service/workspaces v1.80.0
	github.com/aws/aws-sdk-go-v2/service/workspacesweb v1.47.0
	github.com/aws/smithy-go v1.28.1
	github.com/cockroachdb/errors v1.14.0
	github.com/google/uuid v1.6.0
	github.com/hashicorp/go-retryablehttp v0.7.8
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/rs/zerolog v1.35.1
	github.com/spf13/afero v1.15.0
	github.com/stretchr/testify v1.12.1
	go.mondoo.com/mql v0.0.0-20260913225403-92593e868bb9
	golang.org/x/sync v0.23.0
	k8s.io/client-go v0.37.0
)

require github.com/carabiner-dev/spdx3 v0.1.0 // indirect

require (
	dario.cat/mergo v1.0.2 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.23.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.14.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.12.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.9.0 // indirect
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/CycloneDX/cyclonedx-go v0.12.0 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Microsoft/go-winio v0.6.3-0.20251027160822-ad3df93bed29 // indirect
	github.com/ProtonMail/go-crypto v1.4.1 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/anchore/go-struct-converter v0.1.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.20 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect v1.40.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.13.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.0 // indirect
	github.com/awslabs/amazon-ecr-credential-helper/ecr-login v0.12.0 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/cockroachdb/logtags v0.0.0-20241215232642-bb51bb14a506 // indirect
	github.com/cockroachdb/redact v1.1.8 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/typeurl/v2 v2.3.0 // indirect
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/cyphar/filepath-securejoin v0.7.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/cli v29.8.0+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.9 // indirect
	github.com/docker/go-connections v0.8.1 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/facebookincubator/nvdtools v0.1.5 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/fvbommel/sortorder v1.2.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.1 // indirect
	github.com/getsentry/sentry-go v0.49.0 // indirect
	github.com/glebarez/go-sqlite v1.23.0 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.9.1 // indirect
	github.com/go-git/go-git/v5 v5.19.2 // indirect
	github.com/go-jose/go-jose/v3 v3.0.5 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/gobwas/glob v1.0.0 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/gofrs/uuid v4.4.0+incompatible // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-containerregistry v0.21.7 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-plugin v1.8.1-0.20260626113307-2d71c1b8b0e6 // indirect; pinned past v1.8.0 for hashicorp/go-plugin#388 (drops deprecated github.com/golang/protobuf) - revert to a tagged release once one ships
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/hnakamur/go-scp v1.0.2 // indirect
	github.com/hokaccha/go-prettyjson v0.0.0-20211117102719-0474bc63780f // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/kevinburke/ssh_config v1.6.0 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/knqyf263/go-rpmdb v0.1.1 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.1 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mattn/go-runewidth v0.0.30 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/moby/buildkit v0.29.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/moby/api v1.56.0 // indirect
	github.com/moby/moby/client v0.6.0 // indirect
	github.com/moby/sys/atomicwriter v0.1.0 // indirect
	github.com/moby/sys/mount v0.3.5 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/sequential v0.7.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oklog/run v1.2.0 // indirect
	github.com/olekukonko/cat v0.0.0-20250911104152-50322a0618f6 // indirect
	github.com/olekukonko/errors v1.3.0 // indirect
	github.com/olekukonko/ll v0.1.8 // indirect
	github.com/olekukonko/tablewriter v1.1.4 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/package-url/packageurl-go v0.1.7 // indirect
	github.com/pandatix/go-cvss v0.6.4 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pjbgf/sha1cd v0.6.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/sftp v1.13.11 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.24.1 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	github.com/protobom/protobom v0.6.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/segmentio/fasthash v1.0.3 // indirect
	github.com/segmentio/ksuid v1.0.4 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/sethvargo/go-password v0.4.0 // indirect
	github.com/shurcooL/graphql v0.0.0-20240915155400-7ee5256398cf // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/skeema/knownhosts v1.3.3 // indirect
	github.com/spdx/tools-golang v0.5.7 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f // indirect
	github.com/tonistiigi/go-csvvalue v0.0.0-20240814133006-030d3b2625d0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	go.mondoo.com/mondoo-go v0.0.0-20260912001156-c395844c0d2f // indirect
	go.mondoo.com/ranger-rpc v0.8.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.71.0 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260911204522-f61a6ca850bd // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.67.3 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	howett.net/plist v1.0.1 // indirect
	k8s.io/api v0.37.0 // indirect
	k8s.io/apimachinery v0.37.0 // indirect
	k8s.io/component-base v0.37.0 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	k8s.io/kube-openapi v0.0.0-20260721132016-d427ff9ee9ad // indirect
	k8s.io/kubelet v0.37.0 // indirect
	k8s.io/utils v0.0.0-20260707023825-cf1189d6abe3 // indirect
	modernc.org/libc v1.75.7 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
	modernc.org/sqlite v1.58.0 // indirect
	moul.io/http2curl v1.0.0 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/release-utils v0.12.4 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.4.2 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
	software.sslmate.com/src/go-pkcs12 v0.7.3 // indirect
)

replace github.com/hnakamur/go-scp => github.com/mondoohq/go-scp v1.0.4

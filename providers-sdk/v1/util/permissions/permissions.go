// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PermissionManifest is the JSON output for a provider's permissions.
type PermissionManifest struct {
	Provider            string             `json:"provider"`
	Version             string             `json:"version"`
	GeneratedAt         string             `json:"generated_at"`
	Permissions         []string           `json:"permissions"`
	Details             []PermissionDetail `json:"details"`
	OrgLevelPermissions []string           `json:"org_level_permissions,omitempty"`
}

// PermissionDetail describes a single extracted API call and its mapped permission.
type PermissionDetail struct {
	Permission string `json:"permission"`
	Service    string `json:"service"`
	Action     string `json:"action"`
	SourceFile string `json:"source_file"`
	Scope      string `json:"scope,omitempty"`

	// overridden is an internal dedup hint (never serialized): true when the
	// Permission came from an override map rather than the natural derivation of
	// Action. When several call sites in one file resolve to the same permission,
	// dedup keeps the natural detail so the surviving Action reflects the real API
	// call. It is reset to false before the manifest is emitted.
	overridden bool
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: permissions <provider-path> [--output <path>]\n")
		fmt.Fprintf(os.Stderr, "  provider-path: path to provider directory (e.g., providers/aws)\n")
		os.Exit(1)
	}

	providerPath := os.Args[1]
	outputPath := ""
	for i, arg := range os.Args {
		if arg == "--output" && i+1 < len(os.Args) {
			outputPath = os.Args[i+1]
		}
	}

	providerName := filepath.Base(providerPath)

	// Read provider version from config/config.go
	version := readProviderVersion(filepath.Join(providerPath, "config", "config.go"))

	// Detect provider type and extract permissions
	var details []PermissionDetail
	switch providerName {
	case "aws":
		details = extractAWSPermissions(providerPath)
	case "gcp":
		details = extractGCPPermissions(providerPath)
	case "azure":
		details = extractAzurePermissions(providerPath)
	default:
		fmt.Fprintf(os.Stderr, "skipping %s: not a supported cloud provider (aws, gcp, azure)\n", providerName)
		os.Exit(0)
	}

	// Mark org-level permissions (GCP only)
	if providerName == "gcp" {
		for i := range details {
			if gcpOrgLevelPermissions[details[i].Permission] {
				details[i].Scope = "org"
			}
		}
	}

	// Deduplicate and sort permissions, separating org-level ones
	permSet := map[string]bool{}
	orgPermSet := map[string]bool{}
	for _, d := range details {
		if d.Scope == "org" {
			orgPermSet[d.Permission] = true
		} else {
			permSet[d.Permission] = true
		}
	}
	permissions := make([]string, 0, len(permSet))
	for p := range permSet {
		permissions = append(permissions, p)
	}
	sort.Strings(permissions)
	orgPermissions := make([]string, 0, len(orgPermSet))
	for p := range orgPermSet {
		orgPermissions = append(orgPermissions, p)
	}
	sort.Strings(orgPermissions)

	// Sort details for stable output. Permission + source file are the dedup
	// key; Action and Scope are included as tiebreakers so that when the same
	// permission is derived from multiple call sites in one file (e.g. both
	// Folders.Search and Folders.List map to resourcemanager.folders.list), the
	// detail that survives deduplication is deterministic rather than dependent
	// on the unstable sort order — otherwise unrelated `action` churn appears in
	// the manifest every time entries are added.
	sort.Slice(details, func(i, j int) bool {
		if details[i].Permission != details[j].Permission {
			return details[i].Permission < details[j].Permission
		}
		if details[i].SourceFile != details[j].SourceFile {
			return details[i].SourceFile < details[j].SourceFile
		}
		// Prefer the natural derivation over an override-sourced one so the
		// surviving detail's Action reflects the real API call. Without this, an
		// override that redirects method A to a permission also produced naturally
		// by method B (e.g. dlp ListDiscoveryConfigs and ListJobTriggers both →
		// dlp.jobTriggers.list) could leave the override's misleading action.
		if details[i].overridden != details[j].overridden {
			return !details[i].overridden
		}
		if details[i].Action != details[j].Action {
			return details[i].Action < details[j].Action
		}
		return details[i].Scope < details[j].Scope
	})

	// Deduplicate details (same permission + source file)
	if len(details) > 0 {
		deduped := []PermissionDetail{details[0]}
		for i := 1; i < len(details); i++ {
			prev := deduped[len(deduped)-1]
			if details[i].Permission != prev.Permission || details[i].SourceFile != prev.SourceFile {
				deduped = append(deduped, details[i])
			}
		}
		details = deduped
	}

	// overridden is an internal dedup hint only; clear it so it never affects the
	// serialization-equality check used to skip rewrites.
	for i := range details {
		details[i].overridden = false
	}

	manifest := PermissionManifest{
		Provider:            providerName,
		Version:             version,
		GeneratedAt:         deterministicTimestamp(),
		Permissions:         permissions,
		Details:             details,
		OrgLevelPermissions: orgPermissions,
	}

	if outputPath == "" {
		outputPath = filepath.Join(providerPath, "resources", providerName+".permissions.json")
	}

	// Skip writing if only the timestamp changed.
	if existing, err := os.ReadFile(outputPath); err == nil {
		var old PermissionManifest
		if json.Unmarshal(existing, &old) == nil {
			old.GeneratedAt = manifest.GeneratedAt
			if manifestsEqual(old, manifest) {
				fmt.Printf("  %s: %d permissions (unchanged) → %s\n", providerName, len(permissions), outputPath)
				return
			}
		}
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling JSON: %v\n", err)
		os.Exit(1)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating output directory: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  %s: %d permissions → %s\n", providerName, len(permissions), outputPath)
}

var versionRegex = regexp.MustCompile(`Version:\s*"([^"]+)"`)

func readProviderVersion(configPath string) string {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "unknown"
	}
	m := versionRegex.FindSubmatch(data)
	if m == nil {
		return "unknown"
	}
	return string(m[1])
}

// deterministicTimestamp returns a reproducible timestamp for the manifest.
// It checks SOURCE_DATE_EPOCH first (standard reproducible-builds env var),
// then falls back to the latest git commit timestamp.
func deterministicTimestamp() string {
	// Check SOURCE_DATE_EPOCH (Unix timestamp) and format as RFC 3339
	if epoch := os.Getenv("SOURCE_DATE_EPOCH"); epoch != "" {
		secs, err := strconv.ParseInt(epoch, 10, 64)
		if err == nil {
			return time.Unix(secs, 0).UTC().Format(time.RFC3339)
		}
	}

	// Fall back to git commit timestamp
	out, err := exec.Command("git", "log", "-1", "--format=%cI").Output()
	if err == nil {
		ts := strings.TrimSpace(string(out))
		if ts != "" {
			return ts
		}
	}

	return "unknown"
}

// manifestsEqual reports whether two manifests are identical in all fields.
func manifestsEqual(a, b PermissionManifest) bool {
	if a.Provider != b.Provider || a.Version != b.Version || a.GeneratedAt != b.GeneratedAt {
		return false
	}
	if len(a.Permissions) != len(b.Permissions) {
		return false
	}
	for i := range a.Permissions {
		if a.Permissions[i] != b.Permissions[i] {
			return false
		}
	}
	if len(a.Details) != len(b.Details) {
		return false
	}
	for i := range a.Details {
		if a.Details[i] != b.Details[i] {
			return false
		}
	}
	return true
}

// listGoFiles returns all non-test, non-generated .go files in a directory tree.
func listGoFiles(dir string) []string {
	var files []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		if strings.HasSuffix(name, "_test.go") || strings.HasSuffix(name, ".lr.go") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	return files
}

// =============================================================================
// AWS Permission Extraction
// =============================================================================

// awsServiceNameOverrides maps AWS SDK package names to IAM service prefixes
// where they differ from the Go package name.
var awsServiceNameOverrides = map[string]string{
	"bedrockagent":             "bedrock",
	"bedrockagentcorecontrol":  "bedrock-agentcore",
	"cloudhsmv2":               "cloudhsm",
	"cloudwatchlogs":           "logs",
	"configservice":            "config",
	"costexplorer":             "ce",
	"cognitoidentityprovider":  "cognito-idp",
	"cognitoidentity":          "cognito-identity",
	"databasemigrationservice": "dms",
	"directoryservice":         "ds",
	"docdb":                    "rds",
	"docdbelastic":             "docdb-elastic",
	"efs":                      "elasticfilesystem",
	"emr":                      "elasticmapreduce",
	"elasticsearchservice":     "es",
	"elasticloadbalancing":     "elasticloadbalancing",
	"elasticloadbalancingv2":   "elasticloadbalancing",
	"firehose":                 "firehose",
	"inspector2":               "inspector2",
	"kafka":                    "kafka",
	"lightsail":                "lightsail",
	"macie2":                   "macie2",
	"memorydb":                 "memorydb",
	"mq":                       "mq",
	"neptune":                  "rds",
	"networkfirewall":          "network-firewall",
	"opensearch":               "es",
	"organizations":            "organizations",
	"pipes":                    "pipes",
	"route53domains":           "route53domains",
	"s3control":                "s3",
	"secretsmanager":           "secretsmanager",
	"securityhub":              "securityhub",
	"sesv2":                    "ses",
	"shield":                   "shield",
	"timestreamwrite":          "timestream",
	"timestreaminfluxdb":       "timestream-influxdb",
	"workspacesweb":            "workspaces-web",
	"neptunegraph":             "neptune-graph",
	"applicationautoscaling":   "application-autoscaling",
	"elasticbeanstalk":         "elasticbeanstalk",
	"elasticache":              "elasticache",
	"accessanalyzer":           "access-analyzer",
	"acmpca":                   "acm-pca",
	"ecrpublic":                "ecr-public",
	"apigatewayv2":             "apigateway",
	"eventbridge":              "events",
	"sfn":                      "states",
	"ssoadmin":                 "sso",
}

// awsPermissionOverrides maps a generated "service:Action" permission to the
// correct IAM action for the cases where the AWS SDK operation name does not
// match the IAM action name (the per-service-prefix renames are handled by
// awsServiceNameOverrides instead). An empty-string value means the operation
// has no corresponding IAM action and should be skipped entirely. Every entry
// here was verified live against IAM Access Analyzer (validate-policy) — the
// left side reported INVALID_ACTION and the right side validated clean.
var awsPermissionOverrides = map[string]string{
	// S3 API operation names differ from the S3 IAM action names.
	"s3:GetBucketAccelerateConfiguration":           "s3:GetAccelerateConfiguration",
	"s3:GetBucketEncryption":                        "s3:GetEncryptionConfiguration",
	"s3:GetBucketLifecycleConfiguration":            "s3:GetLifecycleConfiguration",
	"s3:GetBucketNotificationConfiguration":         "s3:GetBucketNotification",
	"s3:GetBucketReplication":                       "s3:GetReplicationConfiguration",
	"s3:GetObjectLockConfiguration":                 "s3:GetBucketObjectLockConfiguration",
	"s3:GetPublicAccessBlock":                       "s3:GetBucketPublicAccessBlock",
	"s3:ListBuckets":                                "s3:ListAllMyBuckets",
	"s3:ListBucketAnalyticsConfigurations":          "s3:GetAnalyticsConfiguration",
	"s3:ListBucketIntelligentTieringConfigurations": "s3:GetIntelligentTieringConfiguration",
	"s3:ListBucketInventoryConfigurations":          "s3:GetInventoryConfiguration",
	"s3:ListBucketMetricsConfigurations":            "s3:GetMetricsConfiguration",

	// API Gateway reads are all governed by the single apigateway:GET action.
	"apigateway:GetApiKeys":           "apigateway:GET",
	"apigateway:GetApis":              "apigateway:GET",
	"apigateway:GetAuthorizers":       "apigateway:GET",
	"apigateway:GetDeployments":       "apigateway:GET",
	"apigateway:GetDomainNames":       "apigateway:GET",
	"apigateway:GetRequestValidators": "apigateway:GET",
	"apigateway:GetRestApis":          "apigateway:GET",
	"apigateway:GetRoutes":            "apigateway:GET",
	"apigateway:GetStages":            "apigateway:GET",
	"apigateway:GetUsagePlans":        "apigateway:GET",
	"apigateway:GetVpcLinks":          "apigateway:GET",

	// Budgets reads are governed by budgets:ViewBudget.
	"budgets:DescribeBudgets":                    "budgets:ViewBudget",
	"budgets:DescribeNotificationsForBudget":     "budgets:ViewBudget",
	"budgets:DescribeSubscribersForNotification": "budgets:ViewBudget",

	// Detective's IAM action is singular (the SDK operation is plural).
	"detective:ListOrganizationAdminAccounts": "detective:ListOrganizationAdminAccount",

	// The Access Analyzer ListFindingsV2 API maps to access-analyzer:ListFindings.
	"access-analyzer:ListFindingsV2": "access-analyzer:ListFindings",

	// Amazon Keyspaces uses the cassandra: IAM prefix; reads require
	// cassandra:Select and tag reads require cassandra:TagResource.
	"keyspaces:GetKeyspace":         "cassandra:Select",
	"keyspaces:GetTable":            "cassandra:Select",
	"keyspaces:ListKeyspaces":       "cassandra:Select",
	"keyspaces:ListTables":          "cassandra:Select",
	"keyspaces:ListTagsForResource": "cassandra:TagResource",

	// Bedrock advanced prompt optimization jobs have no published IAM action
	// yet; skip rather than emit an action that does not exist.
	"bedrock:GetAdvancedPromptOptimizationJob":   "",
	"bedrock:ListAdvancedPromptOptimizationJobs": "",
}

// awsApplyOverride resolves a generated "service:Action" permission against
// awsPermissionOverrides. It returns the final permission and whether it should
// be emitted (false means skip — the operation maps to no IAM action).
func awsApplyOverride(perm string) (string, bool) {
	if override, ok := awsPermissionOverrides[perm]; ok {
		if override == "" {
			return "", false
		}
		return override, true
	}
	return perm, true
}

func extractAWSPermissions(root string) []PermissionDetail {
	var details []PermissionDetail
	files := listGoFiles(root)

	for _, filePath := range files {
		fileName := filepath.Base(filePath)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filePath, nil, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to parse %s: %v\n", filePath, err)
			continue
		}

		// Build import map: alias -> package name
		// e.g., "sns" -> "sns", "s3control" -> "s3control"
		awsImports := extractAWSImports(f)
		if len(awsImports) == 0 {
			continue
		}

		// Track variable -> service mappings within each function
		// e.g., svc := conn.Sns(region) -> svc maps to "sns"
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}

			// Build variable -> service map for this function.
			varServices := map[string]string{}

			// Detect clients passe passed as function parameters.
			if fn.Type != nil && fn.Type.Params != nil {
				for _, param := range fn.Type.Params.List {
					svcPkg, ok := awsClientParamService(param.Type, awsImports)
					if !ok {
						continue
					}
					for _, name := range param.Names {
						varServices[name.Name] = svcPkg
					}
				}
			}

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assignStmt, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				// Look for: svc := conn.ServiceMethod(region)
				// or: svc, err := conn.ServiceMethod(region)
				for i, rhs := range assignStmt.Rhs {
					call, ok := rhs.(*ast.CallExpr)
					if !ok {
						continue
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					methodName := sel.Sel.Name
					// Check if this is a known connection method (e.g., conn.Sns, conn.Ec2)
					svcName := awsConnectionMethodToService(methodName)
					if svcName == "" {
						continue
					}
					if i < len(assignStmt.Lhs) {
						if ident, ok := assignStmt.Lhs[i].(*ast.Ident); ok {
							varServices[ident.Name] = svcName
						}
					}
				}
				return true
			})

			// Find API calls: svc.MethodName(ctx, &input)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}

				methodName := sel.Sel.Name

				// Pattern 1: svc.MethodName() where svc is a tracked variable
				if ident, ok := sel.X.(*ast.Ident); ok {
					if svcName, ok := varServices[ident.Name]; ok {
						if isAWSAPIMethod(methodName) {
							iamService := awsServiceToIAM(svcName)
							if perm, ok := awsApplyOverride(iamService + ":" + methodName); ok {
								details = append(details, PermissionDetail{
									Permission: perm,
									Service:    strings.SplitN(perm, ":", 2)[0],
									Action:     methodName,
									SourceFile: fileName,
								})
							}
						}
					}
				}

				// Pattern 2: pkg.NewMethodPaginator() where pkg is an AWS import
				if ident, ok := sel.X.(*ast.Ident); ok {
					if _, isAWSPkg := awsImports[ident.Name]; isAWSPkg {
						if strings.HasPrefix(methodName, "New") && strings.HasSuffix(methodName, "Paginator") {
							action := strings.TrimPrefix(methodName, "New")
							action = strings.TrimSuffix(action, "Paginator")
							iamService := awsServiceToIAM(awsImports[ident.Name])
							if perm, ok := awsApplyOverride(iamService + ":" + action); ok {
								details = append(details, PermissionDetail{
									Permission: perm,
									Service:    strings.SplitN(perm, ":", 2)[0],
									Action:     action,
									SourceFile: fileName,
								})
							}
						}
					}
				}

				return true
			})

			return false // don't recurse into nested functions again
		})
	}

	return details
}

// extractAWSImports returns a map of import alias -> package name for AWS SDK imports.
func extractAWSImports(f *ast.File) map[string]string {
	result := map[string]string{}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if !strings.Contains(path, "github.com/aws/aws-sdk-go-v2/service/") {
			continue
		}
		pkgName := filepath.Base(path)
		alias := pkgName
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		result[alias] = pkgName
	}
	return result
}

// awsClientParamService reports the AWS SDK package name for a function
// parameter typed *<alias>.Client (or the rare non-pointer <alias>.Client),
// where <alias> is an AWS SDK import in this file — e.g. `svc *route53.Client`
// returns "route53".
func awsClientParamService(expr ast.Expr, awsImports map[string]string) (string, bool) {
	// Unwrap a leading pointer: *route53.Client -> route53.Client.
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Client" {
		return "", false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	pkg, ok := awsImports[ident.Name]
	if !ok {
		return "", false
	}
	return pkg, true
}

// awsConnectionMethodToService maps AwsConnection method names to service names.
// e.g., "Sns" -> "sns", "Ec2" -> "ec2", "S3Control" -> "s3control"
func awsConnectionMethodToService(method string) string {
	// The connection methods are PascalCase versions of the service name
	// e.g., Ec2, Iam, Sns, S3, S3Control, CloudwatchLogs, etc.
	lower := strings.ToLower(method)
	// Known connection method names (lowercase -> service package name)
	knownMethods := map[string]string{
		"organizations":            "organizations",
		"ec2":                      "ec2",
		"wafv2":                    "wafv2",
		"ecs":                      "ecs",
		"iam":                      "iam",
		"ecr":                      "ecr",
		"ecrpublic":                "ecrpublic",
		"s3":                       "s3",
		"s3control":                "s3control",
		"cloudhsmv2":               "cloudhsmv2",
		"cloudtrail":               "cloudtrail",
		"cloudwatch":               "cloudwatch",
		"cloudwatchlogs":           "cloudwatchlogs",
		"configservice":            "configservice",
		"rds":                      "rds",
		"lakeformation":            "lakeformation",
		"lambda":                   "lambda",
		"dynamodb":                 "dynamodb",
		"kms":                      "kms",
		"sns":                      "sns",
		"sqs":                      "sqs",
		"storagegateway":           "storagegateway",
		"redshift":                 "redshift",
		"cloudfront":               "cloudfront",
		"cloudformation":           "cloudformation",
		"ssm":                      "ssm",
		"sts":                      "sts",
		"acm":                      "acm",
		"elb":                      "elasticloadbalancing",
		"elbv2":                    "elasticloadbalancingv2",
		"route53":                  "route53",
		"route53domains":           "route53domains",
		"route53resolver":          "route53resolver",
		"eks":                      "eks",
		"efs":                      "efs",
		"apigateway":               "apigateway",
		"autoscaling":              "autoscaling",
		"backup":                   "backup",
		"datasync":                 "datasync",
		"vpclattice":               "vpclattice",
		"directconnect":            "directconnect",
		"globalaccelerator":        "globalaccelerator",
		"appflow":                  "appflow",
		"codebuild":                "codebuild",
		"emr":                      "emr",
		"guardduty":                "guardduty",
		"kinesis":                  "kinesis",
		"kinesisvideo":             "kinesisvideo",
		"secretsmanager":           "secretsmanager",
		"securityhub":              "securityhub",
		"signer":                   "signer",
		"sesv2":                    "sesv2",
		"shield":                   "shield",
		"batch":                    "batch",
		"drs":                      "drs",
		"athena":                   "athena",
		"glue":                     "glue",
		"dms":                      "databasemigrationservice",
		"databasemigrationservice": "databasemigrationservice",
		"dax":                      "dax",
		"documentdb":               "docdb",
		"fsx":                      "fsx",
		"neptune":                  "neptune",
		"opensearch":               "opensearch",
		"docdb":                    "docdb",
		"elasticache":              "elasticache",
		"elasticbeanstalk":         "elasticbeanstalk",
		"elasticsearchservice":     "elasticsearchservice",
		"es":                       "elasticsearchservice",
		"eventbridge":              "eventbridge",
		"firehose":                 "firehose",
		"inspector2":               "inspector2",
		"inspector":                "inspector2",
		"kafka":                    "kafka",
		"keyspaces":                "keyspaces",
		"lightsail":                "lightsail",
		"macie2":                   "macie2",
		"memorydb":                 "memorydb",
		"mq":                       "mq",
		"fms":                      "fms",
		"networkfirewall":          "networkfirewall",
		"apprunner":                "apprunner",
		"appstream":                "appstream",
		"appsync":                  "appsync",
		"applicationautoscaling":   "applicationautoscaling",
		"account":                  "account",
		"sagemaker":                "sagemaker",
		"cognitoidentity":          "cognitoidentity",
		"cognitoidentityprovider":  "cognitoidentityprovider",
		"detective":                "detective",
		"directoryservice":         "directoryservice",
		"pipes":                    "pipes",
		"scheduler":                "scheduler",
		"sfn":                      "sfn",
		"accessanalyzer":           "accessanalyzer",
		"timestreamliveanalytics":  "timestreamwrite",
		"timestreamwrite":          "timestreamwrite",
		"timestreaminfluxdb":       "timestreaminfluxdb",
		"workdocs":                 "workdocs",
		"workspaces":               "workspaces",
		"workspacesweb":            "workspacesweb",
		"codeartifact":             "codeartifact",
		"codedeploy":               "codedeploy",
		"codepipeline":             "codepipeline",
		"dsql":                     "dsql",
		"neptunegraph":             "neptunegraph",
		"apigatewayv2":             "apigatewayv2",
		"budgets":                  "budgets",
		"costexplorer":             "costexplorer",
		"bedrock":                  "bedrock",
		"bedrockagent":             "bedrockagent",
		"qbusiness":                "qbusiness",
		"bedrockagentcorecontrol":  "bedrockagentcorecontrol",
		"personalize":              "personalize",
	}
	if svc, ok := knownMethods[lower]; ok {
		return svc
	}
	return ""
}

// awsServiceToIAM maps an AWS SDK package name to the IAM service prefix.
func awsServiceToIAM(sdkPkg string) string {
	if override, ok := awsServiceNameOverrides[sdkPkg]; ok {
		return override
	}
	return sdkPkg
}

// isAWSAPIMethod returns true if the method name looks like an AWS API call.
func isAWSAPIMethod(name string) bool {
	prefixes := []string{
		"Describe", "List", "Get", "Put", "Create", "Delete", "Update",
		"Batch", "Generate", "Assume", "Decode", "Lookup", "Search",
		"Tag", "Untag", "Enable", "Disable", "Start", "Stop",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// =============================================================================
// GCP Permission Extraction
// =============================================================================

func extractGCPPermissions(root string) []PermissionDetail {
	var details []PermissionDetail
	files := listGoFiles(root)

	for _, filePath := range files {
		fileName := filepath.Base(filePath)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filePath, nil, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to parse %s: %v\n", filePath, err)
			continue
		}

		// Build import map
		gcpImports := extractGCPImports(f)
		if len(gcpImports) == 0 {
			continue
		}

		// Track client/service variables and find API calls
		details = append(details, extractGCPgRPCCalls(f, gcpImports, fileName)...)
	}

	return details
}

// gcpImportInfo holds information about a GCP import.
type gcpImportInfo struct {
	alias   string // import alias used in code
	service string // GCP service name (e.g., "compute", "iam", "kms")
	style   string // "rest" or "grpc"
	path    string // full import path
}

func extractGCPImports(f *ast.File) map[string]*gcpImportInfo {
	result := map[string]*gcpImportInfo{}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		info := classifyGCPImport(path)
		if info == nil {
			continue
		}
		if imp.Name != nil {
			info.alias = imp.Name.Name
		}
		result[info.alias] = info
	}
	return result
}

// classifyGCPImport determines if an import path is a GCP SDK and returns info.
func classifyGCPImport(path string) *gcpImportInfo {
	// REST discovery-based APIs: google.golang.org/api/<service>/v1
	// e.g., google.golang.org/api/compute/v1 -> parts: [google.golang.org, api, compute, v1]
	if strings.HasPrefix(path, "google.golang.org/api/") {
		parts := strings.Split(path, "/")
		if len(parts) >= 3 {
			svc := parts[2] // "compute", "dns", "sqladmin", etc.
			return &gcpImportInfo{
				alias:   svc,
				service: gcpServiceName(svc),
				style:   "rest",
				path:    path,
			}
		}
	}

	// gRPC client APIs: cloud.google.com/go/<service>/apiv1
	// e.g., cloud.google.com/go/kms/apiv1 -> service "kms"
	//        cloud.google.com/go/spanner/admin/database/apiv1 -> service "spanner"
	//        cloud.google.com/go/logging/logadmin -> service "logging"
	//        cloud.google.com/go/pubsub -> service "pubsub"
	// cloud.google.com/go/<service>[/<sub>...]/apiv1
	// e.g., cloud.google.com/go/kms/apiv1 -> parts: [cloud.google.com, go, kms, apiv1]
	//        cloud.google.com/go/iam/admin/apiv1 -> parts: [cloud.google.com, go, iam, admin, apiv1]
	//        cloud.google.com/go/pubsub -> parts: [cloud.google.com, go, pubsub]
	if strings.HasPrefix(path, "cloud.google.com/go/") {
		parts := strings.Split(path, "/")
		if len(parts) >= 3 {
			// The primary service name is always parts[2] (first component after "go")
			svc := parts[2] // "kms", "iam", "compute", "pubsub", etc.
			// Determine the alias: use the last path component unless it's a version
			alias := filepath.Base(path)
			if strings.HasPrefix(alias, "apiv") || alias == "v2" {
				alias = svc
			}
			// Skip protobuf packages (end in "pb")
			if strings.HasSuffix(alias, "pb") {
				return nil
			}
			return &gcpImportInfo{
				alias:   alias,
				service: gcpServiceName(svc),
				style:   "grpc",
				path:    path,
			}
		}
	}

	return nil
}

// gcpServiceName normalizes GCP service names.
var gcpServiceNameMap = map[string]string{
	"compute":              "compute",
	"cloudresourcemanager": "resourcemanager",
	"iam":                  "iam",
	"dns":                  "dns",
	"bigquery":             "bigquery",
	"logging":              "logging",
	"monitoring":           "monitoring",
	"container":            "container",
	"storage":              "storage",
	"sqladmin":             "cloudsql",
	"serviceusage":         "serviceusage",
	"apikeys":              "apikeys",
	"kms":                  "cloudkms",
	"functions":            "cloudfunctions",
	"run":                  "run",
	"artifactregistry":     "artifactregistry",
	"alloydb":              "alloydb",
	"aiplatform":           "aiplatform",
	"privateca":            "privateca",
	"security":             "privateca",
	"binaryauthorization":  "binaryauthorization",
	"spanner":              "spanner",
	"redis":                "redis",
	"filestore":            "file",
	"scheduler":            "cloudscheduler",
	"deploy":               "clouddeploy",
	"firestore":            "datastore",
	"essentialcontacts":    "essentialcontacts",
	"accessapproval":       "accessapproval",
	"logadmin":             "logging",
	"pubsub":               "pubsub",
	"dataproc":             "dataproc",
	"notebooks":            "notebooks",
	"composer":             "composer",
	"bigtable":             "bigtable",
	"memcache":             "memcache",
	"recaptchaenterprise":  "recaptchaenterprise",
	"cloudbuild":           "cloudbuild",
	"certificatemanager":   "certificatemanager",
	"secretmanager":        "secretmanager",
	"batch":                "batch",
	"dataplex":             "dataplex",
	"orgpolicy":            "orgpolicy",
	"asset":                "cloudasset",
}

func gcpServiceName(pkg string) string {
	if name, ok := gcpServiceNameMap[pkg]; ok {
		return name
	}
	return pkg
}

// extractGCPgRPCCalls finds gRPC client creation and subsequent method calls.
type gcpClientVar struct {
	imp        *gcpImportInfo
	clientType string // e.g., "InstanceAdmin" (from NewInstanceAdminClient)
}

func extractGCPgRPCCalls(f *ast.File, imports map[string]*gcpImportInfo, fileName string) []PermissionDetail {
	var details []PermissionDetail

	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok {
			return true
		}
		if fn.Body == nil {
			return true
		}

		// Track client variables: varName -> service + client type info
		clientVars := map[string]*gcpClientVar{}

		// Also track REST service variables
		restVars := map[string]*gcpImportInfo{}

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			assignStmt, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}

			for i, rhs := range assignStmt.Rhs {
				call, ok := rhs.(*ast.CallExpr)
				if !ok {
					continue
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				methodName := sel.Sel.Name

				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok {
					continue
				}
				pkgName := pkgIdent.Name

				imp, isGCPImport := imports[pkgName]
				if !isGCPImport {
					continue
				}

				// gRPC client creation: pkg.NewXxxClient(ctx, ...)
				if strings.HasPrefix(methodName, "New") && strings.HasSuffix(methodName, "Client") && imp.style == "grpc" {
					if i < len(assignStmt.Lhs) {
						if ident, ok := assignStmt.Lhs[i].(*ast.Ident); ok {
							clientType := strings.TrimSuffix(strings.TrimPrefix(methodName, "New"), "Client")
							clientVars[ident.Name] = &gcpClientVar{imp: imp, clientType: clientType}
						}
					}
				}

				// REST service creation: pkg.NewService(ctx, ...)
				if methodName == "NewService" && imp.style == "rest" {
					if i < len(assignStmt.Lhs) {
						if ident, ok := assignStmt.Lhs[i].(*ast.Ident); ok {
							restVars[ident.Name] = imp
						}
					}
				}
			}
			return true
		})

		// Now find calls on client variables: client.ListXxx(ctx, req)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			methodName := sel.Sel.Name

			// gRPC client calls
			if ident, ok := sel.X.(*ast.Ident); ok {
				if cv, ok := clientVars[ident.Name]; ok {
					if isGCPAPIMethod(methodName) || hasGCPPermissionOverride(cv.imp.service, cv.clientType, methodName) {
						perm, overridden := gcpMethodToPermission(cv.imp.service, cv.clientType, methodName)
						if perm != "" {
							details = append(details, PermissionDetail{
								Permission: perm,
								Service:    cv.imp.service,
								Action:     methodName,
								SourceFile: fileName,
								overridden: overridden,
							})
						}
					}
				}
			}

			// REST chained calls: restVar.Resource.Method(...)
			if innerSel, ok := sel.X.(*ast.SelectorExpr); ok {
				resource := innerSel.Sel.Name
				if ident, ok := innerSel.X.(*ast.Ident); ok {
					if imp, ok := restVars[ident.Name]; ok {
						perm, overridden := gcpRESTToPermission(imp.service, resource, methodName)
						if perm != "" {
							details = append(details, PermissionDetail{
								Permission: perm,
								Service:    imp.service,
								Action:     resource + "." + methodName,
								SourceFile: fileName,
								overridden: overridden,
							})
						}
					}
				}
				// Deeper chains: restVar.Projects.Locations.Resource.Method(...)
				if innerSel2, ok := innerSel.X.(*ast.SelectorExpr); ok {
					_ = innerSel2
					// Walk up the chain to find the root variable
					rootVar, chain := walkSelectorChain(sel)
					if rootVar != "" {
						if imp, ok := restVars[rootVar]; ok {
							// The last element is the method, the rest form the resource path
							if len(chain) >= 2 {
								method := chain[len(chain)-1]
								// Find the meaningful resource (skip "Projects", "Locations")
								resourceName := findMeaningfulResource(chain[:len(chain)-1])
								perm, overridden := gcpRESTToPermission(imp.service, resourceName, method)
								if perm != "" {
									details = append(details, PermissionDetail{
										Permission: perm,
										Service:    imp.service,
										Action:     resourceName + "." + method,
										SourceFile: fileName,
										overridden: overridden,
									})
								}
							}
						}
					}
				}
			}

			return true
		})

		return false
	})

	return details
}

// walkSelectorChain walks a nested selector expression and returns the root variable
// name and the chain of selected names.
// e.g., svc.Projects.Locations.Keys.List -> ("svc", ["Projects", "Locations", "Keys", "List"])
func walkSelectorChain(sel *ast.SelectorExpr) (string, []string) {
	chain := []string{sel.Sel.Name}
	current := sel.X
	for {
		switch x := current.(type) {
		case *ast.SelectorExpr:
			chain = append([]string{x.Sel.Name}, chain...)
			current = x.X
		case *ast.Ident:
			return x.Name, chain
		case *ast.CallExpr:
			// Handle cases like svc.Method().Chain
			if s, ok := x.Fun.(*ast.SelectorExpr); ok {
				chain = append([]string{s.Sel.Name}, chain...)
				current = s.X
			} else {
				return "", chain
			}
		default:
			return "", chain
		}
	}
}

// findMeaningfulResource finds the meaningful resource name from a chain,
// skipping common parent levels like "Projects", "Locations". The terminal
// segment is always the resource the call operates on (e.g. the "Zones" in
// dataplex's Lakes.Zones.List), so it's never skipped — the skip set only
// applies to the parent levels that precede it.
func findMeaningfulResource(chain []string) string {
	skip := map[string]bool{
		"Projects": true, "Locations": true, "Regions": true,
		"Zones": true, "Global": true,
	}
	// Generic container segments that collide across different parents. Both
	// WorkloadIdentityPools and WorkforcePools expose a ".Providers.List", so a
	// bare "Providers" cannot be mapped to a single IAM permission. Qualify such
	// leaves with their nearest non-skip parent (e.g. "WorkforcePools.Providers")
	// so the override map can disambiguate them.
	qualify := map[string]bool{"Providers": true}

	leafIdx := -1
	for i := len(chain) - 1; i >= 0; i-- {
		if i == len(chain)-1 || !skip[chain[i]] {
			leafIdx = i
			break
		}
	}
	if leafIdx < 0 {
		if len(chain) > 0 {
			return chain[len(chain)-1]
		}
		return ""
	}

	leaf := chain[leafIdx]
	if qualify[leaf] {
		for j := leafIdx - 1; j >= 0; j-- {
			if !skip[chain[j]] {
				return chain[j] + "." + leaf
			}
		}
	}
	return leaf
}

func isGCPAPIMethod(name string) bool {
	prefixes := []string{
		"List", "Get", "Create", "Delete", "Update", "Set",
		"Aggregated", "Search", "Test",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// hasGCPPermissionOverride reports whether an explicit override exists for the
// method, so that a call the prefix heuristic does not recognize can still be
// recorded.
//
// Without this the override map is unreachable for any method whose name starts
// with something other than the nine prefixes above (AnalyzeIamPolicy,
// QueryActivity, and so on): the method is filtered out before the override is
// ever consulted, and its permission is dropped from the manifest silently
// rather than derived wrongly.
func hasGCPPermissionOverride(service, clientType, method string) bool {
	overrides, ok := gcpPermissionOverrides[service]
	if !ok {
		return false
	}
	if clientType != "" {
		if _, ok := overrides[clientType+"."+method]; ok {
			return true
		}
	}
	_, ok = overrides[method]
	return ok
}

// gcpPermissionOverrides maps (service, method) to the correct IAM permission
// for cases where the automatic derivation produces incorrect results.
var gcpPermissionOverrides = map[string]map[string]string{
	"accessapproval": {
		"GetAccessApprovalSettings": "accessapproval.settings.get",
	},
	"binaryauthorization": {
		"GetSystemPolicy": "binaryauthorization.policy.get",
	},
	"cloudkms": {
		"GetCryptoKey": "cloudkms.cryptoKeys.get",
		"GetIamPolicy": "cloudkms.cryptoKeys.getIamPolicy",
	},
	"secretmanager": {
		"ListSecretVersions": "secretmanager.versions.list",
		"GetIamPolicy":       "secretmanager.secrets.getIamPolicy",
	},
	"artifactregistry": {
		"GetIamPolicy": "artifactregistry.repositories.getIamPolicy",
	},
	"privateca": {
		// CA pool IAM policy reads use the caPools.getIamPolicy permission; the
		// generic derivation yields the non-existent "privateca.iamPolicy.get".
		"GetIamPolicy": "privateca.caPools.getIamPolicy",
	},
	"cloudasset": {
		// Cloud Asset Inventory search methods map to the assets resource with a
		// search* verb, not the naive "allResources"/"allIamPolicies" derivation.
		"SearchAllResources":   "cloudasset.assets.searchAllResources",
		"SearchAllIamPolicies": "cloudasset.assets.searchAllIamPolicies",
		// "Analyze" is not one of the verb prefixes the generic derivation
		// recognizes, so without this entry the IAM policy analysis permission is
		// dropped from the manifest entirely rather than derived incorrectly.
		"AnalyzeIamPolicy": "cloudasset.assets.analyzeIamPolicy",
	},
	"orgpolicy": {
		// Reading a constraint's effective policy is governed by
		// orgpolicy.policy.get (singular "policy"); the generic derivation yields
		// the non-existent "orgpolicy.effectivePolicy.get".
		"GetEffectivePolicy": "orgpolicy.policy.get",
	},
	"serviceusage": {
		"GetService": "serviceusage.services.get",
	},
	"backupdr": {
		"ListDataSources": "backupdr.bvdataSources.list",
	},
	"compute": {
		"NetworkFirewallPolicies.Get":  "compute.firewallPolicies.get",
		"NetworkFirewallPolicies.List": "compute.firewallPolicies.list",
		// Reading the members of a zonal or regional instance group is governed
		// by compute.instanceGroups.list; there is no distinct listInstances or
		// regionInstanceGroups permission namespace in GCP IAM.
		"InstanceGroups.ListInstances":       "compute.instanceGroups.list",
		"RegionInstanceGroups.ListInstances": "compute.instanceGroups.list",
		// Listing the preconfigured WAF expression sets is governed by
		// compute.securityPolicies.list; there is no separate permission for it,
		// and the generic derivation lowercases the method name into
		// "compute.securityPolicies.listpreconfiguredexpressionsets".
		"SecurityPolicies.ListPreconfiguredExpressionSets": "compute.securityPolicies.list",
		// Reading a project's Shared VPC position is governed by
		// compute.projects.get; there are no getXpnHost or getXpnResources
		// permissions, and the generic derivation lowercases the method name into
		// "compute.projects.getxpnhost".
		"Projects.GetXpnHost":      "compute.projects.get",
		"Projects.GetXpnResources": "compute.projects.get",
	},
	"recommender": {
		// recommender.recommendations.list is not a real permission; the Recommender
		// API uses type-specific permissions (e.g., recommender.iamPolicyRecommendations.list).
		// These can't be auto-derived from the code, so skip the generic form.
		"ListRecommendations": "",
		// Same for insights: the permission is per insight type (e.g.
		// recommender.iamPolicyInsights.list,
		// recommender.computeFirewallInsights.list), so there is no single
		// derivable permission to record.
		"ListInsights": "",
	},
	"containeranalysis": {
		// GetGrafeasClient is a Go SDK method to obtain a sub-client, not an API call.
		// The actual API call (ListOccurrences) goes through the Grafeas sub-client.
		"GetGrafeasClient": "containeranalysis.occurrences.list",
		"ListOccurrences":  "containeranalysis.occurrences.list",
	},
	"spanner": {
		"GetDatabaseDdl": "spanner.databases.getDdl",
		// GetIamPolicy is a shared method on both InstanceAdminClient and
		// DatabaseAdminClient; map each to its resource-scoped permission.
		"InstanceAdmin.GetIamPolicy": "spanner.instances.getIamPolicy",
		"DatabaseAdmin.GetIamPolicy": "spanner.databases.getIamPolicy",
	},
	"modelarmor": {
		"GetFloorSetting": "modelarmor.floorSettings.get",
		// GetTemplate → singular "template" by default; the real IAM permission
		// is the plural form (matching modelarmor.templates.list).
		"GetTemplate": "modelarmor.templates.get",
	},
	"cloudbuild": {
		// Cloud Build triggers use the builds permission, not a separate triggers permission
		"ListBuildTriggers": "cloudbuild.builds.list",
		// WorkerPools IAM permission uses lowercase 'p'
		"ListWorkerPools": "cloudbuild.workerpools.list",
	},
	"iap": {
		// IAP brands are accessed via project settings, not a dedicated brands permission
		"ListBrands": "iap.projects.getSettings",
		// OAuth clients are read through the same brand/OAuth-admin surface as
		// brands, which maps to the project settings permission.
		"ListIdentityAwareProxyClients": "iap.projects.getSettings",
		// GetIamPolicy is called on the project-wide iap_web resource; the real
		// permission is iap.web.getIamPolicy, not the auto-derived "iap.iamPolicy.get".
		"GetIamPolicy": "iap.web.getIamPolicy",
		// GetIapSettings on the iap_web resource maps to iap.web.getSettings, not
		// the auto-derived "iap.iapSettings.get".
		"GetIapSettings": "iap.web.getSettings",
	},
	"monitoring": {
		// SLOs use the short permission name, not the full resource name
		"ListServiceLevelObjectives": "monitoring.slos.list",
	},
	"sourcerepo": {
		// Source Repositories uses "source.repos" not "sourcerepo.repos"
		"Repos.List": "source.repos.list",
	},
	"policyanalyzer": {
		// The Policy Analyzer API uses per-activity-type permissions. We only
		// call the serviceAccountLastAuthentication activity type today; other
		// activity types (e.g. serviceAccountKeyLastAuthentication) need their
		// own entries if added.
		"Activities.Query": "policyanalyzer.serviceAccountLastAuthenticationActivities.query",
	},
	"datastream": {
		"GetConnectionProfile": "datastream.connectionProfiles.get",
		"GetPrivateConnection": "datastream.privateConnections.get",
	},
	"cloudfunctions": {
		// GetIamPolicy is called on functions (both the v1 and v2 clients); the
		// real permission is the resource-scoped form, not the auto-derived
		// "cloudfunctions.iamPolicy.get".
		"GetIamPolicy": "cloudfunctions.functions.getIamPolicy",
	},
	"cloudtasks": {
		// GetIamPolicy is called on a queue; the real permission is queue-scoped.
		"GetIamPolicy": "cloudtasks.queues.getIamPolicy",
	},
	"discoveryengine": {
		// GetDataStore → singular "dataStore" by default; the real IAM permission
		// is the plural form.
		"GetDataStore": "discoveryengine.dataStores.get",
	},
	"cloudidentity": {
		// The Cloud Identity Groups API is not governed by project/org IAM
		// permissions (it uses group-scope authorization via member/owner/admin
		// roles), so no IAM permission corresponds to these calls — skip them.
		"Groups.List":      "",
		"Memberships.List": "",
	},
	"dlp": {
		// The DLP API exposes jobs under a `jobs` permission, not `dlpJobs`.
		"ListDlpJobs": "dlp.jobs.list",
		// File store data profiles are listed via dlp.fileStoreProfiles.list
		// (no "Data" segment in the real permission).
		"ListFileStoreDataProfiles": "dlp.fileStoreProfiles.list",
		// Discovery configs are governed by the jobTriggers permission; there is
		// no dlp.discoveryConfigs.* permission.
		"ListDiscoveryConfigs": "dlp.jobTriggers.list",
	},
	"memorystore": {
		"GetInstance":         "memorystore.instances.get",
		"GetBackupCollection": "memorystore.backupCollections.get",
		// Token auth users and their auth tokens are sub-resources of an
		// instance, and GCP publishes no memorystore.tokenAuthUsers.* or
		// memorystore.authTokens.* permission — reading them is governed by
		// read access on the parent instance. The derived plural forms would
		// be rejected by IAM if a customer built a custom role from our
		// manifest, so map both onto the documented instance permission.
		"ListTokenAuthUsers": "memorystore.instances.get",
		"ListAuthTokens":     "memorystore.instances.get",
	},
	"memcache": {
		// CloudMemcacheClient.GetInstance → singular "instance" by default;
		// the real IAM permission is the plural form.
		"GetInstance": "memcache.instances.get",
	},
	"aiplatform": {
		// JobClient.GetCustomJob → singular "customJob" by default; the real
		// IAM permission is the plural form.
		"GetCustomJob": "aiplatform.customJobs.get",
		// ModelClient.GetModel → singular "model" by default; the real IAM
		// permission is the plural form (matching aiplatform.models.list).
		"GetModel": "aiplatform.models.get",
		// EndpointClient.GetEndpoint → singular "endpoint" by default; the real
		// IAM permission is the plural form (matching aiplatform.endpoints.list).
		"GetEndpoint": "aiplatform.endpoints.get",
		// PipelineClient.GetPipelineJob → singular "pipelineJob" by default; the
		// real IAM permission is the plural form (matching
		// aiplatform.pipelineJobs.list).
		"GetPipelineJob": "aiplatform.pipelineJobs.get",
		// NotebookClient.GetNotebookRuntimeTemplate → singular
		// "notebookRuntimeTemplate" by default; the real IAM permission is the
		// plural form (matching aiplatform.notebookRuntimeTemplates.list).
		"GetNotebookRuntimeTemplate": "aiplatform.notebookRuntimeTemplates.get",
		// ScheduleClient.GetSchedule → singular "schedule" by default; the real
		// IAM permission is the plural form (matching
		// aiplatform.schedules.list).
		"GetSchedule": "aiplatform.schedules.get",
		// GetIamPolicy is the shared google.iam.v1 mixin method on both
		// ModelClient and NotebookClient; map each to its resource-scoped
		// permission (clientType derived from NewModelClient/NewNotebookClient).
		"Model.GetIamPolicy":    "aiplatform.models.getIamPolicy",
		"Notebook.GetIamPolicy": "aiplatform.notebookRuntimeTemplates.getIamPolicy",
	},
	"documentai": {
		// DocumentProcessorClient.GetProcessorVersion → singular "processorVersion"
		// by default; the real IAM permission is the plural form (matching
		// documentai.processorVersions.list).
		"GetProcessorVersion": "documentai.processorVersions.get",
	},
	"pubsub": {
		// SchemaClient.GetSchema → singular "schema" by default; real IAM
		// permission is plural.
		"GetSchema": "pubsub.schemas.get",
	},
	"iam": {
		// The resource segment for a pool's providers is the generic "Providers",
		// which findMeaningfulResource qualifies with the parent pool type so the
		// two pool families map to their distinct IAM permissions.
		"WorkloadIdentityPools.Providers.List": "iam.workloadIdentityPoolProviders.list",
		"WorkforcePools.Providers.List":        "iam.workforcePoolProviders.list",
		// IAM v2 deny policies are listed via iam.denypolicies.list, not the
		// generic "iam.policies.list" (which is not a real permission).
		"ListPolicies": "iam.denypolicies.list",
		// GetIamPolicy is called on a service account; the real permission is the
		// resource-scoped form, not the auto-derived "iam.iamPolicy.get".
		"GetIamPolicy": "iam.serviceAccounts.getIamPolicy",
		// Service account keys are listed over REST as
		// Projects.ServiceAccounts.Keys.List, whose resource segment is the bare
		// "Keys"; the real permission names the parent resource type.
		"Keys.List": "iam.serviceAccountKeys.list",
	},
	"kmsinventory": {
		// The KMS Inventory API has no IAM permissions of its own. Reading a
		// key's protected-resources summary is governed by the same permission
		// as searching protected resources, which is the single permission in
		// roles/cloudkms.protectedResourcesViewer. The generic derivation
		// lowercases the whole method name into
		// "kmsinventory.cryptoKeys.getprotectedresourcessummary".
		"CryptoKeys.GetProtectedResourcesSummary": "cloudkms.protectedResources.search",
	},
	"certificatemanager": {
		// The Certificate Manager IAM permissions use abbreviated, all-lowercase
		// resource segments (certs, certissuanceconfigs, certmapentries, certmaps,
		// dnsauthorizations, trustconfigs) that cannot be auto-derived from the
		// SDK method names. Verified against GCP testable permissions.
		"GetCertificate":                 "certificatemanager.certs.get",
		"ListCertificates":               "certificatemanager.certs.list",
		"GetCertificateIssuanceConfig":   "certificatemanager.certissuanceconfigs.get",
		"ListCertificateIssuanceConfigs": "certificatemanager.certissuanceconfigs.list",
		"ListCertificateMapEntries":      "certificatemanager.certmapentries.list",
		"ListCertificateMaps":            "certificatemanager.certmaps.list",
		"GetDnsAuthorization":            "certificatemanager.dnsauthorizations.get",
		"ListDnsAuthorizations":          "certificatemanager.dnsauthorizations.list",
		"ListTrustConfigs":               "certificatemanager.trustconfigs.list",
	},
	"logging": {
		// GetCmekSettings is covered by logging.settings.get; there is no
		// logging.cmekSettings.get permission (verified against GCP testable
		// permissions at project and organization scope).
		"Projects.GetCmekSettings": "logging.settings.get",
		// GetSettings is a separate endpoint from GetCmekSettings and is governed
		// by the same permission. It exists per container type, and the generic
		// derivation would yield "logging.projects.getsettings" and friends.
		"Projects.GetSettings":      "logging.settings.get",
		"Folders.GetSettings":       "logging.settings.get",
		"Organizations.GetSettings": "logging.settings.get",
		// Log-based metrics list under the "logMetrics" resource; the generic
		// derivation from Projects.Metrics.List yields the non-existent
		// "logging.metrics.list".
		"Metrics.List": "logging.logMetrics.list",
	},
	"resourcemanager": {
		// Listing liens has no dedicated permission; it requires
		// resourcemanager.projects.get, which is already emitted by the
		// Projects.Get call in initGcpProject — so skip the generic form here
		// rather than overwriting that entry's action.
		"Liens.List": "",
		// GetAncestry (used by the connection layer to resolve a project's
		// org/folder ancestry) is governed by resourcemanager.projects.get, not
		// the auto-derived "resourcemanager.projects.getancestry" (not a real
		// permission).
		"Projects.GetAncestry": "resourcemanager.projects.get",
		// Tag bindings are listed via the resourceTagBindings permission, not a
		// "resourcemanager.tagBindings.list" form (which is not a real permission).
		"TagBindings.List": "resourcemanager.resourceTagBindings.list",
		// Reading effective tag binding collections on a resource is governed by
		// that resource's listEffectiveTags permission (we only call it for
		// storage buckets in storage.go), not the auto-derived
		// "resourcemanager.effectiveTagBindingCollections.get" (not a real
		// permission).
		"EffectiveTagBindingCollections.Get": "storage.buckets.listEffectiveTags",
	},
}

// gcpOrgLevelPermissions are permissions that only apply at the organization
// level, not the project level. They are placed in the org_level_permissions
// section of the manifest instead of the main permissions list.
var gcpOrgLevelPermissions = map[string]bool{
	// Custom org-policy constraints are an organization-scoped resource;
	// ListCustomConstraints is only callable with an "organizations/{id}"
	// parent, so the permission is rejected in a project-level custom role.
	"orgpolicy.customConstraints.list":           true,
	"resourcemanager.folders.get":                true,
	"resourcemanager.folders.getIamPolicy":       true,
	"resourcemanager.folders.list":               true,
	"resourcemanager.folders.search":             true,
	"resourcemanager.organizations.get":          true,
	"resourcemanager.organizations.getIamPolicy": true,
	"resourcemanager.projects.list":              true,
	"resourcemanager.projects.search":            true,
}

// gcpSkipMethods lists method names that match isGCPAPIMethod patterns but are
// actually protobuf getter methods or internal helpers, not real API calls.
var gcpSkipMethods = map[string]bool{
	"GetConditionAbsent":                  true,
	"GetConditionThreshold":               true,
	"GetConditionMatchedLog":              true,
	"GetConditionMonitoringQueryLanguage": true,
}

// gcpMethodToPermission maps a gRPC method to a GCP IAM permission.
// clientType (e.g., "InstanceAdmin" from NewInstanceAdminClient) lets services with
// multiple admin clients disambiguate methods like GetIamPolicy that don't carry a
// resource hint in their name.
// gcpMethodToPermission returns the IAM permission for a gRPC method and a bool
// reporting whether the result came from an override (rather than the natural
// derivation), used by detail dedup to prefer the natural call site.
func gcpMethodToPermission(service, clientType, method string) (string, bool) {
	// Skip known non-API methods
	if gcpSkipMethods[method] {
		return "", false
	}

	// Strip "Iter" suffix from iterator helper methods (e.g., ListRolesIter -> ListRoles)
	method = strings.TrimSuffix(method, "Iter")

	// Check for explicit overrides. Prefer a clientType-scoped entry first so
	// services with multiple admin clients can disambiguate shared method names.
	if overrides, ok := gcpPermissionOverrides[service]; ok {
		if clientType != "" {
			if perm, ok := overrides[clientType+"."+method]; ok {
				return perm, true
			}
		}
		if perm, ok := overrides[method]; ok {
			return perm, true
		}
	}

	// gRPC methods: ListKeyRings -> cloudkms.keyRings.list
	// ListServiceAccounts -> iam.serviceAccounts.list
	// GetKeyRotationStatus -> cloudkms.cryptoKeys.get

	verb := ""
	resource := ""

	if strings.HasPrefix(method, "AggregatedList") {
		verb = "list"
		resource = strings.TrimPrefix(method, "AggregatedList")
	} else if strings.HasPrefix(method, "List") {
		verb = "list"
		resource = strings.TrimPrefix(method, "List")
	} else if strings.HasPrefix(method, "Get") {
		verb = "get"
		resource = strings.TrimPrefix(method, "Get")
		if resource == "" {
			return "", false // bare Get without resource name is ambiguous
		}
	} else if strings.HasPrefix(method, "Create") {
		verb = "create"
		resource = strings.TrimPrefix(method, "Create")
	} else if strings.HasPrefix(method, "Delete") {
		verb = "delete"
		resource = strings.TrimPrefix(method, "Delete")
	} else if strings.HasPrefix(method, "Update") {
		verb = "update"
		resource = strings.TrimPrefix(method, "Update")
	} else if strings.HasPrefix(method, "Set") {
		verb = "update"
		resource = strings.TrimPrefix(method, "Set")
	} else if strings.HasPrefix(method, "Test") {
		verb = "get"
		resource = strings.TrimPrefix(method, "Test")
	} else if strings.HasPrefix(method, "Search") {
		verb = "list"
		resource = strings.TrimPrefix(method, "Search")
	} else {
		return "", false
	}

	if resource == "" {
		return "", false
	}

	// Convert PascalCase to camelCase
	resource = strings.ToLower(resource[:1]) + resource[1:]

	return service + "." + resource + "." + verb, false
}

// gcpRESTToPermission maps a REST-style call to a GCP IAM permission. The bool
// reports whether the result came from an override (see gcpMethodToPermission).
func gcpRESTToPermission(service, resource, method string) (string, bool) {
	if resource == "" {
		return "", false
	}

	// Check for explicit overrides using "Resource.Method" as the key
	if overrides, ok := gcpPermissionOverrides[service]; ok {
		if perm, ok := overrides[resource+"."+method]; ok {
			return perm, true
		}
	}

	verb := ""
	switch method {
	case "List", "AggregatedList", "Aggregated", "Pages", "Search":
		verb = "list"
	case "Get", "Do":
		verb = "get"
	case "Create", "Insert":
		verb = "create"
	case "Delete":
		verb = "delete"
	case "Update", "Patch":
		verb = "update"
	case "GetIamPolicy":
		return service + "." + strings.ToLower(resource[:1]) + resource[1:] + ".getIamPolicy", false
	case "SetIamPolicy":
		return service + "." + strings.ToLower(resource[:1]) + resource[1:] + ".setIamPolicy", false
	default:
		verb = strings.ToLower(method)
	}

	// Convert PascalCase resource to camelCase
	res := strings.ToLower(resource[:1]) + resource[1:]
	return service + "." + res + "." + verb, false
}

// =============================================================================
// Azure Permission Extraction
// =============================================================================

// extractAzurePermissions statically detects the Azure ARM read calls a provider
// makes and maps each to the IAM permission it requires. It relies only on the
// AST (no type checking), so it recognizes a fixed set of call shapes. Every
// shape resolves to a client whose ARM provider + resource type produce a
// "<Provider>/<resource>/read" permission attributed to the file with the call.
//
// Recognized shapes:
//
//	// (1) Local variable — client built and used in the same function:
//	client, _ := armcompute.NewVirtualMachinesClient(subID, cred, nil)
//	client.NewListAllPager(nil)            // -> Microsoft.Compute/virtualMachines/read
//
//	// (2) Client factory — the ARM provider comes from the factory var:
//	factory, _ := armsecurity.NewClientFactory(subID, cred, nil)
//	factory.NewPricingsClient().Get(ctx, name, nil) // -> Microsoft.Security/pricings/read
//
//	// (3) Struct-field client (added here) — built by a constructor, then used
//	//     across methods via the receiver:
//	type SubscriptionsClient struct {
//	    client *armsubscriptions.Client
//	}
//	func NewSubscriptionsClient(cred azcore.TokenCredential) (*SubscriptionsClient, error) {
//	    c, err := armsubscriptions.NewClient(cred, nil)
//	    if err != nil { return nil, err }
//	    return &SubscriptionsClient{client: c}, nil // field <- client
//	}
//	func (s *SubscriptionsClient) Tags(ctx context.Context, id string) error {
//	    _, err := s.client.Get(ctx, id, nil)        // s.client.Get -> Microsoft.Resources/subscriptions/read
//	    return err
//	}
//
// Before struct-field tracking, shape (3)'s read (`s.client.Get`) was invisible:
// the client is constructed in one function and used in another, and the read's
// receiver is a field selector rather than a tracked local var — so the read
// went unattributed. buildAzureFieldClients records struct-field clients and the
// read pass resolves `s.client` through the method receiver's type.
func extractAzurePermissions(root string) []PermissionDetail {
	var details []PermissionDetail
	files := listGoFiles(root)

	// Pre-pass: resolve ARM clients cached in struct fields (structType -> field
	// -> client info) so reads via a method receiver (e.g. c.client.Get(...)) can
	// be attributed even though the client is constructed in another function.
	fieldClients := buildAzureFieldClients(files)

	for _, filePath := range files {
		fileName := filepath.Base(filePath)
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filePath, nil, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to parse %s: %v\n", filePath, err)
			continue
		}

		// Build import map: alias -> ARM info
		azureImports := extractAzureImports(f)
		if len(azureImports) == 0 {
			continue
		}

		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			if fn.Body == nil {
				return true
			}

			// Track ARM clients and client factories declared as local vars in
			// this function.
			clientVars, factoryVars := trackAzureClientVars(fn.Body, azureImports)
			// Receiver of this function (if it's a method), used to resolve reads
			// on struct-field clients accessed via the receiver: c.client.Get(...).
			recvName, recvType := funcReceiver(fn)

			emitReadPerm := func(armProvider, resourceType, methodName string) {
				perm := azurePermission(armProvider, resourceType)
				// A client serving multiple read methods may need per-method
				// permissions that the client-level derivation can't express.
				if o, ok := azureMethodPermissionOverrides[resourceType+"."+methodName]; ok {
					perm = o
				}
				details = append(details, PermissionDetail{
					Permission: perm,
					Service:    armProvider,
					Action:     methodName,
					SourceFile: fileName,
				})
			}

			// Find pager/method calls on client variables
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				methodName := sel.Sel.Name
				if !isAzureReadMethod(methodName) {
					return true
				}

				switch recv := sel.X.(type) {
				case *ast.Ident:
					// Read method on a tracked client var: client.NewListPager(...)
					if info, ok := clientVars[recv.Name]; ok {
						emitReadPerm(info.armProvider, info.resourceType, methodName)
					}
				case *ast.CallExpr:
					// Inline factory chain: factoryVar.NewXxxClient().NewListPager(...)
					innerSel, ok := recv.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					facIdent, ok := innerSel.X.(*ast.Ident)
					if !ok {
						return true
					}
					prov, isFactory := factoryVars[facIdent.Name]
					if !isFactory {
						return true
					}
					ctor := innerSel.Sel.Name
					if !strings.HasPrefix(ctor, "New") || !strings.HasSuffix(ctor, "Client") {
						return true
					}
					resourceType := strings.TrimSuffix(strings.TrimPrefix(ctor, "New"), "Client")
					// A generic NewClient() on a factory has no resource type in
					// its name and no package to derive one from (the receiver is
					// a factory var, not an import), so skip it — same as the
					// stored-variable path, which also can't map a factory generic.
					if resourceType != "" {
						emitReadPerm(prov, resourceType, methodName)
					}
				case *ast.SelectorExpr:
					// Read on a struct-field client accessed via the method
					// receiver: c.client.Get(...). Resolve the field through the
					// receiver's type so a client cached in a struct (built by a
					// constructor in another function) is still attributed.
					baseIdent, ok := recv.X.(*ast.Ident)
					if !ok || recvName == "" || baseIdent.Name != recvName {
						return true
					}
					if fields, ok := fieldClients[recvType]; ok {
						if info, ok := fields[recv.Sel.Name]; ok {
							emitReadPerm(info.armProvider, info.resourceType, methodName)
						}
					}
				}

				return true
			})

			return false
		})
	}

	return details
}

type azureImportInfo struct {
	alias       string // import alias
	armProvider string // e.g., "Microsoft.Compute"
	pkgName     string // e.g., "armcompute"
}

type azureClientInfo struct {
	armProvider  string // e.g., "Microsoft.Compute"
	resourceType string // e.g., "VirtualMachines"
}

// trackAzureClientVars walks a function body and records ARM clients and client
// factories assigned to local variables:
//   - clientVars: varName -> client info, from `x := pkg.NewXxxClient(...)` (or
//     `x := factoryVar.NewXxxClient(...)`).
//   - factoryVars: varName -> ARM provider, from `f := pkg.NewClientFactory(...)`.
func trackAzureClientVars(body *ast.BlockStmt, azureImports map[string]*azureImportInfo) (map[string]*azureClientInfo, map[string]string) {
	clientVars := map[string]*azureClientInfo{}
	factoryVars := map[string]string{}

	ast.Inspect(body, func(n ast.Node) bool {
		assignStmt, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		for i, rhs := range assignStmt.Rhs {
			call, ok := rhs.(*ast.CallExpr)
			if !ok {
				continue
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				continue
			}

			// Pattern: f := pkg.NewClientFactory(...) — remember the factory var
			// so its clients resolve to this ARM provider.
			if sel.Sel.Name == "NewClientFactory" {
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok {
					continue
				}
				if imp, isAzureImport := azureImports[pkgIdent.Name]; isAzureImport && i < len(assignStmt.Lhs) {
					if ident, ok := assignStmt.Lhs[i].(*ast.Ident); ok {
						factoryVars[ident.Name] = imp.armProvider
					}
				}
				continue
			}

			// Pattern: pkg.NewXxxClient(...) or factoryVar.NewXxxClient(...)
			info := resolveAzureConstructorCall(call, azureImports, factoryVars)
			if info == nil {
				continue
			}
			if i < len(assignStmt.Lhs) {
				if ident, ok := assignStmt.Lhs[i].(*ast.Ident); ok {
					clientVars[ident.Name] = info
				}
			}
		}
		return true
	})

	return clientVars, factoryVars
}

// resolveAzureConstructorCall resolves a `pkg.NewXxxClient(...)` or
// `factoryVar.NewXxxClient(...)` call to the ARM client it creates, or nil if
// the call is not an Azure client constructor.
func resolveAzureConstructorCall(call *ast.CallExpr, azureImports map[string]*azureImportInfo, factoryVars map[string]string) *azureClientInfo {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	methodName := sel.Sel.Name
	if !strings.HasPrefix(methodName, "New") || !strings.HasSuffix(methodName, "Client") {
		return nil
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil
	}

	// Resolve the ARM provider: either the receiver is a tracked azure package
	// import, or a tracked client-factory var.
	imp, isAzureImport := azureImports[pkgIdent.Name]
	armProvider := ""
	if isAzureImport {
		armProvider = imp.armProvider
	} else if prov, isFactory := factoryVars[pkgIdent.Name]; isFactory {
		armProvider = prov
	} else {
		return nil
	}

	// Extract resource type from constructor name, e.g.
	// NewVirtualMachinesClient -> VirtualMachines. A generic NewClient carries
	// no resource type; only a package import can map it via its package name.
	resourceType := strings.TrimSuffix(strings.TrimPrefix(methodName, "New"), "Client")
	if resourceType == "" {
		if !isAzureImport {
			return nil
		}
		resourceType = azureResourceFromPackage(imp.pkgName)
	}
	return &azureClientInfo{armProvider: armProvider, resourceType: resourceType}
}

// resolveAzureClientExpr resolves an expression that may hold an ARM client —
// either a reference to a tracked local client var, or an inline constructor
// call — to its client info, or nil.
func resolveAzureClientExpr(expr ast.Expr, clientVars map[string]*azureClientInfo, factoryVars map[string]string, azureImports map[string]*azureImportInfo) *azureClientInfo {
	switch e := expr.(type) {
	case *ast.Ident:
		if info, ok := clientVars[e.Name]; ok {
			return info
		}
	case *ast.CallExpr:
		return resolveAzureConstructorCall(e, azureImports, factoryVars)
	}
	return nil
}

// buildAzureFieldClients scans every file for ARM clients assigned to struct
// fields and returns structType -> fieldName -> client info. It recognizes two
// constructor shapes: composite literals `&T{field: <client>}` and receiver
// assignments `r.field = <client>` inside a method of T. This lets reads on
// c.field elsewhere be attributed via the receiver's type.
func buildAzureFieldClients(files []string) map[string]map[string]*azureClientInfo {
	fieldClients := map[string]map[string]*azureClientInfo{}
	record := func(structType, field string, info *azureClientInfo) {
		if structType == "" || field == "" || info == nil {
			return
		}
		if fieldClients[structType] == nil {
			fieldClients[structType] = map[string]*azureClientInfo{}
		}
		fieldClients[structType][field] = info
	}

	for _, filePath := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filePath, nil, 0)
		if err != nil {
			continue
		}
		azureImports := extractAzureImports(f)
		if len(azureImports) == 0 {
			continue
		}

		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			clientVars, factoryVars := trackAzureClientVars(fn.Body, azureImports)
			recvName, recvType := funcReceiver(fn)

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CompositeLit:
					// &T{field: <client>} or T{field: <client>}
					structType := typeIdentName(node.Type)
					if structType == "" {
						return true
					}
					for _, elt := range node.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := kv.Key.(*ast.Ident)
						if !ok {
							continue
						}
						if info := resolveAzureClientExpr(kv.Value, clientVars, factoryVars, azureImports); info != nil {
							record(structType, key.Name, info)
						}
					}
				case *ast.AssignStmt:
					// r.field = <client> inside a method of the receiver's type.
					if recvName == "" || recvType == "" {
						return true
					}
					for i, lhs := range node.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if !ok {
							continue
						}
						baseIdent, ok := sel.X.(*ast.Ident)
						if !ok || baseIdent.Name != recvName {
							continue
						}
						if i < len(node.Rhs) {
							if info := resolveAzureClientExpr(node.Rhs[i], clientVars, factoryVars, azureImports); info != nil {
								record(recvType, sel.Sel.Name, info)
							}
						}
					}
				}
				return true
			})
			return true
		})
	}

	return fieldClients
}

// funcReceiver returns the receiver variable name and type name of a method
// declaration (unwrapping a pointer receiver), or empty strings for a plain
// function.
func funcReceiver(fn *ast.FuncDecl) (name string, typeName string) {
	if fn.Recv == nil || len(fn.Recv.List) != 1 {
		return "", ""
	}
	field := fn.Recv.List[0]
	if len(field.Names) == 1 {
		name = field.Names[0].Name
	}
	return name, typeIdentName(field.Type)
}

// typeIdentName returns the identifier name of a type expression, unwrapping a
// leading pointer (*T -> "T"). Returns "" for non-identifier types (e.g. a
// qualified pkg.T, which is not a locally-declared struct).
func typeIdentName(expr ast.Expr) string {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

func extractAzureImports(f *ast.File) map[string]*azureImportInfo {
	result := map[string]*azureImportInfo{}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if !strings.Contains(path, "azure-sdk-for-go/sdk/resourcemanager/") {
			continue
		}
		// e.g., github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7
		parts := strings.Split(path, "/")
		// Find the "resourcemanager" index
		rmIdx := -1
		for i, p := range parts {
			if p == "resourcemanager" {
				rmIdx = i
				break
			}
		}
		if rmIdx < 0 || rmIdx+2 >= len(parts) {
			continue
		}
		serviceName := parts[rmIdx+1] // e.g., "compute"
		armPkg := parts[rmIdx+2]      // e.g., "armcompute"

		alias := armPkg
		// Strip version suffix from alias if package has /v7 etc.
		if imp.Name != nil {
			alias = imp.Name.Name
		}

		armProvider := azureServiceToARM(serviceName)

		result[alias] = &azureImportInfo{
			alias:       alias,
			armProvider: armProvider,
			pkgName:     armPkg,
		}
	}
	return result
}

// azureServiceToARM maps Azure SDK service names to ARM provider namespaces.
var azureServiceToARMMap = map[string]string{
	"compute":               "Microsoft.Compute",
	"network":               "Microsoft.Network",
	"storage":               "Microsoft.Storage",
	"keyvault":              "Microsoft.KeyVault",
	"sql":                   "Microsoft.Sql",
	"postgresql":            "Microsoft.DBforPostgreSQL",
	"mysql":                 "Microsoft.DBforMySQL",
	"mariadb":               "Microsoft.DBforMariaDB",
	"cosmos":                "Microsoft.DocumentDB",
	"cosmosdb":              "Microsoft.DocumentDB",
	"redis":                 "Microsoft.Cache",
	"containerservice":      "Microsoft.ContainerService",
	"containerregistry":     "Microsoft.ContainerRegistry",
	"web":                   "Microsoft.Web",
	"monitor":               "Microsoft.Insights",
	"applicationinsights":   "Microsoft.Insights",
	"advisor":               "Microsoft.Advisor",
	"authorization":         "Microsoft.Authorization",
	"security":              "Microsoft.Security",
	"subscription":          "Microsoft.Resources",
	"resources":             "Microsoft.Resources",
	"search":                "Microsoft.Search",
	"servicebus":            "Microsoft.ServiceBus",
	"eventhub":              "Microsoft.EventHub",
	"iothub":                "Microsoft.Devices",
	"managedidentity":       "Microsoft.ManagedIdentity",
	"desktopvirtualization": "Microsoft.DesktopVirtualization",
	"appservice":            "Microsoft.Web",
	"databoxedge":           "Microsoft.DataBoxEdge",
	"logic":                 "Microsoft.Logic",
	"msi":                   "Microsoft.ManagedIdentity",
	"frontdoor":             "Microsoft.Network",
	"datafactory":           "Microsoft.DataFactory",
	"cosmosforpostgresql":   "Microsoft.DBforPostgreSQL",
	"batch":                 "Microsoft.Batch",
	"databricks":            "Microsoft.Databricks",
	"synapse":               "Microsoft.Synapse",
	"operationalinsights":   "Microsoft.OperationalInsights",
	"recoveryservices":      "Microsoft.RecoveryServices",
	"hybridcompute":         "Microsoft.HybridCompute",
	"appcontainers":         "Microsoft.App",
	"containerinstance":     "Microsoft.ContainerInstance",
	"machinelearning":       "Microsoft.MachineLearningServices",
	// The SDK package is armmanagementgroups but the ARM namespace is
	// Microsoft.Management; without this the default branch would emit
	// "Microsoft.Managementgroups", which is not a real provider.
	"managementgroups": "Microsoft.Management",
	// The default branch capitalizes only the first letter, giving
	// "Microsoft.Eventgrid" and "Microsoft.Apimanagement" for these two.
	"eventgrid":     "Microsoft.EventGrid",
	"apimanagement": "Microsoft.ApiManagement",
	// Same again: the default branch would emit "Microsoft.Dataprotection" and
	// "Microsoft.Databox", neither of which is a real provider namespace.
	"dataprotection": "Microsoft.DataProtection",
	"databox":        "Microsoft.DataBox",
	// Same again: the default branch would emit "Microsoft.Netapp", which is
	// not a real provider namespace.
	"netapp": "Microsoft.NetApp",
	// Same again: the default branch would emit "Microsoft.Fileshares", which
	// is not a real provider namespace.
	"fileshares": "Microsoft.FileShares",
	// Same again: the default branch would emit "Microsoft.Elasticsan", which
	// is not a real provider namespace.
	"elasticsan": "Microsoft.ElasticSan",
	// Same again: the default branch would emit "Microsoft.Storagecache",
	// which is not a real provider namespace.
	"storagecache": "Microsoft.StorageCache",
}

func azureServiceToARM(service string) string {
	if service == "" {
		return "Microsoft.Unknown"
	}
	if arm, ok := azureServiceToARMMap[service]; ok {
		return arm
	}
	// Default: Microsoft.<Capitalized service name>
	return "Microsoft." + strings.ToUpper(service[:1]) + service[1:]
}

// azureMethodPermissionOverrides maps "<ResourceType>.<Method>" to the correct
// permission for cases where one SDK client serves multiple read methods that
// require different RBAC permissions. The client-derived permission is the same
// for every method on the client, so a permission-string override (which keys on
// that shared result) cannot distinguish them — this map keys on the
// constructor-derived resource type plus the read method name instead.
var azureMethodPermissionOverrides = map[string]string{
	// SQLResourcesClient serves SQL container, role-assignment and role-definition
	// reads. The client maps everything to sqlDatabases/containers/read (see the
	// sQLResources override below), so the role calls each need their own mapping
	// to the correct resource.
	"SQLResources.NewListSQLRoleAssignmentsPager": "Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/read",
	"SQLResources.NewListSQLRoleDefinitionsPager": "Microsoft.DocumentDB/databaseAccounts/sqlRoleDefinitions/read",

	// The Cassandra, Gremlin, Table and MongoMI resource clients each serve
	// role-assignment and role-definition reads that the client name derives to a
	// coarse <api>Resources/read; redirect them to the correct databaseAccounts
	// sub-resource, matching the SQLResources entries above.
	"CassandraResources.NewListCassandraRoleAssignmentsPager": "Microsoft.DocumentDB/databaseAccounts/cassandraRoleAssignments/read",
	"CassandraResources.NewListCassandraRoleDefinitionsPager": "Microsoft.DocumentDB/databaseAccounts/cassandraRoleDefinitions/read",
	"GremlinResources.NewListGremlinRoleAssignmentsPager":     "Microsoft.DocumentDB/databaseAccounts/gremlinRoleAssignments/read",
	"GremlinResources.NewListGremlinRoleDefinitionsPager":     "Microsoft.DocumentDB/databaseAccounts/gremlinRoleDefinitions/read",
	"TableResources.NewListTableRoleAssignmentsPager":         "Microsoft.DocumentDB/databaseAccounts/tableRoleAssignments/read",
	"TableResources.NewListTableRoleDefinitionsPager":         "Microsoft.DocumentDB/databaseAccounts/tableRoleDefinitions/read",
	"MongoMIResources.NewListMongoMIRoleAssignmentsPager":     "Microsoft.DocumentDB/databaseAccounts/mongoMIRoleAssignments/read",
	"MongoMIResources.NewListMongoMIRoleDefinitionsPager":     "Microsoft.DocumentDB/databaseAccounts/mongoMIRoleDefinitions/read",

	// armlocks lives under the resourcemanager/resources directory, so the
	// service derives to Microsoft.Resources; locks are actually governed by
	// Microsoft.Authorization. The service key cannot be remapped because
	// armresources, armdeployments, armsubscriptions and armpolicy legitimately
	// share it.
	"ManagementLocks.NewListAtSubscriptionLevelPager": "Microsoft.Authorization/locks/read",

	// The entities listing walks the management group hierarchy; the governing
	// permission is on managementGroups, not on an "entities" resource type.
	"Entities.NewListPager": "Microsoft.Management/managementGroups/read",

	// Synapse client names begin with an acronym (IPFirewallRules, SQLPools),
	// which the resource-type derivation lower-cases one character at a time
	// into "iPFirewallRules" and "sQLPools". They are also all children of a
	// workspace, which the client name does not carry.
	"IPFirewallRules.NewListByWorkspacePager": "Microsoft.Synapse/workspaces/firewallRules/read",
	"SQLPools.NewListByWorkspacePager":        "Microsoft.Synapse/workspaces/sqlPools/read",
	"SQLPoolTransparentDataEncryptions.Get":   "Microsoft.Synapse/workspaces/sqlPools/transparentDataEncryption/read",
	"SQLPoolBlobAuditingPolicies.Get":         "Microsoft.Synapse/workspaces/sqlPools/auditingSettings/read",

	// armfrontdoor's client is named PoliciesClient, which derives to a bare
	// "policies" resource type under Microsoft.Network rather than the Front
	// Door firewall policy type it actually reads.
	"Policies.NewListBySubscriptionPager": "Microsoft.Network/frontdoorWebApplicationFirewallPolicies/read",
	"Policies.Get":                        "Microsoft.Network/frontdoorWebApplicationFirewallPolicies/read",

	// Event Grid event subscriptions are children of the topic, system topic or
	// domain they belong to; the client names flatten that nesting.
	"TopicEventSubscriptions.NewListPager":                    "Microsoft.EventGrid/topics/eventSubscriptions/read",
	"SystemTopicEventSubscriptions.NewListBySystemTopicPager": "Microsoft.EventGrid/systemTopics/eventSubscriptions/read",
	"DomainEventSubscriptions.NewListPager":                   "Microsoft.EventGrid/domains/eventSubscriptions/read",

	// Every API Management child resource sits under service/, and the acronym
	// clients (APIClient, APIPolicyClient) derive to "aPI" and "aPIPolicy".
	"API.NewListByServicePager":        "Microsoft.ApiManagement/service/apis/read",
	"APIPolicy.Get":                    "Microsoft.ApiManagement/service/apis/policies/read",
	"Product.NewListByServicePager":    "Microsoft.ApiManagement/service/products/read",
	"ProductPolicy.Get":                "Microsoft.ApiManagement/service/products/policies/read",
	"NamedValue.NewListByServicePager": "Microsoft.ApiManagement/service/namedValues/read",
	"Policy.Get":                       "Microsoft.ApiManagement/service/policies/read",
	"Subscription.NewListPager":        "Microsoft.ApiManagement/service/subscriptions/read",
}

// azurePermissionOverrides maps generated permission strings to the correct
// Azure RBAC permission. Many Azure SDK client names don't include parent
// resource paths (e.g., servers/) or use different names than the ARM API.
var azurePermissionOverrides = map[string]string{
	// Batch: client names don't match ARM resource types
	"Microsoft.Batch/account/read": "Microsoft.Batch/batchAccounts/read",
	"Microsoft.Batch/pool/read":    "Microsoft.Batch/batchAccounts/pools/read",

	// Cache (Redis): sub-resources need redis/ parent path
	"Microsoft.Cache/firewallRules/read":  "Microsoft.Cache/redis/firewallRules/read",
	"Microsoft.Cache/patchSchedules/read": "Microsoft.Cache/redis/patchSchedules/read",

	// Cosmos DB for PostgreSQL: SDK package maps to different ARM resource type
	"Microsoft.DBforPostgreSQL/clusters/read": "Microsoft.DBforPostgreSQL/serverGroupsv2/read",

	// MySQL: sub-resources need servers/ parent path
	"Microsoft.DBforMySQL/configurations/read": "Microsoft.DBforMySQL/servers/configurations/read",
	"Microsoft.DBforMySQL/databases/read":      "Microsoft.DBforMySQL/servers/databases/read",
	"Microsoft.DBforMySQL/firewallRules/read":  "Microsoft.DBforMySQL/servers/firewallRules/read",

	// PostgreSQL: the legacy single-server resource type (servers/) is retired
	// and not in the RBAC catalog; all sub-resources resolve to flexibleServers/.
	"Microsoft.DBforPostgreSQL/configurations/read":                   "Microsoft.DBforPostgreSQL/flexibleServers/configurations/read",
	"Microsoft.DBforPostgreSQL/databases/read":                        "Microsoft.DBforPostgreSQL/flexibleServers/databases/read",
	"Microsoft.DBforPostgreSQL/firewallRules/read":                    "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/read",
	"Microsoft.DBforPostgreSQL/advancedThreatProtectionSettings/read": "Microsoft.DBforPostgreSQL/flexibleServers/advancedThreatProtectionSettings/read",

	// Network: client names don't match ARM resource types
	"Microsoft.Network/interfaces/read":                       "Microsoft.Network/networkInterfaces/read",
	"Microsoft.Network/securityGroups/read":                   "Microsoft.Network/networkSecurityGroups/read",
	"Microsoft.Network/subnets/read":                          "Microsoft.Network/virtualNetworks/subnets/read",
	"Microsoft.Network/flowLogs/read":                         "Microsoft.Network/networkWatchers/flowLogs/read",
	"Microsoft.Network/watchers/read":                         "Microsoft.Network/networkWatchers/read",
	"Microsoft.Network/virtualNetworkPeerings/read":           "Microsoft.Network/virtualNetworks/virtualNetworkPeerings/read",
	"Microsoft.Network/virtualNetworkGatewayConnections/read": "Microsoft.Network/connections/read",

	// SQL: sub-resources need servers/ or servers/databases/ parent paths
	"Microsoft.Sql/databases/read":                                "Microsoft.Sql/servers/databases/read",
	"Microsoft.Sql/firewallRules/read":                            "Microsoft.Sql/servers/firewallRules/read",
	"Microsoft.Sql/iPv6FirewallRules/read":                        "Microsoft.Sql/servers/ipv6FirewallRules/read",
	"Microsoft.Sql/virtualNetworkRules/read":                      "Microsoft.Sql/servers/virtualNetworkRules/read",
	"Microsoft.Sql/encryptionProtectors/read":                     "Microsoft.Sql/servers/encryptionProtector/read",
	"Microsoft.Sql/backupShortTermRetentionPolicies/read":         "Microsoft.Sql/servers/databases/backupShortTermRetentionPolicies/read",
	"Microsoft.Sql/longTermRetentionPolicies/read":                "Microsoft.Sql/servers/databases/backupLongTermRetentionPolicies/read",
	"Microsoft.Sql/transparentDataEncryptions/read":               "Microsoft.Sql/servers/databases/transparentDataEncryption/read",
	"Microsoft.Sql/databaseAdvancedThreatProtectionSettings/read": "Microsoft.Sql/servers/databases/advancedThreatProtectionSettings/read",
	"Microsoft.Sql/databaseBlobAuditingPolicies/read":             "Microsoft.Sql/servers/databases/auditingSettings/read",
	"Microsoft.Sql/databaseSecurityAlertPolicies/read":            "Microsoft.Sql/servers/databases/securityAlertPolicies/read",
	"Microsoft.Sql/databaseUsages/read":                           "Microsoft.Sql/servers/databases/usages/read",
	"Microsoft.Sql/serverAdvancedThreatProtectionSettings/read":   "Microsoft.Sql/servers/advancedThreatProtectionSettings/read",
	"Microsoft.Sql/serverAzureADAdministrators/read":              "Microsoft.Sql/servers/administrators/read",
	"Microsoft.Sql/serverAzureADOnlyAuthentications/read":         "Microsoft.Sql/servers/azureADOnlyAuthentications/read",
	"Microsoft.Sql/serverBlobAuditingPolicies/read":               "Microsoft.Sql/servers/auditingSettings/read",
	"Microsoft.Sql/serverConnectionPolicies/read":                 "Microsoft.Sql/servers/connectionPolicies/read",
	"Microsoft.Sql/serverSecurityAlertPolicies/read":              "Microsoft.Sql/servers/securityAlertPolicies/read",
	"Microsoft.Sql/serverVulnerabilityAssessments/read":           "Microsoft.Sql/servers/vulnerabilityAssessments/read",

	// Storage: client names don't match ARM resource types
	"Microsoft.Storage/accounts/read":       "Microsoft.Storage/storageAccounts/read",
	"Microsoft.Storage/blobContainers/read": "Microsoft.Storage/storageAccounts/blobServices/containers/read",

	// Web: client names don't match ARM resource types
	"Microsoft.Web/environments/read": "Microsoft.Web/hostingEnvironments/read",
	"Microsoft.Web/plans/read":        "Microsoft.Web/serverfarms/read",
	"Microsoft.Web/webApps/read":      "Microsoft.Web/sites/read",

	// CDN: Azure Front Door SDK clients omit the profiles/ parent path
	"Microsoft.Cdn/aFDCustomDomains/read": "Microsoft.Cdn/profiles/customdomains/read",
	"Microsoft.Cdn/aFDEndpoints/read":     "Microsoft.Cdn/profiles/afdendpoints/read",
	"Microsoft.Cdn/aFDOriginGroups/read":  "Microsoft.Cdn/profiles/origingroups/read",
	"Microsoft.Cdn/aFDOrigins/read":       "Microsoft.Cdn/profiles/origingroups/origins/read",
	"Microsoft.Cdn/securityPolicies/read": "Microsoft.Cdn/profiles/securitypolicies/read",

	// ContainerRegistry: sub-resources need registries/ parent path
	"Microsoft.ContainerRegistry/cacheRules/read":          "Microsoft.ContainerRegistry/registries/cacheRules/read",
	"Microsoft.ContainerRegistry/connectedRegistries/read": "Microsoft.ContainerRegistry/registries/connectedRegistries/read",
	"Microsoft.ContainerRegistry/credentialSets/read":      "Microsoft.ContainerRegistry/registries/credentialSets/read",
	"Microsoft.ContainerRegistry/replications/read":        "Microsoft.ContainerRegistry/registries/replications/read",
	"Microsoft.ContainerRegistry/scopeMaps/read":           "Microsoft.ContainerRegistry/registries/scopeMaps/read",
	"Microsoft.ContainerRegistry/tokens/read":              "Microsoft.ContainerRegistry/registries/tokens/read",
	"Microsoft.ContainerRegistry/webhooks/read":            "Microsoft.ContainerRegistry/registries/webhooks/read",

	// DNS: Azure DNS lives under Microsoft.Network, not Microsoft.Dns
	"Microsoft.Dns/recordSets/read": "Microsoft.Network/dnszones/recordsets/read",
	"Microsoft.Dns/zones/read":      "Microsoft.Network/dnszones/read",

	// Private DNS: lives under Microsoft.Network/privateDnsZones, not Microsoft.Privatedns
	"Microsoft.Privatedns/privateZones/read":        "Microsoft.Network/privateDnsZones/read",
	"Microsoft.Privatedns/virtualNetworkLinks/read": "Microsoft.Network/privateDnsZones/virtualNetworkLinks/read",

	// EventHub: sub-resources need namespaces/ (or namespaces/eventhubs/) parent path
	"Microsoft.EventHub/consumerGroups/read": "Microsoft.EventHub/namespaces/eventhubs/consumergroups/read",
	"Microsoft.EventHub/eventHubs/read":      "Microsoft.EventHub/namespaces/eventhubs/read",

	// Network: SDK calls Application Gateway WAF, which has a longer ARM type name
	"Microsoft.Network/webApplicationFirewallPolicies/read": "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read",

	// OperationalInsights: sub-resources need workspaces/ parent path;
	// queryPacks is the standalone resource and uses lowercase querypacks;
	// log queries map to workspaces/savedSearches
	"Microsoft.OperationalInsights/dataExports/read":    "Microsoft.OperationalInsights/workspaces/dataexports/read",
	"Microsoft.OperationalInsights/linkedServices/read": "Microsoft.OperationalInsights/workspaces/linkedservices/read",
	"Microsoft.OperationalInsights/queries/read":        "Microsoft.OperationalInsights/workspaces/savedSearches/read",
	"Microsoft.OperationalInsights/queryPacks/read":     "Microsoft.OperationalInsights/querypacks/read",
	"Microsoft.OperationalInsights/tables/read":         "Microsoft.OperationalInsights/workspaces/tables/read",

	// RecoveryServices: backup sub-resources need Vaults/ parent path; backupResourceVaultConfigs
	// is the SDK client name but the ARM operation is called backupconfig
	"Microsoft.RecoveryServices/backupPolicies/read":             "Microsoft.RecoveryServices/Vaults/backupPolicies/read",
	"Microsoft.RecoveryServices/backupProtectedItems/read":       "Microsoft.RecoveryServices/Vaults/backupProtectedItems/read",
	"Microsoft.RecoveryServices/backupResourceVaultConfigs/read": "Microsoft.RecoveryServices/Vaults/backupconfig/read",

	// Resources: resource groups are nested under subscriptions/
	"Microsoft.Resources/resourceGroups/read": "Microsoft.Resources/subscriptions/resourceGroups/read",

	// ServiceBus: sub-resources need namespaces/ parent path; subscriptions are nested under topics
	"Microsoft.ServiceBus/queues/read":        "Microsoft.ServiceBus/namespaces/queues/read",
	"Microsoft.ServiceBus/topics/read":        "Microsoft.ServiceBus/namespaces/topics/read",
	"Microsoft.ServiceBus/subscriptions/read": "Microsoft.ServiceBus/namespaces/topics/subscriptions/read",

	// Storage: encryption/management policy and local user sub-resources need
	// storageAccounts/ parent path
	"Microsoft.Storage/encryptionScopes/read":           "Microsoft.Storage/storageAccounts/encryptionScopes/read",
	"Microsoft.Storage/localUsers/read":                 "Microsoft.Storage/storageAccounts/localUsers/read",
	"Microsoft.Storage/managementPolicies/read":         "Microsoft.Storage/storageAccounts/managementPolicies/read",
	"Microsoft.Storage/fileShares/read":                 "Microsoft.Storage/storageAccounts/fileServices/shares/read",
	"Microsoft.Storage/privateEndpointConnections/read": "Microsoft.Storage/storageAccounts/privateEndpointConnections/read",
	"Microsoft.Storage/objectReplicationPolicies/read":  "Microsoft.Storage/storageAccounts/objectReplicationPolicies/read",
	"Microsoft.Storage/inventoryPolicies/read":          "Microsoft.Storage/storageAccounts/inventoryPolicies/read",
	"Microsoft.Storage/blobInventoryPolicies/read":      "Microsoft.Storage/storageAccounts/inventoryPolicies/read",
	"Microsoft.Storage/queue/read":                      "Microsoft.Storage/storageAccounts/queueServices/queues/read",
	"Microsoft.Storage/table/read":                      "Microsoft.Storage/storageAccounts/tableServices/tables/read",

	// Data Factory: child resources are nested under factories/
	"Microsoft.DataFactory/linkedServices/read":          "Microsoft.DataFactory/factories/linkedservices/read",
	"Microsoft.DataFactory/integrationRuntimes/read":     "Microsoft.DataFactory/factories/integrationruntimes/read",
	"Microsoft.DataFactory/managedVirtualNetworks/read":  "Microsoft.DataFactory/factories/managedvirtualnetworks/read",
	"Microsoft.DataFactory/managedPrivateEndpoints/read": "Microsoft.DataFactory/factories/managedvirtualnetworks/managedprivateendpoints/read",

	// CDN: AFD routes are nested under profiles/afdendpoints/
	"Microsoft.Cdn/routes/read": "Microsoft.Cdn/profiles/afdendpoints/routes/read",

	// Network: privateDnsZoneGroups are nested under privateEndpoints/
	"Microsoft.Network/privateDNSZoneGroups/read": "Microsoft.Network/privateEndpoints/privateDnsZoneGroups/read",

	// HybridCompute: machine extensions are nested under machines/, not a top-level type
	"Microsoft.HybridCompute/machineExtensions/read": "Microsoft.HybridCompute/machines/extensions/read",

	// App (Container Apps): SDK client names omit the managedEnvironments/ or
	// containerApps/ parent path.
	"Microsoft.App/certificates/read":                                 "Microsoft.App/managedEnvironments/certificates/read",
	"Microsoft.App/daprComponents/read":                               "Microsoft.App/managedEnvironments/daprComponents/read",
	"Microsoft.App/maintenanceConfigurations/read":                    "Microsoft.App/managedEnvironments/maintenanceConfigurations/read",
	"Microsoft.App/managedEnvironmentPrivateEndpointConnections/read": "Microsoft.App/managedEnvironments/privateEndpointConnections/read",
	"Microsoft.App/hTTPRouteConfig/read":                              "Microsoft.App/managedEnvironments/httpRouteConfigs/read",
	"Microsoft.App/containerAppsAuthConfigs/read":                     "Microsoft.App/containerApps/authConfigs/read",
	"Microsoft.App/containerAppsRevisions/read":                       "Microsoft.App/containerApps/revisions/read",

	// Cognitive Services: sub-resources are nested under accounts/ (and projects/).
	"Microsoft.Cognitiveservices/accountConnections/read":    "Microsoft.CognitiveServices/accounts/connections/read",
	"Microsoft.Cognitiveservices/projectConnections/read":    "Microsoft.CognitiveServices/accounts/projects/connections/read",
	"Microsoft.Cognitiveservices/projects/read":              "Microsoft.CognitiveServices/accounts/projects/read",
	"Microsoft.Cognitiveservices/deployments/read":           "Microsoft.CognitiveServices/accounts/deployments/read",
	"Microsoft.Cognitiveservices/defenderForAISettings/read": "Microsoft.CognitiveServices/accounts/defenderForAISettings/read",
	"Microsoft.Cognitiveservices/raiPolicies/read":           "Microsoft.CognitiveServices/accounts/raiPolicies/read",
	"Microsoft.Cognitiveservices/raiTopics/read":             "Microsoft.CognitiveServices/accounts/raiTopics/read",

	// Compute: dedicated hosts live under hostGroups/; gallery images under
	// galleries/; scale-set sub-resources under virtualMachineScaleSets/.
	"Microsoft.Compute/dedicatedHostGroups/read":              "Microsoft.Compute/hostGroups/read",
	"Microsoft.Compute/dedicatedHosts/read":                   "Microsoft.Compute/hostGroups/hosts/read",
	"Microsoft.Compute/galleryImages/read":                    "Microsoft.Compute/galleries/images/read",
	"Microsoft.Compute/galleryImageVersions/read":             "Microsoft.Compute/galleries/images/versions/read",
	"Microsoft.Compute/virtualMachineScaleSetExtensions/read": "Microsoft.Compute/virtualMachineScaleSets/extensions/read",
	"Microsoft.Compute/virtualMachineScaleSetVMs/read":        "Microsoft.Compute/virtualMachineScaleSets/virtualMachines/read",

	// ContainerService: agent pools are nested under managedClusters/.
	"Microsoft.ContainerService/agentPools/read": "Microsoft.ContainerService/managedClusters/agentPools/read",

	// DBforPostgreSQL: the SDK ServersClient maps to the flexibleServers/ resource
	// type (the configurations/databases/firewallRules sub-resources are handled by
	// the existing PostgreSQL entries above, which already resolve to flexibleServers/).
	"Microsoft.DBforPostgreSQL/servers/read":                    "Microsoft.DBforPostgreSQL/flexibleServers/read",
	"Microsoft.DBforPostgreSQL/privateEndpointConnections/read": "Microsoft.DBforPostgreSQL/flexibleServers/privateEndpointConnections/read",

	// DocumentDB: private endpoint connections are nested under databaseAccounts/;
	// the SQLResources client reads SQL containers.
	"Microsoft.DocumentDB/privateEndpointConnections/read": "Microsoft.DocumentDB/databaseAccounts/privateEndpointConnections/read",
	"Microsoft.DocumentDB/sQLResources/read":               "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/read",

	// Mongo cluster operations live under the Microsoft.DocumentDB provider.
	"Microsoft.Mongocluster/mongoClusters/read": "Microsoft.DocumentDB/mongoClusters/read",

	// MachineLearningServices: sub-resources are nested under workspaces/.
	"Microsoft.MachineLearningServices/compute/read":             "Microsoft.MachineLearningServices/workspaces/computes/read",
	"Microsoft.MachineLearningServices/modelContainers/read":     "Microsoft.MachineLearningServices/workspaces/models/read",
	"Microsoft.MachineLearningServices/onlineDeployments/read":   "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/read",
	"Microsoft.MachineLearningServices/onlineEndpoints/read":     "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read",
	"Microsoft.MachineLearningServices/serverlessEndpoints/read": "Microsoft.MachineLearningServices/workspaces/serverlessEndpoints/read",

	// Network: several SDK clients omit the parent resource path.
	"Microsoft.Network/connectionMonitors/read":                "Microsoft.Network/networkWatchers/connectionMonitors/read",
	"Microsoft.Network/expressRouteCircuitAuthorizations/read": "Microsoft.Network/expressRouteCircuits/authorizations/read",
	"Microsoft.Network/expressRouteCircuitPeerings/read":       "Microsoft.Network/expressRouteCircuits/peerings/read",
	"Microsoft.Network/hubRouteTables/read":                    "Microsoft.Network/virtualHubs/hubRouteTables/read",
	"Microsoft.Network/hubVirtualNetworkConnections/read":      "Microsoft.Network/virtualHubs/hubVirtualNetworkConnections/read",
	"Microsoft.Network/packetCaptures/read":                    "Microsoft.Network/networkWatchers/packetCaptures/read",
	// Traffic Manager operations live under the Microsoft.Network provider.
	"Microsoft.Trafficmanager/profiles/read": "Microsoft.Network/trafficManagerProfiles/read",

	// Search: the ARM resource type is searchServices, not services.
	"Microsoft.Search/services/read": "Microsoft.Search/searchServices/read",

	// Security: Defender for Storage settings use the longer resource type name.
	"Microsoft.Security/defenderForStorage/read": "Microsoft.Security/defenderForStorageSettings/read",
	// Security: the APICollections client name lowercases to an odd acronym casing.
	"Microsoft.Security/aPICollections/read": "Microsoft.Security/apiCollections/read",

	// Sql: server- and database-scoped sub-resources need their parent paths.
	"Microsoft.Sql/dataMaskingPolicies/read":                  "Microsoft.Sql/servers/databases/dataMaskingPolicies/read",
	"Microsoft.Sql/dataMaskingRules/read":                     "Microsoft.Sql/servers/databases/dataMaskingPolicies/rules/read",
	"Microsoft.Sql/databaseVulnerabilityAssessmentScans/read": "Microsoft.Sql/servers/databases/vulnerabilityAssessments/scans/read",
	"Microsoft.Sql/databaseVulnerabilityAssessments/read":     "Microsoft.Sql/servers/databases/vulnerabilityAssessments/read",
	"Microsoft.Sql/failoverGroups/read":                       "Microsoft.Sql/servers/failoverGroups/read",
	"Microsoft.Sql/geoBackupPolicies/read":                    "Microsoft.Sql/servers/databases/geoBackupPolicies/read",
	"Microsoft.Sql/ledgerDigestUploads/read":                  "Microsoft.Sql/servers/databases/ledgerDigestUploads/read",
	"Microsoft.Sql/managedDatabases/read":                     "Microsoft.Sql/managedInstances/databases/read",
	"Microsoft.Sql/outboundFirewallRules/read":                "Microsoft.Sql/servers/outboundFirewallRules/read",
	"Microsoft.Sql/privateEndpointConnections/read":           "Microsoft.Sql/servers/privateEndpointConnections/read",
	"Microsoft.Sql/replicationLinks/read":                     "Microsoft.Sql/servers/replicationLinks/read",
	"Microsoft.Sql/serverDevOpsAuditSettings/read":            "Microsoft.Sql/servers/devOpsAuditingSettings/read",
	"Microsoft.Sql/serverKeys/read":                           "Microsoft.Sql/servers/keys/read",

	// Storage: network security perimeter configs are nested under storageAccounts/.
	"Microsoft.Storage/networkSecurityPerimeterConfigurations/read": "Microsoft.Storage/storageAccounts/networkSecurityPerimeterConfigurations/read",

	// NetApp: the ARM resource type is netAppAccounts, and pools and volumes
	// are nested under it, which the AccountsClient/PoolsClient/VolumesClient
	// names do not carry.
	"Microsoft.NetApp/accounts/read": "Microsoft.NetApp/netAppAccounts/read",
	"Microsoft.NetApp/pools/read":    "Microsoft.NetApp/netAppAccounts/capacityPools/read",
	"Microsoft.NetApp/volumes/read":  "Microsoft.NetApp/netAppAccounts/capacityPools/volumes/read",
	// File shares: armfileshares exposes a generic NewClient, so the resource
	// type comes from the package name and loses the camel hump. Snapshots are
	// nested under the share, which the FileShareSnapshotsClient name does not
	// carry.
	"Microsoft.FileShares/fileshares/read":         "Microsoft.FileShares/fileShares/read",
	"Microsoft.FileShares/fileShareSnapshots/read": "Microsoft.FileShares/fileShares/snapshots/read",
	// Elastic SAN: volume groups are nested under elasticSans/, which the
	// VolumeGroupsClient name does not carry.
	"Microsoft.ElasticSan/volumeGroups/read": "Microsoft.ElasticSan/elasticSans/volumeGroups/read",
}

// azurePermission constructs the RBAC permission string.
func azurePermission(armProvider, resourceType string) string {
	// Convert PascalCase to camelCase for the resource type
	rt := pascalToCamelCase(resourceType)
	perm := armProvider + "/" + rt + "/read"

	// Check for overrides where SDK names don't match ARM resource types
	if override, ok := azurePermissionOverrides[perm]; ok {
		return override
	}
	return perm
}

func pascalToCamelCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// azureResourceFromPackage derives a resource type from an Azure ARM package name
// when the constructor is generic (NewClient).
// e.g., "armresources" -> "resources", "armsubscriptions" -> "subscriptions"
func azureResourceFromPackage(pkgName string) string {
	name := strings.TrimPrefix(pkgName, "arm")
	if name == "" {
		return pkgName
	}
	return name
}

func isAzureReadMethod(name string) bool {
	readMethods := []string{
		"NewListPager", "NewListAllPager", "NewListBySubscriptionPager",
		"NewListByResourceGroupPager", "Get",
		"NewListByServerPager", "NewListByAccountPager",
		"NewListByNamespacePager",
		// The Data Protection SDK names its subscription-wide enumeration
		// NewGetInSubscriptionPager, which the NewList*Pager catch-all below
		// does not reach. Other New*Pager verbs exist elsewhere in the SDKs
		// and are also reads, but widening the catch-all to every New*Pager
		// surfaces permissions for calls this provider already makes, and
		// getting their strings right is separate work from this one.
		"NewGetInSubscriptionPager",
		// Non-paged list variants (some SDKs return the full list in one call)
		"ListByServer", "ListBySubscription",
	}
	for _, m := range readMethods {
		if name == m {
			return true
		}
	}
	// Catch-all for other list pagers
	return strings.HasPrefix(name, "NewList") && strings.HasSuffix(name, "Pager")
}

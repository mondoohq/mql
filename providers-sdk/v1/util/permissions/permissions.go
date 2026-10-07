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
//
// Permission is the IAM permission the call needs; Action is the SDK operation
// the provider calls. They are usually the same name, and differ where the
// cloud authorizes several operations with one permission (AWS GetFindingV2
// is authorized by access-analyzer:GetFinding; every API Gateway read by
// apigateway:GET) or names the permission after the resource rather than the
// method (GCP, Azure).
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
		var err error
		details, err = extractAzurePermissions(providerPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
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
	"opensearchserverless":     "aoss",
	"redshiftserverless":       "redshift-serverless",
	"mwaa":                     "airflow",
	// VPC Lattice's IAM prefix is hyphenated; the SDK package is not.
	"vpclattice": "vpc-lattice",
}

// awsPermissionOverrides maps a generated "service:Action" permission to the
// correct IAM action for the cases where the AWS SDK operation name does not
// match the IAM action name (the per-service-prefix renames are handled by
// awsServiceNameOverrides instead). An empty-string value means the operation
// has no corresponding IAM action and should be skipped entirely. Every entry
// here was verified against IAM Access Analyzer (validate-policy) or the
// Service Authorization Reference — the left side is not an IAM action and the
// right side is. `go run ./providers-sdk/v1/util/permissions/validate` checks
// the whole manifest against the published catalogs; run it after adding one.
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
	"apigateway:GetResources":         "apigateway:GET",
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

	// The Access Analyzer V2 APIs are governed by the V1 actions: the SDK
	// documents that GetFinding and GetFindingV2 both use
	// access-analyzer:GetFinding, and ListFindingsV2 likewise.
	"access-analyzer:ListFindingsV2": "access-analyzer:ListFindings",
	"access-analyzer:GetFindingV2":   "access-analyzer:GetFinding",

	// IAM spells these actions differently from the SDK operations. Action
	// matching is case-insensitive, so the SDK spelling would be granted, but
	// the manifest is what customers paste into policies and should carry the
	// documented spelling.
	"memorydb:DescribeACLs": "memorydb:DescribeAcls",
	"s3:GetBucketCors":      "s3:GetBucketCORS",

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

	// AWS's Service Reference lists these operations but maps them to no
	// action, and has no action of the obvious name (checked 2026-10-07):
	// knowledge-base VPC configurations (bedrockagent SDK, 2026-09-25) and
	// Client VPN Cedar authorization policies (ec2 SDK, 2026-09-28). The
	// validator's `unpublished` list re-checks them on every run and fails
	// once AWS publishes an action, which is the signal to emit it here.
	"bedrock:GetVpcConfiguration":                 "",
	"bedrock:ListVpcConfigurations":               "",
	"ec2:GetClientVpnEndpointAuthorizationPolicy": "",
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

				// Pattern 3: conn.ServiceMethod(region).MethodName() — the client is
				// used inline instead of being stored in a variable first, so the
				// assignment scan above never saw it.
				if inner, ok := sel.X.(*ast.CallExpr); ok {
					if innerSel, ok := inner.Fun.(*ast.SelectorExpr); ok {
						if svcName := awsConnectionMethodToService(innerSel.Sel.Name); svcName != "" && isAWSAPIMethod(methodName) {
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
		"controltower":             "controltower",
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
		"opensearchserverless":     "opensearchserverless",
		"redshiftserverless":       "redshiftserverless",
		"mwaa":                     "mwaa",
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
	"datastore": {
		// Firestore index permissions were renamed to datastore.schemas.*; the
		// datastore.indexes.* names are in no predefined role any more and the
		// Firestore IAM documentation lists only the schemas spelling.
		"ListIndexes": "datastore.schemas.list",
	},
	"networkmanagement": {
		// Network Management permissions are all lowercase; the generic
		// derivation keeps the method's camel case.
		"ListConnectivityTests": "networkmanagement.connectivitytests.list",
	},
	"networksecurity": {
		// Gateway security policy rules are a nested collection whose REST
		// resource is just "Rules"; the generic derivation yields the
		// non-existent networksecurity.rules.list.
		"Rules.List": "networksecurity.gatewaySecurityPolicyRules.list",
	},
	"securitycenter": {
		// Security Command Center permissions are all lowercase; the generic
		// derivation keeps the method's camel case.
		"ListEffectiveSecurityHealthAnalyticsCustomModules": "securitycenter.effectivesecurityhealthanalyticscustommodules.list",
		// Event Threat Detection custom modules are governed by the Security
		// Command Center Management permissions even through the v1 API; no
		// securitycenter.*eventthreatdetectioncustommodules permission exists.
		"ListEffectiveEventThreatDetectionCustomModules": "securitycentermanagement.effectiveEventThreatDetectionCustomModules.list",
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
		// Regional network firewall policies are governed by the
		// compute.regionFirewallPolicies namespace; the generic derivation
		// yields the non-existent compute.regionNetworkFirewallPolicies.*. The
		// aggregated list is only read for its regional scopes, the global
		// ones being covered by NetworkFirewallPolicies.List.
		"NetworkFirewallPolicies.AggregatedList": "compute.regionFirewallPolicies.list",
		"RegionNetworkFirewallPolicies.Get":      "compute.regionFirewallPolicies.get",
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
		"Groups.List":                "",
		"Memberships.List":           "",
		"Groups.GetSecuritySettings": "",
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
		// ModelClient and NotebookClient (clientType derived from
		// NewModelClient/NewNotebookClient). Notebook runtime templates have a
		// resource-scoped permission; models do not: queryTestablePermissions
		// knows no aiplatform.models.getIamPolicy at project or organization
		// scope (checked 2026-10-07, while aiplatform.endpoints.getIamPolicy
		// and the other Vertex AI getIamPolicy permissions are all listed), so
		// nothing is emitted for the model call rather than a name IAM would
		// never grant.
		"Model.GetIamPolicy":    "",
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
		// Google names the workload identity and workforce pool permissions in
		// the service-qualified form; the dotted spellings exist only as aliases
		// (queryTestablePermissions reports the qualified name as the
		// primaryPermission of each). The resource segment for a pool's providers
		// is the generic "Providers", which findMeaningfulResource qualifies with
		// the parent pool type so the two pool families stay distinct.
		"WorkloadIdentityPools.List":           "iam.googleapis.com/workloadIdentityPools.list",
		"WorkloadIdentityPools.Providers.List": "iam.googleapis.com/workloadIdentityPoolProviders.list",
		"WorkforcePools.List":                  "iam.googleapis.com/workforcePools.list",
		"WorkforcePools.Providers.List":        "iam.googleapis.com/workforcePoolProviders.list",
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
		// IAM v3 principal access boundary permissions are all lowercase; the
		// generic derivation keeps the method's camel case.
		"ListPolicyBindings":                  "iam.policybindings.list",
		"ListPrincipalAccessBoundaryPolicies": "iam.principalaccessboundarypolicies.list",
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
		// Listing the tag bindings of a project is governed by the hierarchy
		// node's listTagBindings permission (the one in roles/resourcemanager
		// .tagViewer); neither "resourcemanager.tagBindings.list" nor
		// "resourcemanager.resourceTagBindings.list" is a real permission.
		"TagBindings.List": "resourcemanager.hierarchyNodes.listTagBindings",
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
	"orgpolicy.customConstraints.list": true,
	// Workforce pools are an organization resource: the permissions are
	// absent from queryTestablePermissions at project scope and present at
	// organization scope (GA, custom-role supported).
	"iam.googleapis.com/workforcePools.list":         true,
	"iam.googleapis.com/workforcePoolProviders.list": true,
	"resourcemanager.folders.get":                    true,
	"resourcemanager.folders.getIamPolicy":           true,
	"resourcemanager.folders.list":                   true,
	"resourcemanager.folders.search":                 true,
	"resourcemanager.organizations.get":              true,
	"resourcemanager.organizations.getIamPolicy":     true,
	"resourcemanager.projects.list":                  true,
	"resourcemanager.projects.search":                true,
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
//
// Azure names an operation from the ARM URL path of the call: the resource
// provider namespace and the resource type segments after the last
// /providers/ in the path, then the verb, read for a GET and <segment>/action
// for a POST. Every generated Azure SDK client method carries that path in its
// request builder (the <method>CreateRequest function next to it), so the
// permission is read from the SDK source in the module cache, at the version
// the provider's go.mod pins, rather than guessed from the client's name. A
// client's name says nothing about its parent resource (DatabasesClient reads
// clusters/{c}/databases) and one client's methods read different resources
// (WebAppsClient lists sites, but also sites/{s}/slots); the path knows both.
//
// Two small tables remain. azurePathOperationOverrides covers the operations
// whose registered name differs from the path convention, and
// azureUnregisteredOperations the operations no resource provider registers
// at all, which Azure refuses in a custom role and which are therefore not
// emitted. azureSDKCallOverrides is the escape hatch for a call whose request
// builder cannot be read.

// azureCall is one SDK method call the provider makes.
type azureCall struct {
	importPath string // e.g. github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto/v2
	client     string // e.g. DatabasesClient; "Client" for a package's generic client
	method     string // e.g. NewListByClusterPager
	file       string // the provider file the call is in
}

// key identifies the call independently of the file: "<import path> <Client>.<Method>".
func (c azureCall) key() string {
	return c.importPath + " " + c.client + "." + c.method
}

// azureSDKCallOverrides maps a call, by key, to the operation it needs, for the
// rare call whose request builder cannot be read from the SDK source. An empty
// value means the call needs no operation and is skipped. Prefer fixing the
// derivation over adding an entry.
var azureSDKCallOverrides = map[string]string{}

// azurePathOperationOverrides maps an operation as the path convention names
// it (lower-cased) to the name the resource provider actually registered, for
// the providers that deviate from the convention. The registered name is what
// a custom role must carry.
var azurePathOperationOverrides = map[string]string{
	// Data Protection registers Resource Guards under a subscription and
	// resource-group prefix that the API path does not have.
	"microsoft.dataprotection/resourceguards/read": "Microsoft.DataProtection/subscriptions/resourceGroups/providers/resourceGuards/read",
	// Two singleton segments the path has and the registered name drops: the
	// activity log is read at eventtypes/management/values, and the vault
	// config at backupconfig/vaultconfig.
	"microsoft.insights/eventtypes/management/values/read":            "Microsoft.Insights/eventtypes/values/Read",
	"microsoft.recoveryservices/vaults/backupconfig/vaultconfig/read": "Microsoft.RecoveryServices/Vaults/backupconfig/read",
}

// azureUnregisteredOperations lists, lower-cased, the operations the provider
// calls for which no resource provider has registered an operation with Azure
// Resource Manager (`az provider operation list` does not list them). Azure
// refuses an unregistered operation in a custom role with
// InvalidActionOrNotAction, so a manifest naming one could not be used to
// build a role, and nothing is emitted for these. Checked 2026-10-07; when
// Azure registers one, remove it here so it is emitted again. Several are
// calls the provider should stop making: the classic administrators and
// auto-provisioning APIs are retired, as is the single-server PostgreSQL SDK.
var azureUnregisteredOperations = map[string]string{
	"microsoft.authorization/classicadministrators/read":                                 "retired API; iam.go still lists classic administrators",
	"microsoft.security/autoprovisioningsettings/read":                                   "retired API; cloud_defender.go still reads it",
	"microsoft.security/regulatorycompliancestandards/read":                              "API exists, operation never registered",
	"microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols/read": "API exists, operation never registered",
	"microsoft.dbforpostgresql/servergroupsv2/read":                                      "only child operations are registered",
	"microsoft.dbforpostgresql/servers/read":                                             "retired single-server API; postgresql.go still uses it",
	"microsoft.dbforpostgresql/servers/configurations/read":                              "retired single-server API; postgresql.go still uses it",
	"microsoft.dbforpostgresql/servers/databases/read":                                   "retired single-server API; postgresql.go still uses it",
	"microsoft.dbforpostgresql/servers/firewallrules/read":                               "retired single-server API; postgresql.go still uses it",
	"microsoft.documentdb/databaseaccounts/cassandraroleassignments/read":                "preview data-plane RBAC API",
	"microsoft.documentdb/databaseaccounts/cassandraroledefinitions/read":                "preview data-plane RBAC API",
	"microsoft.documentdb/databaseaccounts/gremlinroleassignments/read":                  "preview data-plane RBAC API",
	"microsoft.documentdb/databaseaccounts/gremlinroledefinitions/read":                  "preview data-plane RBAC API",
	"microsoft.documentdb/databaseaccounts/mongomiroleassignments/read":                  "preview data-plane RBAC API",
	"microsoft.documentdb/databaseaccounts/mongomiroledefinitions/read":                  "preview data-plane RBAC API",
	"microsoft.documentdb/databaseaccounts/tableroleassignments/read":                    "preview data-plane RBAC API",
	"microsoft.documentdb/databaseaccounts/tableroledefinitions/read":                    "preview data-plane RBAC API",
	"microsoft.fileshares/fileshares/filesharesnapshots/read":                            "preview",
}

func extractAzurePermissions(root string) ([]PermissionDetail, error) {
	sdk, err := loadAzureSDKIndex(root)
	if err != nil {
		return nil, err
	}
	return extractAzurePermissionsWith(sdk, root)
}

// extractAzurePermissionsWith derives the permissions for every read call under
// root, resolving the calls' SDK sources through sdk.
func extractAzurePermissionsWith(sdk *azureSDKIndex, root string) ([]PermissionDetail, error) {
	var details []PermissionDetail
	for _, call := range azureCalls(root) {
		d, emit, err := azureDetail(sdk, call)
		if err != nil {
			return nil, err
		}
		if emit {
			details = append(details, d)
		}
	}
	return details, nil
}

// azureDetail derives the permission for one call.
func azureDetail(sdk *azureSDKIndex, call azureCall) (PermissionDetail, bool, error) {
	if op, ok := azureSDKCallOverrides[call.key()]; ok {
		if op == "" {
			return PermissionDetail{}, false, nil
		}
		return PermissionDetail{Permission: op, Service: azureNamespaceOf(op), Action: call.method, SourceFile: call.file}, true, nil
	}
	urlPath, httpMethod, err := sdk.request(call)
	if err != nil {
		return PermissionDetail{}, false, fmt.Errorf("%s in %s: %w\n  (if the SDK really builds no request for this call, add an azureSDKCallOverrides entry)", call.key(), call.file, err)
	}
	ns, op := azureOperationFromPath(urlPath, httpMethod)
	if registered, ok := azurePathOperationOverrides[strings.ToLower(op)]; ok {
		op = registered
	}
	if _, skip := azureUnregisteredOperations[strings.ToLower(op)]; skip {
		return PermissionDetail{}, false, nil
	}
	return PermissionDetail{Permission: op, Service: ns, Action: call.method, SourceFile: call.file}, true, nil
}

// azureNamespaceOf returns the resource provider namespace of an operation.
func azureNamespaceOf(op string) string {
	ns, _, _ := strings.Cut(op, "/")
	return ns
}

// azureOperationFromPath derives the operation Azure names for a call from the
// URL template and HTTP method of its request: the namespace and resource type
// segments after the last /providers/ in the path, without the {parameters}
// and without the literal "default" singleton segment, then read for GET and
// <segment>/action for POST. A path with no /providers/ is Azure Resource
// Manager's own, under Microsoft.Resources. It returns the namespace and the
// operation.
func azureOperationFromPath(urlPath, httpMethod string) (string, string) {
	urlPath, _, _ = strings.Cut(urlPath, "?")
	ns := "Microsoft.Resources"
	rest := urlPath
	if i := strings.LastIndex(urlPath, "/providers/"); i >= 0 {
		rest = urlPath[i+len("/providers/"):]
		ns, rest, _ = strings.Cut(rest, "/")
	}
	var segs []string
	for _, s := range strings.Split(rest, "/") {
		if s == "" || strings.HasPrefix(s, "{") || s == "default" {
			continue
		}
		segs = append(segs, s)
	}
	typ := strings.Join(segs, "/")
	switch httpMethod {
	case "GET":
		if typ == "" {
			return ns, ns + "/read"
		}
		return ns, ns + "/" + typ + "/read"
	case "POST":
		return ns, ns + "/" + typ + "/action"
	default:
		return ns, ns + "/" + typ + "/" + strings.ToLower(httpMethod)
	}
}

// azureCalls finds every read call the provider makes on an Azure SDK client:
// the client variable is created from an imported package
// (`client, err := armkusto.NewDatabasesClient(...)`), from a client factory
// (`f := armsecurity.NewClientFactory(...)` then `f.NewPricingsClient()`), or
// inline (`f.NewPricingsClient().Get(...)`); the read methods are the pagers
// and getters isAzureReadMethod names.
func azureCalls(root string) []azureCall {
	var calls []azureCall
	for _, filePath := range listGoFiles(root) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, filePath, nil, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to parse %s: %v\n", filePath, err)
			continue
		}
		calls = append(calls, azureCallsInFile(f, filepath.Base(filePath))...)
	}
	return calls
}

// azureCallsInFile finds the read calls in one parsed provider file.
func azureCallsInFile(f *ast.File, fileName string) []azureCall {
	imports := extractAzureImports(f) // alias -> import path
	if len(imports) == 0 {
		return nil
	}
	var calls []azureCall
	{
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			clientVars := map[string]azureCall{} // var -> import path + client type
			factoryVars := map[string]string{}   // var -> import path

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, rhs := range assign.Rhs {
					call, ok := rhs.(*ast.CallExpr)
					if !ok || i >= len(assign.Lhs) {
						continue
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					recv, ok := sel.X.(*ast.Ident)
					if !ok {
						continue
					}
					lhs, ok := assign.Lhs[i].(*ast.Ident)
					if !ok {
						continue
					}
					ctor := sel.Sel.Name
					switch {
					case ctor == "NewClientFactory":
						if path, ok := imports[recv.Name]; ok {
							factoryVars[lhs.Name] = path
						}
					case strings.HasPrefix(ctor, "New") && strings.HasSuffix(ctor, "Client"):
						path, ok := imports[recv.Name]
						if !ok {
							path, ok = factoryVars[recv.Name]
						}
						if ok {
							clientVars[lhs.Name] = azureCall{importPath: path, client: strings.TrimPrefix(ctor, "New")}
						}
					}
				}
				return true
			})

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !isAzureReadMethod(sel.Sel.Name) {
					return true
				}
				switch recv := sel.X.(type) {
				case *ast.Ident:
					// client.NewListPager(...)
					if c, ok := clientVars[recv.Name]; ok {
						c.method, c.file = sel.Sel.Name, fileName
						calls = append(calls, c)
					}
				case *ast.CallExpr:
					// factoryVar.NewXxxClient().NewListPager(...)
					inner, ok := recv.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					fac, ok := inner.X.(*ast.Ident)
					if !ok {
						return true
					}
					path, ok := factoryVars[fac.Name]
					ctor := inner.Sel.Name
					if ok && strings.HasPrefix(ctor, "New") && strings.HasSuffix(ctor, "Client") {
						calls = append(calls, azureCall{importPath: path, client: strings.TrimPrefix(ctor, "New"), method: sel.Sel.Name, file: fileName})
					}
				}
				return true
			})
			return false
		})
	}
	return calls
}

// extractAzureImports returns alias -> import path for the Azure SDK resource
// manager packages a file imports.
func extractAzureImports(f *ast.File) map[string]string {
	result := map[string]string{}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if !strings.Contains(path, "azure-sdk-for-go/sdk/resourcemanager/") {
			continue
		}
		alias := ""
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			// The package name is the last path element, or the one before a
			// major-version element: .../armcompute/v7 is package armcompute.
			parts := strings.Split(path, "/")
			alias = parts[len(parts)-1]
			if len(parts) > 1 && regexp.MustCompile(`^v\d+$`).MatchString(alias) {
				alias = parts[len(parts)-2]
			}
		}
		result[alias] = path
	}
	return result
}

// isAzureReadMethod reports whether an SDK method is one of the reads the
// manifest accounts for.
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

// =============================================================================
// Reading the Azure SDK
// =============================================================================

// azureSDKIndex locates the Azure SDK sources the provider compiles against:
// the module versions from its go.mod, unpacked in the module cache.
type azureSDKIndex struct {
	versions map[string]string // module path -> version
	cache    string            // GOMODCACHE
	read     func(string) ([]byte, error)
}

// loadAzureSDKIndex reads <providerRoot>/go.mod and finds the module cache
// (GOMODCACHE, or `go env GOMODCACHE`).
func loadAzureSDKIndex(providerRoot string) (*azureSDKIndex, error) {
	data, err := os.ReadFile(filepath.Join(providerRoot, "go.mod"))
	if err != nil {
		return nil, err
	}
	versions := parseAzureSDKVersions(data)
	if len(versions) == 0 {
		return nil, fmt.Errorf("%s/go.mod pins no Azure SDK modules", providerRoot)
	}
	cache := os.Getenv("GOMODCACHE")
	if cache == "" {
		out, err := exec.Command("go", "env", "GOMODCACHE").Output()
		if err != nil {
			return nil, fmt.Errorf("GOMODCACHE is not set and `go env GOMODCACHE` failed: %w", err)
		}
		cache = strings.TrimSpace(string(out))
	}
	return &azureSDKIndex{versions: versions, cache: cache, read: os.ReadFile}, nil
}

// parseAzureSDKVersions returns the Azure SDK modules a go.mod pins, module
// path to version.
func parseAzureSDKVersions(gomod []byte) map[string]string {
	versions := map[string]string{}
	// A require line: module path, version, optionally a trailing comment such
	// as "// indirect". Anchored at both ends so nothing else on a line counts.
	re := regexp.MustCompile(`^\s*(github\.com/Azure/azure-sdk-for-go/\S+)\s+(v\S+)\s*(?://.*)?$`)
	for _, line := range strings.Split(string(gomod), "\n") {
		if m := re.FindStringSubmatch(line); m != nil {
			versions[m[1]] = m[2]
		}
	}
	return versions
}

// dir returns the unpacked directory of the package at importPath: the longest
// pinned module that is a prefix of it, plus the remaining path inside it.
func (x *azureSDKIndex) dir(importPath string) (string, bool) {
	best := ""
	for mod := range x.versions {
		if (importPath == mod || strings.HasPrefix(importPath, mod+"/")) && len(mod) > len(best) {
			best = mod
		}
	}
	if best == "" {
		return "", false
	}
	// The module cache escapes upper-case letters as !lower.
	var esc strings.Builder
	for _, r := range best {
		if r >= 'A' && r <= 'Z' {
			esc.WriteByte('!')
			esc.WriteRune(r + ('a' - 'A'))
		} else {
			esc.WriteRune(r)
		}
	}
	return filepath.Join(x.cache, esc.String()+"@"+x.versions[best], strings.TrimPrefix(importPath, best)), true
}

// request finds the SDK function that builds the request for the call and
// returns its URL template and HTTP method. Generated clients name it
// <method>CreateRequest, where <method> is the operation's name in lower camel
// case (NewListByClusterPager -> listByClusterCreateRequest), in the file
// <client>_client.go (client.go for a package's generic Client).
func (x *azureSDKIndex) request(call azureCall) (urlPath, httpMethod string, err error) {
	dir, ok := x.dir(call.importPath)
	if !ok {
		return "", "", fmt.Errorf("%s is not pinned in go.mod", call.importPath)
	}
	file := filepath.Join(dir, "client.go")
	if call.client != "Client" {
		file = filepath.Join(dir, strings.ToLower(strings.TrimSuffix(call.client, "Client"))+"_client.go")
	}
	src, err := x.read(file)
	if err != nil {
		return "", "", fmt.Errorf("%w (is the module cache populated? `go mod download` in the provider)", err)
	}
	op := strings.TrimSuffix(strings.TrimPrefix(call.method, "New"), "Pager")
	fn := strings.ToLower(op[:1]) + op[1:] + "CreateRequest"
	re := regexp.MustCompile(`(?s)func \(client \*` + regexp.QuoteMeta(call.client) + `\) ` + regexp.QuoteMeta(fn) + `\(.*?\n\}`)
	body := re.Find(src)
	if body == nil {
		return "", "", fmt.Errorf("no %s on %s in %s", fn, call.client, filepath.Base(file))
	}
	u := regexp.MustCompile(`urlPath := "([^"]+)"`).FindSubmatch(body)
	h := regexp.MustCompile(`http\.Method(\w+)`).FindSubmatch(body)
	if u == nil || h == nil {
		return "", "", fmt.Errorf("%s on %s builds no URL path", fn, call.client)
	}
	return string(u[1]), strings.ToUpper(string(h[1])), nil
}

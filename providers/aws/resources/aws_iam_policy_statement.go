// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/resources/awspolicy"
	"go.mondoo.com/mql/types"
)

// newPolicyStatementResources parses an IAM-grammar policy document (an IAM
// policy, role trust policy, or any resource-based policy) into a slice of
// aws.iam.policyStatement resources. The document may be a plain JSON string
// or, as the IAM API returns policy and trust documents, URL-encoded JSON.
// parentID is used to build a stable, synthetic __id for each statement.
func newPolicyStatementResources(runtime *plugin.Runtime, parentID string, policyJSON string) ([]any, error) {
	if strings.TrimSpace(policyJSON) == "" {
		return []any{}, nil
	}

	policy, err := parsePolicyStatements(policyJSON)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(policy.Statements))
	for i := range policy.Statements {
		stmt := policy.Statements[i]

		var conditions any
		if len(stmt.Condition) > 0 {
			if err := json.Unmarshal(stmt.Condition, &conditions); err != nil {
				return nil, err
			}
		}

		mqlStatement, err := CreateResource(runtime, ResourceAwsIamPolicyStatement,
			map[string]*llx.RawData{
				"__id":          llx.StringData(fmt.Sprintf("%s/statement/%d", parentID, i)),
				"sid":           llx.StringData(stmt.Sid),
				"effect":        llx.StringData(stmt.Effect),
				"actions":       llx.ArrayData(convert.SliceAnyToInterface(stmt.Action.Value()), types.String),
				"notActions":    llx.ArrayData(convert.SliceAnyToInterface(stmt.NotAction.Value()), types.String),
				"resources":     llx.ArrayData(convert.SliceAnyToInterface(stmt.Resource.Value()), types.String),
				"notResources":  llx.ArrayData(convert.SliceAnyToInterface(stmt.NotResource.Value()), types.String),
				"principals":    llx.MapData(stringSliceMapToAny(stmt.Principal.Data()), types.Array(types.String)),
				"notPrincipals": llx.MapData(stringSliceMapToAny(stmt.NotPrincipal.Data()), types.Array(types.String)),
				"conditions":    llx.DictData(conditions),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlStatement)
	}
	return res, nil
}

// parsePolicyStatements unmarshals a policy document into the shared
// S3BucketPolicy shape, which preserves the full principal map and the Not*
// elements across every AWS policy grammar. It first tries the raw bytes and
// falls back to URL-decoding, since IAM policy and role trust documents are
// returned URL-encoded while resource-based policies are not.
func parsePolicyStatements(policyJSON string) (*awspolicy.S3BucketPolicy, error) {
	var policy awspolicy.S3BucketPolicy
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		decoded, decodeErr := url.QueryUnescape(policyJSON)
		if decodeErr != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
			return nil, err
		}
	}
	return &policy, nil
}

// policyStatementsFromString parses a resource policy held as a raw JSON
// string field (e.g. an EFS file system policy or VPC endpoint policy).
func policyStatementsFromString(runtime *plugin.Runtime, parentID string, doc *plugin.TValue[string]) ([]any, error) {
	if doc.Error != nil {
		return nil, doc.Error
	}
	return newPolicyStatementResources(runtime, parentID, doc.Data)
}

// policyStatementsFromDict parses a resource policy held as a parsed dict
// field (e.g. an SNS topic or SQS queue policy). The dict is round-tripped
// back to JSON, which is loss-free because these policies are stored as the
// faithful raw document rather than a reduced shape.
func policyStatementsFromDict(runtime *plugin.Runtime, parentID string, doc *plugin.TValue[any]) ([]any, error) {
	if doc.Error != nil {
		return nil, doc.Error
	}
	if doc.Data == nil {
		return []any{}, nil
	}
	raw, err := json.Marshal(doc.Data)
	if err != nil {
		return nil, err
	}
	return newPolicyStatementResources(runtime, parentID, string(raw))
}

func (a *mqlAwsIamPolicy) statements() ([]any, error) {
	defaultVersion, err := a.defaultVersion()
	if err != nil {
		return nil, err
	}
	return defaultVersion.statements()
}

// anyWildcardResource reports whether any element covers a service's whole
// resource namespace — the global `*`, or an ARN whose resource part is a bare
// wildcard such as `arn:aws:s3:::*`, which names every bucket in the account.
// This is the same `:*` test anyWildcardAction applies to actions.
//
// A path wildcard under a named resource (`arn:aws:s3:::my-bucket/*`, every
// object in one bucket) is scoped to that resource and deliberately does not
// match — it is what a correctly written bucket policy looks like.
func anyWildcardResource(resources []any) bool {
	for _, r := range resources {
		s, ok := r.(string)
		if !ok {
			continue
		}
		if s == "*" || strings.HasSuffix(s, ":*") {
			return true
		}
	}
	return false
}

// anyWildcardAction reports whether any element grants service-wide or global
// access — the global `*` action or a service-wide wildcard such as `s3:*`.
func anyWildcardAction(actions []any) bool {
	for _, raw := range actions {
		s, ok := raw.(string)
		if !ok {
			continue
		}
		if s == "*" || strings.HasSuffix(s, ":*") {
			return true
		}
	}
	return false
}

// hasWildcardResource reports whether the statement applies to every resource:
// through a wildcard in Resource, or through any NotResource at all.
//
// NotResource inverts the set. `{"Effect":"Allow","NotResource":["arn:...:my-secret"]}`
// applies to every resource except the one named, which is broader than any
// wildcard the statement could have written out, so the exclusion list only has
// to be non-empty. hasPublicPrincipal reads NotPrincipal the same way.
func (a *mqlAwsIamPolicyStatement) hasWildcardResource() (bool, error) {
	notResources := a.GetNotResources()
	if notResources.Error != nil {
		return false, notResources.Error
	}
	if len(notResources.Data) > 0 {
		return true, nil
	}

	resources := a.GetResources()
	if resources.Error != nil {
		return false, resources.Error
	}
	return anyWildcardResource(resources.Data), nil
}

// hasWildcardAction reports whether the statement grants service-wide or global
// access: the global `*` action, a service-wide wildcard such as `s3:*`, or any
// NotAction at all.
//
// NotAction inverts the set the same way NotResource does.
// `{"Effect":"Allow","NotAction":["iam:*"]}` grants every action in AWS except
// the IAM ones, which is near-administrator and read as no wildcard at all
// while only Action was consulted.
func (a *mqlAwsIamPolicyStatement) hasWildcardAction() (bool, error) {
	notActions := a.GetNotActions()
	if notActions.Error != nil {
		return false, notActions.Error
	}
	if len(notActions.Data) > 0 {
		return true, nil
	}

	actions := a.GetActions()
	if actions.Error != nil {
		return false, actions.Error
	}
	return anyWildcardAction(actions.Data), nil
}

// hasWildcardAllow reports whether any Allow statement in the policy default
// version grants wildcard access through its actions or resources.
func (a *mqlAwsIamPolicy) hasWildcardAllow() (bool, error) {
	statements, err := a.statements()
	if err != nil {
		return false, err
	}
	return statementsAllowWildcard(statements)
}

// statementsAllowWildcard reports whether any Allow statement in the set grants
// wildcard access through its actions or resources.
func statementsAllowWildcard(statements []any) (bool, error) {
	for _, raw := range statements {
		stmt, ok := raw.(*mqlAwsIamPolicyStatement)
		if !ok {
			continue
		}
		effect := stmt.GetEffect()
		if effect.Error != nil {
			return false, effect.Error
		}
		if !strings.EqualFold(effect.Data, "Allow") {
			continue
		}
		hasRes, err := stmt.hasWildcardResource()
		if err != nil {
			return false, err
		}
		hasAct, err := stmt.hasWildcardAction()
		if err != nil {
			return false, err
		}
		if hasRes || hasAct {
			return true, nil
		}
	}
	return false, nil
}

func (a *mqlAwsIamPolicyversion) statements() ([]any, error) {
	rawDoc, err := a.rawDocument()
	if err != nil {
		return nil, err
	}
	parentID := a.Arn.Data + "/" + a.VersionId.Data
	return newPolicyStatementResources(a.MqlRuntime, parentID, rawDoc)
}

func (a *mqlAwsIamRole) assumeRolePolicyStatements() ([]any, error) {
	doc := a.GetAssumeRolePolicyDocument()
	if doc.Error != nil {
		return nil, doc.Error
	}
	if doc.Data == nil {
		return []any{}, nil
	}
	raw, err := json.Marshal(doc.Data)
	if err != nil {
		return nil, err
	}
	return newPolicyStatementResources(a.MqlRuntime, a.Arn.Data+"/trust", string(raw))
}

func (a *mqlAwsKmsKey) policyStatements() ([]any, error) {
	policy := a.GetPolicy()
	if policy.Error != nil {
		return nil, policy.Error
	}
	// A key policy AWS refused to disclose reads null, and its statements are
	// unknown with it. Parsing the empty string would produce an empty
	// statement list, which statementsAllowPublic answers "not public" for.
	if policy.IsNull() {
		a.PolicyStatements.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newPolicyStatementResources(a.MqlRuntime, a.Arn.Data, policy.Data)
}

func (a *mqlAwsVpcEndpoint) policyStatements() ([]any, error) {
	return policyStatementsFromString(a.MqlRuntime, a.Id.Data, a.GetPolicyDocument())
}

func (a *mqlAwsEfsFilesystem) policyStatements() ([]any, error) {
	return policyStatementsFromString(a.MqlRuntime, a.Arn.Data, a.GetFileSystemPolicy())
}

func (a *mqlAwsSnsTopic) policyStatements() ([]any, error) {
	return policyStatementsFromDict(a.MqlRuntime, a.Arn.Data, a.GetPolicy())
}

func (a *mqlAwsSqsQueue) policyStatements() ([]any, error) {
	// aws.sqs.queue.arn is a computed field; reading a.Arn.Data directly yields
	// "" unless something already resolved it, which made every queue's
	// statements share the cache key "/statement/N".
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	return policyStatementsFromDict(a.MqlRuntime, arn.Data, a.GetPolicy())
}

func (a *mqlAwsEcrRepository) policyStatements() ([]any, error) {
	// GetPolicy has to run first: it is what decides whether the policy was
	// read at all, and policyUnreadable is only meaningful afterwards.
	policy := a.GetPolicy()
	if a.policyUnreadable {
		// An empty statement list is an assertion that the policy grants
		// nothing. A policy the scan could not read supports no such claim.
		a.PolicyStatements.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return policyStatementsFromDict(a.MqlRuntime, a.Arn.Data, policy)
}

func (a *mqlAwsLambdaFunction) policyStatements() ([]any, error) {
	return policyStatementsFromDict(a.MqlRuntime, a.Arn.Data, a.GetPolicy())
}

func (a *mqlAwsSecretsmanagerSecret) policyStatements() ([]any, error) {
	return policyStatementsFromString(a.MqlRuntime, a.Arn.Data, a.GetResourcePolicy())
}

func (a *mqlAwsS3Bucket) policyStatements() ([]any, error) {
	policy := a.GetPolicy()
	if policy.Error != nil {
		return nil, policy.Error
	}
	if policy.Data == nil {
		return []any{}, nil
	}
	return policyStatementsFromString(a.MqlRuntime, a.Name.Data, policy.Data.GetDocument())
}

// hasPublicPrincipal reports whether an Allow statement grants access to a
// wildcard principal ("*"). It is a structural predicate — it does not evaluate
// conditions — mirroring hasWildcardAction and hasWildcardResource. Callers that
// need "effectively public" should also check that conditions do not scope the
// grant (see statementsAllowPublic / the resource-level isPublic fields).
func (a *mqlAwsIamPolicyStatement) hasPublicPrincipal() (bool, error) {
	effect := a.GetEffect()
	if effect.Error != nil {
		return false, effect.Error
	}
	if !strings.EqualFold(effect.Data, "Allow") {
		return false, nil
	}
	// An Allow with NotPrincipal grants everyone *except* the listed principals,
	// so it is public by construction. Only Principal was consulted before, so
	// `{"Effect":"Allow","NotPrincipal":{...}}` on a bucket read as not-public.
	notPrincipals := a.GetNotPrincipals()
	if notPrincipals.Error != nil {
		return false, notPrincipals.Error
	}
	if len(notPrincipals.Data) > 0 {
		return true, nil
	}

	principals := a.GetPrincipals()
	if principals.Error != nil {
		return false, principals.Error
	}
	return hasWildcardPrincipal(principals.Data), nil
}

// statementsAllowPublic reports whether any statement grants a wildcard
// principal access that is not scoped by a condition on aws:SourceArn,
// aws:SourceAccount, or aws:PrincipalOrgID. It shares hasWildcardPrincipal and
// hasSourceScopingCondition with aws.lambda.function.allowsPublicAccess so the
// two predicates cannot disagree; conditions that don't scope the principal
// (for example aws:RequestedRegion) do not make a public grant private.
func statementsAllowPublic(statements []any) (bool, error) {
	for _, s := range statements {
		stmt, ok := s.(*mqlAwsIamPolicyStatement)
		if !ok {
			continue
		}
		public, err := stmt.hasPublicPrincipal()
		if err != nil {
			return false, err
		}
		if !public {
			continue
		}
		conditions := stmt.GetConditions()
		if conditions.Error != nil {
			return false, conditions.Error
		}
		if !hasSourceScopingCondition(conditions.Data) {
			return true, nil
		}
	}
	return false, nil
}

// resourceIsPublic is shared by the resource-level isPublic fields: a resource
// is public when its policy contains a statement that grants to a wildcard
// principal without a source-scoping condition.
func resourceIsPublic(statements *plugin.TValue[[]any]) (bool, error) {
	if statements.Error != nil {
		return false, statements.Error
	}
	return statementsAllowPublic(statements.Data)
}

// resourceIsPublicOrUnknown is resourceIsPublic for a resource whose policy
// read can be refused. A null statement list means the policy could not be
// read, and "we were not allowed to look" must not be published as "not
// public": the isPublic field is marked null instead.
//
// A statement list that was read and is merely empty still answers false. The
// distinction is three-way, and collapsing the first case into the second is
// how a denied read became a confident isPublic:false.
//
// Not every caller is migrated yet. resourceIsPublic above still collapses an
// unread policy into false for sns.topic, sqs.queue, lambda.function,
// s3.bucket, secretsmanager.secret, backup.vault, es.domain, opensearch.domain,
// apigatewayv2.route, sagemaker.modelPackageGroup, the bedrock resources and
// the snapshot resources. Those are the same defect and want the same helper;
// each needs its policy accessor to null a denied read first, or the null never
// reaches here.
func resourceIsPublicOrUnknown(statements *plugin.TValue[[]any], field *plugin.TValue[bool]) (bool, error) {
	if statements.Error != nil {
		return false, statements.Error
	}
	if statements.IsNull() {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return statementsAllowPublic(statements.Data)
}

func (a *mqlAwsKmsKey) isPublic() (bool, error) {
	return resourceIsPublicOrUnknown(a.GetPolicyStatements(), &a.IsPublic)
}

func (a *mqlAwsSnsTopic) isPublic() (bool, error) {
	return resourceIsPublic(a.GetPolicyStatements())
}

func (a *mqlAwsSqsQueue) isPublic() (bool, error) {
	return resourceIsPublic(a.GetPolicyStatements())
}

func (a *mqlAwsEcrRepository) isPublic() (bool, error) {
	return resourceIsPublicOrUnknown(a.GetPolicyStatements(), &a.IsPublic)
}

// isPublic reports whether the function is exposed publicly — either its
// resource policy grants a wildcard principal, or it has a Function URL whose
// auth type is NONE (unauthenticated invocation over the internet).
func (a *mqlAwsLambdaFunction) isPublic() (bool, error) {
	policyPublic, err := resourceIsPublic(a.GetPolicyStatements())
	if err != nil {
		return false, err
	}
	if policyPublic {
		return true, nil
	}

	url := a.GetUrlConfig()
	if url.Error != nil {
		return false, url.Error
	}
	if url.Data == nil {
		return false, nil
	}
	authType := url.Data.GetAuthType()
	if authType.Error != nil {
		return false, authType.Error
	}
	return functionUrlIsPublic(authType.Data), nil
}

// functionUrlIsPublic reports whether a Lambda Function URL auth type permits
// unauthenticated public invocation. AWS_IAM requires a signed request; NONE
// allows anyone on the internet.
func functionUrlIsPublic(authType string) bool {
	return strings.EqualFold(authType, "NONE")
}

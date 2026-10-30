// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

const (
	inlinePolicyEntityUser  = "user"
	inlinePolicyEntityGroup = "group"
	inlinePolicyEntityRole  = "role"
)

// decodeIamPolicyDocument turns an IAM policy document into a parsed map. IAM
// returns policy and trust documents URL-encoded, so the raw bytes are tried
// first and a URL-decoded pass follows. A document that parses as neither
// yields a nil map rather than an error, matching how the API treats a missing
// document.
func decodeIamPolicyDocument(document *string) map[string]any {
	if document == nil {
		return nil
	}
	parsed, err := parseIamPolicyDocument(*document)
	if err != nil {
		return nil
	}
	return parsed
}

// parseIamPolicyDocument decodes an IAM policy or trust document to its parsed
// JSON form, reporting why a document could not be read. Callers that treat an
// unreadable document the way the API treats a missing one use
// decodeIamPolicyDocument instead.
func parseIamPolicyDocument(raw string) (map[string]any, error) {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
		return parsed, nil
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(decoded), &parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

// newInlinePolicyResource builds an aws.iam.inlinePolicy for one embedded
// policy. The entity ARN keys the cache entry, since an inline policy name is
// only unique within the principal it is embedded in.
func newInlinePolicyResource(runtime *plugin.Runtime, entityType, entityName, entityArn, policyName string, document *string) (plugin.Resource, error) {
	return CreateResource(runtime, ResourceAwsIamInlinePolicy,
		map[string]*llx.RawData{
			"__id":       llx.StringData(entityArn + "/inlinePolicy/" + policyName),
			"name":       llx.StringData(policyName),
			"entityType": llx.StringData(entityType),
			"entityName": llx.StringData(entityName),
			"document":   llx.MapData(decodeIamPolicyDocument(document), types.Any),
		})
}

// inlinePolicyResources resolves a list of inline policy names to
// aws.iam.inlinePolicy resources, fetching each document through getDocument.
// A single policy the caller cannot read is logged and skipped so one denied
// document does not fail the whole principal, but any other error is returned
// rather than silently reducing the list.
func inlinePolicyResources(runtime *plugin.Runtime, entityType, entityName, entityArn string, policyNames []string, getDocument func(policyName string) (*string, error)) ([]any, error) {
	res := make([]any, 0, len(policyNames))
	for _, policyName := range policyNames {
		document, err := getDocument(policyName)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str(entityType, entityName).Str("policy", policyName).
					Msg("no permission to read inline policy document")
				continue
			}
			return nil, err
		}
		mqlPolicy, err := newInlinePolicyResource(runtime, entityType, entityName, entityArn, policyName, document)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}
	return res, nil
}

// listRoleInlinePolicyNames returns the names of the policies embedded in a role.
func listRoleInlinePolicyNames(ctx context.Context, svc *iam.Client, roleName string) ([]string, error) {
	res := []string{}
	paginator := iam.NewListRolePoliciesPaginator(svc, &iam.ListRolePoliciesInput{RoleName: &roleName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		res = append(res, page.PolicyNames...)
	}
	return res, nil
}

// listUserInlinePolicyNames returns the names of the policies embedded in a user.
func listUserInlinePolicyNames(ctx context.Context, svc *iam.Client, userName string) ([]string, error) {
	res := []string{}
	paginator := iam.NewListUserPoliciesPaginator(svc, &iam.ListUserPoliciesInput{UserName: &userName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		res = append(res, page.PolicyNames...)
	}
	return res, nil
}

// listGroupInlinePolicyNames returns the names of the policies embedded in a group.
func listGroupInlinePolicyNames(ctx context.Context, svc *iam.Client, groupName string) ([]string, error) {
	res := []string{}
	paginator := iam.NewListGroupPoliciesPaginator(svc, &iam.ListGroupPoliciesInput{GroupName: &groupName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		res = append(res, page.PolicyNames...)
	}
	return res, nil
}

func (a *mqlAwsIamRole) inlinePolicyDetails() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Iam("")
	ctx := context.Background()

	roleName := a.Name.Data
	policyNames, err := listRoleInlinePolicyNames(ctx, svc, roleName)
	if err != nil {
		return nil, err
	}

	return inlinePolicyResources(a.MqlRuntime, inlinePolicyEntityRole, roleName, a.Arn.Data, policyNames,
		func(policyName string) (*string, error) {
			policy, err := svc.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
				RoleName:   &roleName,
				PolicyName: &policyName,
			})
			if err != nil {
				return nil, err
			}
			return policy.PolicyDocument, nil
		})
}

func (a *mqlAwsIamUser) inlinePolicyDetails() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Iam("")
	ctx := context.Background()

	userName := a.Name.Data
	policyNames, err := listUserInlinePolicyNames(ctx, svc, userName)
	if err != nil {
		return nil, err
	}

	return inlinePolicyResources(a.MqlRuntime, inlinePolicyEntityUser, userName, a.Arn.Data, policyNames,
		func(policyName string) (*string, error) {
			policy, err := svc.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
				UserName:   &userName,
				PolicyName: &policyName,
			})
			if err != nil {
				return nil, err
			}
			return policy.PolicyDocument, nil
		})
}

func (a *mqlAwsIamGroup) inlinePolicyDetails() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Iam("")
	ctx := context.Background()

	groupName := a.Name.Data
	policyNames, err := listGroupInlinePolicyNames(ctx, svc, groupName)
	if err != nil {
		return nil, err
	}

	return inlinePolicyResources(a.MqlRuntime, inlinePolicyEntityGroup, groupName, a.Arn.Data, policyNames,
		func(policyName string) (*string, error) {
			policy, err := svc.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{
				GroupName:  &groupName,
				PolicyName: &policyName,
			})
			if err != nil {
				return nil, err
			}
			return policy.PolicyDocument, nil
		})
}

// statements parses the inline policy document into individual statements.
func (a *mqlAwsIamInlinePolicy) statements() ([]any, error) {
	return policyStatementsFromDict(a.MqlRuntime, a.MqlID(), a.GetDocument())
}

// hasWildcardAllow reports whether any Allow statement in the inline policy
// grants wildcard access through its actions or resources.
func (a *mqlAwsIamInlinePolicy) hasWildcardAllow() (bool, error) {
	statements := a.GetStatements()
	if statements.Error != nil {
		return false, statements.Error
	}
	return statementsAllowWildcard(statements.Data)
}

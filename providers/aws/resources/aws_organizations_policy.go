// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
)

// isPolicyTypeUnavailable reports whether the error means the policy type is
// simply not in play for this organization, rather than a failure. Organizations
// rejects a list or describe call for a policy type that has not been enabled,
// and every type has to be enabled explicitly, so this is the common case rather
// than an edge case.
//
// A standalone account is not this: it has no organization at all, which makes
// the question not applicable (classifyAwsError).
func isPolicyTypeUnavailable(err error) bool {
	var notEnabled *orgtypes.PolicyTypeNotEnabledException
	var notAvailable *orgtypes.PolicyTypeNotAvailableForOrganizationException
	return errors.As(err, &notEnabled) || errors.As(err, &notAvailable)
}

func newOrganizationPolicyResource(runtime *plugin.Runtime, policy orgtypes.PolicySummary) (plugin.Resource, error) {
	return CreateResource(runtime, ResourceAwsOrganizationPolicy,
		map[string]*llx.RawData{
			"__id":        llx.StringDataPtr(policy.Id),
			"id":          llx.StringDataPtr(policy.Id),
			"arn":         llx.StringDataPtr(policy.Arn),
			"name":        llx.StringDataPtr(policy.Name),
			"description": llx.StringDataPtr(policy.Description),
			"type":        llx.StringData(string(policy.Type)),
			"awsManaged":  llx.BoolData(policy.AwsManaged),
		})
}

// listOrganizationPolicies lists the organization's policies of every type
// known to the SDK. Reading the types off the enum rather than a hand-written
// list means a policy type AWS adds later is picked up with the next SDK bump.
// An empty targetId lists every policy in the organization; otherwise only the
// policies attached directly to that root, organizational unit, or account.
func listOrganizationPolicies(ctx context.Context, runtime *plugin.Runtime, client *organizations.Client, targetId string) ([]any, error) {
	res := []any{}
	for _, policyType := range orgtypes.PolicyType("").Values() {
		policies, err := listOrganizationPoliciesOfType(ctx, runtime, client, targetId, policyType)
		if err != nil {
			return nil, err
		}
		res = append(res, policies...)
	}
	return res, nil
}

func listOrganizationPoliciesOfType(ctx context.Context, runtime *plugin.Runtime, client *organizations.Client, targetId string, policyType orgtypes.PolicyType) ([]any, error) {
	var hasMorePages func() bool
	var nextPage func(context.Context) ([]orgtypes.PolicySummary, error)
	permission := "organizations:ListPoliciesForTarget"

	if targetId == "" {
		permission = "organizations:ListPolicies"
		paginator := organizations.NewListPoliciesPaginator(client, &organizations.ListPoliciesInput{
			Filter: policyType,
		})
		hasMorePages = paginator.HasMorePages
		nextPage = func(ctx context.Context) ([]orgtypes.PolicySummary, error) {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			return page.Policies, nil
		}
	} else {
		paginator := organizations.NewListPoliciesForTargetPaginator(client, &organizations.ListPoliciesForTargetInput{
			TargetId: &targetId,
			Filter:   policyType,
		})
		hasMorePages = paginator.HasMorePages
		nextPage = func(ctx context.Context) ([]orgtypes.PolicySummary, error) {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			return page.Policies, nil
		}
	}

	res := []any{}
	for hasMorePages() {
		policies, err := nextPage(ctx)
		if err != nil {
			if isPolicyTypeUnavailable(err) || Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, classifyAwsError(err, permission)
		}
		for i := range policies {
			mqlPolicy, err := newOrganizationPolicyResource(runtime, policies[i])
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPolicy)
		}
	}
	return res, nil
}

// describePolicyContent returns the raw content document of one policy.
func describePolicyContent(ctx context.Context, client *organizations.Client, policyId string) (string, error) {
	resp, err := client.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: &policyId})
	if err != nil {
		return "", classifyAwsError(err, "organizations:DescribePolicy")
	}
	if resp.Policy == nil || resp.Policy.Content == nil {
		return "", nil
	}
	return *resp.Policy.Content, nil
}

func (a *mqlAwsOrganization) policies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return listOrganizationPolicies(context.Background(), a.MqlRuntime, conn.Organizations(""), "")
}

func (a *mqlAwsOrganizationOrganizationalUnit) policies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return listOrganizationPolicies(context.Background(), a.MqlRuntime, conn.Organizations(""), a.Id.Data)
}

func (a *mqlAwsAccount) policies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return listOrganizationPolicies(context.Background(), a.MqlRuntime, conn.Organizations(""), a.Id.Data)
}

func (a *mqlAwsOrganizationPolicy) content() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return describePolicyContent(context.Background(), conn.Organizations(""), a.Id.Data)
}

// statements parses the policy content for the types written in the IAM policy
// grammar. The remaining types carry their own document formats, which the IAM
// statement parser would silently misread, so they resolve to no statements.
func (a *mqlAwsOrganizationPolicy) statements() ([]any, error) {
	if !policyTypeUsesIamGrammar(orgtypes.PolicyType(a.Type.Data)) {
		return []any{}, nil
	}
	return policyStatementsFromString(a.MqlRuntime, a.Arn.Data, a.GetContent())
}

// policyTypeUsesIamGrammar reports whether an organization policy type is
// written in the IAM policy grammar of Statement/Effect/Action/Resource.
func policyTypeUsesIamGrammar(policyType orgtypes.PolicyType) bool {
	switch policyType {
	case orgtypes.PolicyTypeServiceControlPolicy, orgtypes.PolicyTypeResourceControlPolicy:
		return true
	}
	return false
}

// isEffectivePolicyAbsent reports whether the error means no effective policy of
// that type applies to the target, which is an ordinary answer rather than a
// failure.
func isEffectivePolicyAbsent(err error) bool {
	var notFound *orgtypes.EffectivePolicyNotFoundException
	return errors.As(err, &notFound) || isPolicyTypeUnavailable(err)
}

func (a *mqlAwsAccount) effectivePolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Organizations("")
	ctx := context.Background()
	accountId := a.Id.Data

	res := []any{}
	// Organizations computes an effective policy for the management policy types
	// only; service and resource control policies are absent from this enum
	// because AWS does not expose their combined effect.
	for _, policyType := range orgtypes.EffectivePolicyType("").Values() {
		resp, err := client.DescribeEffectivePolicy(ctx, &organizations.DescribeEffectivePolicyInput{
			PolicyType: policyType,
			TargetId:   &accountId,
		})
		if err != nil {
			if isEffectivePolicyAbsent(err) || Is400AccessDeniedError(err) {
				continue
			}
			return nil, classifyAwsError(err, "organizations:DescribeEffectivePolicy")
		}
		if resp.EffectivePolicy == nil {
			continue
		}

		mqlPolicy, err := CreateResource(a.MqlRuntime, ResourceAwsOrganizationEffectivePolicy,
			map[string]*llx.RawData{
				"__id":          llx.StringData(accountId + "/effectivePolicy/" + string(policyType)),
				"type":          llx.StringData(string(policyType)),
				"content":       llx.StringDataPtr(resp.EffectivePolicy.PolicyContent),
				"lastUpdatedAt": llx.TimeDataPtr(resp.EffectivePolicy.LastUpdatedTimestamp),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}
	return res, nil
}

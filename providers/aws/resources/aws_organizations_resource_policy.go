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

// isResourcePolicyAbsent reports whether the error means the organization has
// no resource-based delegation policy. That is the ordinary state for an
// organization administered entirely from its management account, and it is
// also the non-compliant answer an audit is looking for, so it has to reach
// the caller as absence rather than as a failed read.
func isResourcePolicyAbsent(err error) bool {
	var notFound *orgtypes.ResourcePolicyNotFoundException
	return errors.As(err, &notFound) || isPolicyTypeUnavailable(err)
}

func (a *mqlAwsOrganization) resourcePolicy() (*mqlAwsOrganizationResourcePolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	client := conn.Organizations("")

	resp, err := client.DescribeResourcePolicy(context.Background(), &organizations.DescribeResourcePolicyInput{})
	if err != nil {
		// A member account that is not a delegated administrator cannot read
		// this, which is a permissions answer rather than "no policy exists".
		// Both resolve to null so a check can be written once, but only the
		// absent case is a statement about the organization.
		if isResourcePolicyAbsent(err) || Is400AccessDeniedError(err) {
			a.ResourcePolicy.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if resp == nil || resp.ResourcePolicy == nil {
		a.ResourcePolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	policy := resp.ResourcePolicy
	var id, arn *string
	if policy.ResourcePolicySummary != nil {
		id = policy.ResourcePolicySummary.Id
		arn = policy.ResourcePolicySummary.Arn
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAwsOrganizationResourcePolicy,
		map[string]*llx.RawData{
			"__id":    llx.StringData(a.Id.Data + "/resourcePolicy"),
			"id":      llx.StringDataPtr(id),
			"arn":     llx.StringDataPtr(arn),
			"content": llx.StringDataPtr(policy.Content),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsOrganizationResourcePolicy), nil
}

// statements parses the delegation policy, which is written in the IAM policy
// grammar, so the principals and actions it grants are readable directly.
func (a *mqlAwsOrganizationResourcePolicy) statements() ([]any, error) {
	return policyStatementsFromString(a.MqlRuntime, a.Arn.Data, a.GetContent())
}

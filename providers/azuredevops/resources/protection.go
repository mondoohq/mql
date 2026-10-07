// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/types"
)

// mqlAzuredevopsBranchInternal ties a branch to its repository, whose
// policies and permissions decide its protection.
type mqlAzuredevopsBranchInternal struct {
	repo *mqlAzuredevopsRepository
}

// enforcedPolicies is the enabled, blocking policies that apply to the branch.
// A failed read of the policies is returned as the client reported it; the
// callers classify a 403.
func (b *mqlAzuredevopsBranch) enforcedPolicies() ([]connection.PolicyConfiguration, error) {
	all, err := b.repo.projectPolicies()
	if err != nil {
		return nil, err
	}
	var out []connection.PolicyConfiguration
	for _, p := range all {
		if p.Enforced() && p.Covers(b.repo.Id.Data, b.RefName.Data, b.repo.DefaultBranch.Data) {
			out = append(out, p)
		}
	}
	return out, nil
}

func (b *mqlAzuredevopsBranch) isProtected() (bool, error) {
	enforced, err := b.enforcedPolicies()
	if err != nil {
		return false, classifyForbidden(err)
	}
	return len(enforced) > 0, nil
}

// protection is what the enforced policies of a branch require.
type protection struct {
	reviewCount     int64
	codeOwners      bool
	commentsResolve bool
	statusChecks    bool
}

// summarize folds the enforced policies of a branch into one protection. The
// review count is the highest one, since every policy must pass.
func summarize(enforced []connection.PolicyConfiguration) protection {
	var out protection
	for _, p := range enforced {
		switch strings.ToLower(p.Type.ID) {
		case connection.PolicyTypeMinimumReviewers:
			if n, ok := p.Settings.All["minimumApproverCount"].(float64); ok && int64(n) > out.reviewCount {
				out.reviewCount = int64(n)
			}
		case connection.PolicyTypeRequiredReviewers:
			out.codeOwners = true
		case connection.PolicyTypeCommentResolution:
			out.commentsResolve = true
		case connection.PolicyTypeBuild, connection.PolicyTypeStatus:
			out.statusChecks = true
		}
	}
	return out
}

func (b *mqlAzuredevopsBranch) protectionRules() (*mqlAzuredevopsBranchProtection, error) {
	enforced, err := b.enforcedPolicies()
	if err != nil {
		return nil, classifyForbidden(err)
	}
	policies := make([]any, 0, len(enforced))
	for _, p := range enforced {
		res, err := newPolicy(b.repo, p)
		if err != nil {
			return nil, err
		}
		policies = append(policies, res)
	}
	sum := summarize(enforced)
	res, err := CreateResource(b.MqlRuntime, "azuredevops.branchProtection", map[string]*llx.RawData{
		"__id":                                  llx.StringData("azuredevops.branchProtection/" + b.repo.Id.Data + "/" + b.RefName.Data),
		"refName":                               llx.StringData(b.RefName.Data),
		"requiredPullRequestReviewsEnabled":     llx.BoolData(sum.reviewCount >= 1),
		"requiredApprovingReviewCount":          llx.IntData(sum.reviewCount),
		"requireCodeOwnerReviews":               llx.BoolData(sum.codeOwners),
		"requiredConversationResolutionEnabled": llx.BoolData(sum.commentsResolve),
		"requiredStatusChecksEnabled":           llx.BoolData(sum.statusChecks),
		"policies":                              llx.ArrayData(policies, types.Resource("azuredevops.policy")),
	})
	if err != nil {
		return nil, err
	}
	rules := res.(*mqlAzuredevopsBranchProtection)
	rules.repo = b.repo
	return rules, nil
}

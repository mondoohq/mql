// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"sort"

	"github.com/google/go-github/v93/github"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

// branchRulesSummary is the rules in effect on a branch, merged across the
// rulesets that apply.
type branchRulesSummary struct {
	requiresPullRequest            bool
	requiredApprovingReviewCount   int64
	requireCodeOwnerReview         bool
	dismissStaleReviewsOnPush      bool
	requireLastPushApproval        bool
	requiredReviewThreadResolution bool
	requiresStatusChecks           bool
	requiredStatusChecks           []string
	requiresSignatures             bool
	requiresLinearHistory          bool
	blocksForcePushes              bool
	blocksDeletions                bool
	restrictsUpdates               bool
	requiresDeployments            bool
	requiresCodeScanning           bool
	requiresMergeQueue             bool
	rulesetIDs                     []int64
}

// summarizeBranchRules merges the rules of every ruleset that applies: a rule
// is required when any ruleset requires it, and the approval count is the
// highest one.
func summarizeBranchRules(r *github.BranchRules) branchRulesSummary {
	var s branchRulesSummary
	if r == nil {
		return s
	}
	ids := map[int64]bool{}
	note := func(m github.BranchRuleMetadata) {
		if m.RulesetID != 0 {
			ids[m.RulesetID] = true
		}
	}
	for _, x := range r.PullRequest {
		note(x.BranchRuleMetadata)
		s.requiresPullRequest = true
		p := x.Parameters
		if int64(p.RequiredApprovingReviewCount) > s.requiredApprovingReviewCount {
			s.requiredApprovingReviewCount = int64(p.RequiredApprovingReviewCount)
		}
		s.requireCodeOwnerReview = s.requireCodeOwnerReview || p.RequireCodeOwnerReview
		s.dismissStaleReviewsOnPush = s.dismissStaleReviewsOnPush || p.DismissStaleReviewsOnPush
		s.requireLastPushApproval = s.requireLastPushApproval || p.RequireLastPushApproval
		s.requiredReviewThreadResolution = s.requiredReviewThreadResolution || p.RequiredReviewThreadResolution
	}
	checks := map[string]bool{}
	for _, x := range r.RequiredStatusChecks {
		note(x.BranchRuleMetadata)
		s.requiresStatusChecks = true
		for _, c := range x.Parameters.RequiredStatusChecks {
			if c != nil && c.Context != "" {
				checks[c.Context] = true
			}
		}
	}
	for c := range checks {
		s.requiredStatusChecks = append(s.requiredStatusChecks, c)
	}
	sort.Strings(s.requiredStatusChecks)
	for _, x := range r.RequiredSignatures {
		note(*x)
		s.requiresSignatures = true
	}
	for _, x := range r.RequiredLinearHistory {
		note(*x)
		s.requiresLinearHistory = true
	}
	for _, x := range r.NonFastForward {
		note(*x)
		s.blocksForcePushes = true
	}
	for _, x := range r.Deletion {
		note(*x)
		s.blocksDeletions = true
	}
	for _, x := range r.Update {
		note(x.BranchRuleMetadata)
		s.restrictsUpdates = true
	}
	for _, x := range r.RequiredDeployments {
		note(x.BranchRuleMetadata)
		s.requiresDeployments = true
	}
	for _, x := range r.CodeScanning {
		note(x.BranchRuleMetadata)
		s.requiresCodeScanning = true
	}
	for _, x := range r.MergeQueue {
		note(x.BranchRuleMetadata)
		s.requiresMergeQueue = true
	}
	for id := range ids {
		s.rulesetIDs = append(s.rulesetIDs, id)
	}
	sort.Slice(s.rulesetIDs, func(i, j int) bool { return s.rulesetIDs[i] < s.rulesetIDs[j] })
	return s
}

func (g *mqlGithubBranch) rules() (*mqlGithubBranchRules, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.RepoName.Error != nil {
		return nil, g.RepoName.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	owner := g.GetOwner()
	if owner.Error != nil {
		return nil, owner.Error
	}
	if owner.Data == nil {
		g.Rules.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	login := owner.Data.GetLogin()
	if login.Error != nil {
		return nil, login.Error
	}

	var all github.BranchRules
	opts := &github.ListOptions{PerPage: 100}
	for {
		page, resp, err := conn.Client().Repositories.ListRulesForBranch(conn.Context(), login.Data, g.RepoName.Data, g.Name.Data, opts)
		if err != nil {
			// A branch no ruleset targets has no rules.
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				break
			}
			return nil, err
		}
		if page != nil {
			appendBranchRules(&all, page)
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	s := summarizeBranchRules(&all)
	checks := make([]any, len(s.requiredStatusChecks))
	for i, c := range s.requiredStatusChecks {
		checks[i] = c
	}
	ids := make([]any, len(s.rulesetIDs))
	for i, id := range s.rulesetIDs {
		ids[i] = id
	}
	r, err := CreateResource(g.MqlRuntime, "github.branchRules", map[string]*llx.RawData{
		"__id":                           llx.StringData(login.Data + "/" + g.RepoName.Data + "/" + g.Name.Data + "/rules"),
		"requiresPullRequest":            llx.BoolData(s.requiresPullRequest),
		"requiredApprovingReviewCount":   llx.IntData(s.requiredApprovingReviewCount),
		"requireCodeOwnerReview":         llx.BoolData(s.requireCodeOwnerReview),
		"dismissStaleReviewsOnPush":      llx.BoolData(s.dismissStaleReviewsOnPush),
		"requireLastPushApproval":        llx.BoolData(s.requireLastPushApproval),
		"requiredReviewThreadResolution": llx.BoolData(s.requiredReviewThreadResolution),
		"requiresStatusChecks":           llx.BoolData(s.requiresStatusChecks),
		"requiredStatusChecks":           llx.ArrayData(checks, types.String),
		"requiresSignatures":             llx.BoolData(s.requiresSignatures),
		"requiresLinearHistory":          llx.BoolData(s.requiresLinearHistory),
		"blocksForcePushes":              llx.BoolData(s.blocksForcePushes),
		"blocksDeletions":                llx.BoolData(s.blocksDeletions),
		"restrictsUpdates":               llx.BoolData(s.restrictsUpdates),
		"requiresDeployments":            llx.BoolData(s.requiresDeployments),
		"requiresCodeScanning":           llx.BoolData(s.requiresCodeScanning),
		"requiresMergeQueue":             llx.BoolData(s.requiresMergeQueue),
		"rulesetIds":                     llx.ArrayData(ids, types.Int),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlGithubBranchRules), nil
}

// appendBranchRules adds one page of rules to the rules gathered so far.
func appendBranchRules(all, page *github.BranchRules) {
	all.Creation = append(all.Creation, page.Creation...)
	all.Update = append(all.Update, page.Update...)
	all.Deletion = append(all.Deletion, page.Deletion...)
	all.RequiredLinearHistory = append(all.RequiredLinearHistory, page.RequiredLinearHistory...)
	all.MergeQueue = append(all.MergeQueue, page.MergeQueue...)
	all.RequiredDeployments = append(all.RequiredDeployments, page.RequiredDeployments...)
	all.RequiredSignatures = append(all.RequiredSignatures, page.RequiredSignatures...)
	all.PullRequest = append(all.PullRequest, page.PullRequest...)
	all.RequiredStatusChecks = append(all.RequiredStatusChecks, page.RequiredStatusChecks...)
	all.NonFastForward = append(all.NonFastForward, page.NonFastForward...)
	all.CodeScanning = append(all.CodeScanning, page.CodeScanning...)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azuredevops/connection"
)

// newBranch builds the resource of one branch of a repository. The id carries
// the repository id, since two repositories can both have a main branch.
func newBranch(repo *mqlAzuredevopsRepository, ref connection.Ref) (*mqlAzuredevopsBranch, error) {
	res, err := CreateResource(repo.MqlRuntime, "azuredevops.branch", map[string]*llx.RawData{
		"__id":          llx.StringData("azuredevops.branch/" + repo.Id.Data + "/" + ref.Name),
		"name":          llx.StringData(strings.TrimPrefix(ref.Name, "refs/heads/")),
		"refName":       llx.StringData(ref.Name),
		"headCommitSha": llx.StringData(ref.ObjectID),
		"isDefault":     llx.BoolData(strings.EqualFold(ref.Name, repo.DefaultBranch.Data)),
	})
	if err != nil {
		return nil, err
	}
	branch := res.(*mqlAzuredevopsBranch)
	branch.repo = repo
	return branch, nil
}

func (r *mqlAzuredevopsRepository) branches() ([]any, error) {
	refs, err := connectionOf(r.MqlRuntime).Client().Refs(apiContext(), r.ProjectName.Data, r.Id.Data)
	if err != nil {
		return nil, classifyForbidden(err)
	}
	out := make([]any, 0, len(refs))
	for _, ref := range refs {
		b, err := newBranch(r, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

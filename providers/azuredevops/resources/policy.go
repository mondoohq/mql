// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azuredevops/connection"
	"go.mondoo.com/mql/types"
)

// newPolicy builds the resource of one policy configuration of a project.
// Policy ids are unique within a project, so the id carries the project id.
func newPolicy(repo *mqlAzuredevopsRepository, p connection.PolicyConfiguration) (*mqlAzuredevopsPolicy, error) {
	scope := make([]any, 0, len(p.Settings.Scope))
	for _, s := range p.Settings.Scope {
		scope = append(scope, map[string]any{
			"repositoryId": s.RepositoryID,
			"refName":      s.RefName,
			"matchKind":    s.MatchKind,
		})
	}
	settings := make(map[string]any, len(p.Settings.All))
	for k, v := range p.Settings.All {
		if k != "scope" {
			settings[k] = v
		}
	}
	res, err := CreateResource(repo.MqlRuntime, "azuredevops.policy", map[string]*llx.RawData{
		"__id":     llx.StringData("azuredevops.policy/" + repo.ProjectId.Data + "/" + strconv.FormatInt(p.ID, 10)),
		"id":       llx.IntData(p.ID),
		"type":     llx.StringData(p.Type.ID),
		"typeName": llx.StringData(p.Type.DisplayName),
		"enabled":  llx.BoolData(p.IsEnabled),
		"blocking": llx.BoolData(p.IsBlocking),
		"scope":    llx.ArrayData(scope, types.Dict),
		"settings": llx.DictData(settings),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzuredevopsPolicy), nil
}

// projectPolicies is every policy of the repository's project that is not
// deleted. The list is cached per project by the client.
func (r *mqlAzuredevopsRepository) projectPolicies() ([]connection.PolicyConfiguration, error) {
	all, err := connectionOf(r.MqlRuntime).Client().PolicyConfigurations(apiContext(), r.ProjectName.Data)
	if err != nil {
		return nil, err
	}
	out := make([]connection.PolicyConfiguration, 0, len(all))
	for _, p := range all {
		if !p.IsDeleted {
			out = append(out, p)
		}
	}
	return out, nil
}

func (r *mqlAzuredevopsRepository) policies() ([]any, error) {
	all, err := r.projectPolicies()
	if err != nil {
		return nil, classifyForbidden(err)
	}
	var out []any
	for _, p := range all {
		if !p.AppliesToRepository(r.Id.Data) {
			continue
		}
		res, err := newPolicy(r, p)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	if out == nil {
		out = []any{}
	}
	return out, nil
}

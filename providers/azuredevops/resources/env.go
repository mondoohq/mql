// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azuredevops/connection"
)

type mqlAzuredevopsEnvironmentInternal struct {
	projectName string
}

// environments lists the pipeline environments of the project. A project with
// none has an empty list; a credential that cannot read them gets a forbidden
// error.
func (p *mqlAzuredevopsProject) environments() ([]any, error) {
	envs, err := connectionOf(p.MqlRuntime).Client().Environments(apiContext(), p.Name.Data)
	if err != nil {
		return nil, classifyForbidden(err)
	}

	out := make([]any, 0, len(envs))
	for _, e := range envs {
		res, err := CreateResource(p.MqlRuntime, "azuredevops.environment", map[string]*llx.RawData{
			"__id":        llx.StringData("azuredevops.environment/" + p.Id.Data + "/" + strconv.FormatInt(e.ID, 10)),
			"id":          llx.IntData(e.ID),
			"name":        llx.StringData(e.Name),
			"description": llx.StringData(e.Description),
		})
		if err != nil {
			return nil, err
		}
		env := res.(*mqlAzuredevopsEnvironment)
		env.projectName = p.Name.Data
		out = append(out, env)
	}
	return out, nil
}

// protectionRules lists the checks of the environment. preventSelfReview is true
// only for an approval whose settings keep the requester from approving; any
// other check type reports false.
func (e *mqlAzuredevopsEnvironment) protectionRules() ([]any, error) {
	checks, err := connectionOf(e.MqlRuntime).Client().EnvironmentChecks(apiContext(), e.projectName, e.Id.Data)
	if err != nil {
		return nil, classifyForbidden(err)
	}

	out := make([]any, 0, len(checks))
	for _, c := range checks {
		approval := strings.EqualFold(c.Type.ID, connection.CheckTypeApproval)
		settings := c.Settings
		if settings == nil {
			settings = map[string]any{}
		}
		res, err := CreateResource(e.MqlRuntime, "azuredevops.environmentProtectionRule", map[string]*llx.RawData{
			"__id":                 llx.StringData("azuredevops.environmentProtectionRule/" + e.__id + "/" + strconv.FormatInt(c.ID, 10)),
			"id":                   llx.IntData(c.ID),
			"type":                 llx.StringData(c.Type.Name),
			"typeId":               llx.StringData(strings.ToLower(c.Type.ID)),
			"preventSelfReview":    llx.BoolData(approval && c.RequesterCannotBeApprover()),
			"minRequiredApprovers": llx.IntData(c.MinRequiredApprovers()),
			"settings":             llx.DictData(settings),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/circleci/connection"
)

// mqlCircleciProjectInternal caches values from the project's creation
// context that are needed later for lazy-loaded typed references and
// paginated sub-resource lookups, which the CircleCI API addresses by
// project slug (e.g. "gh/org/repo") rather than by the project's UUID.
type mqlCircleciProjectInternal struct {
	cacheOrgId string
	cacheSlug  string
}

// newMqlCircleciProject maps a single API project to its MQL resource.
func newMqlCircleciProject(runtime *plugin.Runtime, p *connection.Project) (plugin.Resource, error) {
	vcsInfo := map[string]any{
		"provider": p.VCSInfo.Provider,
		"vcsUrl":   p.VCSInfo.VcsURL,
	}

	res, err := CreateResource(runtime, "circleci.project", map[string]*llx.RawData{
		"__id":                       llx.StringData(p.ID),
		"id":                         llx.StringData(p.ID),
		"name":                       llx.StringData(p.Name),
		"vcsInfo":                    llx.DictData(vcsInfo),
		"defaultBranch":              llx.StringData(p.VCSInfo.DefaultBranch),
		"buildForkPrs":               llx.BoolData(p.AdvancedSettings.BuildForkPrs),
		"forksReceiveSecretEnvVars":  llx.BoolData(p.AdvancedSettings.ForksReceiveSecretEnvVars),
		"buildPrsOnly":               llx.BoolData(p.AdvancedSettings.BuildPrsOnly),
		"writeSettingsRequiresAdmin": llx.BoolData(p.AdvancedSettings.WriteSettingsRequiresAdmin),
		"disableSsh":                 llx.BoolData(p.AdvancedSettings.DisableSsh),
		"setGithubStatus":            llx.BoolData(p.AdvancedSettings.SetGithubStatus),
	})
	if err != nil {
		return nil, err
	}

	mqlProject := res.(*mqlCircleciProject)
	mqlProject.cacheOrgId = p.OrganizationID
	mqlProject.cacheSlug = p.Slug
	return mqlProject, nil
}

// organization resolves the organization that owns this project.
func (p *mqlCircleciProject) organization() (*mqlCircleciOrganization, error) {
	if p.cacheOrgId == "" {
		p.Organization.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(p.MqlRuntime, "circleci.organization", map[string]*llx.RawData{
		"id": llx.StringData(p.cacheOrgId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlCircleciOrganization), nil
}

// environmentVariables lists the environment variables defined directly on
// this project. Values are never returned by the API; maskedValue carries
// only the truncated, non-secret suffix CircleCI itself returns.
func (p *mqlCircleciProject) environmentVariables() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.CircleciConnection)
	client := conn.Client()

	var all []any
	pageToken := ""
	for {
		resp, err := client.ListProjectEnvVars(context.Background(), p.cacheSlug, pageToken)
		if err != nil {
			return nil, err
		}
		for _, v := range resp.Items {
			res, err := CreateResource(p.MqlRuntime, "circleci.project.environmentVariable", map[string]*llx.RawData{
				"__id":        llx.StringData(p.Id.Data + "/" + v.Name),
				"name":        llx.StringData(v.Name),
				"maskedValue": llx.StringData(v.Value),
			})
			if err != nil {
				return nil, err
			}
			res.(*mqlCircleciProjectEnvironmentVariable).cacheProject = p
			all = append(all, res)
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return all, nil
}

// mqlCircleciProjectEnvironmentVariableInternal caches the project this
// environment variable belongs to, so the project() typed reference resolves
// without an extra API call.
type mqlCircleciProjectEnvironmentVariableInternal struct {
	cacheProject *mqlCircleciProject
}

// project resolves the project this environment variable is defined on.
func (v *mqlCircleciProjectEnvironmentVariable) project() (*mqlCircleciProject, error) {
	if v.cacheProject == nil {
		v.Project.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return v.cacheProject, nil
}

// mqlCircleciCheckoutKeyInternal caches the project this checkout key belongs
// to, so the project() typed reference resolves without an extra API call.
type mqlCircleciCheckoutKeyInternal struct {
	cacheProject *mqlCircleciProject
}

// project resolves the project this checkout key is configured on.
func (k *mqlCircleciCheckoutKey) project() (*mqlCircleciProject, error) {
	if k.cacheProject == nil {
		k.Project.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return k.cacheProject, nil
}

// checkoutKeys lists the deploy credentials CircleCI uses to check out this
// project's source.
func (p *mqlCircleciProject) checkoutKeys() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.CircleciConnection)
	client := conn.Client()

	var all []any
	pageToken := ""
	for {
		resp, err := client.ListCheckoutKeys(context.Background(), p.cacheSlug, pageToken)
		if err != nil {
			return nil, err
		}
		for _, k := range resp.Items {
			res, err := CreateResource(p.MqlRuntime, "circleci.checkoutKey", map[string]*llx.RawData{
				"__id":        llx.StringData(k.Fingerprint),
				"fingerprint": llx.StringData(k.Fingerprint),
				"type":        llx.StringData(k.Type),
				"publicKey":   llx.StringData(k.PublicKey),
				"preferred":   llx.BoolData(k.Preferred),
				"createdAt":   llx.TimeDataPtr(parseCircleciTime(k.CreatedAt)),
			})
			if err != nil {
				return nil, err
			}
			res.(*mqlCircleciCheckoutKey).cacheProject = p
			all = append(all, res)
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return all, nil
}

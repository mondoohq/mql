// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"sync/atomic"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/circleci/connection"
	"go.mondoo.com/mql/types"
)

// mqlCircleciProjectInternal caches values from the project's creation
// context that are needed later for lazy-loaded typed references and
// paginated sub-resource lookups, which the CircleCI API addresses by
// project slug (e.g. "gh/org/repo") rather than by the project's UUID. It
// also memoizes the project's advanced settings, which come from a separate
// GET /project/{slug}/settings call made only when one of those fields is
// read.
type mqlCircleciProjectInternal struct {
	cacheOrgId string
	cacheSlug  string

	settingsLock sync.Mutex
	settingsDone atomic.Bool
	settings     *connection.AdvancedSettings
	settingsErr  error
}

// advancedSettings lazily fetches and memoizes the project's advanced
// settings from GET /project/{slug}/settings. The call fires only on the
// first read of one of the advanced-settings fields.
// advancedSettings fetches the project's advanced settings once and shares
// the result across every accessor that reads from them. The outcome is
// memoized either way: without caching the error, a project whose settings
// are unreadable costs one failing request per accessor.
func (p *mqlCircleciProject) advancedSettings() (*connection.AdvancedSettings, error) {
	if p.settingsDone.Load() {
		return p.settings, p.settingsErr
	}
	p.settingsLock.Lock()
	defer p.settingsLock.Unlock()
	if p.settingsDone.Load() {
		return p.settings, p.settingsErr
	}
	conn := p.MqlRuntime.Connection.(*connection.CircleciConnection)
	p.settings, p.settingsErr = conn.Client().GetProjectSettings(context.Background(), p.cacheSlug)
	p.settingsDone.Store(true)
	return p.settings, p.settingsErr
}

func (p *mqlCircleciProject) buildForkPrs() (bool, error) {
	s, err := p.advancedSettings()
	if err != nil {
		return false, err
	}
	if s.BuildForkPrs == nil {
		p.BuildForkPrs.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *s.BuildForkPrs, nil
}

func (p *mqlCircleciProject) forksReceiveSecretEnvVars() (bool, error) {
	s, err := p.advancedSettings()
	if err != nil {
		return false, err
	}
	if s.ForksReceiveSecretEnvVars == nil {
		p.ForksReceiveSecretEnvVars.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *s.ForksReceiveSecretEnvVars, nil
}

func (p *mqlCircleciProject) buildPrsOnly() (bool, error) {
	s, err := p.advancedSettings()
	if err != nil {
		return false, err
	}
	if s.BuildPrsOnly == nil {
		p.BuildPrsOnly.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *s.BuildPrsOnly, nil
}

func (p *mqlCircleciProject) writeSettingsRequiresAdmin() (bool, error) {
	s, err := p.advancedSettings()
	if err != nil {
		return false, err
	}
	if s.WriteSettingsRequiresAdmin == nil {
		p.WriteSettingsRequiresAdmin.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *s.WriteSettingsRequiresAdmin, nil
}

func (p *mqlCircleciProject) disableSsh() (bool, error) {
	s, err := p.advancedSettings()
	if err != nil {
		return false, err
	}
	if s.DisableSsh == nil {
		p.DisableSsh.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *s.DisableSsh, nil
}

func (p *mqlCircleciProject) setGithubStatus() (bool, error) {
	s, err := p.advancedSettings()
	if err != nil {
		return false, err
	}
	if s.SetGithubStatus == nil {
		p.SetGithubStatus.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *s.SetGithubStatus, nil
}

func (p *mqlCircleciProject) autoCancelBuilds() (bool, error) {
	s, err := p.advancedSettings()
	if err != nil {
		return false, err
	}
	if s.AutocancelBuilds == nil {
		p.AutoCancelBuilds.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *s.AutocancelBuilds, nil
}

func (p *mqlCircleciProject) prOnlyBranchOverrides() ([]any, error) {
	s, err := p.advancedSettings()
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(s.PrOnlyBranchOverrides), nil
}

// newMqlCircleciProject maps a single API project to its MQL resource.
func newMqlCircleciProject(runtime *plugin.Runtime, p *connection.Project) (plugin.Resource, error) {
	vcsInfo := map[string]any{
		"provider": p.VCSInfo.Provider,
		"vcsUrl":   p.VCSInfo.VcsURL,
	}

	res, err := CreateResource(runtime, "circleci.project", map[string]*llx.RawData{
		"__id":          llx.StringData(p.ID),
		"id":            llx.StringData(p.ID),
		"name":          llx.StringData(p.Name),
		"vcsInfo":       llx.DictData(vcsInfo),
		"defaultBranch": llx.StringData(p.VCSInfo.DefaultBranch),
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
	var walker pageWalker
	for {
		resp, err := client.ListProjectEnvVars(context.Background(), p.cacheSlug, pageToken)
		if err != nil {
			return nil, err
		}
		for _, v := range resp.Items {
			res, err := CreateResource(p.MqlRuntime, "circleci.project.environmentVariable", map[string]*llx.RawData{
				"__id": llx.StringData(p.Id.Data + "/" + v.Name),
				"name": llx.StringData(v.Name),
			})
			if err != nil {
				return nil, err
			}
			res.(*mqlCircleciProjectEnvironmentVariable).cacheProject = p
			all = append(all, res)
		}
		next, done, err := walker.next(resp.NextPageToken)
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
		pageToken = next
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

// mqlCircleciWebhookInternal caches the project this webhook belongs to, so
// the project() typed reference resolves without an extra API call.
type mqlCircleciWebhookInternal struct {
	cacheProject *mqlCircleciProject
}

// project resolves the project this webhook is configured on.
func (w *mqlCircleciWebhook) project() (*mqlCircleciProject, error) {
	if w.cacheProject == nil {
		w.Project.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return w.cacheProject, nil
}

// webhooks lists the outbound webhooks configured on this project. CircleCI
// never returns a webhook's signing secret; signingSecretSet reports only
// whether one is configured.
func (p *mqlCircleciProject) webhooks() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.CircleciConnection)
	client := conn.Client()

	var all []any
	pageToken := ""
	var walker pageWalker
	for {
		resp, err := client.ListWebhooks(context.Background(), p.Id.Data, "project", pageToken)
		if err != nil {
			return nil, err
		}
		for _, w := range resp.Items {
			res, err := CreateResource(p.MqlRuntime, "circleci.webhook", map[string]*llx.RawData{
				"__id":             llx.StringData(w.ID),
				"id":               llx.StringData(w.ID),
				"name":             llx.StringData(w.Name),
				"url":              llx.StringData(w.URL),
				"verifyTls":        llx.BoolDataPtr(w.VerifyTLS),
				"signingSecretSet": llx.BoolData(w.SigningSecret != ""),
				"events":           llx.ArrayData(convert.SliceAnyToInterface(w.Events), types.String),
			})
			if err != nil {
				return nil, err
			}
			res.(*mqlCircleciWebhook).cacheProject = p
			all = append(all, res)
		}
		next, done, err := walker.next(resp.NextPageToken)
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
		pageToken = next
	}
	return all, nil
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
	var walker pageWalker
	for {
		resp, err := client.ListCheckoutKeys(context.Background(), p.cacheSlug, pageToken)
		if err != nil {
			return nil, err
		}
		for _, k := range resp.Items {
			res, err := CreateResource(p.MqlRuntime, "circleci.checkoutKey", map[string]*llx.RawData{
				"__id":        llx.StringData(p.Id.Data + "/" + k.Fingerprint),
				"fingerprint": llx.StringData(k.Fingerprint),
				"type":        llx.StringData(k.Type),
				"publicKey":   llx.StringData(k.PublicKey),
				"preferred":   llx.BoolDataPtr(k.Preferred),
				"createdAt":   llx.TimeDataPtr(parseCircleciTime(k.CreatedAt)),
			})
			if err != nil {
				return nil, err
			}
			res.(*mqlCircleciCheckoutKey).cacheProject = p
			all = append(all, res)
		}
		next, done, err := walker.next(resp.NextPageToken)
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
		pageToken = next
	}
	return all, nil
}

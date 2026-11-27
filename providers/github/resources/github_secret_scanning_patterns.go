// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/google/go-github/v93/github"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

func (g *mqlGithubSecretScanningCustomPattern) id() (string, error) {
	return g.__id, nil
}

func (g *mqlGithubSecretScanningPatternConfiguration) id() (string, error) {
	return g.__id, nil
}

// secretScanningCustomPatternID keys a custom pattern by the scope that
// defines it.
func secretScanningCustomPatternID(scope, owner, repo string, id int64) string {
	if scope == scopeOrganization {
		return "github.secretScanningCustomPattern/org/" + owner + "/" + strconv.FormatInt(id, 10)
	}
	return "github.secretScanningCustomPattern/repo/" + owner + "/" + repo + "/" + strconv.FormatInt(id, 10)
}

func customPatternsToMql(runtime *plugin.Runtime, scope, owner, repo string, patterns []*github.SecretScanningCustomPattern) ([]any, error) {
	res := make([]any, 0, len(patterns))
	for _, p := range patterns {
		if p == nil {
			continue
		}
		r, err := CreateResource(runtime, "github.secretScanningCustomPattern", map[string]*llx.RawData{
			"__id":                  llx.StringData(secretScanningCustomPatternID(scope, owner, repo, p.ID)),
			"id":                    llx.IntData(p.ID),
			"name":                  llx.StringData(p.Name),
			"slug":                  llx.StringData(p.Slug),
			"pattern":               llx.StringData(p.Pattern),
			"state":                 llx.StringData(p.State),
			"pushProtectionEnabled": llx.BoolData(p.PushProtectionEnabled),
			"startDelimiter":        llx.StringDataPtr(p.StartDelimiter),
			"endDelimiter":          llx.StringDataPtr(p.EndDelimiter),
			"mustMatch":             llx.ArrayData(convert.SliceAnyToInterface(p.MustMatch), types.String),
			"mustNotMatch":          llx.ArrayData(convert.SliceAnyToInterface(p.MustNotMatch), types.String),
			"scope":                 llx.StringData(scope),
			"createdAt":             llx.TimeDataPtr(githubTime(p.CreatedAt)),
			"updatedAt":             llx.TimeDataPtr(githubTime(p.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (g *mqlGithubOrganization) secretScanningCustomPatterns() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	all, err := collectPages(func(opts *github.ListOptions) ([]*github.SecretScanningCustomPattern, *github.Response, error) {
		return conn.Client().SecretScanning.ListCustomPatternsForOrg(conn.Context(), orgLogin,
			&github.SecretScanningCustomPatternListOptions{ListOptions: *opts})
	})
	if err != nil {
		if err := classifyReadErr(err, "secret scanning custom patterns", orgLogin); err != nil {
			return nil, err
		}
		g.SecretScanningCustomPatterns.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return customPatternsToMql(g.MqlRuntime, scopeOrganization, orgLogin, "", all)
}

func (g *mqlGithubRepository) secretScanningCustomPatterns() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	owner, repo, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	all, err := collectPages(func(opts *github.ListOptions) ([]*github.SecretScanningCustomPattern, *github.Response, error) {
		return conn.Client().SecretScanning.ListCustomPatternsForRepo(conn.Context(), owner, repo,
			&github.SecretScanningCustomPatternListOptions{ListOptions: *opts})
	})
	if err != nil {
		if err := classifyReadErr(err, "secret scanning custom patterns", owner+"/"+repo); err != nil {
			return nil, err
		}
		g.SecretScanningCustomPatterns.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return customPatternsToMql(g.MqlRuntime, scopeRepository, owner, repo, all)
}

const (
	patternKindProvider = "provider"
	patternKindCustom   = "custom"
)

// secretScanningPatternConfigurationID keys a pattern's settings by
// organization, kind and token type. A custom pattern's token type is unique
// to it, and a provider pattern's token type names exactly one pattern.
func secretScanningPatternConfigurationID(orgLogin, kind string, o *github.SecretScanningPatternOverride) string {
	return "github.secretScanningPatternConfiguration/" + orgLogin + "/" + kind + "/" + o.GetTokenType() + "/" + o.GetSlug()
}

// patternOverrideArgs maps one pattern override onto the resource fields. The
// statistics are pointers in the response and stay null when GitHub leaves
// them out, which is not the same as a pattern that raised no alerts.
func patternOverrideArgs(orgLogin, kind string, o *github.SecretScanningPatternOverride) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                 llx.StringData(secretScanningPatternConfigurationID(orgLogin, kind, o)),
		"kind":                 llx.StringData(kind),
		"tokenType":            llx.StringDataPtr(o.TokenType),
		"slug":                 llx.StringDataPtr(o.Slug),
		"displayName":          llx.StringDataPtr(o.DisplayName),
		"customPatternVersion": llx.StringDataPtr(o.CustomPatternVersion),
		"setting":              llx.StringDataPtr(o.Setting),
		"defaultSetting":       llx.StringDataPtr(o.DefaultSetting),
		"enterpriseSetting":    llx.StringDataPtr(o.EnterpriseSetting),
		"alertTotal":           intPtrData(o.AlertTotal),
		"alertTotalPercentage": intPtrData(o.AlertTotalPercentage),
		"falsePositives":       intPtrData(o.FalsePositives),
		"falsePositiveRate":    intPtrData(o.FalsePositiveRate),
		"bypassRate":           intPtrData(o.Bypassrate),
	}
}

// intPtrData reports an optional int, null when it is absent.
func intPtrData(v *int) *llx.RawData {
	if v == nil {
		return llx.NilData
	}
	return llx.IntData(int64(*v))
}

func (g *mqlGithubOrganization) secretScanningPatternConfigurations() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	configs, _, err := conn.Client().SecretScanning.ListPatternConfigsForOrg(conn.Context(), orgLogin)
	if err != nil {
		if err := classifyReadErr(err, "secret scanning pattern configurations", orgLogin); err != nil {
			return nil, err
		}
		g.SecretScanningPatternConfigurations.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if configs == nil {
		g.SecretScanningPatternConfigurations.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := []any{}
	for _, group := range []struct {
		kind      string
		overrides []*github.SecretScanningPatternOverride
	}{
		{patternKindProvider, configs.ProviderPatternOverrides},
		{patternKindCustom, configs.CustomPatternOverrides},
	} {
		for _, o := range group.overrides {
			if o == nil {
				continue
			}
			r, err := CreateResource(g.MqlRuntime, "github.secretScanningPatternConfiguration", patternOverrideArgs(orgLogin, group.kind, o))
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
	}
	return res, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"sync"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/github/connection"
)

// An allowedActions of "selected" is the restrictive-looking setting, but the
// restriction it applies lives entirely in a second endpoint: the allowlist of
// action patterns, plus the two switches for GitHub-owned and verified-creator
// actions. Without them a scope that permits everything through a `*/*` pattern
// reads exactly like one that permits a handful of pinned actions.

const allowedActionsSelected = "selected"

type mqlGithubRepositoryActionsSettingsInternal struct {
	ownerLogin string
	repoName   string

	allowlistOnce sync.Once
	allowlist     *github.ActionsAllowed
	allowlistErr  error
}

type mqlGithubOrganizationActionsSettingsInternal struct {
	orgLogin string

	allowlistOnce sync.Once
	allowlist     *github.ActionsAllowed
	allowlistErr  error
}

// classifyAllowlistErr maps a refused or inapplicable allowlist read to "no
// allowlist to report", which the callers render as null. A read that failed
// for any other reason stays an error rather than becoming a permissive-looking
// empty answer.
func classifyAllowlistErr(err error, scope string) (*github.ActionsAllowed, error) {
	switch {
	case githubForbidden(err):
		log.Warn().Err(err).Str("scope", scope).
			Msg("permission denied reading the allowed-actions allowlist; reporting it as unknown")
		return nil, nil
	case githubNotAvailable(err):
		log.Debug().Err(err).Str("scope", scope).
			Msg("the allowed-actions allowlist is not available for this scope")
		return nil, nil
	}
	return nil, err
}

// allowlistPatterns renders the patterns of an allowlist, or null when there is
// no allowlist in force. An allowlist that is present but empty is a real
// answer: it permits no third-party actions at all.
func allowlistPatterns(allowed *github.ActionsAllowed, field *plugin.TValue[[]any]) ([]any, error) {
	if allowed == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return convert.SliceAnyToInterface(allowed.PatternsAllowed), nil
}

// allowlistBool renders one of the allowlist switches, or null when there is no
// allowlist in force or GitHub did not report the switch.
func allowlistBool(v *bool, field *plugin.TValue[bool]) (bool, error) {
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *v, nil
}

// ---------- repository ----------

// actionsAllowlist reads the repository's allowlist at most once. It returns no
// allowlist when allowedActions is not "selected", where GitHub keeps none and
// answers the endpoint with a 409.
func (g *mqlGithubRepositoryActionsSettings) actionsAllowlist() (*github.ActionsAllowed, error) {
	g.allowlistOnce.Do(func() {
		if g.AllowedActions.Error != nil {
			g.allowlistErr = g.AllowedActions.Error
			return
		}
		if g.AllowedActions.Data != allowedActionsSelected {
			return
		}
		conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
		allowed, _, err := conn.Client().Repositories.GetActionsAllowed(conn.Context(), g.ownerLogin, g.repoName)
		if err != nil {
			g.allowlist, g.allowlistErr = classifyAllowlistErr(err, g.ownerLogin+"/"+g.repoName)
			return
		}
		g.allowlist = allowed
	})
	return g.allowlist, g.allowlistErr
}

func (g *mqlGithubRepositoryActionsSettings) patternsAllowed() ([]any, error) {
	allowed, err := g.actionsAllowlist()
	if err != nil {
		return nil, err
	}
	return allowlistPatterns(allowed, &g.PatternsAllowed)
}

func (g *mqlGithubRepositoryActionsSettings) githubOwnedAllowed() (bool, error) {
	allowed, err := g.actionsAllowlist()
	if err != nil {
		return false, err
	}
	if allowed == nil {
		g.GithubOwnedAllowed.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return allowlistBool(allowed.GithubOwnedAllowed, &g.GithubOwnedAllowed)
}

func (g *mqlGithubRepositoryActionsSettings) verifiedAllowed() (bool, error) {
	allowed, err := g.actionsAllowlist()
	if err != nil {
		return false, err
	}
	if allowed == nil {
		g.VerifiedAllowed.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return allowlistBool(allowed.VerifiedAllowed, &g.VerifiedAllowed)
}

// accessLevel reports how far outside the repository its own actions and
// reusable workflows can be consumed. The setting exists only for a private or
// internal repository; a public one answers 422 "Access policy only applies to
// internal and private repositories", which is the endpoint declining to apply
// rather than a failure. Letting that escape fails the whole actionsSettings
// resource, so every field on it disappears for every public repository.
func (g *mqlGithubRepositoryActionsSettings) accessLevel() (string, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	level, _, err := conn.Client().Repositories.GetActionsAccessLevel(conn.Context(), g.ownerLogin, g.repoName)
	if err != nil {
		switch {
		case githubResponseStatus(err) == http.StatusUnprocessableEntity:
			log.Debug().Str("owner", g.ownerLogin).Str("repo", g.repoName).
				Msg("the Actions access level applies only to private and internal repositories")
		case githubForbidden(err):
			log.Warn().Err(err).Str("owner", g.ownerLogin).Str("repo", g.repoName).
				Msg("permission denied reading the Actions access level; reporting it as unknown")
		case githubNotAvailable(err):
			log.Debug().Err(err).Str("owner", g.ownerLogin).Str("repo", g.repoName).
				Msg("the Actions access level does not apply to this repository")
		default:
			return "", err
		}
		g.AccessLevel.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	if level == nil || level.AccessLevel == nil {
		g.AccessLevel.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *level.AccessLevel, nil
}

// ---------- organization ----------

func (g *mqlGithubOrganizationActionsSettings) actionsAllowlist() (*github.ActionsAllowed, error) {
	g.allowlistOnce.Do(func() {
		if g.AllowedActions.Error != nil {
			g.allowlistErr = g.AllowedActions.Error
			return
		}
		if g.AllowedActions.Data != allowedActionsSelected {
			return
		}
		conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
		allowed, _, err := conn.Client().Organizations.GetActionsAllowed(conn.Context(), g.orgLogin)
		if err != nil {
			g.allowlist, g.allowlistErr = classifyAllowlistErr(err, g.orgLogin)
			return
		}
		g.allowlist = allowed
	})
	return g.allowlist, g.allowlistErr
}

func (g *mqlGithubOrganizationActionsSettings) patternsAllowed() ([]any, error) {
	allowed, err := g.actionsAllowlist()
	if err != nil {
		return nil, err
	}
	return allowlistPatterns(allowed, &g.PatternsAllowed)
}

func (g *mqlGithubOrganizationActionsSettings) githubOwnedAllowed() (bool, error) {
	allowed, err := g.actionsAllowlist()
	if err != nil {
		return false, err
	}
	if allowed == nil {
		g.GithubOwnedAllowed.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return allowlistBool(allowed.GithubOwnedAllowed, &g.GithubOwnedAllowed)
}

func (g *mqlGithubOrganizationActionsSettings) verifiedAllowed() (bool, error) {
	allowed, err := g.actionsAllowlist()
	if err != nil {
		return false, err
	}
	if allowed == nil {
		g.VerifiedAllowed.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return allowlistBool(allowed.VerifiedAllowed, &g.VerifiedAllowed)
}

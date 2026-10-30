// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

func (g *mqlGithubRepositoryCodeScanningDefaultSetup) id() (string, error) {
	return g.__id, nil
}

// initGithubRepositoryCodeScanningDefaultSetup delegates to the repository, so
// the dotted path resolves to the same populated resource the repository field
// hands out rather than instantiating a blank one.
func initGithubRepositoryCodeScanningDefaultSetup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	repo, err := NewResource(runtime, "github.repository", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	setup := repo.(*mqlGithubRepository).GetCodeScanningDefaultSetup()
	if setup.Error != nil {
		return nil, nil, setup.Error
	}
	if setup.Data == nil {
		return nil, nil, errors.New("code scanning default setup is not readable for this repository")
	}
	return args, setup.Data, nil
}

// codeScanningDefaultSetup reports the CodeQL default setup as configured on
// the repository. A repository that scans through its own Actions workflow
// reports a state of not-configured with no query suite and no languages, which
// is the endpoint's answer rather than a missing read.
//
// Null when the configuration cannot be read at all: a 404 for a repository
// where code scanning is unavailable, or a 403 for a token without the
// security_events scope. Reporting either as "nothing configured" would let an
// unread repository pass a check on the query suite.
func (g *mqlGithubRepository) codeScanningDefaultSetup() (*mqlGithubRepositoryCodeScanningDefaultSetup, error) {
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	setup, err := g.defaultSetupConfig()
	if err != nil {
		switch {
		case githubForbidden(err):
			log.Warn().Err(err).Str("owner", ownerLogin).Str("repo", repoName).
				Msg("permission denied reading the code scanning default setup; reporting it as unknown")
		case githubNotAvailable(err):
			log.Debug().Err(err).Str("owner", ownerLogin).Str("repo", repoName).
				Msg("code scanning default setup is not available for this repository")
		default:
			return nil, err
		}
		g.CodeScanningDefaultSetup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if setup == nil {
		g.CodeScanningDefaultSetup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Absent rather than empty. GitHub does report a language list for a
	// repository whose default setup is not configured, describing the eligible
	// languages, but a repository that reports none at all is a different answer
	// from one that reports an empty set, and an empty list would read as
	// "scanning nothing".
	languages := llx.NilData
	if setup.Languages != nil {
		languages = llx.ArrayData(convert.SliceAnyToInterface(setup.Languages), types.String)
	}

	res, err := CreateResource(g.MqlRuntime, "github.repository.codeScanningDefaultSetup", map[string]*llx.RawData{
		"__id":       llx.StringData("github.repository.codeScanningDefaultSetup/" + ownerLogin + "/" + repoName),
		"state":      llx.StringDataPtr(setup.State),
		"querySuite": llx.StringDataPtr(setup.QuerySuite),
		"languages":  languages,
		"updatedAt":  llx.TimeDataPtr(githubTime(setup.UpdatedAt)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubRepositoryCodeScanningDefaultSetup), nil
}

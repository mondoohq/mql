// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

func (g *mqlGithubRepositoryPages) id() (string, error) {
	if g.__id == "" {
		return "", errors.New("github.repository.pages requires __id set by the creator")
	}
	return g.__id, nil
}

func initGithubRepositoryPages(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	repo, err := NewResource(runtime, "github.repository", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	pages := repo.(*mqlGithubRepository).GetPages()
	if pages.Error != nil {
		return nil, nil, pages.Error
	}
	if pages.Data == nil {
		return nil, nil, errors.New("GitHub Pages is not enabled for this repository")
	}
	return args, pages.Data, nil
}

func (g *mqlGithubRepository) pages() (*mqlGithubRepositoryPages, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	pages, _, err := conn.Client().Repositories.GetPagesInfo(conn.Context(), ownerLogin, repoName)
	if err != nil {
		switch githubResponseStatus(err) {
		case 404:
			// Pages not enabled for this repository
			g.Pages.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		case 403, 401:
			log.Debug().Err(err).Msg("GitHub Pages configuration not accessible")
			g.Pages.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if pages == nil {
		g.Pages.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	args := map[string]*llx.RawData{
		"__id":          llx.StringData("github.repository.pages/" + ownerLogin + "/" + repoName),
		"url":           llx.StringDataPtr(pages.URL),
		"htmlUrl":       llx.StringDataPtr(pages.HTMLURL),
		"status":        llx.StringDataPtr(pages.Status),
		"cname":         llx.StringDataPtr(pages.CNAME),
		"custom404":     llx.BoolData(pages.GetCustom404()),
		"buildType":     llx.StringDataPtr(pages.BuildType),
		"public":        llx.BoolData(pages.GetPublic()),
		"httpsEnforced": llx.BoolData(pages.GetHTTPSEnforced()),
	}

	if cert := pages.HTTPSCertificate; cert != nil {
		args["httpsCertificateState"] = llx.StringDataPtr(cert.State)
		args["httpsCertificateDescription"] = llx.StringDataPtr(cert.Description)
		args["httpsCertificateDomains"] = llx.ArrayData(convert.SliceAnyToInterface[string](cert.Domains), types.String)
		args["httpsCertificateExpiresAt"] = llx.StringDataPtr(cert.ExpiresAt)
	}
	// When HTTPSCertificate is nil the API has not provisioned one yet; leave
	// the four fields unset so they read as null rather than empty strings.

	if src := pages.Source; src != nil {
		args["sourceBranch"] = llx.StringDataPtr(src.Branch)
		args["sourcePath"] = llx.StringDataPtr(src.Path)
	}
	// Source is nil for workflow-built sites; leave sourceBranch/sourcePath
	// unset so consumers can distinguish "legacy build with no branch" from
	// "workflow build" via null rather than empty string.

	res, err := CreateResource(g.MqlRuntime, "github.repository.pages", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubRepositoryPages), nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/github/connection"
)

const (
	GITHUB_PACKAGE_VISIBILITY_PUBLIC   = "public"
	GITHUB_PACKAGE_VISIBILITY_PRIVATE  = "private"
	GITHUB_PACKAGE_VISIBILITY_INTERNAL = "internal"
)

func (g *mqlGithubPackage) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "github.package/" + strconv.FormatInt(id, 10), nil
}

func (g *mqlGithubPackages) id() (string, error) {
	return "github.packages", nil
}

func (g *mqlGithubPackages) list() ([]any, error) {
	return newMqlGithubPackages(g.MqlRuntime, nil)
}

func (g *mqlGithubPackages) public() ([]any, error) {
	visibility := GITHUB_PACKAGE_VISIBILITY_PUBLIC
	return newMqlGithubPackages(g.MqlRuntime, &visibility)
}

func (g *mqlGithubPackages) private() ([]any, error) {
	visibility := GITHUB_PACKAGE_VISIBILITY_PRIVATE
	return newMqlGithubPackages(g.MqlRuntime, &visibility)
}

func (g *mqlGithubPackages) internal() ([]any, error) {
	visibility := GITHUB_PACKAGE_VISIBILITY_INTERNAL
	return newMqlGithubPackages(g.MqlRuntime, &visibility)
}

func (g *mqlGithubPackageVersion) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "github.packageVersion/" + strconv.FormatInt(g.Id.Data, 10), nil
}

func (g *mqlGithubPackage) versions() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	// Package versions are only available for organization-scoped connections.
	org, err := conn.Organization()
	if err != nil {
		log.Debug().Err(err).Msg("cannot fetch package versions: organization not available")
		return nil, nil
	}

	// Always read from the resource's own schema fields so versions() works
	// regardless of how the package was created (list, cache, or recording).
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	pkgName := g.Name.Data
	if g.PackageType.Error != nil {
		return nil, g.PackageType.Error
	}
	pkgType := g.PackageType.Data
	if pkgName == "" || pkgType == "" {
		log.Debug().Msg("package name or type not available, cannot fetch versions")
		return nil, nil
	}

	listOpts := &github.PackageListOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}
	var allVersions []*github.PackageVersion
	for {
		versions, resp, err := conn.Client().Organizations.PackageGetAllVersions(conn.Context(), org.Name, pkgType, pkgName, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allVersions = append(allVersions, versions...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := make([]any, 0, len(allVersions))
	for _, v := range allVersions {
		r, err := CreateResource(g.MqlRuntime, "github.packageVersion", map[string]*llx.RawData{
			"id":             llx.IntDataPtr(v.ID),
			"name":           llx.StringDataPtr(v.Name),
			"url":            llx.StringDataPtr(v.URL),
			"packageHtmlUrl": llx.StringDataPtr(v.PackageHTMLURL),
			"license":        llx.StringDataPtr(v.License),
			"description":    llx.StringDataPtr(v.Description),
			"createdAt":      llx.TimeDataPtr(githubTimestamp(v.CreatedAt)),
			"updatedAt":      llx.TimeDataPtr(githubTimestamp(v.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func newMqlGithubPackages(runtime *plugin.Runtime, visibility *string) ([]any, error) {
	conn := runtime.Connection.(*connection.GithubConnection)
	orgId, err := conn.Organization()
	if err != nil {
		return nil, err
	}

	pkgTypes := []string{"npm", "maven", "rubygems", "docker", "nuget", "container"}
	res := []any{}
	for i := range pkgTypes {
		listOpts := &github.PackageListOptions{
			ListOptions: github.ListOptions{PerPage: paginationPerPage},
			PackageType: github.String(pkgTypes[i]),
			Visibility:  visibility,
		}

		var allPackages []*github.Package
		for {
			packages, resp, err := conn.Client().Organizations.ListPackages(conn.Context(), orgId.Name, listOpts)
			if err != nil {
				if strings.Contains(err.Error(), "404") {
					return nil, nil
				}
				return nil, err
			}
			allPackages = append(allPackages, packages...)
			if resp.NextPage == 0 {
				break
			}
			listOpts.Page = resp.NextPage
		}

		for i := range allPackages {
			p := allPackages[i]

			owner, err := NewResource(runtime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntData(p.GetOwner().GetID()),
				"login": llx.StringData(p.GetOwner().GetLogin()),
			})
			if err != nil {
				return nil, err
			}

			mqlGhPackage, err := CreateResource(runtime, "github.package", map[string]*llx.RawData{
				"id":           llx.IntDataPtr(p.ID),
				"name":         llx.StringDataPtr(p.Name),
				"packageType":  llx.StringDataPtr(p.PackageType),
				"owner":        llx.ResourceData(owner, owner.MqlName()),
				"createdAt":    llx.TimeDataPtr(githubTimestamp(p.CreatedAt)),
				"updatedAt":    llx.TimeDataPtr(githubTimestamp(p.UpdatedAt)),
				"versionCount": llx.IntDataPtr(p.VersionCount),
				"visibility":   llx.StringDataPtr(p.Visibility),
			})
			if err != nil {
				return nil, err
			}
			pkg := mqlGhPackage.(*mqlGithubPackage)

			// NOTE: we need to fetch repo separately because the Github repo object is not complete, instead of
			// call the repo fetching all the time, we make this lazy loading
			if p.Repository != nil && p.Repository.Name != nil {
				pkg.packageRepository = convert.ToValue(p.Repository.Name)
			}
			res = append(res, pkg)
		}
	}

	return res, nil
}

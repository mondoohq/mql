// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/netlify/connection"
)

// maxDeploysPerSite bounds how far back a site's deploy list is read. Deploys
// are an append-only history that a long-lived site accumulates without limit,
// and Netlify returns them newest first, so the bound keeps the most recent
// ones. The schema states the bound so a truncated list reads as a documented
// window rather than as a site with no older deploys.
const maxDeploysPerSite = 500

// mqlNetlifySiteDeployInternal caches the site the deploy belongs to, which its
// site reference resolves against.
type mqlNetlifySiteDeployInternal struct {
	cacheSiteID string
}

// mqlNetlifySiteDeployedBranchInternal caches the site the branch belongs to
// and the deploy currently published for it.
type mqlNetlifySiteDeployedBranchInternal struct {
	cacheSiteID   string
	cacheDeployID string
}

type deployRecord struct {
	ID           string      `json:"id"`
	SiteID       string      `json:"site_id"`
	State        string      `json:"state"`
	Context      string      `json:"context"`
	Title        string      `json:"title"`
	Branch       string      `json:"branch"`
	CommitRef    string      `json:"commit_ref"`
	CommitURL    string      `json:"commit_url"`
	DeployURL    string      `json:"deploy_url"`
	DeploySslURL string      `json:"deploy_ssl_url"`
	ReviewID     *int64      `json:"review_id"`
	ReviewURL    string      `json:"review_url"`
	Draft        *bool       `json:"draft"`
	Locked       *bool       `json:"locked"`
	Skipped      *bool       `json:"skipped"`
	Framework    string      `json:"framework"`
	ErrorMessage string      `json:"error_message"`
	CreatedAt    netlifyTime `json:"created_at"`
	UpdatedAt    netlifyTime `json:"updated_at"`
	PublishedAt  netlifyTime `json:"published_at"`
}

// deploys lists the site's published deploys.
//
// The list is narrowed to the ready state, which is what a deploy that is still
// being served reaches, and bounded to the most recent maxDeploysPerSite of
// them. Both narrowings are stated in the schema.
func (s *mqlNetlifySite) deploys() ([]any, error) {
	c := netlifyConn(s.MqlRuntime)

	query := url.Values{}
	query.Set("state", "ready")

	records, err := connection.GetPagedLimit[deployRecord](context.Background(), c,
		"/sites/"+url.PathEscape(s.Id.Data)+"/deploys", query, maxDeploysPerSite)
	if err != nil {
		if connection.IsForbidden(err) {
			s.Deploys = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]
		if rec.SiteID == "" {
			rec.SiteID = s.Id.Data
		}
		deploy, err := newNetlifySiteDeploy(s.MqlRuntime, &rec)
		if err != nil {
			return nil, err
		}
		res = append(res, deploy)
	}
	return res, nil
}

func newNetlifySiteDeploy(runtime *plugin.Runtime, rec *deployRecord) (*mqlNetlifySiteDeploy, error) {
	res, err := CreateResource(runtime, "netlify.site.deploy", map[string]*llx.RawData{
		"id":           llx.StringData(rec.ID),
		"state":        llx.StringData(rec.State),
		"context":      llx.StringData(rec.Context),
		"title":        llx.StringData(rec.Title),
		"branch":       llx.StringData(rec.Branch),
		"commitRef":    llx.StringData(rec.CommitRef),
		"commitUrl":    llx.StringData(rec.CommitURL),
		"deployUrl":    llx.StringData(rec.DeployURL),
		"deploySslUrl": llx.StringData(rec.DeploySslURL),
		"reviewId":     optionalInt(rec.ReviewID),
		"reviewUrl":    llx.StringData(rec.ReviewURL),
		"draft":        optionalBool(rec.Draft),
		"locked":       optionalBool(rec.Locked),
		"skipped":      optionalBool(rec.Skipped),
		"framework":    llx.StringData(rec.Framework),
		"errorMessage": llx.StringData(rec.ErrorMessage),
		"createdAt":    llx.TimeDataPtr(rec.CreatedAt.Time()),
		"updatedAt":    llx.TimeDataPtr(rec.UpdatedAt.Time()),
		"publishedAt":  llx.TimeDataPtr(rec.PublishedAt.Time()),
	})
	if err != nil {
		return nil, err
	}

	deploy := res.(*mqlNetlifySiteDeploy)
	deploy.cacheSiteID = rec.SiteID
	return deploy, nil
}

// initNetlifySiteDeploy resolves a deploy by its identifier, which is what a
// deployed branch falls back to when the deploy it points at is outside the
// window its site's deploy list covers.
func initNetlifySiteDeploy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	deployID := ""
	if data, ok := args["id"]; ok {
		if s, ok := data.Value.(string); ok {
			deployID = s
		}
	}
	if deployID == "" {
		return nil, nil, errors.New("netlify.site.deploy requires an id")
	}

	c := netlifyConn(runtime)

	var rec deployRecord
	if err := c.Get(context.Background(), "/deploys/"+url.PathEscape(deployID), nil, &rec); err != nil {
		return nil, nil, err
	}
	if rec.ID == "" {
		return nil, nil, fmt.Errorf("netlify.site.deploy with id %q not found", deployID)
	}

	deploy, err := newNetlifySiteDeploy(runtime, &rec)
	if err != nil {
		return nil, nil, err
	}
	return args, deploy, nil
}

func (d *mqlNetlifySiteDeploy) id() (string, error) {
	return d.Id.Data, d.Id.Error
}

// site resolves the site the deploy belongs to, against the site list the root
// resource has already fetched so a query over many deploys does not read one
// site per deploy.
func (d *mqlNetlifySiteDeploy) site() (*mqlNetlifySite, error) {
	return resolveSiteByID(d.MqlRuntime, d.cacheSiteID, &d.Site)
}

// resolveSiteByID looks a site up in the list the root resource already
// fetched, falling back to a direct lookup for a site outside the scope that
// list was narrowed to. A site this token cannot read reports as null on the
// record that names it rather than failing that record.
func resolveSiteByID(runtime *plugin.Runtime, siteID string, field *plugin.TValue[*mqlNetlifySite]) (*mqlNetlifySite, error) {
	if siteID == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	root, err := getNetlify(runtime)
	if err != nil {
		return nil, err
	}
	if site, ok := findCachedResource(root.GetSites(), netlifySiteID, siteID); ok {
		return site, nil
	}

	res, err := NewResource(runtime, "netlify.site", map[string]*llx.RawData{
		"id": llx.StringData(siteID),
	})
	if err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlNetlifySite), nil
}

// --- deployed branches ----------------------------------------------------

type deployedBranchRecord struct {
	ID       string `json:"id"`
	DeployID string `json:"deploy_id"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	URL      string `json:"url"`
	SslURL   string `json:"ssl_url"`
}

func (s *mqlNetlifySite) deployedBranches() ([]any, error) {
	c := netlifyConn(s.MqlRuntime)

	records, err := connection.GetPaged[deployedBranchRecord](context.Background(), c,
		"/sites/"+url.PathEscape(s.Id.Data)+"/deployed-branches", nil)
	if err != nil {
		if connection.IsForbidden(err) {
			s.DeployedBranches = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]
		// The branch identifier is unique within the site rather than across
		// the account, so the cache key carries the site as well. Two sites
		// serving a branch of the same name would otherwise collapse into one
		// record.
		branch, err := CreateResource(s.MqlRuntime, "netlify.site.deployedBranch", map[string]*llx.RawData{
			"__id":   llx.StringData(s.Id.Data + "/deployedBranch/" + rec.ID),
			"id":     llx.StringData(rec.ID),
			"name":   llx.StringData(rec.Name),
			"slug":   llx.StringData(rec.Slug),
			"url":    llx.StringData(rec.URL),
			"sslUrl": llx.StringData(rec.SslURL),
		})
		if err != nil {
			return nil, err
		}
		mqlBranch := branch.(*mqlNetlifySiteDeployedBranch)
		mqlBranch.cacheSiteID = s.Id.Data
		mqlBranch.cacheDeployID = rec.DeployID
		res = append(res, mqlBranch)
	}
	return res, nil
}

func (b *mqlNetlifySiteDeployedBranch) id() (string, error) {
	return b.Id.Data, b.Id.Error
}

// deploy resolves the deploy currently published for the branch.
//
// The match runs against the deploy list the branch's own site has already
// fetched, so a site with many branches does not read one deploy per branch.
// That list is bounded, so a branch published by an older deploy misses it and
// falls back to the direct lookup.
func (b *mqlNetlifySiteDeployedBranch) deploy() (*mqlNetlifySiteDeploy, error) {
	if b.cacheDeployID == "" {
		b.Deploy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	root, err := getNetlify(b.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if site, ok := findCachedResource(root.GetSites(), netlifySiteID, b.cacheSiteID); ok {
		if deploy, ok := findCachedResource(site.GetDeploys(), netlifySiteDeployID, b.cacheDeployID); ok {
			return deploy, nil
		}
	}

	res, err := NewResource(b.MqlRuntime, "netlify.site.deploy", map[string]*llx.RawData{
		"id": llx.StringData(b.cacheDeployID),
	})
	if err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			b.Deploy.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlNetlifySiteDeploy), nil
}

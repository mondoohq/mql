// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sort"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vercel/connection"
)

// mqlVercelAliasInternal caches the team the alias was listed under and the
// deployment it points at, so deployment() and project() resolve without a
// second listing.
type mqlVercelAliasInternal struct {
	teamID       string
	deploymentID string
	projectID    string
}

type aliasRecord struct {
	UID                string             `json:"uid"`
	Alias              string             `json:"alias"`
	DeploymentID       *string            `json:"deploymentId"`
	ProjectID          *string            `json:"projectId"`
	Redirect           *string            `json:"redirect"`
	RedirectStatusCode *int64             `json:"redirectStatusCode"`
	Creator            *deploymentCreator `json:"creator"`
	Created            flexTime           `json:"created"`
	CreatedAt          flexTime           `json:"createdAt"`
	UpdatedAt          flexTime           `json:"updatedAt"`
	DeletedAt          flexTime           `json:"deletedAt"`
	// Vercel keys each bypass entry by the bypass secret itself, so the map key
	// is credential material and must never reach a field or the resource id.
	ProtectionBypass map[string]protectionBypassEntry `json:"protectionBypass"`
}

type protectionBypassEntry struct {
	CreatedBy string `json:"createdBy"`
	Scope     string `json:"scope"`
}

// bypassScopes returns the distinct, sorted scopes of an alias's automation
// bypass entries. The map keys are the bypass secrets and are deliberately
// discarded.
func bypassScopes(entries map[string]protectionBypassEntry) []any {
	seen := map[string]struct{}{}
	for _, e := range entries {
		if e.Scope != "" {
			seen[e.Scope] = struct{}{}
		}
	}

	scopes := make([]string, 0, len(seen))
	for s := range seen {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes)

	res := make([]any, 0, len(scopes))
	for _, s := range scopes {
		res = append(res, s)
	}
	return res
}

func (c *mqlVercelProject) aliases() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	query := connection.TeamQuery(c.teamID)
	query.Set("projectId", c.Id.Data)

	records, err := connection.GetPagedFrom[aliasRecord](context.Background(), conn, "/v4/aliases", query, "aliases")
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.Aliases.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		// A 404 means the collection is not provisioned for this scope,
		// which genuinely is none.
		if connection.IsNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := []any{}
	for i := range records {
		rec := records[i]

		created := rec.Created.Time()
		if created == nil {
			created = rec.CreatedAt.Time()
		}
		var creatorUID, creatorUsername, creatorEmail string
		if rec.Creator != nil {
			creatorUID = rec.Creator.UID
			creatorUsername = rec.Creator.Username
			creatorEmail = rec.Creator.Email
		}

		resource, err := CreateResource(c.MqlRuntime, "vercel.alias", map[string]*llx.RawData{
			"id":                 llx.StringData(rec.UID),
			"alias":              llx.StringData(rec.Alias),
			"redirect":           llx.StringDataPtr(rec.Redirect),
			"redirectStatusCode": llx.IntDataPtr(rec.RedirectStatusCode),
			"creatorUid":         llx.StringData(creatorUID),
			"creatorUsername":    llx.StringData(creatorUsername),
			"creatorEmail":       llx.StringData(creatorEmail),
			"createdAt":          llx.TimeDataPtr(created),
			"updatedAt":          llx.TimeDataPtr(rec.UpdatedAt.Time()),
			"deletedAt":          llx.TimeDataPtr(rec.DeletedAt.Time()),
		})
		if err != nil {
			return nil, err
		}

		alias := resource.(*mqlVercelAlias)
		alias.teamID = c.teamID
		alias.projectID = c.Id.Data
		if rec.ProjectID != nil {
			alias.projectID = *rec.ProjectID
		}
		if rec.DeploymentID != nil {
			alias.deploymentID = *rec.DeploymentID
		}
		res = append(res, alias)
	}
	return res, nil
}

func (c *mqlVercelAlias) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

func (c *mqlVercelAlias) deployment() (*mqlVercelDeployment, error) {
	if c.deploymentID == "" {
		c.Deployment.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(c.MqlRuntime, "vercel.deployment", map[string]*llx.RawData{
		"id": llx.StringData(c.deploymentID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVercelDeployment), nil
}

func (c *mqlVercelAlias) project() (*mqlVercelProject, error) {
	if c.projectID == "" {
		c.Project.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(c.MqlRuntime, "vercel.project", map[string]*llx.RawData{
		"id": llx.StringData(c.projectID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVercelProject), nil
}

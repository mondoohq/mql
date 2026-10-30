// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vercel/connection"
	"go.mondoo.com/mql/types"
)

// checkSource is the discriminated source object a check carries, naming what
// registered it. Only one shape arrives per check, selected by kind, so every
// field beyond kind is a pointer that stays null on the other shapes.
type checkSource struct {
	Kind                       string  `json:"kind"`
	IntegrationID              *string `json:"integrationId"`
	IntegrationConfigurationID *string `json:"integrationConfigurationId"`
	WebhookID                  *string `json:"webhookId"`
	Provider                   *string `json:"provider"`
	ExternalCheckName          *string `json:"externalCheckName"`
}

type checkRecord struct {
	ID                               string       `json:"id"`
	Name                             string       `json:"name"`
	Blocks                           *string      `json:"blocks"`
	Requires                         *string      `json:"requires"`
	Targets                          []string     `json:"targets"`
	Timeout                          *int64       `json:"timeout"`
	SourceKind                       *string      `json:"sourceKind"`
	SourceIntegrationConfigurationID *string      `json:"sourceIntegrationConfigurationId"`
	Source                           *checkSource `json:"source"`
	IsRerequestable                  *bool        `json:"isRerequestable"`
	CreatedAt                        flexTime     `json:"createdAt"`
	UpdatedAt                        flexTime     `json:"updatedAt"`
	DeletedAt                        flexTime     `json:"deletedAt"`
}

// checkIntegrationConfigurationID reports the installation that registered the
// check. Vercel reports it both as a top-level field and inside the source
// object, and which one is populated varies, so both are consulted.
func checkIntegrationConfigurationID(rec *checkRecord) *string {
	if rec.SourceIntegrationConfigurationID != nil && *rec.SourceIntegrationConfigurationID != "" {
		return rec.SourceIntegrationConfigurationID
	}
	if rec.Source != nil && rec.Source.IntegrationConfigurationID != nil && *rec.Source.IntegrationConfigurationID != "" {
		return rec.Source.IntegrationConfigurationID
	}
	return nil
}

// checkSourceKind reports what registered the check, falling back to the kind
// carried inside the source object when the top-level field is absent.
func checkSourceKind(rec *checkRecord) *string {
	if rec.SourceKind != nil && *rec.SourceKind != "" {
		return rec.SourceKind
	}
	if rec.Source != nil && rec.Source.Kind != "" {
		kind := rec.Source.Kind
		return &kind
	}
	return nil
}

// integrationConfigCache holds the team's integration installations, fetched at
// most once and shared by every check from the same project. Resolving each
// check separately would repeat the same list call per check.
type integrationConfigCache struct {
	teamID  string
	lock    sync.Mutex
	fetched bool
	records []integrationConfigurationRecord
	err     error
}

func (c *integrationConfigCache) get(runtime *plugin.Runtime) ([]integrationConfigurationRecord, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.fetched {
		return c.records, c.err
	}

	conn := runtime.Connection.(*connection.VercelConnection)
	query := connection.TeamQuery(c.teamID)
	query.Set("view", "account")
	var records []integrationConfigurationRecord
	if err := conn.Get(context.Background(), "/v1/integrations/configurations", query, &records); err != nil {
		// A refused or absent read cannot name the installation; the reference
		// resolves to null rather than to a resource built from the raw id.
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			// a refusal is a definitive answer, so it is cached like a success
			c.fetched = true
			return nil, nil
		}
		// anything else may succeed on a later read, so it is not cached: a
		// transient failure must not poison every later caller in the scan
		return nil, err
	}
	c.records = records
	c.fetched = true
	return c.records, nil
}

// mqlVercelProjectCheckInternal carries the installation the check came from
// and the shared installation cache used to resolve it.
type mqlVercelProjectCheckInternal struct {
	cacheIntegrationConfigurationID *string
	teamID                          string
	integrationConfigs              *integrationConfigCache
}

// checks lists the checks registered against the project's deployments. The
// endpoint returns every check in one response with no pagination envelope.
func (c *mqlVercelProject) checks() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)

	var resp struct {
		Checks []checkRecord `json:"checks"`
	}
	if err := conn.Get(context.Background(), "/v2/projects/"+c.Id.Data+"/checks", connection.TeamQuery(c.teamID), &resp); err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.Checks.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		// A 404 means the project has no checks collection, which genuinely
		// is none.
		if connection.IsNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}

	cache := &integrationConfigCache{teamID: c.teamID}

	res := []any{}
	for i := range resp.Checks {
		rec := resp.Checks[i]

		var provider, externalName *string
		if rec.Source != nil {
			provider = rec.Source.Provider
			externalName = rec.Source.ExternalCheckName
		}

		check, err := CreateResource(c.MqlRuntime, "vercel.project.check", map[string]*llx.RawData{
			"__id":              llx.StringData(c.Id.Data + "/check/" + rec.ID),
			"id":                llx.StringData(rec.ID),
			"name":              llx.StringData(rec.Name),
			"blocks":            llx.StringDataPtr(rec.Blocks),
			"requires":          llx.StringDataPtr(rec.Requires),
			"targets":           llx.ArrayData(strSliceToAny(rec.Targets), types.String),
			"timeout":           llx.IntDataPtr(rec.Timeout),
			"sourceKind":        llx.StringDataPtr(checkSourceKind(&rec)),
			"sourceProvider":    llx.StringDataPtr(provider),
			"externalCheckName": llx.StringDataPtr(externalName),
			"isRerequestable":   llx.BoolDataPtr(rec.IsRerequestable),
			"createdAt":         llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":         llx.TimeDataPtr(rec.UpdatedAt.Time()),
			"deletedAt":         llx.TimeDataPtr(rec.DeletedAt.Time()),
		})
		if err != nil {
			return nil, err
		}

		mqlCheck := check.(*mqlVercelProjectCheck)
		mqlCheck.teamID = c.teamID
		mqlCheck.integrationConfigs = cache
		mqlCheck.cacheIntegrationConfigurationID = checkIntegrationConfigurationID(&rec)
		res = append(res, check)
	}
	return res, nil
}

// integrationConfiguration resolves the marketplace installation that
// registered the check, by scanning the team's installation list rather than
// looking the installation up once per check.
func (c *mqlVercelProjectCheck) integrationConfiguration() (*mqlVercelIntegrationConfiguration, error) {
	if c.cacheIntegrationConfigurationID == nil || *c.cacheIntegrationConfigurationID == "" || c.integrationConfigs == nil {
		c.IntegrationConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	records, err := c.integrationConfigs.get(c.MqlRuntime)
	if err != nil {
		return nil, err
	}

	for i := range records {
		if records[i].ID != *c.cacheIntegrationConfigurationID {
			continue
		}
		cfg, err := newVercelIntegrationConfiguration(c.MqlRuntime, c.teamID, &records[i])
		if err != nil {
			return nil, err
		}
		return cfg, nil
	}

	c.IntegrationConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

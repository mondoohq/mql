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

// mqlVercelInternal caches per-team store listings on the root resource so a
// scan that reads stores across many projects (for example team.projects {
// stores }) fetches each team's store list once and shares it, rather than
// re-listing the whole team store list per project.
type mqlVercelInternal struct {
	storesMu     sync.Mutex
	storesByTeam map[string][]storeRecord
}

// rootVercel returns the cached root vercel resource, creating it if a scan
// reaches a store accessor before the root has been materialized. Both paths
// resolve to the same singleton (cache key "vercel"), so the store cache is
// shared regardless of entry point.
func rootVercel(runtime *plugin.Runtime) (*mqlVercel, error) {
	res, err := CreateResource(runtime, "vercel", nil)
	if err != nil {
		return nil, err
	}
	return res.(*mqlVercel), nil
}

// teamStores returns the team's store list, fetching it once per team and
// caching the result. Errors are not cached, so a transient failure or a
// forbidden response is re-evaluated by the caller on the next access.
func (v *mqlVercel) teamStores(teamID string) ([]storeRecord, error) {
	v.storesMu.Lock()
	defer v.storesMu.Unlock()
	if v.storesByTeam == nil {
		v.storesByTeam = map[string][]storeRecord{}
	}
	if recs, ok := v.storesByTeam[teamID]; ok {
		return recs, nil
	}
	conn := v.MqlRuntime.Connection.(*connection.VercelConnection)
	recs, err := listStores(context.Background(), conn, teamID)
	if err != nil {
		return nil, err
	}
	v.storesByTeam[teamID] = recs
	return recs, nil
}

// mqlVercelStoreInternal caches the team a store belongs to and the ids of the
// projects connected to it, so connectedProjects can resolve typed project
// references without re-listing the store.
type mqlVercelStoreInternal struct {
	teamID          string
	cacheProjectIds []string
}

type storeProduct struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type storeBillingPlan struct {
	Name string `json:"name"`
}

type storeSecret struct {
	Name string `json:"name"`
}

type storeProjectMetadata struct {
	ProjectID string `json:"projectId"`
}

type storeMetadata struct {
	Region string `json:"region"`
}

type storeRecord struct {
	ID                     string                 `json:"id"`
	Name                   string                 `json:"name"`
	Type                   string                 `json:"type"`
	Status                 string                 `json:"status"`
	BillingState           string                 `json:"billingState"`
	UsageQuotaExceeded     bool                   `json:"usageQuotaExceeded"`
	Region                 string                 `json:"region"`
	TotalConnectedProjects *int64                 `json:"totalConnectedProjects"`
	CreatedAt              flexTime               `json:"createdAt"`
	UpdatedAt              flexTime               `json:"updatedAt"`
	Size                   *int64                 `json:"size"`
	Count                  *int64                 `json:"count"`
	Access                 *string                `json:"access"`
	Product                *storeProduct          `json:"product"`
	ExternalResourceID     *string                `json:"externalResourceId"`
	ExternalResourceStatus *string                `json:"externalResourceStatus"`
	BillingPlan            *storeBillingPlan      `json:"billingPlan"`
	Secrets                []storeSecret          `json:"secrets"`
	Metadata               *storeMetadata         `json:"metadata"`
	ProjectsMetadata       []storeProjectMetadata `json:"projectsMetadata"`
}

func listStores(ctx context.Context, conn *connection.VercelConnection, teamID string) ([]storeRecord, error) {
	return connection.GetPaged[storeRecord](ctx, conn, "/v1/storage/stores", connection.TeamQuery(teamID), "stores")
}

func newVercelStore(runtime *plugin.Runtime, teamID string, rec *storeRecord) (*mqlVercelStore, error) {
	region := rec.Region
	if region == "" && rec.Metadata != nil {
		region = rec.Metadata.Region
	}

	var productName, productSlug *string
	if rec.Product != nil {
		productName = &rec.Product.Name
		productSlug = &rec.Product.Slug
	}

	var billingPlan *string
	if rec.BillingPlan != nil {
		billingPlan = &rec.BillingPlan.Name
	}

	secretNames := make([]any, 0, len(rec.Secrets))
	for i := range rec.Secrets {
		secretNames = append(secretNames, rec.Secrets[i].Name)
	}

	projectIDs := make([]string, 0, len(rec.ProjectsMetadata))
	for i := range rec.ProjectsMetadata {
		if rec.ProjectsMetadata[i].ProjectID != "" {
			projectIDs = append(projectIDs, rec.ProjectsMetadata[i].ProjectID)
		}
	}

	res, err := CreateResource(runtime, "vercel.store", map[string]*llx.RawData{
		"id":                     llx.StringData(rec.ID),
		"name":                   llx.StringData(rec.Name),
		"storeType":              llx.StringData(rec.Type),
		"status":                 llx.StringData(rec.Status),
		"billingState":           llx.StringData(rec.BillingState),
		"usageQuotaExceeded":     llx.BoolData(rec.UsageQuotaExceeded),
		"region":                 llx.StringData(region),
		"connectedProjectsCount": llx.IntData(intPtrOrZero(rec.TotalConnectedProjects)),
		"createdAt":              llx.TimeDataPtr(rec.CreatedAt.Time()),
		"updatedAt":              llx.TimeDataPtr(rec.UpdatedAt.Time()),
		"size":                   llx.IntDataPtr(rec.Size),
		"objectCount":            llx.IntDataPtr(rec.Count),
		"access":                 llx.StringDataPtr(rec.Access),
		"productName":            llx.StringDataPtr(productName),
		"productSlug":            llx.StringDataPtr(productSlug),
		"externalResourceId":     llx.StringDataPtr(rec.ExternalResourceID),
		"externalResourceStatus": llx.StringDataPtr(rec.ExternalResourceStatus),
		"billingPlan":            llx.StringDataPtr(billingPlan),
		"secretNames":            llx.ArrayData(secretNames, types.String),
	})
	if err != nil {
		return nil, err
	}
	store := res.(*mqlVercelStore)
	store.teamID = teamID
	store.cacheProjectIds = projectIDs
	return store, nil
}

func (c *mqlVercelStore) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

func (c *mqlVercelTeam) stores() ([]any, error) {
	root, err := rootVercel(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	records, err := root.teamStores(c.Id.Data)
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.Stores.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		// Edge Config stores are exposed through the richer vercel.edgeConfig
		// resource; skip them here to avoid duplicate modeling.
		if rec.Type == "edge-config" {
			continue
		}
		store, err := newVercelStore(c.MqlRuntime, c.Id.Data, &rec)
		if err != nil {
			return nil, err
		}
		res = append(res, store)
	}
	return res, nil
}

func (c *mqlVercelProject) stores() ([]any, error) {
	root, err := rootVercel(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	records, err := root.teamStores(c.teamID)
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.Stores.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		if rec.Type == "edge-config" {
			continue
		}
		if !storeConnectedToProject(&rec, c.Id.Data) {
			continue
		}
		store, err := newVercelStore(c.MqlRuntime, c.teamID, &rec)
		if err != nil {
			return nil, err
		}
		res = append(res, store)
	}
	return res, nil
}

func storeConnectedToProject(rec *storeRecord, projectID string) bool {
	for i := range rec.ProjectsMetadata {
		if rec.ProjectsMetadata[i].ProjectID == projectID {
			return true
		}
	}
	return false
}

func (s *mqlVercelStore) connectedProjects() ([]any, error) {
	return resolveProjectRefs(s.MqlRuntime, s.teamID, s.cacheProjectIds)
}

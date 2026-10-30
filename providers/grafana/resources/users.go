// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/grafana/connection"
)

// userFanout bounds concurrent /api/users/{id} and permissions requests during
// bulk pre-hydration. Eight in-flight requests is well below the connection
// limits of typical Grafana deployments and saturates the JSON decode path.
const userFanout = 8

// mqlGrafanaUserInternal holds cached fields populated from /api/users/{id} and
// /api/access-control/users/{id}/permissions. Each cache is fronted by a
// sync.Once so the bulk pre-hydration kicked off by users() and any lazy
// per-user accessor converge on a single fetch.
type mqlGrafanaUserInternal struct {
	detailOnce sync.Once
	detail     grafanaUserDetailJSON
	detailErr  error

	permsOnce sync.Once
	perms     map[string]any
	permsErr  error

	// prefetch is the shared bulk-fetch coordinator across all users returned
	// from a single grafana.users() call. nil when the user was created outside
	// the bulk path; the lazy per-user fetch fallback still works in that case.
	prefetch *userPrefetchGroup
}

// userPrefetchGroup coordinates one-shot, bounded-concurrency pre-hydration of
// user detail and RBAC permissions across the full list returned by
// grafana.users(). Without it, queries like `grafana.users { mfaEnabled }`
// trigger N sequential /api/users/{id} round trips; with it, the first access
// fans out all N in parallel and subsequent field accesses are cache hits.
type userPrefetchGroup struct {
	users []*mqlGrafanaUser
	conn  *connection.GrafanaConnection

	detailFanOnce sync.Once
	permsFanOnce  sync.Once
}

// ensureDetailsFetched performs (at most once) a bounded-concurrency fan-out
// over every user's /api/users/{id}. Each per-user request is guarded by the
// user's own detailOnce so a lazy caller that races with the fan-out still
// reuses the result.
func (g *userPrefetchGroup) ensureDetailsFetched() {
	g.detailFanOnce.Do(func() {
		grp, ctx := errgroup.WithContext(context.Background())
		grp.SetLimit(userFanout)
		for _, u := range g.users {
			grp.Go(func() error {
				u.detailOnce.Do(func() {
					u.detail, u.detailErr = fetchUserDetail(ctx, g.conn, u.UserId.Data)
				})
				return nil
			})
		}
		_ = grp.Wait()
	})
}

// ensurePermissionsFetched mirrors ensureDetailsFetched for the RBAC
// permissions endpoint. Triggered the first time any user's permissions field
// is read.
func (g *userPrefetchGroup) ensurePermissionsFetched() {
	g.permsFanOnce.Do(func() {
		grp, ctx := errgroup.WithContext(context.Background())
		grp.SetLimit(userFanout)
		for _, u := range g.users {
			grp.Go(func() error {
				u.permsOnce.Do(func() {
					u.perms, u.permsErr = fetchUserPermissions(ctx, g.conn, u.UserId.Data)
				})
				return nil
			})
		}
		_ = grp.Wait()
	})
}

// grafanaUserDetailJSON mirrors /api/users/{id}. Fields like isMFAEnabled may
// only be present on Grafana Cloud / Enterprise; they decode to zero when absent.
type grafanaUserDetailJSON struct {
	ID             int      `json:"id"`
	Email          string   `json:"email"`
	Name           string   `json:"name"`
	Login          string   `json:"login"`
	OrgID          int      `json:"orgId"`
	IsGrafanaAdmin bool     `json:"isGrafanaAdmin"`
	IsDisabled     bool     `json:"isDisabled"`
	IsExternal     bool     `json:"isExternal"`
	AuthLabels     []string `json:"authLabels"`
	IsMFAEnabled   bool     `json:"isMFAEnabled"`
	AuthModule     string   `json:"authModule"`
}

// grafanaConnection is a helper that type-asserts the runtime connection to
// *connection.GrafanaConnection. All resource methods must use this instead of
// raw type assertions to get a clear error on misconfigured runtimes.
func grafanaConnection(runtime *plugin.Runtime) (*connection.GrafanaConnection, error) {
	conn, ok := runtime.Connection.(*connection.GrafanaConnection)
	if !ok {
		return nil, fmt.Errorf("grafana: unexpected connection type %T", runtime.Connection)
	}
	return conn, nil
}

// parseGrafanaTime parses a Grafana RFC3339 timestamp, returning the zero
// time.Time on any parse error (e.g. missing or invalid value).
func parseGrafanaTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// grafanaOrgJSON mirrors the /api/org response.
type grafanaOrgJSON struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// grafanaOrgUserJSON mirrors one element of the /api/org/users response.
type grafanaOrgUserJSON struct {
	OrgID         int    `json:"orgId"`
	UserID        int    `json:"userId"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	Login         string `json:"login"`
	Role          string `json:"role"`
	LastSeenAt    string `json:"lastSeenAt"`
	LastSeenAtAge string `json:"lastSeenAtAge"`
}

// initGrafanaOrganization delegates to the parent grafana resource when the
// organization is accessed directly (e.g. grafana.organization.name). Without
// this, NewResource creates an empty stub with no field data.
func initGrafanaOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	grafanaRes, err := NewResource(runtime, "grafana", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	org := grafanaRes.(*mqlGrafana).GetOrganization()
	if org.Error != nil {
		return nil, nil, org.Error
	}
	return nil, org.Data, nil
}

func (g *mqlGrafana) organization() (*mqlGrafanaOrganization, error) {
	conn, err := grafanaConnection(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	resp, err := conn.Get(context.Background(), "/api/org")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("grafana: GET /api/org returned status %d", resp.StatusCode)
	}

	var org grafanaOrgJSON
	if err := json.NewDecoder(resp.Body).Decode(&org); err != nil {
		return nil, fmt.Errorf("grafana: decoding /api/org response: %w", err)
	}

	res, err := CreateResource(g.MqlRuntime, "grafana.organization", map[string]*llx.RawData{
		"id":   llx.IntData(int64(org.ID)),
		"name": llx.StringData(org.Name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGrafanaOrganization), nil
}

func (g *mqlGrafana) users() ([]any, error) {
	conn, err := grafanaConnection(g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	resp, err := conn.Get(context.Background(), "/api/org/users")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("grafana: GET /api/org/users returned status %d", resp.StatusCode)
	}

	var raw []grafanaOrgUserJSON
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("grafana: decoding /api/org/users response: %w", err)
	}

	list := make([]any, 0, len(raw))
	prefetch := &userPrefetchGroup{conn: conn, users: make([]*mqlGrafanaUser, 0, len(raw))}
	for _, u := range raw {
		res, err := CreateResource(g.MqlRuntime, "grafana.user", map[string]*llx.RawData{
			"userId":        llx.IntData(int64(u.UserID)),
			"orgId":         llx.IntData(int64(u.OrgID)),
			"email":         llx.StringData(u.Email),
			"name":          llx.StringData(u.Name),
			"login":         llx.StringData(u.Login),
			"role":          llx.StringData(u.Role),
			"lastSeenAt":    llx.TimeData(parseGrafanaTime(u.LastSeenAt)),
			"lastSeenAtAge": llx.StringData(u.LastSeenAtAge),
		})
		if err != nil {
			return nil, err
		}
		mqlUser := res.(*mqlGrafanaUser)
		// Only wire prefetch on first-write users — CreateResource may return a
		// cached instance from a prior call with its own (possibly populated)
		// caches; mutating that user's prefetch field would race with concurrent
		// readers.
		if mqlUser.prefetch == nil {
			mqlUser.prefetch = prefetch
		}
		prefetch.users = append(prefetch.users, mqlUser)
		list = append(list, mqlUser)
	}
	return list, nil
}

func (o *mqlGrafanaOrganization) id() (string, error) {
	return "grafana-org/" + strconv.FormatInt(o.Id.Data, 10), nil
}

func (u *mqlGrafanaUser) id() (string, error) {
	return "grafana-user/" + strconv.FormatInt(u.UserId.Data, 10), nil
}

// fetchDetail loads the full /api/users/{id} response, returning the cached
// result if already populated. When this user is part of a bulk users() call,
// the first invocation kicks off a bounded-concurrency fan-out that pre-fills
// every sibling user's cache in parallel — eliminating the sequential N+1.
func (u *mqlGrafanaUser) fetchDetail() (grafanaUserDetailJSON, error) {
	if u.prefetch != nil {
		u.prefetch.ensureDetailsFetched()
	}
	u.detailOnce.Do(func() {
		conn, err := grafanaConnection(u.MqlRuntime)
		if err != nil {
			u.detailErr = err
			return
		}
		u.detail, u.detailErr = fetchUserDetail(context.Background(), conn, u.UserId.Data)
	})
	return u.detail, u.detailErr
}

// fetchUserDetail issues a single /api/users/{id} request. 403 / 404 are
// tolerated — the caller may be an org-admin without server-admin reach, or
// the user may have been deleted. In those cases the zero-value detail is
// returned without an error so org-admin queries still succeed.
func fetchUserDetail(ctx context.Context, conn *connection.GrafanaConnection, userID int64) (grafanaUserDetailJSON, error) {
	var detail grafanaUserDetailJSON
	path := "/api/users/" + strconv.FormatInt(userID, 10)
	resp, err := conn.Get(ctx, path)
	if err != nil {
		return detail, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return detail, nil
	}
	if resp.StatusCode != http.StatusOK {
		return detail, fmt.Errorf("grafana: GET %s returned status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return detail, fmt.Errorf("grafana: decoding %s response: %w", path, err)
	}
	return detail, nil
}

func (u *mqlGrafanaUser) authModule() (string, error) {
	d, err := u.fetchDetail()
	if err != nil {
		return "", err
	}
	if d.AuthModule != "" {
		return d.AuthModule, nil
	}
	// Older Grafana versions only expose the provider in authLabels (e.g., "OAuth").
	if len(d.AuthLabels) > 0 {
		return d.AuthLabels[0], nil
	}
	return "", nil
}

func (u *mqlGrafanaUser) authLabels() ([]any, error) {
	d, err := u.fetchDetail()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(d.AuthLabels))
	for _, l := range d.AuthLabels {
		out = append(out, l)
	}
	return out, nil
}

func (u *mqlGrafanaUser) isExternal() (bool, error) {
	d, err := u.fetchDetail()
	if err != nil {
		return false, err
	}
	if d.IsExternal {
		return true, nil
	}
	// authLabels presence is a reliable secondary signal of external auth.
	return len(d.AuthLabels) > 0, nil
}

func (u *mqlGrafanaUser) isGrafanaAdmin() (bool, error) {
	d, err := u.fetchDetail()
	if err != nil {
		return false, err
	}
	return d.IsGrafanaAdmin, nil
}

func (u *mqlGrafanaUser) isDisabled() (bool, error) {
	d, err := u.fetchDetail()
	if err != nil {
		return false, err
	}
	return d.IsDisabled, nil
}

// mfaEnabled reports the isMFAEnabled flag from /api/users/{id}. The field is
// only populated on Grafana Cloud and Enterprise; OSS Grafana has no per-user
// MFA state and will always return false.
func (u *mqlGrafanaUser) mfaEnabled() (bool, error) {
	d, err := u.fetchDetail()
	if err != nil {
		return false, err
	}
	return d.IsMFAEnabled, nil
}

// permissions returns the RBAC permissions granted to this user as a map of
// action -> []scope. Requires Grafana Enterprise/Cloud with RBAC enabled. When
// this user is part of a bulk users() call, the first invocation fan-outs
// permissions calls for every sibling so the second-pass N+1 is collapsed.
func (u *mqlGrafanaUser) permissions() (map[string]any, error) {
	if u.prefetch != nil {
		u.prefetch.ensurePermissionsFetched()
	}
	u.permsOnce.Do(func() {
		conn, err := grafanaConnection(u.MqlRuntime)
		if err != nil {
			u.permsErr = err
			return
		}
		u.perms, u.permsErr = fetchUserPermissions(context.Background(), conn, u.UserId.Data)
	})
	return u.perms, u.permsErr
}

// fetchUserPermissions issues a single permissions request. 403 / 404 are
// tolerated — the endpoint may not exist (OSS), RBAC may be disabled, or the
// caller may lack access — and return an empty (non-nil) map so MQL iteration
// over the value is safe.
func fetchUserPermissions(ctx context.Context, conn *connection.GrafanaConnection, userID int64) (map[string]any, error) {
	path := "/api/access-control/users/" + strconv.FormatInt(userID, 10) + "/permissions"
	resp, err := conn.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return map[string]any{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("grafana: GET %s returned status %d", path, resp.StatusCode)
	}
	var raw map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("grafana: decoding %s response: %w", path, err)
	}
	out := make(map[string]any, len(raw))
	for k, scopes := range raw {
		anyScopes := make([]any, len(scopes))
		for i, s := range scopes {
			anyScopes[i] = s
		}
		out[k] = anyScopes
	}
	return out, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/vercel/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlVercel) id() (string, error) {
	return "vercel", nil
}

// --- shared helpers -------------------------------------------------------

// flexTime decodes a Vercel timestamp that may arrive either as a millisecond
// epoch number or as an RFC 3339 string, yielding a time value or nil.
type flexTime struct {
	t *time.Time
}

func (f *flexTime) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == "" {
		return nil
	}
	if s[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		if str == "" {
			return nil
		}
		if tt, err := time.Parse(time.RFC3339, str); err == nil {
			f.t = &tt
		}
		return nil
	}
	var ms int64
	if err := json.Unmarshal(b, &ms); err != nil {
		return err
	}
	tt := time.UnixMilli(ms)
	f.t = &tt
	return nil
}

// Time returns the decoded time value, or nil when the source was absent.
func (f flexTime) Time() *time.Time {
	return f.t
}

// strSliceToAny widens a string slice into an any slice for llx.ArrayData.
func strSliceToAny(in []string) []any {
	out := make([]any, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

// dictSliceToAny widens a slice of maps into an any slice for a []dict field.
func dictSliceToAny(in []map[string]any) []any {
	out := make([]any, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

// mapStrToAny widens a string map into a map[string]any for a map field.
func mapStrToAny(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// intPtrOrZero dereferences an int pointer, returning 0 when nil.
func intPtrOrZero(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// --- root resource --------------------------------------------------------

func (v *mqlVercel) teams() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VercelConnection)
	records, err := connection.GetPaged[teamRecord](context.Background(), conn, "/v2/teams", nil, "teams")
	if err != nil {
		return nil, err
	}

	filter := ""
	if conn.Conf != nil && conn.Conf.Options != nil {
		filter = conn.Conf.Options["team"]
	}

	var res []any
	for i := range records {
		rec := records[i]
		if filter != "" && rec.ID != filter && rec.Slug != filter {
			continue
		}
		team, err := newVercelTeam(v.MqlRuntime, &rec)
		if err != nil {
			return nil, err
		}
		res = append(res, team)
	}
	return res, nil
}

func (v *mqlVercel) projects() ([]any, error) {
	teams, err := v.teams()
	if err != nil {
		return nil, err
	}

	var res []any
	for _, it := range teams {
		team := it.(*mqlVercelTeam)
		projects := team.GetProjects()
		if projects.Error != nil {
			return nil, projects.Error
		}
		res = append(res, projects.Data...)
	}
	return res, nil
}

type userRecord struct {
	ID        string   `json:"id"`
	UID       string   `json:"uid"`
	Email     string   `json:"email"`
	Username  string   `json:"username"`
	Name      string   `json:"name"`
	CreatedAt flexTime `json:"createdAt"`
}

func (v *mqlVercel) currentUser() (*mqlVercelUser, error) {
	conn := v.MqlRuntime.Connection.(*connection.VercelConnection)

	var resp struct {
		User userRecord `json:"user"`
	}
	if err := conn.Get(context.Background(), "/v2/user", nil, &resp); err != nil {
		return nil, err
	}

	id := resp.User.ID
	if id == "" {
		id = resp.User.UID
	}

	res, err := CreateResource(v.MqlRuntime, "vercel.user", map[string]*llx.RawData{
		"id":        llx.StringData(id),
		"email":     llx.StringData(resp.User.Email),
		"username":  llx.StringData(resp.User.Username),
		"name":      llx.StringData(resp.User.Name),
		"createdAt": llx.TimeDataPtr(resp.User.CreatedAt.Time()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVercelUser), nil
}

func (c *mqlVercelUser) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

type tokenRecord struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Origin     string   `json:"origin"`
	Scopes     []any    `json:"scopes"`
	ExpiresAt  flexTime `json:"expiresAt"`
	CreatedAt  flexTime `json:"createdAt"`
	LastUsedAt flexTime `json:"lastUsedAt"`
}

func (v *mqlVercel) accessTokens() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VercelConnection)
	records, err := connection.GetPaged[tokenRecord](context.Background(), conn, "/v5/user/tokens", nil, "tokens")
	if err != nil {
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		scopes := rec.Scopes
		if scopes == nil {
			scopes = []any{}
		}
		token, err := CreateResource(v.MqlRuntime, "vercel.accessToken", map[string]*llx.RawData{
			"id":         llx.StringData(rec.ID),
			"name":       llx.StringData(rec.Name),
			"tokenType":  llx.StringData(rec.Type),
			"origin":     llx.StringData(rec.Origin),
			"scopes":     llx.ArrayData(scopes, types.Dict),
			"expiresAt":  llx.TimeDataPtr(rec.ExpiresAt.Time()),
			"createdAt":  llx.TimeDataPtr(rec.CreatedAt.Time()),
			"lastUsedAt": llx.TimeDataPtr(rec.LastUsedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, token)
	}
	return res, nil
}

func (c *mqlVercelAccessToken) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

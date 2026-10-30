// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/url"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/nextdns/connection"
)

func (r *mqlNextdns) id() (string, error) {
	return "nextdns", nil
}

// profileData is one entry of the GET /profiles response.
type profileData struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}

type profilesResponse struct {
	Data []profileData `json:"data"`
	Meta profilesMeta  `json:"meta"`
}

// profilesMeta carries the cursor that continues a profile listing. NextDNS
// returns an empty (or absent) cursor on the last page.
type profilesMeta struct {
	Pagination struct {
		Cursor string `json:"cursor"`
	} `json:"pagination"`
}

// maxProfilePages bounds the pagination walk. It is a backstop against a
// server that keeps handing out fresh cursors forever, not an expected limit:
// a NextDNS account holding this many pages of profiles is far outside any
// real deployment.
const maxProfilePages = 1000

// fetchProfiles returns the profiles visible to the connection. When the
// connection is scoped to a single profile, that profile is fetched directly
// so we never list (or expose) profiles the connection shouldn't see.
//
// The account-level listing is paginated. It is walked to exhaustion, because
// stopping at the first page silently drops every profile beyond it and
// reports the short enumeration as a successful scan: findings on the missing
// profiles simply would not exist. Both termination guards return an error
// rather than the profiles gathered so far, since a knowingly incomplete list
// is the very failure being fixed and must not pass for a complete one.
func fetchProfiles(conn *connection.NextdnsConnection) ([]profileData, error) {
	ctx := context.Background()

	if scoped := conn.ProfileID(); scoped != "" {
		var resp profileDetailResponse
		if err := conn.Get(ctx, "/profiles/"+scoped, &resp); err != nil {
			return nil, err
		}
		return []profileData{{
			ID:          scoped,
			Name:        resp.Data.Name,
			Fingerprint: resp.Data.Fingerprint,
		}}, nil
	}

	var (
		profiles []profileData
		cursor   string
		seen     = map[string]struct{}{}
	)
	for page := range maxProfilePages {
		path := "/profiles"
		if cursor != "" {
			path += "?cursor=" + url.QueryEscape(cursor)
		}

		var resp profilesResponse
		if err := conn.Get(ctx, path, &resp); err != nil {
			return nil, err
		}
		profiles = append(profiles, resp.Data...)

		next := resp.Meta.Pagination.Cursor
		if next == "" {
			return profiles, nil
		}
		// A server that repeats a cursor would otherwise spin the scan
		// forever, re-reading the same page.
		if _, repeated := seen[next]; repeated {
			return nil, fmt.Errorf("nextdns profile listing returned a repeated pagination cursor after %d pages; the profile list is incomplete", page+1)
		}
		seen[next] = struct{}{}
		cursor = next
	}

	return nil, fmt.Errorf("nextdns profile listing did not finish within %d pages; the profile list is incomplete", maxProfilePages)
}

// profilesToResources fetches profiles for the connection and maps them to
// nextdns.profile resources.
func profilesToResources(runtime *plugin.Runtime, conn *connection.NextdnsConnection) ([]any, error) {
	profiles, err := fetchProfiles(conn)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(profiles))
	for _, p := range profiles {
		mqlProfile, err := NewResource(runtime, "nextdns.profile", map[string]*llx.RawData{
			"id":          llx.StringData(p.ID),
			"name":        llx.StringData(p.Name),
			"fingerprint": llx.StringData(p.Fingerprint),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlProfile)
	}
	return res, nil
}

func (r *mqlNextdns) profiles() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.NextdnsConnection)
	return profilesToResources(r.MqlRuntime, conn)
}

func (r *mqlNextdns) account() (*mqlNextdnsAccount, error) {
	conn := r.MqlRuntime.Connection.(*connection.NextdnsConnection)
	res, err := CreateResource(r.MqlRuntime, "nextdns.account", map[string]*llx.RawData{
		"id": llx.StringData(conn.AccountID()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNextdnsAccount), nil
}

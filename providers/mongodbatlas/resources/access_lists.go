// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

// apiAccessListEntry is the normalized form of an access list entry. Atlas
// returns the same entry under two different shapes, one for API keys and one
// for service accounts, with the usage fields named differently in each. Both
// are mapped into this shape so a single resource, and therefore a single
// query, covers either kind of programmatic credential.
type apiAccessListEntry struct {
	cidrBlock       string
	ipAddress       string
	created         *time.Time
	requestCount    int64
	lastUsed        *time.Time
	lastUsedAddress string
}

// apiKeyAccessEntry normalizes an API key access list entry.
func apiKeyAccessEntry(e admin.UserAccessListResponse) apiAccessListEntry {
	return apiAccessListEntry{
		cidrBlock:       e.GetCidrBlock(),
		ipAddress:       e.GetIpAddress(),
		created:         timePtr(e.GetCreated()),
		requestCount:    int64(e.GetCount()),
		lastUsed:        timePtr(e.GetLastUsed()),
		lastUsedAddress: e.GetLastUsedAddress(),
	}
}

// serviceAccountAccessEntry normalizes a service account access list entry.
func serviceAccountAccessEntry(e admin.ServiceAccountIPAccessListEntry) apiAccessListEntry {
	return apiAccessListEntry{
		cidrBlock:       e.GetCidrBlock(),
		ipAddress:       e.GetIpAddress(),
		created:         timePtr(e.GetCreatedAt()),
		requestCount:    int64(e.GetRequestCount()),
		lastUsed:        timePtr(e.GetLastUsedAt()),
		lastUsedAddress: e.GetLastUsedAddress(),
	}
}

// accessListEntryID builds the cache key for an access list entry under the
// credential that grants it. Atlas reports a single address as both an
// ipAddress and an equivalent /32 CIDR block, so the CIDR is the stable key and
// the address is only the fallback for an entry that reports no CIDR.
func accessListEntryID(parent string, e apiAccessListEntry) string {
	value := e.cidrBlock
	if value == "" {
		value = e.ipAddress
	}
	return "mongodbatlas.apiAccessListEntry/" + parent + "/" + value
}

func newMqlMongodbatlasApiAccessListEntry(runtime *plugin.Runtime, parent string, e apiAccessListEntry) (*mqlMongodbatlasApiAccessListEntry, error) {
	res, err := CreateResource(runtime, "mongodbatlas.apiAccessListEntry", map[string]*llx.RawData{
		"__id":            llx.StringData(accessListEntryID(parent, e)),
		"cidrBlock":       llx.StringData(e.cidrBlock),
		"ipAddress":       llx.StringData(e.ipAddress),
		"created":         llx.TimeDataPtr(e.created),
		"requestCount":    llx.IntData(e.requestCount),
		"lastUsed":        llx.TimeDataPtr(e.lastUsed),
		"lastUsedAddress": llx.StringData(e.lastUsedAddress),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasApiAccessListEntry), nil
}

// accessList reports the addresses the API key may authenticate from. An empty
// list means the key carries no source restriction and works from anywhere the
// Atlas API is reachable, which is the state the organization setting
// apiAccessListRequired exists to prevent.
func (r *mqlMongodbatlasApiKey) accessList() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, httpResp, err := client.ProgrammaticAPIKeysAPI.
			ListOrgAccessEntries(ctx, oid, r.cacheApiKeyID).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			// An empty access list is precisely the finding this accessor
			// reports, so a denied read must not render as one. Null instead,
			// which fails an audit over it rather than passing it vacuously.
			if isAccessDenied(httpResp) {
				r.AccessList.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			entry, err := newMqlMongodbatlasApiAccessListEntry(r.MqlRuntime,
				"apiKey/"+r.cacheApiKeyID, apiKeyAccessEntry(results[i]))
			if err != nil {
				return nil, err
			}
			out = append(out, entry)
		}
		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}

// accessList reports the addresses the service account may authenticate from.
// As with an API key, an empty list means the credential is usable from any
// address.
func (r *mqlMongodbatlasServiceAccount) accessList() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()
	clientID := r.ClientId.Data

	out := []any{}
	for page := 1; ; page++ {
		resp, httpResp, err := client.ServiceAccountsAPI.
			ListOrgAccessList(ctx, oid, clientID).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			if isAccessDenied(httpResp) {
				r.AccessList.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			entry, err := newMqlMongodbatlasApiAccessListEntry(r.MqlRuntime,
				"serviceAccount/"+clientID, serviceAccountAccessEntry(results[i]))
			if err != nil {
				return nil, err
			}
			out = append(out, entry)
		}
		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}

// projects resolves the projects the service account is assigned to, which is
// the reach a leaked client secret would carry. The assignment listing returns
// project ids only, so each is resolved against the organization's project
// listing.
func (r *mqlMongodbatlasServiceAccount) projects() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()
	clientID := r.ClientId.Data

	groupIDs := []string{}
	for page := 1; ; page++ {
		resp, httpResp, err := client.ServiceAccountsAPI.
			GetServiceAccountGroups(ctx, oid, clientID).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			// A denied read establishes nothing about the account's reach, so
			// it must not render as "assigned to no project".
			if isAccessDenied(httpResp) {
				r.Projects.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			if id := results[i].GetGroupId(); id != "" {
				groupIDs = append(groupIDs, id)
			}
		}
		if len(results) < pageSize {
			break
		}
	}

	out := []any{}
	for _, id := range groupIDs {
		// A failure here is reported rather than skipped: dropping the entry
		// would under-report the account's reach.
		proj, err := resolveProject(r.MqlRuntime, id)
		if err != nil {
			return nil, err
		}
		out = append(out, proj)
	}
	return out, nil
}

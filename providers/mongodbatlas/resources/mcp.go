// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

// mcpUnavailable reports whether the endpoint answered in a way that means
// Remote MCP is off or unreadable, rather than that no configurations exist.
// The distinction matters: an empty list is the claim "no agent can reach this
// deployment", which a denied read has not established.
func mcpUnavailable(resp *http.Response) bool {
	return isAccessDenied(resp) || (resp != nil && resp.StatusCode == http.StatusNotFound)
}

type mqlMongodbatlasMcpConfigurationInternal struct {
	cacheClientID string
}

const (
	mcpScopeOrganization = "ORGANIZATION"
	mcpScopeProject      = "PROJECT"
)

// mcpConfigFields is the shape shared by the organization and project responses.
// The two SDK types are structurally identical but unrelated, so the lists are
// normalized onto this before the resource is built.
type mcpConfigFields struct {
	id             string
	name           string
	scope          string
	roles          []string
	clientID       string
	egressClientID string
	ipAccessList   []admin.ServiceAccountIPAccessListEntry
}

func newMqlMongodbatlasMcpConfiguration(runtime *plugin.Runtime, parent string, c mcpConfigFields) (*mqlMongodbatlasMcpConfiguration, error) {
	entries := []any{}
	for i := range c.ipAccessList {
		entry, err := newMqlMongodbatlasApiAccessListEntry(runtime, "mcp/"+c.id, serviceAccountAccessEntry(c.ipAccessList[i]))
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	res, err := CreateResource(runtime, "mongodbatlas.mcpConfiguration", map[string]*llx.RawData{
		// The id is unique per scope, not globally, so the cache key carries the
		// organization or project it was read from.
		"__id":           llx.StringData("mongodbatlas.mcpConfiguration/" + parent + "/" + c.id),
		"id":             llx.StringData(c.id),
		"name":           llx.StringData(c.name),
		"scope":          llx.StringData(c.scope),
		"roles":          llx.ArrayData(strSlice(c.roles), types.String),
		"clientId":       llx.StringData(c.clientID),
		"egressClientId": llx.StringData(c.egressClientID),
		"ipAccessList":   llx.ArrayData(entries, types.Resource("mongodbatlas.apiAccessListEntry")),
	})
	if err != nil {
		return nil, err
	}

	mqlCfg := res.(*mqlMongodbatlasMcpConfiguration)
	mqlCfg.cacheClientID = c.clientID
	return mqlCfg, nil
}

// mcpConfigurations reports the Remote MCP configurations defined at the
// organization. Each one is a standing path into every project beneath it, so
// an organization with configurations nobody remembers creating is the finding.
func (r *mqlMongodbatlas) mcpConfigurations() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, httpResp, err := atlasClient(r.MqlRuntime).RemoteMCPConfigurationsAPI.
			ListOrgMcpConfigs(ctx, oid).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			// Remote MCP is not enabled on every organization, and a credential
			// that cannot read it has established nothing about which
			// configurations exist. Render null rather than an empty list, which
			// would assert there are none.
			if mcpUnavailable(httpResp) {
				r.McpConfigurations.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}

		results := resp.GetResults()
		for i := range results {
			c := results[i]
			cfg, err := newMqlMongodbatlasMcpConfiguration(r.MqlRuntime, "org/"+oid, mcpConfigFields{
				id:             c.GetMcpConfigId(),
				name:           c.GetMcpConfigName(),
				scope:          mcpScopeOrganization,
				roles:          c.GetRoles(),
				clientID:       c.GetClientId(),
				egressClientID: c.GetEgressClientId(),
				ipAccessList:   c.GetIpAccessList(),
			})
			if err != nil {
				return nil, err
			}
			out = append(out, cfg)
		}

		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}

// projectMcpConfigurations reports the Remote MCP configurations defined on the
// project. A project can carry its own independently of the organization, so
// both lists have to be read to see every agent path into the data.
func (r *mqlMongodbatlas) projectMcpConfigurations() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, httpResp, err := atlasClient(r.MqlRuntime).RemoteMCPConfigurationsAPI.
			ListGroupMcpConfigs(ctx, pid).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			if mcpUnavailable(httpResp) {
				r.ProjectMcpConfigurations.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}

		results := resp.GetResults()
		for i := range results {
			c := results[i]
			cfg, err := newMqlMongodbatlasMcpConfiguration(r.MqlRuntime, "group/"+pid, mcpConfigFields{
				id:             c.GetMcpConfigId(),
				name:           c.GetMcpConfigName(),
				scope:          mcpScopeProject,
				roles:          c.GetRoles(),
				clientID:       c.GetClientId(),
				egressClientID: c.GetEgressClientId(),
				ipAccessList:   c.GetIpAccessList(),
			})
			if err != nil {
				return nil, err
			}
			out = append(out, cfg)
		}

		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}

// serviceAccount resolves the account the MCP client authenticates as by
// scanning the organization's service account list, which is fetched once and
// cached, rather than looking the account up per configuration.
func (r *mqlMongodbatlasMcpConfiguration) serviceAccount() (*mqlMongodbatlasServiceAccount, error) {
	if r.cacheClientID == "" {
		r.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	atlas, err := CreateResource(r.MqlRuntime, "mongodbatlas", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}

	accounts := atlas.(*mqlMongodbatlas).GetServiceAccounts()
	if accounts.Error != nil {
		return nil, accounts.Error
	}

	for _, a := range accounts.Data {
		sa, ok := a.(*mqlMongodbatlasServiceAccount)
		if !ok {
			continue
		}
		if sa.ClientId.Data == r.cacheClientID {
			return sa, nil
		}
	}

	// The MCP service account is not always visible in the organization list,
	// for instance when the credential reads MCP but not service accounts.
	// Report null rather than an error so the rest of the configuration still
	// renders.
	r.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

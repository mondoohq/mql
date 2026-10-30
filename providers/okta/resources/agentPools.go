// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOkta) agentPools() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.AgentPoolsAPI.ListAgentPools(ctx).Execute()
	if err != nil {
		// Orgs with no on-premises agents deployed have no pools endpoint.
		if isOktaFeatureUnavailable(resp, err) {
			return nil, nil
		}
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.AgentPool) error {
		for i := range datalist {
			r, err := newMqlOktaAgentPool(o.MqlRuntime, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(slice); err != nil {
		return nil, err
	}
	for resp != nil && resp.HasNextPage() {
		var page []okta.AgentPool
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func newMqlOktaAgentPool(runtime *plugin.Runtime, entry *okta.AgentPool) (any, error) {
	poolID := oktaStr(entry.Id)

	agents := []any{}
	for i := range entry.Agents {
		agent, err := newMqlOktaAgent(runtime, poolID, &entry.Agents[i])
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}

	return CreateResource(runtime, "okta.agentPool", map[string]*llx.RawData{
		"id":                llx.StringData(poolID),
		"name":              llx.StringData(oktaStr(entry.Name)),
		"type":              llx.StringData(oktaStr(entry.Type)),
		"operationalStatus": llx.StringData(oktaStr(entry.OperationalStatus)),
		"disruptedAgents":   llx.IntDataPtr(oktaInt64(entry.DisruptedAgents)),
		"inactiveAgents":    llx.IntDataPtr(oktaInt64(entry.InactiveAgents)),
		"agents":            llx.ArrayData(agents, types.Resource("okta.agentPool.agent")),
	})
}

// newMqlOktaAgent builds an agent. Agent ids are unique within a pool rather
// than org-wide, so the pool id qualifies the cache key.
func newMqlOktaAgent(runtime *plugin.Runtime, poolID string, entry *okta.Agent) (any, error) {
	return CreateResource(runtime, "okta.agentPool.agent", map[string]*llx.RawData{
		"__id":                llx.StringData(poolID + "/" + oktaStr(entry.Id)),
		"id":                  llx.StringData(oktaStr(entry.Id)),
		"name":                llx.StringData(oktaStr(entry.Name)),
		"type":                llx.StringData(oktaStr(entry.Type)),
		"version":             llx.StringData(oktaStr(entry.Version)),
		"isLatestGAedVersion": llx.BoolDataPtr(entry.IsLatestGAedVersion),
		"lastConnection":      llx.TimeDataPtr(oktaTimeFromUnixMillis(entry.LastConnection)),
		"operationalStatus":   llx.StringData(oktaStr(entry.OperationalStatus)),
		"updateStatus":        llx.StringData(oktaStr(entry.UpdateStatus)),
		"updateMessage":       llx.StringData(oktaStr(entry.UpdateMessage)),
		"isHidden":            llx.BoolDataPtr(entry.IsHidden),
	})
}

func (o *mqlOktaAgentPool) id() (string, error) {
	return "okta.agentPool/" + o.Id.Data, o.Id.Error
}

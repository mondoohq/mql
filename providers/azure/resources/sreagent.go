// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// Azure SRE Agent has no Go SDK module, so its agents are listed with
// requests through the azcore ARM pipeline (see arm_raw.go).

// sreAgentAPIVersion is a stable Microsoft.App/agents API version.
const sreAgentAPIVersion = "2026-01-01"

// sreAgent is one Microsoft.App/agents row.
type sreAgent struct {
	armTrackedResource
	Properties *struct {
		ProvisioningState           *string `json:"provisioningState"`
		AgentEndpoint               *string `json:"agentEndpoint"`
		RunningState                *string `json:"runningState"`
		PowerState                  *string `json:"powerState"`
		UpgradeChannel              *string `json:"upgradeChannel"`
		KnowledgeGraphConfiguration *struct {
			Identity         *string   `json:"identity"`
			ManagedResources []*string `json:"managedResources"`
		} `json:"knowledgeGraphConfiguration"`
		ActionConfiguration *struct {
			Identity    *string `json:"identity"`
			Mode        *string `json:"mode"`
			AccessLevel *string `json:"accessLevel"`
		} `json:"actionConfiguration"`
	} `json:"properties"`
}

type mqlAzureSubscriptionSreAgentServiceAgentInternal struct {
	cacheActionIdentityId         string
	cacheKnowledgeGraphIdentityId string
}

func (a *mqlAzureSubscription) sreAgent() (*mqlAzureSubscriptionSreAgentService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionSreAgentService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionSreAgentService), nil
}

func initAzureSubscriptionSreAgentService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, err := azureConn(runtime)
	if err != nil {
		return nil, nil, err
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())
	return args, nil, nil
}

func (a *mqlAzureSubscriptionSreAgentService) id() (string, error) {
	return ResourceAzureSubscriptionSreAgentService + "/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionSreAgentService) agents() ([]any, error) {
	conn, err := azureConn(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client, err := newRawArmClient(conn, "mql-azure-sreagent")
	if err != nil {
		return nil, err
	}
	first := armSubscriptionCollectionURL(client, a.SubscriptionId.Data, "Microsoft.App/agents", sreAgentAPIVersion)
	res, err := listPaged(a.MqlRuntime, &a.Agents, "SRE Agents",
		newArmJSONPager[sreAgent](client, "SRE Agents", first),
		func(page armJSONPage[sreAgent]) []*sreAgent { return page.Value },
		createSreAgent,
	)
	if err != nil || res == nil {
		return res, err
	}
	return keepTagMatches(a.MqlRuntime, res), nil
}

// createSreAgent builds the MQL resource for one SRE Agent.
func createSreAgent(runtime *plugin.Runtime, agent *sreAgent) (plugin.Resource, error) {
	p := orZero(agent.Properties)
	kg := orZero(p.KnowledgeGraphConfiguration)
	action := orZero(p.ActionConfiguration)
	args := map[string]*llx.RawData{
		"id":                llx.StringDataPtr(agent.ID),
		"name":              llx.StringDataPtr(agent.Name),
		"location":          llx.StringDataPtr(agent.Location),
		"tags":              llx.MapData(convert.PtrMapStrToInterface(agent.Tags), types.String),
		"provisioningState": llx.StringDataPtr(p.ProvisioningState),
		"powerState":        llx.StringDataPtr(p.PowerState),
		"runningState":      llx.StringDataPtr(p.RunningState),
		"agentEndpoint":     llx.StringDataPtr(p.AgentEndpoint),
		"upgradeChannel":    llx.StringDataPtr(p.UpgradeChannel),
		"actionMode":        llx.StringData(convert.ToValue(action.Mode)),
		"actionAccessLevel": llx.StringData(convert.ToValue(action.AccessLevel)),
		"managedResources":  llx.ArrayData(strPtrsToAny(kg.ManagedResources), types.String),
	}
	if err := setArmResourceIdentity(runtime, args, agent.Identity); err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, ResourceAzureSubscriptionSreAgentServiceAgent, args)
	if err != nil {
		return nil, err
	}
	mqlAgent := res.(*mqlAzureSubscriptionSreAgentServiceAgent)
	mqlAgent.cacheActionIdentityId = convert.ToValue(action.Identity)
	mqlAgent.cacheKnowledgeGraphIdentityId = convert.ToValue(kg.Identity)
	return mqlAgent, nil
}

func (a *mqlAzureSubscriptionSreAgentServiceAgent) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionSreAgentServiceAgent) actionIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	return userAssignedIdentityRef(a.MqlRuntime, a.cacheActionIdentityId, &a.ActionIdentity)
}

func (a *mqlAzureSubscriptionSreAgentServiceAgent) knowledgeGraphIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	return userAssignedIdentityRef(a.MqlRuntime, a.cacheKnowledgeGraphIdentityId, &a.KnowledgeGraphIdentity)
}

// resourceGroupScopes returns the managed scopes that are resource groups,
// lowercased, as a set. A scope below a resource group (a single resource)
// or above one (a subscription) is not a resource group and is left out.
func resourceGroupScopes(scopes []any) map[string]struct{} {
	out := map[string]struct{}{}
	for _, s := range scopes {
		id, ok := s.(string)
		if !ok {
			continue
		}
		parts := strings.Split(strings.Trim(id, "/"), "/")
		if len(parts) == 4 && strings.EqualFold(parts[0], "subscriptions") && strings.EqualFold(parts[2], "resourceGroups") {
			out[strings.ToLower("/"+strings.Join(parts, "/"))] = struct{}{}
		}
	}
	return out
}

// managedResourceGroups resolves the resource-group scopes of the agent
// against the subscription's resource groups, so one listing serves every
// agent.
func (a *mqlAzureSubscriptionSreAgentServiceAgent) managedResourceGroups() ([]any, error) {
	wanted := resourceGroupScopes(a.ManagedResources.Data)
	if len(wanted) == 0 {
		return []any{}, nil
	}
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	sub, err := CreateResource(a.MqlRuntime, ResourceAzureSubscription, map[string]*llx.RawData{
		"__id":           llx.StringData("/subscriptions/" + parsed.SubscriptionID),
		"subscriptionId": llx.StringData(parsed.SubscriptionID),
	})
	if err != nil {
		return nil, err
	}
	rgs := sub.(*mqlAzureSubscription).GetResourceGroups()
	if rgs.Error != nil {
		return nil, rgs.Error
	}
	res := []any{}
	for _, rg := range rgs.Data {
		mqlRg, ok := rg.(*mqlAzureSubscriptionResourcegroup)
		if !ok {
			continue
		}
		if _, ok := wanted[strings.ToLower(mqlRg.Id.Data)]; ok {
			res = append(res, mqlRg)
		}
	}
	return res, nil
}

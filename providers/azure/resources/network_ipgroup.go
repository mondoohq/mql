// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionNetworkServiceIpGroupInternal struct {
	cacheFirewallIds       []string
	cacheFirewallPolicyIds []string
}

// ipGroups lists the IP groups in the subscription. IP groups are reusable
// address/prefix collections that firewall and firewall-policy rules reference
// in bulk.
func (a *mqlAzureSubscriptionNetworkService) ipGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := network.NewIPGroupsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(&network.IPGroupsClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ipg := range page.Value {
			if ipg == nil {
				continue
			}
			mqlIpGroup, err := azureIpGroupToMql(a.MqlRuntime, *ipg)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlIpGroup)
		}
	}
	return res, nil
}

// azureIpGroupToMql maps an IP group into its MQL resource, caching the ARM IDs
// of the firewalls and firewall policies that reference it so the typed
// backreferences resolve lazily. Shared by the list accessor and the init
// (by-ID) path so both produce identical resources.
func azureIpGroupToMql(runtime *plugin.Runtime, ipg network.IPGroup) (*mqlAzureSubscriptionNetworkServiceIpGroup, error) {
	var provisioningState string
	ipAddresses := []any{}
	var firewallIds, firewallPolicyIds []string
	if ipg.Properties != nil {
		if ipg.Properties.ProvisioningState != nil {
			provisioningState = string(*ipg.Properties.ProvisioningState)
		}
		ipAddresses = strPtrsToAny(ipg.Properties.IPAddresses)
		firewallIds = azureNetworkSubResourceIDs(ipg.Properties.Firewalls)
		firewallPolicyIds = azureNetworkSubResourceIDs(ipg.Properties.FirewallPolicies)
	}
	mqlIpGroup, err := CreateResource(runtime, "azure.subscription.networkService.ipGroup",
		map[string]*llx.RawData{
			"id":                llx.StringDataPtr(ipg.ID),
			"name":              llx.StringDataPtr(ipg.Name),
			"location":          llx.StringDataPtr(ipg.Location),
			"tags":              llx.MapData(convert.PtrMapStrToInterface(ipg.Tags), types.String),
			"type":              llx.StringDataPtr(ipg.Type),
			"etag":              llx.StringDataPtr(ipg.Etag),
			"provisioningState": llx.StringData(provisioningState),
			"ipAddresses":       llx.ArrayData(ipAddresses, types.String),
		})
	if err != nil {
		return nil, err
	}
	res := mqlIpGroup.(*mqlAzureSubscriptionNetworkServiceIpGroup)
	res.cacheFirewallIds = firewallIds
	res.cacheFirewallPolicyIds = firewallPolicyIds
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceIpGroup) id() (string, error) {
	return a.Id.Data, nil
}

// firewalls resolves the typed firewalls that reference this IP group from the
// cached ARM IDs. Each firewall resolves lazily through its init.
func (a *mqlAzureSubscriptionNetworkServiceIpGroup) firewalls() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, "azure.subscription.networkService.firewall", a.cacheFirewallIds)
}

// firewallPolicies resolves the typed firewall policies that reference this IP
// group from the cached ARM IDs.
func (a *mqlAzureSubscriptionNetworkServiceIpGroup) firewallPolicies() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, "azure.subscription.networkService.firewallPolicy", a.cacheFirewallPolicyIds)
}

// azureNetworkSubResourceIDs flattens a slice of *network.SubResource into
// their ARM IDs, skipping nil entries and nil inner IDs.
func azureNetworkSubResourceIDs(subs []*network.SubResource) []string {
	var ids []string
	for _, s := range subs {
		if s != nil && s.ID != nil {
			ids = append(ids, *s.ID)
		}
	}
	return ids
}

// azureStrPtrsToStr dereferences a slice of *string into []string, skipping nil
// entries. Unlike convert.SliceStrPtrToStr it does not panic when the Azure API
// returns a nil pointer inside the slice.
func azureStrPtrsToStr(s []*string) []string {
	var res []string
	for _, v := range s {
		if v != nil {
			res = append(res, *v)
		}
	}
	return res
}

// azureResourceRefsByID turns a list of ARM resource IDs into typed MQL
// resource references, letting each resolve lazily through its init function.
func azureResourceRefsByID(runtime *plugin.Runtime, resourceName string, ids []string) ([]any, error) {
	res := []any{}
	for _, id := range ids {
		if id == "" {
			continue
		}
		r, err := NewResource(runtime, resourceName, map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func initAzureSubscriptionNetworkServiceIpGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := azureId.Component("ipGroups")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceIpGroup, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewIPGroupsClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azureIpGroupToMql(runtime, resp.IPGroup)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}

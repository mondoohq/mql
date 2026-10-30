// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// The effective-security-rule values arrive as raw JSON rather than SDK structs:
// armnetwork v9 misshaped EffectiveNetworkSecurityGroup.TagMap, so the provider
// fetches this endpoint over REST (see fetchEffectiveNsgGroups). These readers
// pull the documented EffectiveNetworkSecurityRule fields back out of that JSON,
// tolerating an absent or wrongly-typed key rather than failing the interface.

// ruleString reads a string field, returning "" when absent or not a string.
func ruleString(rule map[string]any, key string) string {
	s, _ := rule[key].(string)
	return s
}

// ruleStringSlice reads a string-list field. Non-string entries are dropped
// rather than rendered as empty strings, which would read as a rule covering an
// unnamed prefix.
func ruleStringSlice(rule map[string]any, key string) []any {
	arr, ok := rule[key].([]any)
	if !ok {
		return []any{}
	}
	out := make([]any, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// newEffectiveSecurityRule builds one merged security rule. nsgID identifies the
// NSG in the effective chain that contributed it, which is the piece the raw
// dict form dropped entirely: a merged rule set says what applies but not which
// NSG to change to alter it.
func newEffectiveSecurityRule(runtime *plugin.Runtime, nicID, nsgID string, index int, rule map[string]any) (plugin.Resource, error) {
	name := ruleString(rule, "name")

	// Rule names repeat across the NSGs in a chain (every NSG carries the same
	// defaultSecurityRules/ set), so the NSG id and the position are both part of
	// the key. Without them the rules of the second NSG would collide with the
	// first and the merged set would silently collapse.
	id := nicID + "/" + nsgID + "/" + strconv.Itoa(index) + "/" + name

	priority, ok := ruleInt(rule, "priority")
	priorityData := llx.NilData
	if ok {
		priorityData = llx.IntData(priority)
	}

	args := map[string]*llx.RawData{
		"__id":                             llx.StringData(id),
		"name":                             llx.StringData(name),
		"direction":                        llx.StringData(ruleString(rule, "direction")),
		"access":                           llx.StringData(ruleString(rule, "access")),
		"protocol":                         llx.StringData(ruleString(rule, "protocol")),
		"priority":                         priorityData,
		"sourcePortRange":                  llx.StringData(ruleString(rule, "sourcePortRange")),
		"sourcePortRanges":                 llx.ArrayData(ruleStringSlice(rule, "sourcePortRanges"), types.String),
		"destinationPortRange":             llx.StringData(ruleString(rule, "destinationPortRange")),
		"destinationPortRanges":            llx.ArrayData(ruleStringSlice(rule, "destinationPortRanges"), types.String),
		"sourceAddressPrefix":              llx.StringData(ruleString(rule, "sourceAddressPrefix")),
		"sourceAddressPrefixes":            llx.ArrayData(ruleStringSlice(rule, "sourceAddressPrefixes"), types.String),
		"destinationAddressPrefix":         llx.StringData(ruleString(rule, "destinationAddressPrefix")),
		"destinationAddressPrefixes":       llx.ArrayData(ruleStringSlice(rule, "destinationAddressPrefixes"), types.String),
		"expandedSourceAddressPrefix":      llx.ArrayData(ruleStringSlice(rule, "expandedSourceAddressPrefix"), types.String),
		"expandedDestinationAddressPrefix": llx.ArrayData(ruleStringSlice(rule, "expandedDestinationAddressPrefix"), types.String),
	}

	res, err := CreateResource(runtime, "azure.subscription.networkService.interface.effectiveSecurityRule", args)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionNetworkServiceInterfaceEffectiveSecurityRule).cacheNsgID = nsgID
	return res, nil
}

type mqlAzureSubscriptionNetworkServiceInterfaceEffectiveSecurityRuleInternal struct {
	cacheNsgID string
}

func (a *mqlAzureSubscriptionNetworkServiceInterfaceEffectiveSecurityRule) networkSecurityGroup() (*mqlAzureSubscriptionNetworkServiceSecurityGroup, error) {
	if a.cacheNsgID == "" {
		a.NetworkSecurityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.securityGroup", map[string]*llx.RawData{
		"id": llx.StringData(a.cacheNsgID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSecurityGroup), nil
}

// effectiveRules is the typed form of effectiveSecurityRules and degrades the
// same way: an unevaluated NIC reports null, not an empty rule set, so a policy
// asserting nothing allows internet ingress cannot pass on rules that were
// never read.
func (a *mqlAzureSubscriptionNetworkServiceInterface) effectiveRules() ([]any, error) {
	groups, evaluated, err := a.effectiveNsgGroupsCached()
	if err != nil {
		return nil, err
	}
	if !evaluated {
		a.EffectiveRules.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := []any{}
	for _, g := range groups {
		for i, rule := range g.rules {
			mqlRule, err := newEffectiveSecurityRule(a.MqlRuntime, a.Id.Data, g.nsgID, i, rule)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRule)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceInterface) effectiveRoutes() ([]any, error) {
	routes, err := a.effectiveRoutesCached()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i, route := range routes {
		mqlRoute, err := newEffectiveRoute(a.MqlRuntime, a.Id.Data, i, route)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRoute)
	}
	return res, nil
}

// newEffectiveRoute builds one merged route. System routes come back with no
// name, so the position on the interface carries the key.
func newEffectiveRoute(runtime *plugin.Runtime, nicID string, index int, route *network.EffectiveRoute) (plugin.Resource, error) {
	name := ""
	if route.Name != nil {
		name = *route.Name
	}

	args := map[string]*llx.RawData{
		"__id":                       llx.StringData(nicID + "/route/" + strconv.Itoa(index) + "/" + name),
		"name":                       llx.StringData(name),
		"addressPrefix":              llx.ArrayData(strPtrSliceToAny(route.AddressPrefix), types.String),
		"nextHopIpAddress":           llx.ArrayData(strPtrSliceToAny(route.NextHopIPAddress), types.String),
		"disableBgpRoutePropagation": llx.BoolDataPtr(route.DisableBgpRoutePropagation),
	}

	// The enums are pointers to typed string aliases; a nil one means Azure did
	// not state the value, which stays an empty string rather than a guess.
	args["source"] = llx.StringData(enumString(route.Source))
	args["state"] = llx.StringData(enumString(route.State))
	args["nextHopType"] = llx.StringData(enumString(route.NextHopType))

	return CreateResource(runtime, "azure.subscription.networkService.interface.effectiveRoute", args)
}

// enumString dereferences a pointer to a string-based SDK enum.
func enumString[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}

// enumStringPtr is the null-preserving form of enumString: it keeps a nil
// enum as nil so the field reads null rather than "". Use it where an
// absent value means "not reported" instead of "empty".
func enumStringPtr[T ~string](v *T) *string {
	if v == nil {
		return nil
	}
	converted := string(*v)
	return &converted
}

// strPtrSliceToAny converts an SDK []*string to the []any llx expects, skipping
// nil elements rather than dereferencing them.
func strPtrSliceToAny(in []*string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		if s == nil {
			continue
		}
		out = append(out, *s)
	}
	return out
}

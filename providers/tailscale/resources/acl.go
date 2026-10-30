// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/tailscale/connection"
	"go.mondoo.com/mql/types"
	tsclient "tailscale.com/client/tailscale/v2"
)

// mqlTailscaleAclPolicyInternal caches the raw HuJSON body across `raw()`
// reads. The Tailscale API exposes the structured ACL (`PolicyFile().Get()`)
// and the raw HuJSON (`PolicyFile().Raw()`) as separate endpoints — the
// structured response does not include the source HuJSON — so a second call
// is required the first time `raw()` is read.
type mqlTailscaleAclPolicyInternal struct {
	rawLock    sync.Mutex
	rawFetched atomic.Bool
	rawValue   string

	// cacheExternalTailnets holds the policy's externalTailnets section from
	// the PolicyFile().Get() response the resource was created from.
	cacheExternalTailnets map[string]tsclient.ExternalTailnet
}

// namedExternalTailnet pairs an external tailnet with the alias it is declared
// under in the policy.
type namedExternalTailnet struct {
	name string
	tsclient.ExternalTailnet
}

// sortedExternalTailnets flattens the policy's alias-keyed external tailnet
// map into a list sorted by alias, so repeated scans of an unchanged policy
// produce an identical list.
func sortedExternalTailnets(in map[string]tsclient.ExternalTailnet) []namedExternalTailnet {
	out := make([]namedExternalTailnet, 0, len(in))
	for name, et := range in {
		out = append(out, namedExternalTailnet{name: name, ExternalTailnet: et})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func (a *mqlTailscaleAclPolicy) externalTailnets() ([]any, error) {
	entries := sortedExternalTailnets(a.cacheExternalTailnets)
	resources := make([]any, 0, len(entries))
	for _, et := range entries {
		resource, err := CreateResource(a.MqlRuntime, "tailscale.aclPolicy.externalTailnet", map[string]*llx.RawData{
			"__id":                      llx.StringData(a.Tailnet.Data + "/externalTailnet/" + et.name),
			"name":                      llx.StringData(et.name),
			"externalId":                llx.StringData(et.ExternalID),
			"allowIncomingConnections":  llx.BoolData(et.AllowIncomingConnections),
			"allowExternalReferencesTo": llx.ArrayData(stringSliceToAny(et.AllowExternalReferencesTo), types.String),
		})
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func (a *mqlTailscaleAclPolicy) id() (string, error) {
	return "tailscale/tailnet/" + a.Tailnet.Data + "/aclPolicy", nil
}

// flattenAutoApprovers splits a policy's auto-approver block into the exit-node
// list and the route-to-owners and service-to-owners maps the resource exposes.
// A policy with no autoApprovers section yields empty values rather than nulls,
// so a query asserting that nothing is auto-approved reads false instead of
// passing on a null comparison.
func flattenAutoApprovers(autoApprovers *tsclient.ACLAutoApprovers) (exitNodes []any, routes, services map[string]any) {
	exitNodes = []any{}
	routes = map[string]any{}
	services = map[string]any{}
	if autoApprovers == nil {
		return exitNodes, routes, services
	}

	for _, v := range autoApprovers.ExitNode {
		exitNodes = append(exitNodes, v)
	}
	return exitNodes,
		stringSliceMapToAny(autoApprovers.Routes),
		stringSliceMapToAny(autoApprovers.Services)
}

func createTailscaleAclPolicyResource(runtime *plugin.Runtime, tailnet string, acl *tsclient.ACL) (plugin.Resource, error) {
	autoApproverExitNodes, autoApproverRoutes, autoApproverServices := flattenAutoApprovers(acl.AutoApprovers)

	acls, err := structSliceToDictSlice(acl.ACLs)
	if err != nil {
		return nil, err
	}
	grants, err := structSliceToDictSlice(acl.Grants)
	if err != nil {
		return nil, err
	}
	ssh, err := structSliceToDictSlice(acl.SSH)
	if err != nil {
		return nil, err
	}
	tests, err := structSliceToDictSlice(acl.Tests)
	if err != nil {
		return nil, err
	}
	nodeAttrs, err := structSliceToDictSlice(acl.NodeAttrs)
	if err != nil {
		return nil, err
	}
	attrConfig, err := structMapToDictMap(acl.AttrConfig)
	if err != nil {
		return nil, err
	}
	derpRegions, omitDefaultDerpRegions, err := flattenDERPMap(acl.DERPMap)
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, "tailscale.aclPolicy", map[string]*llx.RawData{
		"tailnet":                llx.StringData(tailnet),
		"acls":                   llx.ArrayData(acls, types.Dict),
		"grants":                 llx.ArrayData(grants, types.Dict),
		"ipsets":                 llx.MapData(stringSliceMapToAny(acl.IPSets), types.Array(types.String)),
		"attrConfig":             llx.MapData(attrConfig, types.Dict),
		"derpRegions":            llx.ArrayData(derpRegions, types.Dict),
		"omitDefaultDerpRegions": llx.BoolData(omitDefaultDerpRegions),
		"groups":                 llx.MapData(stringSliceMapToAny(acl.Groups), types.Array(types.String)),
		"hosts":                  llx.MapData(stringMapToAny(acl.Hosts), types.String),
		"tagOwners":              llx.MapData(stringSliceMapToAny(acl.TagOwners), types.Array(types.String)),
		"ssh":                    llx.ArrayData(ssh, types.Dict),
		"tests":                  llx.ArrayData(tests, types.Dict),
		"nodeAttrs":              llx.ArrayData(nodeAttrs, types.Dict),
		"autoApproverExitNodes":  llx.ArrayData(autoApproverExitNodes, types.String),
		"autoApproverRoutes":     llx.MapData(autoApproverRoutes, types.Array(types.String)),
		"autoApproverServices":   llx.MapData(autoApproverServices, types.Array(types.String)),
		"defaultSourcePosture":   llx.ArrayData(stringSliceToAny(acl.DefaultSourcePosture), types.String),
		"postures":               llx.MapData(stringSliceMapToAny(acl.Postures), types.Array(types.String)),
		"disableIPv4":            llx.BoolData(acl.DisableIPv4),
		"oneCGNATRoute":          llx.StringData(acl.OneCGNATRoute),
		"randomizeClientPort":    llx.BoolData(acl.RandomizeClientPort),
		"etag":                   llx.StringData(acl.ETag),
	})
	if err != nil {
		return nil, err
	}
	resource.(*mqlTailscaleAclPolicy).cacheExternalTailnets = acl.ExternalTailnets
	return resource, nil
}

// raw lazily fetches the raw HuJSON representation of the policy.
// Note: the `etag` field reflects the structured policy snapshot returned by
// PolicyFile().Get() at resource creation, not this raw HuJSON fetch — the two
// are independent API calls and may briefly diverge if the policy is edited
// between them.
func (a *mqlTailscaleAclPolicy) raw() (string, error) {
	if a.rawFetched.Load() {
		return a.rawValue, nil
	}
	a.rawLock.Lock()
	defer a.rawLock.Unlock()
	if a.rawFetched.Load() {
		return a.rawValue, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.TailscaleConnection)
	raw, err := conn.Client().PolicyFile().Raw(context.Background())
	if err != nil {
		return "", err
	}
	a.rawValue = raw.HuJSON
	a.rawFetched.Store(true)
	return a.rawValue, nil
}

// structSliceToDictSlice JSON-round-trips a slice of policy structs into a
// slice of generic maps, suitable for use as MQL []dict. Field names match
// the JSON tags on the Tailscale SDK types (e.g. "src", "dst", "ports",
// "action", "proto", "users"). Any conversion error is propagated so
// security-sensitive policy entries are never silently dropped.
func structSliceToDictSlice[T any](in []T) ([]any, error) {
	if len(in) == 0 {
		return []any{}, nil
	}
	out := make([]any, 0, len(in))
	for i := range in {
		b, err := json.Marshal(in[i])
		if err != nil {
			return nil, fmt.Errorf("tailscale: failed to marshal policy entry at index %d: %w", i, err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("tailscale: failed to unmarshal policy entry at index %d: %w", i, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// structMapToDictMap JSON-round-trips a map of policy structs into a map of
// generic values, suitable for use as MQL map[string]dict. Any conversion error
// is propagated so security-sensitive policy entries are never silently
// dropped.
func structMapToDictMap[T any](in map[string]T) (map[string]any, error) {
	out := make(map[string]any, len(in))
	for k := range in {
		b, err := json.Marshal(in[k])
		if err != nil {
			return nil, fmt.Errorf("tailscale: failed to marshal policy entry %q: %w", k, err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("tailscale: failed to unmarshal policy entry %q: %w", k, err)
		}
		out[k] = m
	}
	return out, nil
}

// flattenDERPMap splits a policy's custom DERP configuration into the region
// list and the omit-default flag the resource exposes. A policy with no derpMap
// section yields an empty list rather than a null, so a query asserting that no
// custom relay is configured reads an empty list instead of passing on a null
// comparison.
//
// The regions arrive keyed by numeric region id. That id is also carried inside
// each region as `regionID`, so the map is flattened to a list rather than
// exposing a map whose keys duplicate a field of its values.
func flattenDERPMap(derpMap *tsclient.ACLDERPMap) ([]any, bool, error) {
	if derpMap == nil {
		return []any{}, false, nil
	}

	regions := make([]*tsclient.ACLDERPRegion, 0, len(derpMap.Regions))
	for _, region := range derpMap.Regions {
		if region == nil {
			continue
		}
		regions = append(regions, region)
	}
	// Map iteration order is random; sort so repeated scans of an unchanged
	// policy produce an identical list.
	sort.Slice(regions, func(i, j int) bool { return regions[i].RegionID < regions[j].RegionID })

	out, err := structSliceToDictSlice(regions)
	if err != nil {
		return nil, false, err
	}
	return out, derpMap.OmitDefaultRegions, nil
}

func stringSliceMapToAny(in map[string][]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		arr := make([]any, 0, len(v))
		for _, s := range v {
			arr = append(arr, s)
		}
		out[k] = arr
	}
	return out
}

func stringMapToAny(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func stringSliceToAny(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

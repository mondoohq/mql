// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/arista/resources/eos"
	"go.mondoo.com/mql/types"
)

// =====================================================================
// arista.eos.routeMap
// =====================================================================

func (a *mqlAristaEosRouteMap) id() (string, error) {
	return "arista.eos.routeMap/" + a.Name.Data, a.Name.Error
}

func (a *mqlAristaEos) routeMaps() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	maps := eos.ParseRouteMaps(rc)

	res := make([]any, 0, len(maps))
	for _, m := range maps {
		mqlMap, err := CreateResource(a.MqlRuntime, "arista.eos.routeMap", map[string]*llx.RawData{
			"name": llx.StringData(m.Name),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlMap)
	}
	return res, nil
}

// id keys a clause on its map and sequence number, which is what makes it
// unique: one map is many clauses evaluated in order.
func (a *mqlAristaEosRouteMapEntry) id() (string, error) {
	if a.RouteMapName.Error != nil {
		return "", a.RouteMapName.Error
	}
	return "arista.eos.routeMap.entry/" + a.RouteMapName.Data + "/" +
		strconv.FormatInt(a.SequenceNumber.Data, 10), a.SequenceNumber.Error
}

func (a *mqlAristaEosRouteMap) entries() ([]any, error) {
	if a.Name.Error != nil {
		return nil, a.Name.Error
	}
	name := a.Name.Data

	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}

	var entries []eos.RouteMapEntry
	for _, m := range eos.ParseRouteMaps(rc) {
		if m.Name == name {
			entries = m.Entries
			break
		}
	}

	res := make([]any, 0, len(entries))
	for _, e := range entries {
		mqlEntry, err := CreateResource(a.MqlRuntime, "arista.eos.routeMap.entry", map[string]*llx.RawData{
			"routeMapName":   llx.StringData(name),
			"sequenceNumber": llx.IntData(int64(e.SequenceNumber)),
			"action":         llx.StringData(e.Action),
			"description":    llx.StringData(e.Description),
			"match":          llx.ArrayData(stringSliceToAny(e.Match), types.String),
			"set":            llx.ArrayData(stringSliceToAny(e.Set), types.String),
			"continueAt":     llx.IntData(int64(e.Continue)),
		})
		if err != nil {
			return nil, err
		}
		mqlEntry.(*mqlAristaEosRouteMapEntry).cacheMatchPrefixLists = e.MatchPrefixLists
		res = append(res, mqlEntry)
	}
	return res, nil
}

type mqlAristaEosRouteMapEntryInternal struct {
	cacheMatchPrefixLists []string
}

// matchPrefixLists resolves the lists the clause matches against. A name that
// matches nothing on the device is skipped rather than erroring: a clause
// pointing at an undefined prefix-list matches no routes, which the caller
// sees as a shorter list than the clause's match statements suggest.
func (a *mqlAristaEosRouteMapEntry) matchPrefixLists() ([]any, error) {
	if len(a.cacheMatchPrefixLists) == 0 {
		return []any{}, nil
	}

	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	all := eos.ParsePrefixLists(rc)

	res := []any{}
	for _, want := range a.cacheMatchPrefixLists {
		for _, pl := range all {
			if pl.Name != want {
				continue
			}
			mqlList, err := createPrefixListResource(a.MqlRuntime, pl)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlList)
		}
	}
	return res, nil
}

// =====================================================================
// arista.eos.prefixList
// =====================================================================

// id qualifies the list by address family for the same reason the ACL id
// does: IPv4 and IPv6 prefix-lists are separate namespaces that can share a
// name, and keying on the name alone would make one resolve to the other.
func (a *mqlAristaEosPrefixList) id() (string, error) {
	if a.Family.Error != nil {
		return "", a.Family.Error
	}
	return "arista.eos.prefixList/" + a.Family.Data + "/" + a.Name.Data, a.Name.Error
}

// createPrefixListResource builds the resource for a parsed prefix-list. The
// field set matches everywhere else one is built, so all paths produce the
// same __id and share one cached resource.
func createPrefixListResource(runtime *plugin.Runtime, pl eos.PrefixList) (plugin.Resource, error) {
	return CreateResource(runtime, "arista.eos.prefixList", map[string]*llx.RawData{
		"name":   llx.StringData(pl.Name),
		"family": llx.StringData(pl.Family),
	})
}

func (a *mqlAristaEos) prefixLists() ([]any, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	lists := eos.ParsePrefixLists(rc)

	res := make([]any, 0, len(lists))
	for _, pl := range lists {
		mqlList, err := createPrefixListResource(a.MqlRuntime, pl)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlList)
	}
	return res, nil
}

func (a *mqlAristaEosPrefixListEntry) id() (string, error) {
	if a.PrefixListName.Error != nil {
		return "", a.PrefixListName.Error
	}
	if a.PrefixListFamily.Error != nil {
		return "", a.PrefixListFamily.Error
	}
	return "arista.eos.prefixList.entry/" + a.PrefixListFamily.Data + "/" +
		a.PrefixListName.Data + "/" +
		strconv.FormatInt(a.SequenceNumber.Data, 10), a.SequenceNumber.Error
}

func (a *mqlAristaEosPrefixList) entries() ([]any, error) {
	if a.Name.Error != nil {
		return nil, a.Name.Error
	}
	if a.Family.Error != nil {
		return nil, a.Family.Error
	}
	name := a.Name.Data
	family := a.Family.Data

	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return nil, err
	}

	var entries []eos.PrefixListEntry
	for _, pl := range eos.ParsePrefixLists(rc) {
		if pl.Name == name && pl.Family == family {
			entries = pl.Entries
			break
		}
	}

	res := make([]any, 0, len(entries))
	for _, e := range entries {
		mqlEntry, err := CreateResource(a.MqlRuntime, "arista.eos.prefixList.entry", map[string]*llx.RawData{
			"prefixListName":   llx.StringData(name),
			"prefixListFamily": llx.StringData(family),
			"sequenceNumber":   llx.IntData(int64(e.SequenceNumber)),
			"action":           llx.StringData(e.Action),
			"prefix":           llx.StringData(e.Prefix),
			"eq":               llx.IntData(int64(e.Eq)),
			"ge":               llx.IntData(int64(e.Ge)),
			"le":               llx.IntData(int64(e.Le)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEntry)
	}
	return res, nil
}

// =====================================================================
// arista.eos.bgp additions
// =====================================================================

func (a *mqlAristaEosBgp) logNeighborChanges() (bool, error) {
	rc, err := fetchRunningConfig(a.MqlRuntime)
	if err != nil {
		return false, err
	}
	return eos.ParseBgpConfig(rc).LogNeighborChanges, nil
}

// resolveRouteMap builds the route-map a peer policy names, returning
// (nil, nil) when no map by that name is defined. A peer naming a route-map
// that does not exist has no policy applied at all.
func resolveRouteMap(runtime *plugin.Runtime, name string) (*mqlAristaEosRouteMap, error) {
	if name == "" {
		return nil, nil
	}

	rc, err := fetchRunningConfig(runtime)
	if err != nil {
		return nil, err
	}
	for _, m := range eos.ParseRouteMaps(rc) {
		if m.Name != name {
			continue
		}
		mqlMap, err := CreateResource(runtime, "arista.eos.routeMap", map[string]*llx.RawData{
			"name": llx.StringData(m.Name),
		})
		if err != nil {
			return nil, err
		}
		return mqlMap.(*mqlAristaEosRouteMap), nil
	}
	return nil, nil
}

// mqlAristaEosBgpPeerInternal holds the route map names the running-config
// applies to the session, which the policy accessors resolve to route maps.
type mqlAristaEosBgpPeerInternal struct {
	cacheInboundRouteMap  string
	cacheOutboundRouteMap string
}

func (a *mqlAristaEosBgpPeer) inboundPolicy() (*mqlAristaEosRouteMap, error) {
	mqlMap, err := resolveRouteMap(a.MqlRuntime, a.cacheInboundRouteMap)
	if err != nil {
		return nil, err
	}
	if mqlMap == nil {
		a.InboundPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlMap, nil
}

func (a *mqlAristaEosBgpPeer) outboundPolicy() (*mqlAristaEosRouteMap, error) {
	mqlMap, err := resolveRouteMap(a.MqlRuntime, a.cacheOutboundRouteMap)
	if err != nil {
		return nil, err
	}
	if mqlMap == nil {
		a.OutboundPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlMap, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/resources/frr"
	"go.mondoo.com/mql/types"
)

// This file exposes the policy objects of a configuration: the static
// routes, and the lists a route map names. They are read from the same
// parsed file as the rest of frr.config, so they cost no extra read.

func (s *mqlFrrConfig) staticRoutes(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	routes := s.cfg.StaticRoutes()
	res := make([]any, 0, len(routes))
	for i := range routes {
		r := &routes[i]
		// The id is built from what the route is, not from where it sits,
		// so inserting a line above it does not renumber the rest. A
		// discard route has no target, so the disposition joins the key to
		// keep a blackhole and a reject for the same prefix apart.
		target := r.Nexthop
		if target == "" {
			target = r.Interface
		}
		disposition := ""
		switch {
		case r.Blackhole:
			disposition = "blackhole"
		case r.Reject:
			disposition = "reject"
		}
		id := fmt.Sprintf("%s#staticRoute/%s/%s/%s/%s/%s",
			s.__id, r.AFI, vrfKey(r.VRF), r.Prefix, target, disposition)
		obj, err := CreateResource(s.MqlRuntime, "frr.config.staticRoute", map[string]*llx.RawData{
			"__id":       llx.StringData(id),
			"afi":        llx.StringData(r.AFI),
			"prefix":     llx.StringData(r.Prefix),
			"nexthop":    llx.StringData(r.Nexthop),
			"interface":  llx.StringData(r.Interface),
			"vrf":        llx.StringData(r.VRF),
			"nexthopVrf": llx.StringData(r.NexthopVRF),
			"blackhole":  llx.BoolData(r.Blackhole),
			"reject":     llx.BoolData(r.Reject),
			"distance":   llx.IntData(r.Distance),
			"table":      llx.IntData(r.Table),
			"tag":        llx.IntData(r.Tag),
			"label":      llx.StringData(r.Label),
			"file":       llx.StringData(r.File),
			"line":       llx.IntData(int64(r.Line)),
			"raw":        llx.StringData(r.Raw),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) communityLists(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	lists := s.cfg.CommunityLists()
	res := make([]any, 0, len(lists))
	for i := range lists {
		l := &lists[i]
		obj, err := CreateResource(s.MqlRuntime, "frr.config.communityList", map[string]*llx.RawData{
			"__id":    llx.StringData(s.__id + "#communityList/" + l.Kind + "/" + l.Type + "/" + l.Name),
			"name":    llx.StringData(l.Name),
			"kind":    llx.StringData(l.Kind),
			"type":    llx.StringData(l.Type),
			"entries": llx.ArrayData(frr.PolicyEntriesAsDicts(l.Entries), types.Dict),
			"file":    llx.StringData(l.File),
			"line":    llx.IntData(int64(l.Line)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) accessLists(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	lists := s.cfg.AccessLists()
	res := make([]any, 0, len(lists))
	for i := range lists {
		l := &lists[i]
		obj, err := CreateResource(s.MqlRuntime, "frr.config.accessList", map[string]*llx.RawData{
			"__id":    llx.StringData(s.__id + "#accessList/" + l.AFI + "/" + l.Name),
			"name":    llx.StringData(l.Name),
			"afi":     llx.StringData(l.AFI),
			"entries": llx.ArrayData(frr.PolicyEntriesAsDicts(l.Entries), types.Dict),
			"file":    llx.StringData(l.File),
			"line":    llx.IntData(int64(l.Line)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) asPathAccessLists(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	lists := s.cfg.ASPathAccessLists()
	res := make([]any, 0, len(lists))
	for i := range lists {
		l := &lists[i]
		obj, err := CreateResource(s.MqlRuntime, "frr.config.asPathAccessList", map[string]*llx.RawData{
			"__id":    llx.StringData(s.__id + "#asPathAccessList/" + l.Name),
			"name":    llx.StringData(l.Name),
			"entries": llx.ArrayData(frr.PolicyEntriesAsDicts(l.Entries), types.Dict),
			"file":    llx.StringData(l.File),
			"line":    llx.IntData(int64(l.Line)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

// routeMapClauseArgs adds the typed match and set fields of one clause to
// the arguments of its resource.
func routeMapClauseArgs(args map[string]*llx.RawData, c *frr.RouteMapClauses) {
	args["matchPrefixLists"] = llx.ArrayData(stringSliceToAny(c.MatchPrefixLists), types.String)
	args["matchAccessLists"] = llx.ArrayData(stringSliceToAny(c.MatchAccessLists), types.String)
	args["matchCommunityLists"] = llx.ArrayData(stringSliceToAny(c.MatchCommunityLists), types.String)
	args["matchLargeCommunities"] = llx.ArrayData(stringSliceToAny(c.MatchLargeCommunities), types.String)
	args["matchExtCommunities"] = llx.ArrayData(stringSliceToAny(c.MatchExtCommunities), types.String)
	args["matchAsPathLists"] = llx.ArrayData(stringSliceToAny(c.MatchAsPathLists), types.String)
	args["matchSourceVrf"] = llx.StringData(c.MatchSourceVRF)
	args["matchInterface"] = llx.StringData(c.MatchInterface)
	args["matchPeer"] = llx.StringData(c.MatchPeer)
	args["matchEvpnRouteType"] = llx.StringData(c.MatchEvpnRouteType)
	args["matchEvpnVni"] = llx.IntData(c.MatchEvpnVNI)
	args["matchTag"] = llx.IntData(c.MatchTag)
	args["matchMetric"] = llx.IntData(c.MatchMetric)
	args["matchLocalPreference"] = llx.IntData(c.MatchLocalPreference)

	args["setCommunities"] = llx.ArrayData(stringSliceToAny(c.SetCommunities), types.String)
	args["setCommunityAdditive"] = llx.BoolData(c.SetCommunityAdditive)
	args["setCommunityNone"] = llx.BoolData(c.SetCommunityNone)
	args["setLargeCommunities"] = llx.ArrayData(stringSliceToAny(c.SetLargeCommunities), types.String)
	args["setExtCommunities"] = llx.ArrayData(stringSliceToAny(c.SetExtCommunities), types.String)
	args["setCommunityDelete"] = llx.StringData(c.SetCommunityDelete)
	args["setLocalPreference"] = llx.IntData(c.SetLocalPreference)
	args["setMetric"] = llx.StringData(c.SetMetric)
	args["setWeight"] = llx.IntData(c.SetWeight)
	args["setOrigin"] = llx.StringData(c.SetOrigin)
	args["setAsPathPrepend"] = llx.ArrayData(stringSliceToAny(c.SetAsPathPrepend), types.String)
	args["setAsPathExclude"] = llx.ArrayData(stringSliceToAny(c.SetAsPathExclude), types.String)
	args["setNextHop"] = llx.StringData(c.SetNextHop)
	args["setSourceAddress"] = llx.StringData(c.SetSourceAddress)
	args["setTag"] = llx.IntData(c.SetTag)
	args["setTable"] = llx.IntData(c.SetTable)
	args["setDistance"] = llx.IntData(c.SetDistance)
	args["setAtomicAggregate"] = llx.BoolData(c.SetAtomicAggregate)
}

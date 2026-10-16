// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/frr"
	"go.mondoo.com/mql/types"
)

// This file reads the BGP routing information base: the EVPN table and the
// routes of one session. Both grow with the fabric, so both use the bounded
// pattern of frr.routeTable. The filters go into the vtysh command, so FRR
// narrows the output before it prints.

// frrRIBByteLimit caps how much RIB output one query decodes.
const frrRIBByteLimit = 128 << 20

// runVtyshStream runs a vtysh command and returns a reader over its output.
// It reports whether vtysh refused the query, which it answers with a
// percent sign and a zero exit status.
func runVtyshStream(conn shared.Connection, command string) (io.Reader, bool, error) {
	cmd, err := conn.RunCommand(vtyshCommand(command))
	if err != nil {
		return nil, false, fmt.Errorf("cannot run %q: %w", command, err)
	}
	if cmd == nil {
		return nil, false, fmt.Errorf("cannot run %q, the connection returned no result", command)
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, false, fmt.Errorf("%q failed with exit status %d: %s",
			command, cmd.ExitStatus, strings.TrimSpace(string(stderr)))
	}

	reader := bufio.NewReader(io.LimitReader(cmd.Stdout, frrRIBByteLimit))
	if head, perr := reader.Peek(1); perr == nil && head[0] == '%' {
		rest, _ := io.ReadAll(reader)
		log.Debug().Str("command", command).
			Str("answer", strings.TrimSpace(string(head)+string(rest))).
			Msg("vtysh refused the query")
		return nil, true, nil
	}
	return reader, false, nil
}

// createBGPRoutes turns parsed paths into resources.
func createBGPRoutes(runtime *plugin.Runtime, prefix string, routes []frr.BGPRoute) ([]any, error) {
	res := make([]any, 0, len(routes))
	for i := range routes {
		r := &routes[i]
		id := fmt.Sprintf("%s/%d/%s/%s", prefix, i, r.Prefix, r.Nexthop)
		obj, err := CreateResource(runtime, "frr.bgp.route", map[string]*llx.RawData{
			"__id":                llx.StringData(id),
			"prefix":              llx.StringData(r.Prefix),
			"prefixLength":        llx.IntData(r.PrefixLen),
			"nexthop":             llx.StringData(r.Nexthop),
			"peer":                llx.StringData(r.Peer),
			"asPath":              llx.StringData(r.ASPath),
			"origin":              llx.StringData(r.Origin),
			"metric":              llx.IntData(r.Metric),
			"localPreference":     llx.IntData(r.LocalPreference),
			"weight":              llx.IntData(r.Weight),
			"valid":               llx.BoolData(r.Valid),
			"bestPath":            llx.BoolData(r.BestPath),
			"communities":         llx.ArrayData(stringSliceToAny(r.Communities), types.String),
			"largeCommunities":    llx.ArrayData(stringSliceToAny(r.LargeCommunities), types.String),
			"extendedCommunities": llx.ArrayData(stringSliceToAny(r.ExtendedCommunities), types.String),
			"routeTargets":        llx.ArrayData(stringSliceToAny(r.RouteTargets), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

// ======================================================================
// frr.evpn.routeTable
// ======================================================================

func frrEVPNRouteTableID(vni int64) string {
	if vni == 0 {
		return "frr.evpn.routeTable/all"
	}
	return "frr.evpn.routeTable/vni/" + strconv.FormatInt(vni, 10)
}

// initFrrEvpnRouteTable fills the defaults of the query. The VNI is a number,
// so it cannot change the command it is placed in.
func initFrrEvpnRouteTable(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	var vni int64
	if x, ok := args["vni"]; ok {
		v, ok := x.Value.(int64)
		if !ok {
			return nil, nil, errors.New("wrong type for 'vni' in frr.evpn.routeTable initialization, it must be an int")
		}
		if v < 0 || v > 16777215 {
			return nil, nil, errors.New("'vni' in frr.evpn.routeTable initialization must be a VXLAN network identifier")
		}
		vni = v
	}

	limit := int64(frr.DefaultRIBLimit)
	if x, ok := args["limit"]; ok {
		v, ok := x.Value.(int64)
		if !ok {
			return nil, nil, errors.New("wrong type for 'limit' in frr.evpn.routeTable initialization, it must be an int")
		}
		if v <= 0 {
			return nil, nil, errors.New("'limit' in frr.evpn.routeTable initialization must be greater than zero")
		}
		limit = v
	}

	args["vni"] = llx.IntData(vni)
	args["limit"] = llx.IntData(limit)
	args["__id"] = llx.StringData(frrEVPNRouteTableID(vni))
	return args, nil, nil
}

type mqlFrrEvpnRouteTableInternal struct {
	lock   sync.Mutex
	table  *frr.EVPNRouteSet
	loaded bool
}

func (n *mqlFrr) evpnRoutes() (*mqlFrrEvpnRouteTable, error) {
	obj, err := CreateResource(n.MqlRuntime, "frr.evpn.routeTable", map[string]*llx.RawData{
		"__id":  llx.StringData(frrEVPNRouteTableID(0)),
		"vni":   llx.IntData(0),
		"limit": llx.IntData(int64(frr.DefaultRIBLimit)),
	})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlFrrEvpnRouteTable), nil
}

func (s *mqlFrrEvpnRouteTable) load() (*frr.EVPNRouteSet, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.loaded {
		return s.table, nil
	}

	vni := s.GetVni()
	if vni.Error != nil {
		return nil, vni.Error
	}
	limit := s.GetLimit()
	if limit.Error != nil {
		return nil, limit.Error
	}

	command := "show bgp l2vpn evpn json"
	if vni.Data != 0 {
		command = "show bgp l2vpn evpn route vni " + strconv.FormatInt(vni.Data, 10) + " json"
	}

	conn := s.MqlRuntime.Connection.(shared.Connection)
	reader, refused, err := runVtyshStream(conn, command)
	if err != nil {
		return nil, err
	}
	if refused {
		// A router without an EVPN address family has no table.
		s.table = &frr.EVPNRouteSet{}
		s.loaded = true
		return s.table, nil
	}

	table, err := frr.StreamEVPNRoutes(reader, int(limit.Data))
	if err != nil {
		return nil, err
	}
	s.table = table
	s.loaded = true
	return s.table, nil
}

func (s *mqlFrrEvpnRouteTable) total() (int64, error) {
	table, err := s.load()
	if err != nil {
		return 0, err
	}
	return table.Total, nil
}

func (s *mqlFrrEvpnRouteTable) truncated() (bool, error) {
	table, err := s.load()
	if err != nil {
		return false, err
	}
	return table.Truncated, nil
}

func (s *mqlFrrEvpnRouteTable) entries() ([]any, error) {
	table, err := s.load()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(table.Routes))
	for i := range table.Routes {
		r := &table.Routes[i]
		id := fmt.Sprintf("%s/%d/%s/%s", s.__id, i, r.RD, r.Prefix)
		paths, err := createBGPRoutes(s.MqlRuntime, id, r.Paths)
		if err != nil {
			return nil, err
		}
		obj, err := CreateResource(s.MqlRuntime, "frr.evpn.route", map[string]*llx.RawData{
			"__id":          llx.StringData(id),
			"rd":            llx.StringData(r.RD),
			"prefix":        llx.StringData(r.Prefix),
			"routeType":     llx.IntData(r.RouteType),
			"routeTypeName": llx.StringData(r.RouteTypeName),
			"ethernetTag":   llx.IntData(r.EthernetTag),
			"macAddress":    llx.StringData(r.MACAddress),
			"ip":            llx.StringData(r.IP),
			"routeTargets":  llx.ArrayData(stringSliceToAny(r.RouteTargets), types.String),
			"paths":         llx.ArrayData(paths, types.Resource("frr.bgp.route")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

// ======================================================================
// frr.bgp.peerRoutes
// ======================================================================

func frrPeerRoutesID(peer, direction, vrf, afi string) string {
	return "frr.bgp.peerRoutes/" + vrfKey(vrf) + "/" + afi + "/" + direction + "/" + peer
}

// initFrrBgpPeerRoutes validates the query. The peer and the VRF reach the
// vtysh command line, so both are checked before they are placed in it.
func initFrrBgpPeerRoutes(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	x, ok := args["peer"]
	if !ok {
		return nil, nil, errors.New("frr.bgp.peerRoutes needs a 'peer' to query")
	}
	peer, ok := x.Value.(string)
	if !ok {
		return nil, nil, errors.New("wrong type for 'peer' in frr.bgp.peerRoutes initialization, it must be a string")
	}
	if err := frr.ValidatePeer(peer); err != nil {
		return nil, nil, err
	}

	direction := "advertised"
	if x, ok := args["direction"]; ok {
		v, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'direction' in frr.bgp.peerRoutes initialization, it must be a string")
		}
		direction = strings.ToLower(v)
	}
	if direction != "advertised" && direction != "received" {
		return nil, nil, fmt.Errorf("unsupported direction %q for frr.bgp.peerRoutes, use advertised or received", direction)
	}

	vrf := ""
	if x, ok := args["vrf"]; ok {
		v, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'vrf' in frr.bgp.peerRoutes initialization, it must be a string")
		}
		vrf = v
	}
	if vrf != "" {
		if err := frr.ValidateName("vrf", vrf); err != nil {
			return nil, nil, err
		}
	}

	afi := "ipv4"
	if x, ok := args["afi"]; ok {
		v, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'afi' in frr.bgp.peerRoutes initialization, it must be a string")
		}
		afi = strings.ToLower(v)
	}
	if afi != "ipv4" && afi != "ipv6" && afi != "l2vpn" {
		return nil, nil, fmt.Errorf("unsupported address family %q for frr.bgp.peerRoutes, use ipv4, ipv6 or l2vpn", afi)
	}

	limit := int64(frr.DefaultRIBLimit)
	if x, ok := args["limit"]; ok {
		v, ok := x.Value.(int64)
		if !ok {
			return nil, nil, errors.New("wrong type for 'limit' in frr.bgp.peerRoutes initialization, it must be an int")
		}
		if v <= 0 {
			return nil, nil, errors.New("'limit' in frr.bgp.peerRoutes initialization must be greater than zero")
		}
		limit = v
	}

	args["peer"] = llx.StringData(peer)
	args["direction"] = llx.StringData(direction)
	args["vrf"] = llx.StringData(vrf)
	args["afi"] = llx.StringData(afi)
	args["limit"] = llx.IntData(limit)
	args["__id"] = llx.StringData(frrPeerRoutesID(peer, direction, vrf, afi))
	return args, nil, nil
}

type mqlFrrBgpPeerRoutesInternal struct {
	lock   sync.Mutex
	routes *frr.RouteSet
	// answered is false when vtysh refused the query, which it does for
	// received routes without inbound soft reconfiguration.
	answered bool
	loaded   bool
}

func (s *mqlFrrBgpPeerRoutes) load() (*frr.RouteSet, bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.loaded {
		return s.routes, s.answered, nil
	}

	peer := s.GetPeer()
	if peer.Error != nil {
		return nil, false, peer.Error
	}
	direction := s.GetDirection()
	if direction.Error != nil {
		return nil, false, direction.Error
	}
	vrf := s.GetVrf()
	if vrf.Error != nil {
		return nil, false, vrf.Error
	}
	afi := s.GetAfi()
	if afi.Error != nil {
		return nil, false, afi.Error
	}
	limit := s.GetLimit()
	if limit.Error != nil {
		return nil, false, limit.Error
	}

	// The values are validated in init, and again here because a resource
	// can also be built from a recording.
	if err := frr.ValidatePeer(peer.Data); err != nil {
		return nil, false, err
	}
	if vrf.Data != "" {
		if err := frr.ValidateName("vrf", vrf.Data); err != nil {
			return nil, false, err
		}
	}
	if direction.Data != "advertised" && direction.Data != "received" {
		return nil, false, fmt.Errorf("unsupported direction %q for frr.bgp.peerRoutes, use advertised or received", direction.Data)
	}
	if afi.Data != "ipv4" && afi.Data != "ipv6" && afi.Data != "l2vpn" {
		return nil, false, fmt.Errorf("unsupported address family %q for frr.bgp.peerRoutes, use ipv4, ipv6 or l2vpn", afi.Data)
	}

	command := "show bgp"
	if vrf.Data != "" {
		command += " vrf " + vrf.Data
	}
	switch afi.Data {
	case "ipv6":
		command += " ipv6 unicast"
	case "l2vpn":
		command += " l2vpn evpn"
	default:
		command += " ipv4 unicast"
	}
	command += " neighbor " + peer.Data + " " + direction.Data + "-routes json"

	conn := s.MqlRuntime.Connection.(shared.Connection)
	reader, refused, err := runVtyshStream(conn, command)
	if err != nil {
		return nil, false, err
	}
	if refused {
		// Received routes need inbound soft reconfiguration on the session.
		// Without it FRR has no copy of what the peer sent.
		s.routes = &frr.RouteSet{FilteredCount: -1}
		s.answered = false
		s.loaded = true
		return s.routes, s.answered, nil
	}

	routes, err := frr.StreamPeerRoutes(reader, int(limit.Data))
	if err != nil {
		return nil, false, err
	}
	s.routes = routes
	s.answered = true
	s.loaded = true
	return s.routes, s.answered, nil
}

func (s *mqlFrrBgpPeerRoutes) available() (bool, error) {
	_, answered, err := s.load()
	if err != nil {
		return false, err
	}
	return answered, nil
}

func (s *mqlFrrBgpPeerRoutes) total() (int64, error) {
	routes, _, err := s.load()
	if err != nil {
		return 0, err
	}
	return routes.Total, nil
}

func (s *mqlFrrBgpPeerRoutes) truncated() (bool, error) {
	routes, _, err := s.load()
	if err != nil {
		return false, err
	}
	return routes.Truncated, nil
}

func (s *mqlFrrBgpPeerRoutes) filteredCount() (int64, error) {
	routes, _, err := s.load()
	if err != nil {
		return 0, err
	}
	return routes.FilteredCount, nil
}

func (s *mqlFrrBgpPeerRoutes) entries() ([]any, error) {
	routes, _, err := s.load()
	if err != nil {
		return nil, err
	}
	return createBGPRoutes(s.MqlRuntime, s.__id, routes.Routes)
}

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
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/frr"
	"go.mondoo.com/mql/types"
)

// This file reads the runtime state of FRR. It runs vtysh and `ip` on the
// asset, unlike frr.go which only reads files.
//
// Runtime state is time-varying. A session state or a prefix counter
// describes the moment of the scan, so a policy over these resources tests
// the running router, not its configuration.
//
// The same resources serve both deployments. With FRR on the host, the
// connection runs vtysh on the host. With FRR in a Host Based Networking
// container, a connection to that container runs the vtysh inside it.

// rtTablesPath names the numeric routing tables of the kernel.
const rtTablesPath = "/etc/iproute2/rt_tables"

// frrRouteByteLimit caps how much route output is read from one command. A
// node that holds a full table prints far more than any policy needs, and
// the cap keeps one query from pulling the whole table into memory.
const frrRouteByteLimit = 64 << 20

// vtyshCommand builds a vtysh invocation. Every name that reaches the
// command line is validated by the caller, so the quoting cannot be broken.
func vtyshCommand(args string) string {
	return `vtysh -c "` + args + `"`
}

// runOutput runs a command and returns its standard output. A non-zero exit
// status is an error, because a silent empty result would read as a clean
// posture.
func runOutput(conn shared.Connection, command string) ([]byte, error) {
	cmd, err := conn.RunCommand(command)
	if err != nil {
		return nil, fmt.Errorf("cannot run %q: %w", command, err)
	}
	if cmd == nil {
		return nil, fmt.Errorf("cannot run %q, the connection returned no result", command)
	}
	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, fmt.Errorf("cannot read output of %q: %w", command, err)
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(data))
		}
		return nil, fmt.Errorf("%q failed with exit status %d: %s", command, cmd.ExitStatus, msg)
	}
	return data, nil
}

// ======================================================================
// frr — runtime accessors
// ======================================================================

type mqlFrrInternal struct {
	lock sync.Mutex
	// vrfState caches the merged VRF view, which several accessors need.
	vrfState []frr.VRFState
	// rules caches the policy routing rules.
	rules []frr.RoutingRule
	// tableNames caches /etc/iproute2/rt_tables.
	tableNames map[int64]string
	loadedVRFs bool
	loadedRule bool
}

// tableNameMap reads /etc/iproute2/rt_tables once and caches the result. A
// missing file is not an error, it only means the tables have no names.
//
// It does not take the lock of its own. Every caller already holds n.lock,
// which is what keeps the cache safe.
func (n *mqlFrr) tableNameMap(conn shared.Connection) map[int64]string {
	if n.tableNames != nil {
		return n.tableNames
	}
	n.tableNames = map[int64]string{}
	data, err := afero.ReadFile(conn.FileSystem(), rtTablesPath)
	if err != nil {
		log.Debug().Err(err).Str("path", rtTablesPath).Msg("cannot read routing table names")
		return n.tableNames
	}
	n.tableNames = frr.ParseRtTables(string(data))
	return n.tableNames
}

// loadVRFs merges the zebra view and the kernel view of the VRFs.
func (n *mqlFrr) loadVRFs() ([]frr.VRFState, error) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.loadedVRFs {
		return n.vrfState, nil
	}
	conn := n.MqlRuntime.Connection.(shared.Connection)

	var zebra []frr.ZebraVRF
	out, vtyshErr := runOutput(conn, vtyshCommand("show vrf"))
	if vtyshErr != nil {
		// The kernel view alone is still worth returning. A VRF device
		// without FRR is exactly what `inFrr` reports.
		log.Debug().Err(vtyshErr).Msg("cannot read vrfs from vtysh")
	} else {
		zebra = frr.ParseShowVRF(string(out))
	}

	var kernel []frr.KernelVRF
	kernelOut, kernelErr := runOutput(conn, "ip -j link show type vrf")
	if kernelErr != nil {
		log.Debug().Err(kernelErr).Msg("cannot read vrf devices from ip")
	} else {
		parsed, err := frr.ParseIPLinkVRF(kernelOut)
		if err != nil {
			log.Debug().Err(err).Msg("cannot parse vrf devices")
		} else {
			kernel = parsed
		}
	}

	// A node without VRFs is a valid answer, so the empty result only counts
	// as a failure when neither command could run.
	if vtyshErr != nil && kernelErr != nil {
		return nil, errors.New("cannot read vrfs, neither vtysh nor ip could be run on this asset")
	}

	n.vrfState = frr.MergeVRFs(zebra, kernel, n.tableNameMap(conn))
	n.loadedVRFs = true
	return n.vrfState, nil
}

// loadRules reads the policy routing rules of the kernel.
func (n *mqlFrr) loadRules() ([]frr.RoutingRule, error) {
	n.lock.Lock()
	defer n.lock.Unlock()

	if n.loadedRule {
		return n.rules, nil
	}
	conn := n.MqlRuntime.Connection.(shared.Connection)

	out, err := runOutput(conn, "ip -j rule show")
	if err != nil {
		return nil, err
	}
	rules, err := frr.ParseIPRules(out, n.tableNameMap(conn))
	if err != nil {
		return nil, err
	}
	n.rules = rules
	n.loadedRule = true
	return n.rules, nil
}

func (n *mqlFrr) vrfs() ([]any, error) {
	states, err := n.loadVRFs()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(states))
	for i := range states {
		v := &states[i]
		obj, err := CreateResource(n.MqlRuntime, "frr.vrf", map[string]*llx.RawData{
			"__id":      llx.StringData("frr.vrf/" + v.Name),
			"name":      llx.StringData(v.Name),
			"id":        llx.IntData(v.ID),
			"tableId":   llx.IntData(v.TableID),
			"tableName": llx.StringData(v.TableName),
			"ifindex":   llx.IntData(v.Ifindex),
			"mtu":       llx.IntData(v.MTU),
			"operState": llx.StringData(v.OperState),
			"up":        llx.BoolData(v.Up),
			"inFrr":     llx.BoolData(v.InFRR),
			"inKernel":  llx.BoolData(v.InKernel),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (n *mqlFrr) routingRules() ([]any, error) {
	rules, err := n.loadRules()
	if err != nil {
		return nil, err
	}
	return createFrrRules(n.MqlRuntime, "frr.routingRules", rules)
}

// createFrrRules turns parsed rules into resources. The prefix keeps the ids
// unique between the global list and the per VRF lists.
func createFrrRules(runtime *plugin.Runtime, prefix string, rules []frr.RoutingRule) ([]any, error) {
	res := make([]any, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		id := fmt.Sprintf("%s/%d/%d", prefix, r.Priority, i)
		obj, err := CreateResource(runtime, "frr.routingRule", map[string]*llx.RawData{
			"__id":                 llx.StringData(id),
			"priority":             llx.IntData(r.Priority),
			"source":               llx.StringData(r.Source),
			"dest":                 llx.StringData(r.Dest),
			"table":                llx.StringData(r.Table),
			"tableId":              llx.IntData(r.TableID),
			"inputInterface":       llx.StringData(r.InputIf),
			"outputInterface":      llx.StringData(r.OutputIf),
			"l3mdev":               llx.BoolData(r.L3mdev),
			"action":               llx.StringData(r.Action),
			"protocol":             llx.StringData(r.Protocol),
			"fwmark":               llx.StringData(r.FwMark),
			"invert":               llx.BoolData(r.Invert),
			"suppressPrefixLength": llx.IntData(r.SuppressPrefixLength),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (n *mqlFrr) bgpNeighbors() ([]any, error) {
	return frrBGPNeighbors(n.MqlRuntime, "")
}

func (n *mqlFrr) evpnVnis() ([]any, error) {
	conn := n.MqlRuntime.Connection.(shared.Connection)

	out, err := runOutput(conn, vtyshCommand("show evpn vni json"))
	if err != nil {
		return nil, err
	}
	vnis, err := frr.ParseEVPNVNIs(out)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(vnis))
	for i := range vnis {
		v := &vnis[i]
		obj, err := CreateResource(n.MqlRuntime, "frr.evpn.vni", map[string]*llx.RawData{
			"__id":            llx.StringData("frr.evpn.vni/" + strconv.FormatInt(v.VNI, 10)),
			"vni":             llx.IntData(v.VNI),
			"type":            llx.StringData(v.Type),
			"vrf":             llx.StringData(v.VRF),
			"vxlanInterface":  llx.StringData(v.VxlanInterface),
			"sviInterface":    llx.StringData(v.SVIInterface),
			"routerMac":       llx.StringData(v.RouterMAC),
			"state":           llx.StringData(v.State),
			"macCount":        llx.IntData(v.NumMacs),
			"arpNdCount":      llx.IntData(v.NumArpNd),
			"remoteVtepCount": llx.IntData(v.NumRemoteVteps),
			"remoteVteps":     llx.ArrayData(stringSliceToAny(v.RemoteVteps), types.String),
			"details":         llx.DictData(anyMapToDict(v.Details)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

// ======================================================================
// frr.vrf
// ======================================================================

func (s *mqlFrrVrf) routes() (*mqlFrrRouteTable, error) {
	name := s.GetName()
	if name.Error != nil {
		return nil, name.Error
	}
	obj, err := CreateResource(s.MqlRuntime, "frr.routeTable", map[string]*llx.RawData{
		"__id":  llx.StringData(frrRouteTableID(name.Data, "ipv4")),
		"vrf":   llx.StringData(name.Data),
		"afi":   llx.StringData("ipv4"),
		"limit": llx.IntData(int64(frr.DefaultRouteLimit)),
	})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlFrrRouteTable), nil
}

func (s *mqlFrrVrf) bgpNeighbors() ([]any, error) {
	name := s.GetName()
	if name.Error != nil {
		return nil, name.Error
	}
	return frrBGPNeighbors(s.MqlRuntime, name.Data)
}

func (s *mqlFrrVrf) rules() ([]any, error) {
	tableID := s.GetTableId()
	if tableID.Error != nil {
		return nil, tableID.Error
	}
	name := s.GetName()
	if name.Error != nil {
		return nil, name.Error
	}

	root, err := NewResource(s.MqlRuntime, "frr", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	rules, err := root.(*mqlFrr).loadRules()
	if err != nil {
		return nil, err
	}

	var mine []frr.RoutingRule
	for i := range rules {
		if tableID.Data != 0 && rules[i].TableID == tableID.Data {
			mine = append(mine, rules[i])
			continue
		}
		// A rule can also name the table, for example when the operator
		// listed the VRF table in /etc/iproute2/rt_tables.
		if rules[i].Table != "" && rules[i].Table == name.Data {
			mine = append(mine, rules[i])
		}
	}
	return createFrrRules(s.MqlRuntime, "frr.vrf/"+name.Data+"/rules", mine)
}

// ======================================================================
// frr.bgp.neighbor
// ======================================================================

// frrBGPNeighbors reads the sessions of one VRF. The VRF is part of the
// command, so FRR filters before it prints.
func frrBGPNeighbors(runtime *plugin.Runtime, vrf string) ([]any, error) {
	conn := runtime.Connection.(shared.Connection)

	summaryCmd := "show bgp summary json"
	neighborCmd := "show bgp neighbors json"
	if vrf != "" {
		if err := frr.ValidateName("vrf", vrf); err != nil {
			return nil, err
		}
		summaryCmd = "show bgp vrf " + vrf + " summary json"
		neighborCmd = "show bgp vrf " + vrf + " neighbors json"
	}

	out, err := runOutput(conn, vtyshCommand(summaryCmd))
	if err != nil {
		return nil, err
	}
	if frr.Refused(out) {
		// A VRF that BGP does not serve has no sessions. The VRF device can
		// still exist, which `frr.vrfs` reports.
		log.Debug().Str("vrf", vrf).Str("answer", strings.TrimSpace(string(out))).
			Msg("vtysh has no bgp summary for this vrf")
		return []any{}, nil
	}
	peers, err := frr.ParseBGPSummary(vrf, out)
	if err != nil {
		return nil, err
	}
	if len(peers) == 0 {
		return []any{}, nil
	}

	// The detail is what carries the running policy and the accepted
	// counters. A failure here must not drop the sessions themselves.
	if detail, derr := runOutput(conn, vtyshCommand(neighborCmd)); derr != nil {
		log.Debug().Err(derr).Str("vrf", vrf).Msg("cannot read bgp neighbor detail")
	} else if eerr := frr.EnrichBGPPeers(peers, detail); eerr != nil {
		log.Debug().Err(eerr).Str("vrf", vrf).Msg("cannot parse bgp neighbor detail")
	}

	// One resource per peer, with the address families underneath.
	type peerGroup struct {
		first    *frr.BGPPeer
		families []*frr.BGPPeer
	}
	var order []string
	groups := map[string]*peerGroup{}
	for i := range peers {
		p := &peers[i]
		g, ok := groups[p.Name]
		if !ok {
			g = &peerGroup{first: p}
			groups[p.Name] = g
			order = append(order, p.Name)
		}
		g.families = append(g.families, p)
	}

	res := make([]any, 0, len(order))
	for _, name := range order {
		g := groups[name]
		id := "frr.bgp.neighbor/" + vrfKey(vrf) + "/" + name

		families := make([]any, 0, len(g.families))
		for _, p := range g.families {
			afID := fmt.Sprintf("%s/%s/%s", id, p.AFI, p.SAFI)
			obj, err := CreateResource(runtime, "frr.bgp.neighbor.addressFamily", map[string]*llx.RawData{
				"__id":                  llx.StringData(afID),
				"afi":                   llx.StringData(p.AFI),
				"safi":                  llx.StringData(p.SAFI),
				"prefixesReceived":      llx.IntData(p.PrefixesReceived),
				"prefixesSent":          llx.IntData(p.PrefixesSent),
				"prefixesAccepted":      llx.IntData(p.PrefixesAccepted),
				"prefixesFiltered":      llx.IntData(p.PrefixesFiltered),
				"prefixesFilteredKnown": llx.BoolData(p.PrefixesFilteredKnown),
				"routeMapIn":            llx.StringData(p.RouteMapIn),
				"routeMapOut":           llx.StringData(p.RouteMapOut),
				"prefixListIn":          llx.StringData(p.PrefixListIn),
				"prefixListOut":         llx.StringData(p.PrefixListOut),
				"details":               llx.DictData(anyMapToDict(p.Details)),
			})
			if err != nil {
				return nil, err
			}
			families = append(families, obj)
		}

		p := g.first
		obj, err := CreateResource(runtime, "frr.bgp.neighbor", map[string]*llx.RawData{
			"__id":                   llx.StringData(id),
			"name":                   llx.StringData(p.Name),
			"vrf":                    llx.StringData(p.VRF),
			"remoteAsn":              llx.IntData(p.RemoteAS),
			"localAsn":               llx.IntData(p.LocalAS),
			"hostname":               llx.StringData(p.Hostname),
			"state":                  llx.StringData(p.State),
			"established":            llx.BoolData(p.Established),
			"uptimeMsec":             llx.IntData(p.UptimeMsec),
			"messagesReceived":       llx.IntData(p.MessagesReceived),
			"messagesSent":           llx.IntData(p.MessagesSent),
			"connectionsEstablished": llx.IntData(p.ConnectionsEstablished),
			"connectionsDropped":     llx.IntData(p.ConnectionsDropped),
			"idType":                 llx.StringData(p.IDType),
			"addressFamilies":        llx.ArrayData(families, types.Resource("frr.bgp.neighbor.addressFamily")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func vrfKey(vrf string) string {
	if vrf == "" {
		return "default"
	}
	return vrf
}

// anyMapToDict passes a decoded JSON object through as a dict value.
func anyMapToDict(in map[string]any) any {
	if in == nil {
		return map[string]any{}
	}
	return in
}

// ======================================================================
// frr.routeTable
// ======================================================================

func frrRouteTableID(vrf, afi string) string {
	return "frr.routeTable/" + vrfKey(vrf) + "/" + afi
}

// initFrrRouteTable fills the defaults of the query and validates the VRF
// name, which becomes part of the vtysh command.
func initFrrRouteTable(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	vrf := ""
	if x, ok := args["vrf"]; ok {
		v, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'vrf' in frr.routeTable initialization, it must be a string")
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
			return nil, nil, errors.New("wrong type for 'afi' in frr.routeTable initialization, it must be a string")
		}
		afi = strings.ToLower(v)
	}
	if afi != "ipv4" && afi != "ipv6" {
		return nil, nil, fmt.Errorf("unsupported address family %q for frr.routeTable, use ipv4 or ipv6", afi)
	}

	limit := int64(frr.DefaultRouteLimit)
	if x, ok := args["limit"]; ok {
		v, ok := x.Value.(int64)
		if !ok {
			return nil, nil, errors.New("wrong type for 'limit' in frr.routeTable initialization, it must be an int")
		}
		if v <= 0 {
			return nil, nil, errors.New("'limit' in frr.routeTable initialization must be greater than zero")
		}
		limit = v
	}

	args["vrf"] = llx.StringData(vrf)
	args["afi"] = llx.StringData(afi)
	args["limit"] = llx.IntData(limit)
	args["__id"] = llx.StringData(frrRouteTableID(vrf, afi))
	return args, nil, nil
}

type mqlFrrRouteTableInternal struct {
	lock   sync.Mutex
	table  *frr.RouteTable
	loaded bool
}

// load runs the route command for the VRF and address family of this
// resource. FRR does the filtering, so the output is already narrowed.
func (s *mqlFrrRouteTable) load() (*frr.RouteTable, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.loaded {
		return s.table, nil
	}

	vrf := s.GetVrf()
	if vrf.Error != nil {
		return nil, vrf.Error
	}
	afi := s.GetAfi()
	if afi.Error != nil {
		return nil, afi.Error
	}
	limit := s.GetLimit()
	if limit.Error != nil {
		return nil, limit.Error
	}

	command := "show ip route"
	if afi.Data == "ipv6" {
		command = "show ipv6 route"
	}
	if vrf.Data != "" {
		if err := frr.ValidateName("vrf", vrf.Data); err != nil {
			return nil, err
		}
		command += " vrf " + vrf.Data
	}
	command += " json"

	conn := s.MqlRuntime.Connection.(shared.Connection)
	cmd, err := conn.RunCommand(vtyshCommand(command))
	if err != nil {
		return nil, fmt.Errorf("cannot run %q: %w", command, err)
	}
	if cmd == nil {
		return nil, fmt.Errorf("cannot run %q, the connection returned no result", command)
	}
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("%q failed with exit status %d: %s",
			command, cmd.ExitStatus, strings.TrimSpace(string(stderr)))
	}

	// vtysh answers an unknown VRF with a percent sign and a zero exit
	// status, so the first byte decides whether this is a result at all.
	reader := bufio.NewReader(io.LimitReader(cmd.Stdout, frrRouteByteLimit))
	if head, perr := reader.Peek(1); perr == nil && head[0] == '%' {
		rest, _ := io.ReadAll(reader)
		log.Debug().Str("vrf", vrf.Data).Str("answer", strings.TrimSpace(string(head)+string(rest))).
			Msg("vtysh has no routes for this vrf")
		s.table = &frr.RouteTable{}
		s.loaded = true
		return s.table, nil
	}

	table, err := frr.StreamRoutes(reader, int(limit.Data))
	if err != nil {
		return nil, err
	}

	s.table = table
	s.loaded = true
	return s.table, nil
}

func (s *mqlFrrRouteTable) total() (int64, error) {
	table, err := s.load()
	if err != nil {
		return 0, err
	}
	return table.Total, nil
}

func (s *mqlFrrRouteTable) truncated() (bool, error) {
	table, err := s.load()
	if err != nil {
		return false, err
	}
	return table.Truncated, nil
}

func (s *mqlFrrRouteTable) entries() ([]any, error) {
	table, err := s.load()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(table.Entries))
	for i := range table.Entries {
		e := &table.Entries[i]
		nexthops := make([]any, 0, len(e.Nexthops))
		for j := range e.Nexthops {
			h := &e.Nexthops[j]
			nexthops = append(nexthops, map[string]any{
				"ip":                h.IP,
				"interface":         h.Interface,
				"vrf":               h.VRF,
				"active":            h.Active,
				"fib":               h.FIB,
				"directlyConnected": h.DirectlyConnected,
			})
		}

		id := fmt.Sprintf("%s/%d/%s/%s", s.__id, i, e.Prefix, e.Protocol)
		obj, err := CreateResource(s.MqlRuntime, "frr.route", map[string]*llx.RawData{
			"__id":         llx.StringData(id),
			"prefix":       llx.StringData(e.Prefix),
			"prefixLength": llx.IntData(e.PrefixLen),
			"protocol":     llx.StringData(e.Protocol),
			"vrf":          llx.StringData(e.VRF),
			"table":        llx.IntData(e.Table),
			"selected":     llx.BoolData(e.Selected),
			"installed":    llx.BoolData(e.Installed),
			"distance":     llx.IntData(e.Distance),
			"metric":       llx.IntData(e.Metric),
			"uptime":       llx.StringData(e.Uptime),
			"nexthops":     llx.ArrayData(nexthops, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

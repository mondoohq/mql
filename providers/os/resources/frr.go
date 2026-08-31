// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/frr"
	"go.mondoo.com/mql/types"
)

// ======================================================================
// frr — root resource (version detection)
// ======================================================================

// reFrrVersion matches the banner of `vtysh --version`, which starts with
// "FRRouting 8.5.4 (hostname)".
var reFrrVersion = regexp.MustCompile(`FRRouting (\S+)`)

func (n *mqlFrr) version() (string, error) {
	conn := n.MqlRuntime.Connection.(shared.Connection)

	// vtysh is the only binary that reports the version of the whole suite.
	// It exists next to the daemons, on the host for a native install and
	// inside the HBN container for a containerized one.
	cmd, err := conn.RunCommand("vtysh --version")
	if err != nil {
		// The connection could not run the command at all, which is the
		// normal case for an asset snapshot or a filesystem-only scan.
		log.Debug().Err(err).Msg("could not run vtysh --version")
	} else if cmd.ExitStatus == 0 {
		data, rerr := io.ReadAll(cmd.Stdout)
		if rerr != nil {
			log.Debug().Err(rerr).Msg("could not read vtysh --version output")
		} else if m := reFrrVersion.FindSubmatch(data); m != nil {
			return string(m[1]), nil
		}
	}

	// Connections that cannot exec still get the version, because FRR writes
	// a `frr version <x>` line into every config it saves.
	cfg, cerr := NewResource(n.MqlRuntime, "frr.config", map[string]*llx.RawData{})
	if cerr == nil {
		v := cfg.(*mqlFrrConfig).GetVersion()
		if v.Error == nil && v.Data != "" {
			return v.Data, nil
		}
	}

	n.Version = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	return "", nil
}

// ======================================================================
// frr.config — file discovery + parse coordination
// ======================================================================

type mqlFrrConfigInternal struct {
	lock sync.Mutex
	cfg  *frr.Config
	// parseErr keeps the parse failure, so every accessor that runs after
	// the first one reports the same error instead of an empty config.
	parseErr error
}

// frrConfPaths lists where frr.conf is found, in the order the resource
// tries them.
//
// The first entry covers FRR running natively on the host and FRR running
// inside a Host Based Networking container, because the path inside the
// container is the same. The remaining entries cover a container whose
// config is scanned from the host: HBN keeps the container root under
// /var/lib/hbn, and the CRA agent writes the rendered config to /etc/cra.
var frrConfPaths = []string{
	"/etc/frr/frr.conf",
	"/var/lib/hbn/etc/frr/frr.conf",
	"/etc/cra/frr.conf",
	"/usr/local/etc/frr/frr.conf",
}

const defaultFrrConf = "/etc/frr/frr.conf"

// frrVtyshConfPaths mirrors frrConfPaths for vtysh.conf.
var frrVtyshConfPaths = []string{
	"/etc/frr/vtysh.conf",
	"/var/lib/hbn/etc/frr/vtysh.conf",
	"/etc/cra/vtysh.conf",
	"/usr/local/etc/frr/vtysh.conf",
}

const defaultFrrVtyshConf = "/etc/frr/vtysh.conf"

// firstExistingPath returns the first candidate that exists on the asset. It
// falls back to fallback so a missing file surfaces as a file error on the
// default path instead of an empty resource.
func firstExistingPath(conn shared.Connection, candidates []string, fallback string) string {
	afs := &afero.Afero{Fs: conn.FileSystem()}
	for _, p := range candidates {
		if ok, err := afs.Exists(p); err == nil && ok {
			return p
		}
	}
	return fallback
}

func initFrrConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFrrFileArg(runtime, args, "frr.config")
}

func initFrrVtyshConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFrrFileArg(runtime, args, "frr.vtysh.config")
}

// initFrrFileArg turns the optional `path` argument into the `file` field.
func initFrrFileArg(runtime *plugin.Runtime, args map[string]*llx.RawData, resource string) (map[string]*llx.RawData, plugin.Resource, error) {
	x, ok := args["path"]
	if !ok {
		return args, nil, nil
	}
	path, ok := x.Value.(string)
	if !ok {
		return nil, nil, errors.New("wrong type for 'path' in " + resource + " initialization, it must be a string")
	}
	f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, nil, err
	}
	args["file"] = llx.ResourceData(f, "file")
	delete(args, "path")
	return args, nil, nil
}

func (s *mqlFrrConfig) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	return file.Data.Path.Data, nil
}

func (s *mqlFrrConfig) file() (*mqlFile, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	path := firstExistingPath(conn, frrConfPaths, defaultFrrConf)

	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// parse reads and parses the config file once. Every field accessor calls it
// first, so a query that touches several fields still reads the file once.
func (s *mqlFrrConfig) parse(file *mqlFile) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.cfg != nil {
		return s.parseErr
	}
	if file == nil {
		return errors.New("no frr config file to read")
	}

	cfg, err := parseFrrFile(s.MqlRuntime, file)
	if err != nil {
		s.cfg = &frr.Config{}
		s.parseErr = err
		s.markParseErrors(err)
		return err
	}
	s.cfg = cfg
	return nil
}

// parseFrrFile opens a config file over the connection filesystem and parses
// it. The connection decides the filesystem, so a container connection reads
// the config of the container without any extra handling here.
func parseFrrFile(runtime *plugin.Runtime, file *mqlFile) (*frr.Config, error) {
	conn := runtime.Connection.(shared.Connection)
	path := file.Path.Data

	f, err := conn.FileSystem().Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg, err := frr.Parse(path, f)
	if err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (s *mqlFrrConfig) markParseErrors(err error) {
	strVal := plugin.TValue[string]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
	boolVal := plugin.TValue[bool]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
	arrVal := plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}

	s.Hostname = strVal
	s.Version = strVal
	s.Defaults = strVal
	s.IntegratedVtyshConfig = boolVal
	s.Bgp = arrVal
	s.Vrfs = arrVal
	s.Interfaces = arrVal
	s.PrefixLists = arrVal
	s.RouteMaps = arrVal
	s.Blocks = arrVal
	s.Directives = arrVal
	s.StaticRoutes = arrVal
	s.CommunityLists = arrVal
	s.AccessLists = arrVal
	s.AsPathAccessLists = arrVal
	s.Ospf = arrVal
	s.Isis = arrVal
	s.BfdPeers = arrVal
	s.PbrMaps = arrVal
	s.KeyChains = arrVal
	s.VtyLines = arrVal
	s.Rpki = plugin.TValue[*mqlFrrConfigRpkiSettings]{
		Error: err, State: plugin.StateIsSet | plugin.StateIsNull,
	}
	s.SegmentRouting = plugin.TValue[*mqlFrrConfigSegmentRoutingSettings]{
		Error: err, State: plugin.StateIsSet | plugin.StateIsNull,
	}
	s.Service = plugin.TValue[*mqlFrrConfigServiceSettings]{
		Error: err, State: plugin.StateIsSet | plugin.StateIsNull,
	}
}

func (s *mqlFrrConfig) hostname(file *mqlFile) (string, error) {
	if err := s.parse(file); err != nil {
		return "", err
	}
	return s.cfg.Hostname(), nil
}

func (s *mqlFrrConfig) version(file *mqlFile) (string, error) {
	if err := s.parse(file); err != nil {
		return "", err
	}
	return s.cfg.Version(), nil
}

func (s *mqlFrrConfig) defaults(file *mqlFile) (string, error) {
	if err := s.parse(file); err != nil {
		return "", err
	}
	return s.cfg.Defaults(), nil
}

func (s *mqlFrrConfig) integratedVtyshConfig(file *mqlFile) (bool, error) {
	if err := s.parse(file); err != nil {
		return false, err
	}
	return s.cfg.IntegratedVtyshConfig(), nil
}

func (s *mqlFrrConfig) directives(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	return frr.DirectivesAsDicts(s.cfg.Directives), nil
}

func (s *mqlFrrConfig) blocks(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	return s.createBlocks(s.__id, s.cfg.Blocks)
}

func (s *mqlFrrConfig) createBlocks(prefix string, blocks []frr.Block) ([]any, error) {
	res := make([]any, 0, len(blocks))
	for i := range blocks {
		blk := &blocks[i]
		id := fmt.Sprintf("%s#block/%d/%s/%s", prefix, i, blk.Type, blk.Name)
		nested, err := s.createBlocks(id, blk.Blocks)
		if err != nil {
			return nil, err
		}
		obj, err := CreateResource(s.MqlRuntime, "frr.config.block", map[string]*llx.RawData{
			"__id":       llx.StringData(id),
			"type":       llx.StringData(blk.Type),
			"name":       llx.StringData(blk.Name),
			"args":       llx.ArrayData(stringSliceToAny(blk.Args), types.String),
			"file":       llx.StringData(blk.File),
			"startLine":  llx.IntData(int64(blk.StartLine)),
			"endLine":    llx.IntData(int64(blk.EndLine)),
			"directives": llx.ArrayData(frr.DirectivesAsDicts(blk.Directives), types.Dict),
			"blocks":     llx.ArrayData(nested, types.Resource("frr.config.block")),
			"raw":        llx.StringData(blk.Raw),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) bgp(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	instances := s.cfg.BGPInstances()
	res := make([]any, 0, len(instances))
	for i := range instances {
		b := &instances[i]
		// The id is built from what the instance is, not from where it
		// sits, so reordering the blocks does not renumber the rest. An ASN
		// and a VRF name identify an instance.
		id := fmt.Sprintf("%s#bgp/%d/%s", s.__id, b.ASN, b.VRF)

		neighbors, err := s.createNeighbors(id, b.Neighbors)
		if err != nil {
			return nil, err
		}
		families, err := s.createAddressFamilies(id, b.AddressFamilies)
		if err != nil {
			return nil, err
		}

		obj, err := CreateResource(s.MqlRuntime, "frr.config.router", map[string]*llx.RawData{
			"__id":               llx.StringData(id),
			"asn":                llx.IntData(b.ASN),
			"vrf":                llx.StringData(b.VRF),
			"routerId":           llx.StringData(b.RouterID),
			"clusterId":          llx.StringData(b.ClusterID),
			"ebgpRequiresPolicy": llx.BoolData(b.EbgpRequiresPolicy),
			"defaultIpv4Unicast": llx.BoolData(b.DefaultIPv4Unicast),
			"neighbors":          llx.ArrayData(neighbors, types.Resource("frr.config.router.neighbor")),
			"addressFamilies":    llx.ArrayData(families, types.Resource("frr.config.router.addressFamily")),
			"params":             llx.MapData(stringMapToAny(b.Params), types.String),
			"file":               llx.StringData(b.File),
			"startLine":          llx.IntData(int64(b.StartLine)),
			"raw":                llx.StringData(b.Raw),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) createNeighbors(prefix string, neighbors []frr.Neighbor) ([]any, error) {
	res := make([]any, 0, len(neighbors))
	for i := range neighbors {
		n := &neighbors[i]
		id := fmt.Sprintf("%s#neighbor/%s", prefix, n.Name)

		families := make([]any, 0, len(n.AddressFamilies))
		for j := range n.AddressFamilies {
			naf := &n.AddressFamilies[j]
			afID := fmt.Sprintf("%s#af/%s/%s", id, naf.AFI, naf.SAFI)
			obj, err := CreateResource(s.MqlRuntime, "frr.config.router.neighbor.addressFamily", map[string]*llx.RawData{
				"__id":                 llx.StringData(afID),
				"afi":                  llx.StringData(naf.AFI),
				"safi":                 llx.StringData(naf.SAFI),
				"activate":             llx.BoolData(naf.Activate),
				"routeMapIn":           llx.StringData(naf.RouteMapIn),
				"routeMapOut":          llx.StringData(naf.RouteMapOut),
				"prefixListIn":         llx.StringData(naf.PrefixListIn),
				"prefixListOut":        llx.StringData(naf.PrefixListOut),
				"filterListIn":         llx.StringData(naf.FilterListIn),
				"filterListOut":        llx.StringData(naf.FilterListOut),
				"maximumPrefix":        llx.IntData(naf.MaximumPrefix),
				"routeReflectorClient": llx.BoolData(naf.RouteReflectorClient),
				"allowasIn":            llx.BoolData(naf.AllowasIn),
				"nextHopSelf":          llx.BoolData(naf.NextHopSelf),
				"softReconfiguration":  llx.BoolData(naf.SoftReconfiguration),
				"defaultOriginate":     llx.BoolData(naf.DefaultOriginate),
				"removePrivateAs":      llx.BoolData(naf.RemovePrivateAS),
			})
			if err != nil {
				return nil, err
			}
			families = append(families, obj)
		}

		obj, err := CreateResource(s.MqlRuntime, "frr.config.router.neighbor", map[string]*llx.RawData{
			"__id":                     llx.StringData(id),
			"name":                     llx.StringData(n.Name),
			"isInterface":              llx.BoolData(n.Interface),
			"isPeerGroup":              llx.BoolData(n.IsPeerGroup),
			"peerGroup":                llx.StringData(n.PeerGroup),
			"remoteAs":                 llx.StringData(n.RemoteAs),
			"remoteAsn":                llx.IntData(n.RemoteASN),
			"localAsn":                 llx.IntData(n.LocalASN),
			"description":              llx.StringData(n.Description),
			"updateSource":             llx.StringData(n.UpdateSource),
			"listenRange":              llx.StringData(n.ListenRange),
			"bfd":                      llx.BoolData(n.BFD),
			"shutdown":                 llx.BoolData(n.Shutdown),
			"passwordSet":              llx.BoolData(n.PasswordSet),
			"ttlSecurityHops":          llx.IntData(n.TTLSecurityHops),
			"keepaliveTime":            llx.IntData(n.KeepaliveTime),
			"holdTime":                 llx.IntData(n.HoldTime),
			"addressFamilies":          llx.ArrayData(families, types.Resource("frr.config.router.neighbor.addressFamily")),
			"activatedAddressFamilies": llx.ArrayData(stringSliceToAny(n.ActivatedAddressFamilies), types.String),
			"routeMapsIn":              llx.ArrayData(stringSliceToAny(n.RouteMapsIn), types.String),
			"routeMapsOut":             llx.ArrayData(stringSliceToAny(n.RouteMapsOut), types.String),
			"prefixListsIn":            llx.ArrayData(stringSliceToAny(n.PrefixListsIn), types.String),
			"prefixListsOut":           llx.ArrayData(stringSliceToAny(n.PrefixListsOut), types.String),
			"filterListsIn":            llx.ArrayData(stringSliceToAny(n.FilterListsIn), types.String),
			"filterListsOut":           llx.ArrayData(stringSliceToAny(n.FilterListsOut), types.String),
			"params":                   llx.MapData(stringMapToAny(n.Params), types.String),
			"file":                     llx.StringData(n.File),
			"line":                     llx.IntData(int64(n.Line)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) createAddressFamilies(prefix string, families []frr.AddressFamily) ([]any, error) {
	res := make([]any, 0, len(families))
	for i := range families {
		af := &families[i]
		id := fmt.Sprintf("%s#af/%s/%s", prefix, af.AFI, af.SAFI)
		obj, err := CreateResource(s.MqlRuntime, "frr.config.router.addressFamily", map[string]*llx.RawData{
			"__id":               llx.StringData(id),
			"afi":                llx.StringData(af.AFI),
			"safi":               llx.StringData(af.SAFI),
			"networks":           llx.ArrayData(stringSliceToAny(af.Networks), types.String),
			"redistribute":       llx.ArrayData(stringSliceToAny(af.Redistribute), types.String),
			"importVrfs":         llx.ArrayData(stringSliceToAny(af.ImportVrfs), types.String),
			"importVrfRouteMap":  llx.StringData(af.ImportVrfRouteMap),
			"routeTargetsImport": llx.ArrayData(stringSliceToAny(af.RouteTargetsImport), types.String),
			"routeTargetsExport": llx.ArrayData(stringSliceToAny(af.RouteTargetsExport), types.String),
			"advertise":          llx.ArrayData(stringSliceToAny(af.Advertise), types.String),
			"advertiseAllVni":    llx.BoolData(af.AdvertiseAllVNI),
			"vnis":               llx.ArrayData(frr.VNIsAsDicts(af.VNIs), types.Dict),
			"params":             llx.MapData(stringMapToAny(af.Params), types.String),
			"file":               llx.StringData(af.File),
			"startLine":          llx.IntData(int64(af.StartLine)),
			"raw":                llx.StringData(af.Raw),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) vrfs(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	vrfs := s.cfg.VRFs()
	res := make([]any, 0, len(vrfs))
	for i := range vrfs {
		v := &vrfs[i]
		obj, err := CreateResource(s.MqlRuntime, "frr.config.vrf", map[string]*llx.RawData{
			"__id":               llx.StringData(s.__id + "#vrf/" + v.Name),
			"name":               llx.StringData(v.Name),
			"vni":                llx.IntData(v.VNI),
			"staticRoutes":       llx.ArrayData(stringSliceToAny(v.StaticRoutes), types.String),
			"routerAsn":          llx.IntData(v.RouterASN),
			"routeTargetsImport": llx.ArrayData(stringSliceToAny(v.RouteTargetsImport), types.String),
			"routeTargetsExport": llx.ArrayData(stringSliceToAny(v.RouteTargetsExport), types.String),
			"importedVrfs":       llx.ArrayData(stringSliceToAny(v.ImportedVrfs), types.String),
			"params":             llx.MapData(stringMapToAny(v.Params), types.String),
			"file":               llx.StringData(v.File),
			"startLine":          llx.IntData(int64(v.StartLine)),
			"raw":                llx.StringData(v.Raw),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) interfaces(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	ifaces := s.cfg.Interfaces()
	res := make([]any, 0, len(ifaces))
	for i := range ifaces {
		iface := &ifaces[i]
		ifaceArgs := map[string]*llx.RawData{
			"__id":          llx.StringData(s.__id + "#interface/" + iface.Name),
			"name":          llx.StringData(iface.Name),
			"vrf":           llx.StringData(iface.VRF),
			"description":   llx.StringData(iface.Description),
			"ipAddresses":   llx.ArrayData(stringSliceToAny(iface.IPAddresses), types.String),
			"ipv6Addresses": llx.ArrayData(stringSliceToAny(iface.IPv6Addresses), types.String),
			"shutdown":      llx.BoolData(iface.Shutdown),
			"pbrPolicy":     llx.StringData(iface.PBRPolicy),
			"params":        llx.MapData(stringMapToAny(iface.Params), types.String),
			"file":          llx.StringData(iface.File),
			"startLine":     llx.IntData(int64(iface.StartLine)),
			"raw":           llx.StringData(iface.Raw),
		}
		interfaceProtocolArgs(ifaceArgs, &iface.Protocols)

		obj, err := CreateResource(s.MqlRuntime, "frr.config.interface", ifaceArgs)
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) prefixLists(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	lists := s.cfg.PrefixLists()
	res := make([]any, 0, len(lists))
	for i := range lists {
		pl := &lists[i]
		obj, err := CreateResource(s.MqlRuntime, "frr.config.prefixList", map[string]*llx.RawData{
			"__id":    llx.StringData(s.__id + "#prefixList/" + pl.AFI + "/" + pl.Name),
			"name":    llx.StringData(pl.Name),
			"afi":     llx.StringData(pl.AFI),
			"entries": llx.ArrayData(frr.PrefixListEntriesAsDicts(pl.Entries), types.Dict),
			"file":    llx.StringData(pl.File),
			"line":    llx.IntData(int64(pl.Line)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

func (s *mqlFrrConfig) routeMaps(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	maps := s.cfg.RouteMaps()
	res := make([]any, 0, len(maps))
	for i := range maps {
		rm := &maps[i]
		id := s.__id + "#routeMap/" + rm.Name

		entries := make([]any, 0, len(rm.Entries))
		for j := range rm.Entries {
			e := &rm.Entries[j]
			entryArgs := map[string]*llx.RawData{
				"__id":      llx.StringData(id + "/" + strconv.FormatInt(e.Sequence, 10) + "/" + strconv.Itoa(j)),
				"name":      llx.StringData(e.Name),
				"action":    llx.StringData(e.Action),
				"sequence":  llx.IntData(e.Sequence),
				"match":     llx.ArrayData(stringSliceToAny(e.Match), types.String),
				"set":       llx.ArrayData(stringSliceToAny(e.Set), types.String),
				"call":      llx.StringData(e.Call),
				"onMatch":   llx.StringData(e.OnMatch),
				"file":      llx.StringData(e.File),
				"startLine": llx.IntData(int64(e.StartLine)),
				"raw":       llx.StringData(e.Raw),
			}
			routeMapClauseArgs(entryArgs, &e.Clauses)

			obj, err := CreateResource(s.MqlRuntime, "frr.config.routeMap.entry", entryArgs)
			if err != nil {
				return nil, err
			}
			entries = append(entries, obj)
		}

		obj, err := CreateResource(s.MqlRuntime, "frr.config.routeMap", map[string]*llx.RawData{
			"__id":    llx.StringData(id),
			"name":    llx.StringData(rm.Name),
			"entries": llx.ArrayData(entries, types.Resource("frr.config.routeMap.entry")),
			"file":    llx.StringData(rm.File),
			"line":    llx.IntData(int64(rm.Line)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, obj)
	}
	return res, nil
}

// ======================================================================
// frr.vtysh.config — vtysh.conf
// ======================================================================

type mqlFrrVtyshConfigInternal struct {
	lock sync.Mutex
	cfg  *frr.Config
	// parseErr keeps the parse failure, see mqlFrrConfigInternal.
	parseErr error
}

func (s *mqlFrrVtyshConfig) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	return file.Data.Path.Data, nil
}

func (s *mqlFrrVtyshConfig) file() (*mqlFile, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	path := firstExistingPath(conn, frrVtyshConfPaths, defaultFrrVtyshConf)

	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (s *mqlFrrVtyshConfig) parse(file *mqlFile) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.cfg != nil {
		return s.parseErr
	}
	if file == nil {
		return errors.New("no vtysh config file to read")
	}

	cfg, err := parseFrrFile(s.MqlRuntime, file)
	if err != nil {
		s.cfg = &frr.Config{}
		s.parseErr = err
		s.markParseErrors(err)
		return err
	}
	s.cfg = cfg
	return nil
}

func (s *mqlFrrVtyshConfig) markParseErrors(err error) {
	s.Hostname = plugin.TValue[string]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
	s.IntegratedConfig = plugin.TValue[bool]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
	s.Users = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
	s.Directives = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
	s.Params = plugin.TValue[map[string]any]{Error: err, State: plugin.StateIsSet | plugin.StateIsNull}
}

func (s *mqlFrrVtyshConfig) hostname(file *mqlFile) (string, error) {
	if err := s.parse(file); err != nil {
		return "", err
	}
	return s.cfg.Hostname(), nil
}

func (s *mqlFrrVtyshConfig) integratedConfig(file *mqlFile) (bool, error) {
	if err := s.parse(file); err != nil {
		return false, err
	}
	return s.cfg.IntegratedVtyshConfig(), nil
}

func (s *mqlFrrVtyshConfig) users(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	return frr.VtyshUsersAsDicts(s.cfg.VtyshUsers()), nil
}

func (s *mqlFrrVtyshConfig) directives(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	return frr.DirectivesAsDicts(s.cfg.Directives), nil
}

func (s *mqlFrrVtyshConfig) params(file *mqlFile) (map[string]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	return stringMapToAny(s.cfg.Params()), nil
}

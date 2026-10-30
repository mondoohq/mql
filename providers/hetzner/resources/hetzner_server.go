// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sync"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

type mqlHetznerInternal struct {
	// serversOnce guards a single project-wide Server.List so the servers()
	// field and the location server rollups share one API round-trip
	// instead of each firing its own list call.
	serversOnce sync.Once
	serversList []*hcloud.Server
	serversErr  error

	// The remaining caches serve DNS record resolution, which asks whether an
	// address record points at anything the project holds. Answering that for
	// one record needs every public address in the project, so each list is
	// taken once per scan and shared across all records. See
	// hetzner_dnsrecords.go.
	primaryIPsOnce sync.Once
	primaryIPsList []*hcloud.PrimaryIP
	primaryIPsErr  error

	floatingIPsOnce sync.Once
	floatingIPsList []*hcloud.FloatingIP
	floatingIPsErr  error

	loadBalancersOnce sync.Once
	loadBalancersList []*hcloud.LoadBalancer
	loadBalancersErr  error

	// certificatesOnce backs the load balancer certificate union, which
	// resolves certificate IDs against the project list rather than looking
	// each one up on its own.
	certificatesOnce sync.Once
	certificatesList []*hcloud.Certificate
	certificatesErr  error

	// volumesOnce and storageBoxesOnce back the location residency rollups
	// alongside the address lists above, so `hetzner.locations { volumes }`
	// costs one list call rather than one per location.
	volumesOnce sync.Once
	volumesList []*hcloud.Volume
	volumesErr  error

	storageBoxesOnce sync.Once
	storageBoxesList []*hcloud.StorageBox
	storageBoxesErr  error

	// zoneRecords backs the reverse edge, server.dnsRecords. It costs a zone
	// list plus one record-set list per zone, so it stays separate from the
	// address lists above and is only paid when that edge is queried.
	zoneRecordsOnce sync.Once
	zoneRecordsList []zoneRecord
	zoneRecordsErr  error
}

type mqlHetznerServerInternal struct {
	cacheServerType     *hcloud.ServerType
	cacheLocation       *hcloud.Location
	cacheImage          *hcloud.Image
	cacheVolumes        []*hcloud.Volume
	cacheFloatingIPs    []*hcloud.FloatingIP
	cachePrimaryIPv4ID  int64
	cachePrimaryIPv6ID  int64
	cachePlacementGroup *hcloud.PlacementGroup
	cacheISO            *hcloud.ISO
	cachePrivateNet     []hcloud.ServerPrivateNet
	cacheFirewalls      []*hcloud.ServerFirewallStatus
	cacheLoadBalancers  []*hcloud.LoadBalancer
	cachePublicNet      hcloud.ServerPublicNet
}

func (r *mqlHetznerServer) id() (string, error) {
	return fmt.Sprintf("hetzner.server/%d", r.Id.Data), nil
}

// allServers lists every project server exactly once and caches the raw
// result on the hetzner namespace resource. The servers() field and the
// location/datacenter server rollups all resolve through here, so a bulk query
// like `hetzner.locations { servers }` costs a single Server.List rather than
// one per location.
func (h *mqlHetzner) allServers() ([]*hcloud.Server, error) {
	h.serversOnce.Do(func() {
		c := conn(h.MqlRuntime)
		h.serversList, h.serversErr = paginate(func(opts hcloud.ListOpts) ([]*hcloud.Server, *hcloud.Response, error) {
			return c.Client().Server.List(ctx(), hcloud.ServerListOpts{ListOpts: opts})
		})
	})
	return h.serversList, h.serversErr
}

func (h *mqlHetzner) servers() ([]any, error) {
	items, err := h.allServers()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, s := range items {
		res, err := newMqlHetznerServer(h.MqlRuntime, s)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// hetznerNamespace resolves the singleton hetzner namespace resource so shared
// caches (e.g. the server list) can be reached from other resources.
func hetznerNamespace(runtime *plugin.Runtime) (*mqlHetzner, error) {
	res, err := NewResource(runtime, "hetzner", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHetzner), nil
}

// serversMatching returns full server resources for the servers the match
// predicate selects, filtering the once-cached project server list in memory.
// The location.servers reverse edge uses it so repeated calls across a bulk
// query share a single Server.List round-trip.
func serversMatching(runtime *plugin.Runtime, match func(*hcloud.Server) bool) ([]any, error) {
	h, err := hetznerNamespace(runtime)
	if err != nil {
		return nil, err
	}
	items, err := h.allServers()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, s := range items {
		if !match(s) {
			continue
		}
		res, err := newMqlHetznerServer(runtime, s)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerServer(runtime *plugin.Runtime, s *hcloud.Server) (*mqlHetznerServer, error) {
	// Hetzner assigns a /64 to each server; prefer the network CIDR and fall
	// back to the bare address when the network is not populated.
	ipv6 := ipNetString(s.PublicNet.IPv6.Network)
	if ipv6 == "" {
		ipv6 = ipString(s.PublicNet.IPv6.IP)
	}
	res, err := CreateResource(runtime, "hetzner.server", map[string]*llx.RawData{
		"__id":              llx.StringData(fmt.Sprintf("hetzner.server/%d", s.ID)),
		"id":                llx.IntData(s.ID),
		"name":              llx.StringData(s.Name),
		"status":            llx.StringData(string(s.Status)),
		"created":           llx.TimeDataPtr(timePtr(s.Created)),
		"primaryDiskSize":   llx.IntData(int64(s.PrimaryDiskSize)),
		"publicIpv4":        llx.StringData(ipString(s.PublicNet.IPv4.IP)),
		"publicIpv4Blocked": llx.BoolData(s.PublicNet.IPv4.Blocked),
		"publicIpv4DnsPtr":  llx.StringData(s.PublicNet.IPv4.DNSPtr),
		"publicIpv6":        llx.StringData(ipv6),
		"publicIpv6Blocked": llx.BoolData(s.PublicNet.IPv6.Blocked),
		"publicIpv6DnsPtr":  dictArrayData(dnsPtrSliceFromMap(s.PublicNet.IPv6.DNSPtr)),
		"backupWindow":      llx.StringData(s.BackupWindow),
		"backupsEnabled":    llx.BoolData(s.BackupWindow != ""),
		"rescueEnabled":     llx.BoolData(s.RescueEnabled),
		"locked":            llx.BoolData(s.Locked),
		"includedTraffic":   llx.IntData(int64(s.IncludedTraffic)),
		"outgoingTraffic":   llx.IntData(int64(s.OutgoingTraffic)),
		"ingoingTraffic":    llx.IntData(int64(s.IngoingTraffic)),
		"labels":            labelData(s.Labels),
		"protection":        llx.DictData(protectionDictRebuild(s.Protection.Delete, s.Protection.Rebuild)),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerServer)
	m.cacheServerType = s.ServerType
	m.cacheLocation = s.Location
	m.cacheImage = s.Image
	m.cacheVolumes = s.Volumes
	m.cacheFloatingIPs = s.PublicNet.FloatingIPs
	m.cachePublicNet = s.PublicNet
	m.cachePrimaryIPv4ID = s.PublicNet.IPv4.ID
	m.cachePrimaryIPv6ID = s.PublicNet.IPv6.ID
	m.cachePlacementGroup = s.PlacementGroup
	m.cacheISO = s.ISO
	m.cachePrivateNet = s.PrivateNet
	m.cacheFirewalls = s.PublicNet.Firewalls
	m.cacheLoadBalancers = s.LoadBalancers
	return m, nil
}

func initHetznerServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "server")
	if err != nil {
		return nil, nil, err
	}
	s, _, err := conn(runtime).Client().Server.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if s == nil {
		return nil, nil, notFoundErr("server", id)
	}
	res, err := newMqlHetznerServer(runtime, s)
	return args, res, err
}

func (m *mqlHetznerServer) serverType() (*mqlHetznerServerType, error) {
	return resolveTypedResource(&m.ServerType, m.cacheServerType, func(t *hcloud.ServerType) (*mqlHetznerServerType, error) {
		return newMqlHetznerServerType(m.MqlRuntime, t)
	})
}

func (m *mqlHetznerServer) location() (*mqlHetznerLocation, error) {
	return resolveTypedResource(&m.Location, m.cacheLocation, func(l *hcloud.Location) (*mqlHetznerLocation, error) {
		return newMqlHetznerLocation(m.MqlRuntime, l)
	})
}

func (m *mqlHetznerServer) image() (*mqlHetznerImage, error) {
	return resolveTypedResource(&m.Image, m.cacheImage, func(img *hcloud.Image) (*mqlHetznerImage, error) {
		return newMqlHetznerImage(m.MqlRuntime, img)
	})
}

func (m *mqlHetznerServer) volumes() ([]any, error) {
	out := make([]any, 0, len(m.cacheVolumes))
	for _, v := range m.cacheVolumes {
		// Server.Volumes carries partial Volume objects (just IDs); resolve via init.
		ref, err := NewResource(m.MqlRuntime, "hetzner.volume", map[string]*llx.RawData{
			"id": llx.IntData(v.ID),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}

func (m *mqlHetznerServer) floatingIps() ([]any, error) {
	out := make([]any, 0, len(m.cacheFloatingIPs))
	for _, f := range m.cacheFloatingIPs {
		ref, err := NewResource(m.MqlRuntime, "hetzner.floatingIp", map[string]*llx.RawData{
			"id": llx.IntData(f.ID),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}

func (m *mqlHetznerServer) firewalls() ([]any, error) {
	out := make([]any, 0, len(m.cacheFirewalls))
	for _, fw := range m.cacheFirewalls {
		ref, err := NewResource(m.MqlRuntime, "hetzner.firewall", map[string]*llx.RawData{
			"id": llx.IntData(fw.Firewall.ID),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}

func (m *mqlHetznerServer) firewallBindings() ([]any, error) {
	out := make([]any, 0, len(m.cacheFirewalls))
	for _, fw := range m.cacheFirewalls {
		res, err := newMqlHetznerServerFirewallBinding(m.MqlRuntime, m.Id.Data, fw)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (m *mqlHetznerServer) loadBalancers() ([]any, error) {
	out := make([]any, 0, len(m.cacheLoadBalancers))
	for _, lb := range m.cacheLoadBalancers {
		ref, err := NewResource(m.MqlRuntime, "hetzner.loadBalancer", map[string]*llx.RawData{
			"id": llx.IntData(lb.ID),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}

func (m *mqlHetznerServer) primaryIpv4() (*mqlHetznerPrimaryIp, error) {
	return primaryIpRefByID(m.MqlRuntime, &m.PrimaryIpv4, m.cachePrimaryIPv4ID)
}

func (m *mqlHetznerServer) primaryIpv6() (*mqlHetznerPrimaryIp, error) {
	return primaryIpRefByID(m.MqlRuntime, &m.PrimaryIpv6, m.cachePrimaryIPv6ID)
}

func primaryIpRefByID(runtime *plugin.Runtime, field *plugin.TValue[*mqlHetznerPrimaryIp], id int64) (*mqlHetznerPrimaryIp, error) {
	if id == 0 {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ref, err := NewResource(runtime, "hetzner.primaryIp", map[string]*llx.RawData{
		"id": llx.IntData(id),
	})
	if err != nil {
		return nil, err
	}
	return ref.(*mqlHetznerPrimaryIp), nil
}

func (m *mqlHetznerServer) placementGroup() (*mqlHetznerPlacementGroup, error) {
	return resolveTypedResource(&m.PlacementGroup, m.cachePlacementGroup, func(pg *hcloud.PlacementGroup) (*mqlHetznerPlacementGroup, error) {
		return newMqlHetznerPlacementGroup(m.MqlRuntime, pg)
	})
}

func (m *mqlHetznerServer) iso() (*mqlHetznerIso, error) {
	return resolveTypedResource(&m.Iso, m.cacheISO, func(iso *hcloud.ISO) (*mqlHetznerIso, error) {
		return newMqlHetznerIso(m.MqlRuntime, iso)
	})
}

func (m *mqlHetznerServer) privateNet() ([]any, error) {
	out := make([]any, 0, len(m.cachePrivateNet))
	for _, p := range m.cachePrivateNet {
		res, err := newMqlHetznerServerPrivateNet(m.MqlRuntime, m.Id.Data, p)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// --- server.privateNet sub-resource ---

// mqlHetznerServerPrivateNetInternal holds the server and network the
// attachment joins, which the server and network accessors resolve.
type mqlHetznerServerPrivateNetInternal struct {
	cacheServerID  int64
	cacheNetworkID int64
}

func (r *mqlHetznerServerPrivateNet) id() (string, error) {
	return fmt.Sprintf("hetzner.server.privateNet/%d/%d", r.cacheServerID, r.cacheNetworkID), nil
}

func newMqlHetznerServerPrivateNet(runtime *plugin.Runtime, serverID int64, p hcloud.ServerPrivateNet) (*mqlHetznerServerPrivateNet, error) {
	var networkID int64
	if p.Network != nil {
		networkID = p.Network.ID
	}
	aliases := make([]any, 0, len(p.Aliases))
	for _, a := range p.Aliases {
		aliases = append(aliases, ipString(a))
	}
	res, err := CreateResource(runtime, "hetzner.server.privateNet", map[string]*llx.RawData{
		"__id":       llx.StringData(fmt.Sprintf("hetzner.server.privateNet/%d/%d", serverID, networkID)),
		"ip":         llx.StringData(ipString(p.IP)),
		"aliasIps":   llx.ArrayData(aliases, types.String),
		"macAddress": llx.StringData(p.MACAddress),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerServerPrivateNet)
	m.cacheServerID = serverID
	m.cacheNetworkID = networkID
	return m, nil
}

// serverRef builds a lazy hetzner.server reference from its id, used by the
// sub-resources that point back at their parent server.
func serverRef(runtime *plugin.Runtime, field *plugin.TValue[*mqlHetznerServer], id int64) (*mqlHetznerServer, error) {
	if id == 0 {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ref, err := NewResource(runtime, "hetzner.server", map[string]*llx.RawData{
		"id": llx.IntData(id),
	})
	if err != nil {
		return nil, err
	}
	return ref.(*mqlHetznerServer), nil
}

func (m *mqlHetznerServerPrivateNet) server() (*mqlHetznerServer, error) {
	return serverRef(m.MqlRuntime, &m.Server, m.cacheServerID)
}

func (m *mqlHetznerServerPrivateNet) network() (*mqlHetznerNetwork, error) {
	if m.cacheNetworkID == 0 {
		m.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ref, err := NewResource(m.MqlRuntime, "hetzner.network", map[string]*llx.RawData{
		"id": llx.IntData(m.cacheNetworkID),
	})
	if err != nil {
		return nil, err
	}
	return ref.(*mqlHetznerNetwork), nil
}

// --- server.firewallBinding sub-resource ---

// mqlHetznerServerFirewallBindingInternal holds the server and firewall the
// binding joins, which the server and firewall accessors resolve.
type mqlHetznerServerFirewallBindingInternal struct {
	cacheServerID   int64
	cacheFirewallID int64
}

func (r *mqlHetznerServerFirewallBinding) id() (string, error) {
	return fmt.Sprintf("hetzner.server.firewallBinding/%d/%d", r.cacheServerID, r.cacheFirewallID), nil
}

func newMqlHetznerServerFirewallBinding(runtime *plugin.Runtime, serverID int64, fw *hcloud.ServerFirewallStatus) (*mqlHetznerServerFirewallBinding, error) {
	res, err := CreateResource(runtime, "hetzner.server.firewallBinding", map[string]*llx.RawData{
		"__id":   llx.StringData(fmt.Sprintf("hetzner.server.firewallBinding/%d/%d", serverID, fw.Firewall.ID)),
		"status": llx.StringData(string(fw.Status)),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerServerFirewallBinding)
	m.cacheServerID = serverID
	m.cacheFirewallID = fw.Firewall.ID
	return m, nil
}

func (m *mqlHetznerServerFirewallBinding) server() (*mqlHetznerServer, error) {
	return serverRef(m.MqlRuntime, &m.Server, m.cacheServerID)
}

func (m *mqlHetznerServerFirewallBinding) firewall() (*mqlHetznerFirewall, error) {
	if m.cacheFirewallID == 0 {
		m.Firewall.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ref, err := NewResource(m.MqlRuntime, "hetzner.firewall", map[string]*llx.RawData{
		"id": llx.IntData(m.cacheFirewallID),
	})
	if err != nil {
		return nil, err
	}
	return ref.(*mqlHetznerFirewall), nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"sync"
	"sync/atomic"

	vpn "github.com/stackitcloud/stackit-sdk-go/services/vpn/v1api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlStackitVpnGatewayConnectionInternal struct {
	// cacheTunnel1/cacheTunnel2 hold the connection's two tunnel
	// configurations, captured when the connection is built so tunnel1() and
	// tunnel2() can expose them without another API call. cacheIdBase is the
	// connection's own cache key, used to key the tunnel sub-resources.
	// cacheGatewayID is the owning gateway, which the tunnels need to find
	// their live status.
	cacheTunnel1   *vpn.TunnelConfiguration
	cacheTunnel2   *vpn.TunnelConfiguration
	cacheIdBase    string
	cacheGatewayID string
}

// mqlStackitVpnGatewayInternal caches the gateway's live status, read once
// through GetGatewayStatus and shared by the public-address, BGP-peer, and
// per-tunnel negotiated-parameter accessors.
type mqlStackitVpnGatewayInternal struct {
	statusFetched atomic.Bool
	status        *vpn.GatewayStatusResponse
	statusLock    sync.Mutex
}

// mqlStackitVpnTunnelInternal locates a tunnel's live status inside its
// gateway's status response: the gateway, the connection, and the slot
// (tunnel1 or tunnel2).
type mqlStackitVpnTunnelInternal struct {
	cacheGatewayID    string
	cacheConnectionID string
	cacheSlot         string
}

// fetchStatus reads the gateway's live status once and caches it. A nil
// result with a nil error means the status could not be read (denied, or the
// gateway is gone), and every status-derived field reports null.
func (r *mqlStackitVpnGateway) fetchStatus() (*vpn.GatewayStatusResponse, error) {
	if r.statusFetched.Load() {
		return r.status, nil
	}
	r.statusLock.Lock()
	defer r.statusLock.Unlock()
	if r.statusFetched.Load() {
		return r.status, nil
	}
	c := conn(r.MqlRuntime)
	client, err := c.Vpn()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.GetGatewayStatus(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			r.statusFetched.Store(true)
			return nil, nil
		}
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				r.statusFetched.Store(true)
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	r.status = resp
	r.statusFetched.Store(true)
	return r.status, nil
}

// publicIps lists the public addresses of the gateway's tunnel endpoints,
// the internet-facing surface of the VPN. Empty when the status carries
// none; null when the status could not be read.
func (r *mqlStackitVpnGateway) publicIps() ([]any, error) {
	st, err := r.fetchStatus()
	if err != nil {
		return nil, err
	}
	if st == nil {
		r.PublicIps.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return strSlice(gatewayPublicIPs(st)), nil
}

// errorMessage reports the failure the gateway is in, empty when healthy.
// Null when the status could not be read.
func (r *mqlStackitVpnGateway) errorMessage() (string, error) {
	st, err := r.fetchStatus()
	if err != nil {
		return "", err
	}
	if st == nil {
		r.ErrorMessage.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return st.GetErrorMessage(), nil
}

// bgpPeers lists the BGP sessions the gateway's tunnel instances hold, one
// per remote peer, with the session state and the routes exchanged. Empty
// for a static-routing gateway; null when the status could not be read.
func (r *mqlStackitVpnGateway) bgpPeers() ([]any, error) {
	st, err := r.fetchStatus()
	if err != nil {
		return nil, err
	}
	if st == nil {
		r.BgpPeers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	c := conn(r.MqlRuntime)
	out := []any{}
	for _, t := range st.GetTunnels() {
		bgp, ok := t.GetBgpStatusOk()
		if !ok || bgp == nil {
			continue
		}
		slot := string(t.GetName())
		for _, peer := range bgp.GetPeers() {
			res, err := CreateResource(r.MqlRuntime, "stackit.vpn.gateway.bgpPeer", map[string]*llx.RawData{
				"__id":             llx.StringData("stackit.vpn.gateway.bgpPeer/" + c.ProjectID() + "/" + r.Id.Data + "/" + slot + "/" + peer.GetRemoteIP()),
				"tunnel":           llx.StringData(slot),
				"remoteIp":         llx.StringData(peer.GetRemoteIP()),
				"remoteAsn":        llx.IntData(peer.GetRemoteAs()),
				"localAsn":         llx.IntData(peer.GetLocalAs()),
				"state":            llx.StringData(peer.GetState()),
				"uptime":           llx.StringData(peer.GetPeerUptime()),
				"prefixesReceived": llx.IntData(int64(peer.GetPfxRcd())),
				"prefixesSent":     llx.IntData(int64(peer.GetPfxSnt())),
			})
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
	}
	return out, nil
}

// gatewayPublicIPs collects the tunnel endpoints' public addresses out of a
// gateway status, deduplicated and sorted.
func gatewayPublicIPs(st *vpn.GatewayStatusResponse) []string {
	if st == nil {
		return nil
	}
	seen := map[string]struct{}{}
	for _, t := range st.GetTunnels() {
		if ip := t.GetPublicIP(); ip != "" {
			seen[ip] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// findTunnelStatus locates one tunnel's live status in a gateway status by
// connection id and slot name (tunnel1 or tunnel2). Nil when the connection
// or the slot is not in the response.
func findTunnelStatus(st *vpn.GatewayStatusResponse, connectionID, slot string) *vpn.TunnelStatus {
	if st == nil {
		return nil
	}
	for _, c := range st.GetConnections() {
		if c.GetId() != connectionID {
			continue
		}
		tunnels := c.GetTunnels()
		for i := range tunnels {
			if string(tunnels[i].GetName()) == slot {
				return &tunnels[i]
			}
		}
	}
	return nil
}

// tunnelStatus resolves the live status of the tunnel through its gateway,
// whose status fetch is shared across every tunnel and connection on it.
// Nil when the status could not be read or does not carry the tunnel.
func (r *mqlStackitVpnTunnel) tunnelStatus() (*vpn.TunnelStatus, error) {
	if r.cacheGatewayID == "" {
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "stackit.vpn.gateway", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheGatewayID),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		if isAccessDenied(err) {
			if !plugin.StructuredErrors() {
				return nil, nil
			}
			return nil, refusal(err)
		}
		return nil, err
	}
	st, err := res.(*mqlStackitVpnGateway).fetchStatus()
	if err != nil {
		return nil, err
	}
	return findTunnelStatus(st, r.cacheConnectionID, r.cacheSlot), nil
}

// tunnelStatusString reads one string out of the tunnel's live status,
// marking the field null when the status is unavailable or the value absent.
func tunnelStatusString(r *mqlStackitVpnTunnel, field *plugin.TValue[string], pick func(*vpn.TunnelStatus) (*string, bool)) (string, error) {
	ts, err := r.tunnelStatus()
	if err != nil {
		return "", err
	}
	if ts == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	v, ok := pick(ts)
	if !ok || v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *v, nil
}

func (r *mqlStackitVpnTunnel) established() (bool, error) {
	ts, err := r.tunnelStatus()
	if err != nil {
		return false, err
	}
	if ts == nil {
		return nullBool(&r.Established)
	}
	v, ok := ts.GetEstablishedOk()
	if !ok || v == nil {
		return nullBool(&r.Established)
	}
	return *v, nil
}

func (r *mqlStackitVpnTunnel) phase1State() (string, error) {
	return tunnelStatusString(r, &r.Phase1State, func(t *vpn.TunnelStatus) (*string, bool) {
		p, ok := t.GetPhase1Ok()
		if !ok || p == nil {
			return nil, false
		}
		return p.GetStateOk()
	})
}

func (r *mqlStackitVpnTunnel) negotiatedPhase1DhGroup() (string, error) {
	return tunnelStatusString(r, &r.NegotiatedPhase1DhGroup, func(t *vpn.TunnelStatus) (*string, bool) {
		p, ok := t.GetPhase1Ok()
		if !ok || p == nil {
			return nil, false
		}
		return p.GetDhGroupOk()
	})
}

func (r *mqlStackitVpnTunnel) negotiatedPhase1EncryptionAlgorithm() (string, error) {
	return tunnelStatusString(r, &r.NegotiatedPhase1EncryptionAlgorithm, func(t *vpn.TunnelStatus) (*string, bool) {
		p, ok := t.GetPhase1Ok()
		if !ok || p == nil {
			return nil, false
		}
		return p.GetEncryptionAlgorithmOk()
	})
}

func (r *mqlStackitVpnTunnel) negotiatedPhase1IntegrityAlgorithm() (string, error) {
	return tunnelStatusString(r, &r.NegotiatedPhase1IntegrityAlgorithm, func(t *vpn.TunnelStatus) (*string, bool) {
		p, ok := t.GetPhase1Ok()
		if !ok || p == nil {
			return nil, false
		}
		return p.GetIntegrityAlgorithmOk()
	})
}

func (r *mqlStackitVpnTunnel) phase2State() (string, error) {
	return tunnelStatusString(r, &r.Phase2State, func(t *vpn.TunnelStatus) (*string, bool) {
		p, ok := t.GetPhase2Ok()
		if !ok || p == nil {
			return nil, false
		}
		return p.GetStateOk()
	})
}

func (r *mqlStackitVpnTunnel) negotiatedPhase2DhGroup() (string, error) {
	return tunnelStatusString(r, &r.NegotiatedPhase2DhGroup, func(t *vpn.TunnelStatus) (*string, bool) {
		p, ok := t.GetPhase2Ok()
		if !ok || p == nil {
			return nil, false
		}
		return p.GetDhGroupOk()
	})
}

func (r *mqlStackitVpnTunnel) negotiatedPhase2EncryptionAlgorithm() (string, error) {
	return tunnelStatusString(r, &r.NegotiatedPhase2EncryptionAlgorithm, func(t *vpn.TunnelStatus) (*string, bool) {
		p, ok := t.GetPhase2Ok()
		if !ok || p == nil {
			return nil, false
		}
		return p.GetEncryptionAlgorithmOk()
	})
}

func (r *mqlStackitVpnTunnel) negotiatedPhase2IntegrityAlgorithm() (string, error) {
	return tunnelStatusString(r, &r.NegotiatedPhase2IntegrityAlgorithm, func(t *vpn.TunnelStatus) (*string, bool) {
		p, ok := t.GetPhase2Ok()
		if !ok || p == nil {
			return nil, false
		}
		return p.GetIntegrityAlgorithmOk()
	})
}

func (r *mqlStackitVpnTunnel) negotiatedPhase2Encapsulation() (string, error) {
	return tunnelStatusString(r, &r.NegotiatedPhase2Encapsulation, func(t *vpn.TunnelStatus) (*string, bool) {
		p, ok := t.GetPhase2Ok()
		if !ok || p == nil {
			return nil, false
		}
		return p.GetEncapOk()
	})
}

func (r *mqlStackit) vpn() (*mqlStackitVpn, error) {
	res, err := makeNamespace(r.MqlRuntime, "stackit.vpn")
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitVpn), nil
}

// ------------------------- gateways -------------------------

func (r *mqlStackitVpn) gateways() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Vpn()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListGateways(bgctx(), c.ProjectID(), c.Region()).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetGatewaysOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildVpnGateway(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildVpnGateway(runtime *plugin.Runtime, g *vpn.GatewayResponse) (plugin.Resource, error) {
	var (
		bgpLocalAsn int64
		bgpRoutes   []string
	)
	if bgp, ok := g.GetBgpOk(); ok && bgp != nil {
		bgpLocalAsn = bgp.GetLocalAsn()
		bgpRoutes = bgp.GetOverrideAdvertisedRoutes()
	}
	az := g.GetAvailabilityZones()
	args := map[string]*llx.RawData{
		"id":                          llx.StringData(g.GetId()),
		"name":                        llx.StringData(g.GetDisplayName()),
		"status":                      llx.StringData(string(g.GetState())),
		"routingType":                 llx.StringData(string(g.GetRoutingType())),
		"planId":                      llx.StringData(g.GetPlanId()),
		"tunnel1AvailabilityZone":     llx.StringData(az.GetTunnel1()),
		"tunnel2AvailabilityZone":     llx.StringData(az.GetTunnel2()),
		"bgpLocalAsn":                 llx.IntData(bgpLocalAsn),
		"bgpOverrideAdvertisedRoutes": strSliceData(bgpRoutes),
		"labels":                      labelData(g.GetLabels()),
	}
	return CreateResource(runtime, "stackit.vpn.gateway", args)
}

func (r *mqlStackitVpnGateway) id() (string, error) {
	return "stackit.vpn.gateway/" + conn(r.MqlRuntime).ProjectID() + "/" + r.Id.Data, nil
}

func initStackitVpnGateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.Vpn()
	if err != nil {
		return nil, nil, err
	}
	g, err := client.DefaultAPI.GetGateway(bgctx(), c.ProjectID(), c.Region(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := buildVpnGateway(runtime, g)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// ------------------------- connections -------------------------

func (r *mqlStackitVpnGateway) connections() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Vpn()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListGatewayConnections(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetConnectionsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		connResp := items[i]
		idBase := "stackit.vpn.gateway.connection/" + c.ProjectID() + "/" + r.Id.Data + "/" + connResp.GetId()
		res, err := CreateResource(r.MqlRuntime, "stackit.vpn.gateway.connection", map[string]*llx.RawData{
			"__id":          llx.StringData(idBase),
			"id":            llx.StringData(connResp.GetId()),
			"name":          llx.StringData(connResp.GetDisplayName()),
			"enabled":       llx.BoolData(connResp.GetEnabled()),
			"localSubnets":  strSliceData(connResp.GetLocalSubnets()),
			"remoteSubnets": strSliceData(connResp.GetRemoteSubnets()),
			"staticRoutes":  strSliceData(connResp.GetStaticRoutes()),
			"labels":        labelData(connResp.GetLabels()),
		})
		if err != nil {
			return nil, err
		}
		mqlConn := res.(*mqlStackitVpnGatewayConnection)
		t1 := connResp.GetTunnel1()
		t2 := connResp.GetTunnel2()
		mqlConn.cacheTunnel1 = &t1
		mqlConn.cacheTunnel2 = &t2
		mqlConn.cacheIdBase = idBase
		mqlConn.cacheGatewayID = r.Id.Data
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitVpnGatewayConnection) tunnel1() (*mqlStackitVpnTunnel, error) {
	if r.cacheTunnel1 == nil {
		return markNull[mqlStackitVpnTunnel](&r.Tunnel1)
	}
	return r.buildTunnel(r.cacheTunnel1, "tunnel1")
}

func (r *mqlStackitVpnGatewayConnection) tunnel2() (*mqlStackitVpnTunnel, error) {
	if r.cacheTunnel2 == nil {
		return markNull[mqlStackitVpnTunnel](&r.Tunnel2)
	}
	return r.buildTunnel(r.cacheTunnel2, "tunnel2")
}

func (r *mqlStackitVpnGatewayConnection) buildTunnel(t *vpn.TunnelConfiguration, slot string) (*mqlStackitVpnTunnel, error) {
	var (
		bgpRemoteAsn         int64
		peeringLocalAddress  string
		peeringRemoteAddress string
	)
	if bgp, ok := t.GetBgpOk(); ok && bgp != nil {
		bgpRemoteAsn = bgp.GetRemoteAsn()
	}
	if peering, ok := t.GetPeeringOk(); ok && peering != nil {
		peeringLocalAddress = peering.GetLocalAddress()
		peeringRemoteAddress = peering.GetRemoteAddress()
	}
	p1 := t.GetPhase1()
	p2 := t.GetPhase2()
	res, err := CreateResource(r.MqlRuntime, "stackit.vpn.tunnel", map[string]*llx.RawData{
		"__id":                       llx.StringData(r.cacheIdBase + "/" + slot),
		"remoteAddress":              llx.StringData(t.GetRemoteAddress()),
		"bgpRemoteAsn":               llx.IntData(bgpRemoteAsn),
		"peeringLocalAddress":        llx.StringData(peeringLocalAddress),
		"peeringRemoteAddress":       llx.StringData(peeringRemoteAddress),
		"phase1DhGroups":             strSliceData(enumSliceToStr(p1.GetDhGroups())),
		"phase1EncryptionAlgorithms": strSliceData(enumSliceToStr(p1.GetEncryptionAlgorithms())),
		"phase1IntegrityAlgorithms":  strSliceData(enumSliceToStr(p1.GetIntegrityAlgorithms())),
		"phase1RekeyTime":            llx.IntData(int64(p1.GetRekeyTime())),
		"phase2DhGroups":             strSliceData(enumSliceToStr(p2.GetDhGroups())),
		"phase2EncryptionAlgorithms": strSliceData(enumSliceToStr(p2.GetEncryptionAlgorithms())),
		"phase2IntegrityAlgorithms":  strSliceData(enumSliceToStr(p2.GetIntegrityAlgorithms())),
		"phase2RekeyTime":            llx.IntData(int64(p2.GetRekeyTime())),
		"dpdAction":                  llx.StringData(string(p2.GetDpdAction())),
		"startAction":                llx.StringData(string(p2.GetStartAction())),
	})
	if err != nil {
		return nil, err
	}
	tunnel := res.(*mqlStackitVpnTunnel)
	tunnel.cacheGatewayID = r.cacheGatewayID
	tunnel.cacheConnectionID = r.Id.Data
	tunnel.cacheSlot = slot
	return tunnel, nil
}

// enumSliceToStr converts a slice of string-based SDK enum values into a
// plain []string.
func enumSliceToStr[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

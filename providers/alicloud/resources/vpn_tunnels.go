// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"strconv"
	"strings"

	"github.com/alibabacloud-go/tea/tea"
	vpcclient "github.com/alibabacloud-go/vpc-20160428/v7/client"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

// Type aliases for the deeply nested per-tunnel structs DescribeVpnConnections
// returns, so the code below reads as the data it handles.
type (
	vpnTunnelOptions     = vpcclient.DescribeVpnConnectionsResponseBodyVpnConnectionsVpnConnectionTunnelOptionsSpecificationTunnelOptions
	vpnTunnelOptionsSpec = vpcclient.DescribeVpnConnectionsResponseBodyVpnConnectionsVpnConnectionTunnelOptionsSpecification
)

// vpnTunnelFlag maps the true/false strings the per-tunnel options use for
// their DPD and NAT traversal switches to a bool. The connection-level fields
// are already typed as booleans by the SDK; only the tunnel copies arrive as
// strings. An absent or unrecognized value returns nil so the field reads as
// null rather than claiming the feature is switched off.
func vpnTunnelFlag(v *string) *bool {
	if v == nil {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(*v)) {
	case "true":
		enabled := true
		return &enabled
	case "false":
		disabled := false
		return &disabled
	default:
		return nil
	}
}

// vpnTunnelLifetime parses a security association lifetime, which the
// per-tunnel IKE and IPsec configs report as a string of seconds while the
// connection-level fields report it as a number. An absent or unparseable
// value returns nil, so a lifetime that could not be read stays null instead of
// reading as zero seconds.
func vpnTunnelLifetime(v *string) *int64 {
	if v == nil {
		return nil
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(*v), 10, 64)
	if err != nil {
		return nil
	}
	return &seconds
}

// vpnTunnelKey builds the part of a tunnel's cache key that separates it from
// the other tunnels of the same connection. TunnelId is the stable choice, so
// a re-scan keys a tunnel the same way. The index and then the position in the
// response are fallbacks: without them two tunnels reported without an id
// would share a key, and the second would silently report the first one's
// algorithms.
func vpnTunnelKey(t *vpnTunnelOptions, position int) string {
	if t != nil {
		if id := strings.TrimSpace(tea.StringValue(t.TunnelId)); id != "" {
			return id
		}
		if t.TunnelIndex != nil {
			return "index-" + strconv.FormatInt(int64(*t.TunnelIndex), 10)
		}
	}
	return "position-" + strconv.Itoa(position)
}

// mqlAlicloudVpcVpnConnectionTunnelInternal caches the identifier the tunnel's
// customer gateway reference needs.
type mqlAlicloudVpcVpnConnectionTunnelInternal struct {
	cacheCustomerGateway string
}

// newVpnConnectionTunnels builds one resource per tunnel of a connection. The
// options travel in the DescribeVpnConnections response the caller already
// holds, so no tunnel costs an extra call.
func newVpnConnectionTunnels(runtime *plugin.Runtime, connectionKey string, spec *vpnTunnelOptionsSpec) ([]any, error) {
	tunnels := []any{}
	if spec == nil {
		return tunnels, nil
	}
	for position, t := range spec.TunnelOptions {
		if t == nil {
			continue
		}
		tunnel, err := newVpnConnectionTunnel(runtime, connectionKey, vpnTunnelKey(t, position), t)
		if err != nil {
			return nil, err
		}
		tunnels = append(tunnels, tunnel)
	}
	return tunnels, nil
}

// newVpnConnectionTunnel builds one alicloud.vpc.vpnConnection.tunnel. The key
// carries the connection it belongs to, so two connections running tunnels with
// equivalent settings stay distinct. The pre-shared key in TunnelIkeConfig is
// deliberately left unmapped, as it is at the connection level.
func newVpnConnectionTunnel(runtime *plugin.Runtime, connectionKey, tunnelKey string, t *vpnTunnelOptions) (*mqlAlicloudVpcVpnConnectionTunnel, error) {
	var ikeVersion, ikeMode, ikeEncAlg, ikeAuthAlg, ikePfs, ikeLocalID, ikeRemoteID *string
	var ikeLifetime *int64
	if t.TunnelIkeConfig != nil {
		ikeVersion = t.TunnelIkeConfig.IkeVersion
		ikeMode = t.TunnelIkeConfig.IkeMode
		ikeEncAlg = t.TunnelIkeConfig.IkeEncAlg
		ikeAuthAlg = t.TunnelIkeConfig.IkeAuthAlg
		ikePfs = t.TunnelIkeConfig.IkePfs
		ikeLocalID = t.TunnelIkeConfig.LocalId
		ikeRemoteID = t.TunnelIkeConfig.RemoteId
		ikeLifetime = vpnTunnelLifetime(t.TunnelIkeConfig.IkeLifetime)
	}

	var ipsecEncAlg, ipsecAuthAlg, ipsecPfs *string
	var ipsecLifetime *int64
	if t.TunnelIpsecConfig != nil {
		ipsecEncAlg = t.TunnelIpsecConfig.IpsecEncAlg
		ipsecAuthAlg = t.TunnelIpsecConfig.IpsecAuthAlg
		ipsecPfs = t.TunnelIpsecConfig.IpsecPfs
		ipsecLifetime = vpnTunnelLifetime(t.TunnelIpsecConfig.IpsecLifetime)
	}

	resource, err := CreateResource(runtime, "alicloud.vpc.vpnConnection.tunnel", map[string]*llx.RawData{
		"__id":                         llx.StringData(connectionKey + "/" + tunnelKey),
		"tunnelId":                     llx.StringDataPtr(t.TunnelId),
		"tunnelIndex":                  llx.IntDataPtr(t.TunnelIndex),
		"role":                         llx.StringDataPtr(t.Role),
		"status":                       llx.StringDataPtr(t.Status),
		"state":                        llx.StringDataPtr(t.State),
		"internetIp":                   llx.StringDataPtr(t.InternetIp),
		"enableDpd":                    llx.BoolDataPtr(vpnTunnelFlag(t.EnableDpd)),
		"enableNatTraversal":           llx.BoolDataPtr(vpnTunnelFlag(t.EnableNatTraversal)),
		"ikeVersion":                   llx.StringDataPtr(ikeVersion),
		"ikeMode":                      llx.StringDataPtr(ikeMode),
		"ikeEncryptionAlgorithm":       llx.StringDataPtr(ikeEncAlg),
		"ikeAuthenticationAlgorithm":   llx.StringDataPtr(ikeAuthAlg),
		"ikePfs":                       llx.StringDataPtr(ikePfs),
		"ikeLifetime":                  llx.IntDataPtr(ikeLifetime),
		"ikeLocalId":                   llx.StringDataPtr(ikeLocalID),
		"ikeRemoteId":                  llx.StringDataPtr(ikeRemoteID),
		"ipsecEncryptionAlgorithm":     llx.StringDataPtr(ipsecEncAlg),
		"ipsecAuthenticationAlgorithm": llx.StringDataPtr(ipsecAuthAlg),
		"ipsecPfs":                     llx.StringDataPtr(ipsecPfs),
		"ipsecLifetime":                llx.IntDataPtr(ipsecLifetime),
	})
	if err != nil {
		return nil, err
	}

	mqlTunnel := resource.(*mqlAlicloudVpcVpnConnectionTunnel)
	mqlTunnel.cacheCustomerGateway = tea.StringValue(t.CustomerGatewayId)
	return mqlTunnel, nil
}

// ---------------------------------------------------------------------------
// Algorithms in effect across a whole connection
// ---------------------------------------------------------------------------

// vpnAlgorithmsInEffect folds a connection-level setting together with the
// setting every tunnel of that connection negotiated. A dual-tunnel connection
// negotiates IKE and IPsec once per tunnel, so a check reading only the
// connection-level field scores a connection whose second tunnel agreed to a
// weak cipher as if it were strong.
//
// Values the API did not report are left out rather than folded in as an empty
// string, and a connection where nothing reported a value yields an empty list.
// An empty list is distinguishable from a list holding a weak algorithm, where
// a null read by an assertion is not.
func vpnAlgorithmsInEffect(connectionValue *plugin.TValue[string], tunnels []any, tunnelValue func(*mqlAlicloudVpcVpnConnectionTunnel) *plugin.TValue[string]) []any {
	seen := map[string]struct{}{}
	add := func(v *plugin.TValue[string]) {
		if v == nil || v.State&plugin.StateIsNull != 0 {
			return
		}
		value := strings.TrimSpace(v.Data)
		if value == "" {
			return
		}
		seen[value] = struct{}{}
	}

	add(connectionValue)
	for _, t := range tunnels {
		tunnel, ok := t.(*mqlAlicloudVpcVpnConnectionTunnel)
		if !ok {
			continue
		}
		add(tunnelValue(tunnel))
	}

	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return strsToAny(values)
}

// vpnConnectionAlgorithms reads the tunnels a connection is built from and
// hands them to the fold. The tunnels travel in the response the lister already
// holds, so nothing here costs a call.
func vpnConnectionAlgorithms(r *mqlAlicloudVpcVpnConnection, connectionValue *plugin.TValue[string], tunnelValue func(*mqlAlicloudVpcVpnConnectionTunnel) *plugin.TValue[string]) ([]any, error) {
	tunnels := r.GetTunnels()
	if tunnels.Error != nil {
		return nil, tunnels.Error
	}
	return vpnAlgorithmsInEffect(connectionValue, tunnels.Data, tunnelValue), nil
}

func (r *mqlAlicloudVpcVpnConnection) ikeEncryptionAlgorithms() ([]any, error) {
	return vpnConnectionAlgorithms(r, r.GetIkeEncryptionAlgorithm(),
		func(t *mqlAlicloudVpcVpnConnectionTunnel) *plugin.TValue[string] {
			return t.GetIkeEncryptionAlgorithm()
		})
}

func (r *mqlAlicloudVpcVpnConnection) ipsecEncryptionAlgorithms() ([]any, error) {
	return vpnConnectionAlgorithms(r, r.GetIpsecEncryptionAlgorithm(),
		func(t *mqlAlicloudVpcVpnConnectionTunnel) *plugin.TValue[string] {
			return t.GetIpsecEncryptionAlgorithm()
		})
}

func (r *mqlAlicloudVpcVpnConnection) ikePfsGroups() ([]any, error) {
	return vpnConnectionAlgorithms(r, r.GetIkePfs(),
		func(t *mqlAlicloudVpcVpnConnectionTunnel) *plugin.TValue[string] {
			return t.GetIkePfs()
		})
}

func (r *mqlAlicloudVpcVpnConnection) ipsecPfsGroups() ([]any, error) {
	return vpnConnectionAlgorithms(r, r.GetIpsecPfs(),
		func(t *mqlAlicloudVpcVpnConnectionTunnel) *plugin.TValue[string] {
			return t.GetIpsecPfs()
		})
}

// strsToAny widens a []string into the []any an MQL list field takes.
func strsToAny(in []string) []any {
	res := make([]any, 0, len(in))
	for _, s := range in {
		res = append(res, s)
	}
	return res
}

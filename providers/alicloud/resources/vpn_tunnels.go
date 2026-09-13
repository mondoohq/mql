// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	"github.com/alibabacloud-go/tea/tea"
	vpcclient "github.com/alibabacloud-go/vpc-20160428/v7/client"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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

// customerGateway resolves the remote end this tunnel faces. Each tunnel of a
// dual-tunnel connection may terminate on a different customer gateway.
func (r *mqlAlicloudVpcVpnConnectionTunnel) customerGateway() (*mqlAlicloudVpcCustomerGateway, error) {
	gateway := lookupCustomerGateway(r.MqlRuntime, r.cacheCustomerGateway)
	if gateway == nil {
		r.CustomerGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gateway, nil
}

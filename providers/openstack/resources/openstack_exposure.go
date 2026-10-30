// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// --- security-group source classification ---

// includesPublicSource reports whether the rule's source reaches the public
// internet: a public remote CIDR, a remote address group holding a public
// range, or an unscoped rule (no remote IP prefix, group, or address group)
// which Neutron treats as any source. Direction-agnostic, so it also classifies
// egress destinations.
func (r *mqlOpenstackSecurityGroupRule) includesPublicSource() (bool, error) {
	if prefix := r.RemoteIpPrefix.Data; prefix != "" {
		return cidrIsPublic(prefix), nil
	}

	// An address group carries the addresses in its own right, so the rule is
	// only as public as the group's members.
	if r.cacheRemoteAddressGroupID != "" {
		group := r.GetRemoteAddressGroup()
		if group.Error != nil {
			return false, group.Error
		}
		if group.Data == nil {
			// The group could not be resolved (no address-groups extension, or
			// it is not readable), so there is nothing to judge it on.
			return false, nil
		}
		public := group.Data.GetContainsPublicAddress()
		if public.Error != nil {
			return false, public.Error
		}
		return public.Data, nil
	}

	// A rule scoped to a remote security group reaches only that group's
	// members; one scoped to nothing at all matches any source.
	return r.cacheRemoteGroupID == "", nil
}

// allowsPublicIngress reports whether any ingress rule in the security group
// permits traffic from a public source.
func (r *mqlOpenstackSecurityGroup) allowsPublicIngress() (bool, error) {
	rules := r.GetRules()
	if rules.Error != nil {
		return false, rules.Error
	}
	for _, raw := range rules.Data {
		rule, ok := raw.(*mqlOpenstackSecurityGroupRule)
		if !ok || !strings.EqualFold(rule.Direction.Data, "ingress") {
			continue
		}
		public := rule.GetIncludesPublicSource()
		if public.Error != nil {
			return false, public.Error
		}
		if public.Data {
			return true, nil
		}
	}
	return false, nil
}

// --- reverse links ---

// floatingIps returns the floating IPs bound to this port.
func (r *mqlOpenstackPort) floatingIps() ([]any, error) {
	return floatingIpsForPortIDs(r.MqlRuntime, map[string]struct{}{r.Id.Data: {}})
}

// ports returns the Neutron ports attached to this server (those whose
// device_id is the server's ID). Filters the project's already-cached port
// list, so it makes no additional API calls.
func (r *mqlOpenstackComputeServer) ports() ([]any, error) {
	root, err := CreateResource(r.MqlRuntime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := root.(*mqlOpenstack).GetPorts()
	if list.Error != nil {
		return nil, list.Error
	}
	out := make([]any, 0)
	for _, raw := range list.Data {
		port, ok := raw.(*mqlOpenstackPort)
		if !ok {
			continue
		}
		if port.cacheDeviceID == r.Id.Data {
			out = append(out, port)
		}
	}
	return out, nil
}

// floatingIps returns the floating IPs mapped to this server through any of its
// ports.
func (r *mqlOpenstackComputeServer) floatingIps() ([]any, error) {
	ports := r.GetPorts()
	if ports.Error != nil {
		return nil, ports.Error
	}
	portIDs := make(map[string]struct{}, len(ports.Data))
	for _, raw := range ports.Data {
		if port, ok := raw.(*mqlOpenstackPort); ok {
			portIDs[port.Id.Data] = struct{}{}
		}
	}
	return floatingIpsForPortIDs(r.MqlRuntime, portIDs)
}

// floatingIpsForPortIDs returns the floating IPs from the project's floating-IP
// list whose bound port is in the given set.
func floatingIpsForPortIDs(runtime *plugin.Runtime, portIDs map[string]struct{}) ([]any, error) {
	if len(portIDs) == 0 {
		return []any{}, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := root.(*mqlOpenstack).GetFloatingIps()
	if list.Error != nil {
		return nil, list.Error
	}
	out := make([]any, 0)
	for _, raw := range list.Data {
		fip, ok := raw.(*mqlOpenstackFloatingIp)
		if !ok || fip.cachePortID == "" {
			continue
		}
		if _, ok := portIDs[fip.cachePortID]; ok {
			out = append(out, fip)
		}
	}
	return out, nil
}

// --- server exposure ---

func (r *mqlOpenstackComputeServer) exposure() (*mqlOpenstackComputeServerExposure, error) {
	fipsVal := r.GetFloatingIps()
	if fipsVal.Error != nil {
		return nil, fipsVal.Error
	}
	floatingIps := fipsVal.Data

	portsVal := r.GetPorts()
	if portsVal.Error != nil {
		return nil, portsVal.Error
	}

	onExternalNetwork := false
	openIngressRules := []any{}
	seenRules := map[string]struct{}{}
	for _, raw := range portsVal.Data {
		port, ok := raw.(*mqlOpenstackPort)
		if !ok {
			continue
		}
		if net := port.GetNetwork(); net.Error == nil && net.Data != nil {
			if ext := net.Data.GetExternal(); ext.Error == nil && ext.Data {
				onExternalNetwork = true
			}
		}
		sgs := port.GetSecurityGroups()
		if sgs.Error != nil {
			return nil, sgs.Error
		}
		for _, sgRaw := range sgs.Data {
			sg, ok := sgRaw.(*mqlOpenstackSecurityGroup)
			if !ok {
				continue
			}
			rules := sg.GetRules()
			if rules.Error != nil {
				return nil, rules.Error
			}
			for _, ruleRaw := range rules.Data {
				rule, ok := ruleRaw.(*mqlOpenstackSecurityGroupRule)
				if !ok || !strings.EqualFold(rule.Direction.Data, "ingress") {
					continue
				}
				public := rule.GetIncludesPublicSource()
				if public.Error != nil {
					return nil, public.Error
				}
				if !public.Data {
					continue
				}
				if _, dup := seenRules[rule.Id.Data]; dup {
					continue
				}
				seenRules[rule.Id.Data] = struct{}{}
				openIngressRules = append(openIngressRules, rule)
			}
		}
	}

	publiclyAccessible := len(floatingIps) > 0 || onExternalNetwork
	securityGroupAllowsIngress := len(openIngressRules) > 0
	internetReachable := publiclyAccessible && securityGroupAllowsIngress

	res, err := CreateResource(r.MqlRuntime, "openstack.compute.server.exposure", map[string]*llx.RawData{
		"__id":                       llx.StringData("openstack.compute.server.exposure/" + r.Id.Data),
		"internetReachable":          llx.BoolData(internetReachable),
		"publiclyAccessible":         llx.BoolData(publiclyAccessible),
		"securityGroupAllowsIngress": llx.BoolData(securityGroupAllowsIngress),
		"openIngressRules":           llx.ArrayData(openIngressRules, types.Resource("openstack.securityGroup.rule")),
		"floatingIps":                llx.ArrayData(floatingIps, types.Resource("openstack.floatingIp")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackComputeServerExposure), nil
}

// --- load-balancer exposure ---

// listenerProtocolIsPlaintext reports whether an Octavia listener protocol
// carries traffic without TLS. HTTPS and TERMINATED_HTTPS terminate or pass
// through TLS; everything else (HTTP, TCP, UDP, SCTP, PROMETHEUS) is plaintext.
func listenerProtocolIsPlaintext(protocol string) bool {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "HTTPS", "TERMINATED_HTTPS":
		return false
	default:
		return true
	}
}

// enforcesTls reports whether every listener on the load balancer uses an
// encrypted protocol.
func (r *mqlOpenstackOctaviaLoadBalancer) enforcesTls() (bool, error) {
	listeners := r.GetListeners()
	if listeners.Error != nil {
		return false, listeners.Error
	}
	for _, raw := range listeners.Data {
		l, ok := raw.(*mqlOpenstackOctaviaListener)
		if !ok {
			continue
		}
		if listenerProtocolIsPlaintext(l.Protocol.Data) {
			return false, nil
		}
	}
	return true, nil
}

// openToWorld reports whether the listener accepts connections from any source:
// an empty allowedCidrs list (Octavia's allow-all default) or one that contains
// a public CIDR.
func (r *mqlOpenstackOctaviaListener) openToWorld() (bool, error) {
	cidrs := r.GetAllowedCidrs()
	if cidrs.Error != nil {
		return false, cidrs.Error
	}
	if len(cidrs.Data) == 0 {
		return true, nil
	}
	return anyCidrPublic(cidrs.Data), nil
}

func (r *mqlOpenstackOctaviaLoadBalancer) exposure() (*mqlOpenstackOctaviaLoadBalancerExposure, error) {
	publiclyAccessible := false
	if vipNet := r.GetVipNetwork(); vipNet.Error == nil && vipNet.Data != nil {
		if ext := vipNet.Data.GetExternal(); ext.Error == nil && ext.Data {
			publiclyAccessible = true
		}
	}

	floatingIps := []any{}
	if vipPort := r.GetVipPort(); vipPort.Error == nil && vipPort.Data != nil {
		fips := vipPort.Data.GetFloatingIps()
		if fips.Error != nil {
			return nil, fips.Error
		}
		floatingIps = fips.Data
	}
	if len(floatingIps) > 0 {
		publiclyAccessible = true
	}

	openListeners := []any{}
	listeners := r.GetListeners()
	if listeners.Error != nil {
		return nil, listeners.Error
	}
	for _, raw := range listeners.Data {
		l, ok := raw.(*mqlOpenstackOctaviaListener)
		if !ok {
			continue
		}
		open := l.GetOpenToWorld()
		if open.Error != nil {
			return nil, open.Error
		}
		if open.Data {
			openListeners = append(openListeners, l)
		}
	}

	internetReachable := publiclyAccessible && len(openListeners) > 0

	res, err := CreateResource(r.MqlRuntime, "openstack.octavia.loadBalancer.exposure", map[string]*llx.RawData{
		"__id":                 llx.StringData("openstack.octavia.loadBalancer.exposure/" + r.Id.Data),
		"internetReachable":    llx.BoolData(internetReachable),
		"publiclyAccessible":   llx.BoolData(publiclyAccessible),
		"listenersOpenToWorld": llx.ArrayData(openListeners, types.Resource("openstack.octavia.listener")),
		"floatingIps":          llx.ArrayData(floatingIps, types.Resource("openstack.floatingIp")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackOctaviaLoadBalancerExposure), nil
}

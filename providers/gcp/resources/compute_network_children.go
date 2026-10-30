// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"google.golang.org/api/compute/v1"
)

// protocolPort is the shape Compute uses for a layer 4 match, shared by VPC
// firewall rules (as FirewallAllowed / FirewallDenied) and firewall policy
// rules (as FirewallPolicyRuleMatcherLayer4Config). The three are distinct SDK
// types carrying the same two fields, so each is adapted to this one.
type protocolPort struct {
	protocol string
	ports    []string
}

// protocolPorts collapses layer 4 entries into a map keyed by protocol.
//
// Compute returns them as a list of {ipProtocol, ports} objects, which leaves
// the ports a dict level below the rule and out of reach of a query. A protocol
// is not documented to repeat within one rule, but ports are appended rather
// than assigned so a repeat merges instead of silently dropping an entry. An
// empty port list is meaningful: it means every port of that protocol, and is
// the only form protocols carrying no ports (icmp, esp, ah) take.
func protocolPorts(entries []protocolPort) map[string]any {
	res := map[string]any{}
	for _, e := range entries {
		if e.protocol == "" {
			continue
		}
		existing, ok := res[e.protocol].([]any)
		if !ok {
			existing = []any{}
		}
		for _, p := range e.ports {
			existing = append(existing, p)
		}
		res[e.protocol] = existing
	}
	return res
}

// firewallAllowedProtocolPorts adapts a VPC firewall rule's allow list.
func firewallAllowedProtocolPorts(entries []*compute.FirewallAllowed) map[string]any {
	flat := make([]protocolPort, 0, len(entries))
	for _, e := range entries {
		if e == nil {
			continue
		}
		flat = append(flat, protocolPort{protocol: e.IPProtocol, ports: e.Ports})
	}
	return protocolPorts(flat)
}

// firewallDeniedProtocolPorts adapts a VPC firewall rule's deny list.
func firewallDeniedProtocolPorts(entries []*compute.FirewallDenied) map[string]any {
	flat := make([]protocolPort, 0, len(entries))
	for _, e := range entries {
		if e == nil {
			continue
		}
		flat = append(flat, protocolPort{protocol: e.IPProtocol, ports: e.Ports})
	}
	return protocolPorts(flat)
}

// layer4ProtocolPorts adapts a firewall policy rule's layer 4 match.
func layer4ProtocolPorts(entries []*compute.FirewallPolicyRuleMatcherLayer4Config) map[string]any {
	flat := make([]protocolPort, 0, len(entries))
	for _, e := range entries {
		if e == nil {
			continue
		}
		flat = append(flat, protocolPort{protocol: e.IpProtocol, ports: e.Ports})
	}
	return protocolPorts(flat)
}

// parseNetworkURL extracts the project and name from a compute network
// self-link. It accepts both the www.googleapis.com and compute.googleapis.com
// forms, matching parseSubnetworkURL.
func parseNetworkURL(networkUrl string) (project, name string, ok bool) {
	if networkUrl == "" {
		return "", "", false
	}
	// Format is https://www.googleapis.com/compute/v1/projects/project1/global/networks/network-1
	params := strings.TrimPrefix(networkUrl, "https://www.googleapis.com/compute/v1/")
	params = strings.TrimPrefix(params, "https://compute.googleapis.com/compute/v1/")
	parts := strings.Split(params, "/")
	if len(parts) < 5 || parts[0] != "projects" || parts[3] != "networks" {
		return "", "", false
	}
	return parts[1], parts[4], true
}

// networkChildren filters one of the project-wide compute listings down to the
// members of this network.
//
// Compute's firewall and route listings are project-scoped, not network-scoped,
// so there is no call that returns "the firewall rules of this network". Both
// resources reference their network by self-link URL, which is why selecting
// them meant matching that URL by hand. The parent gcp.project.computeService
// is runtime-cached, so a query walking several networks lists once rather than
// once per network.
func networkChildren[T any](
	g *mqlGcpProjectComputeServiceNetwork,
	list func(*mqlGcpProjectComputeService) *plugin.TValue[[]any],
	networkUrlOf func(T) string,
) ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectID, name := g.ProjectId.Data, g.Name.Data

	svc, err := CreateResource(g.MqlRuntime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectID),
	})
	if err != nil {
		return nil, err
	}

	all := list(svc.(*mqlGcpProjectComputeService))
	if all.Error != nil {
		return nil, all.Error
	}

	res := []any{}
	for _, entry := range all.Data {
		child, ok := entry.(T)
		if !ok {
			continue
		}
		// A reference that does not parse is skipped rather than treated as a
		// match: attributing an unrecognized network URL to this network would
		// report a rule as applying where it does not.
		childProject, childName, ok := parseNetworkURL(networkUrlOf(child))
		if !ok {
			continue
		}
		if childProject == projectID && childName == name {
			res = append(res, entry)
		}
	}
	return res, nil
}

func (g *mqlGcpProjectComputeServiceNetwork) firewalls() ([]any, error) {
	return networkChildren(g,
		func(s *mqlGcpProjectComputeService) *plugin.TValue[[]any] { return s.GetFirewalls() },
		func(f *mqlGcpProjectComputeServiceFirewall) string { return f.cacheNetworkUrl })
}

func (g *mqlGcpProjectComputeServiceNetwork) routes() ([]any, error) {
	return networkChildren(g,
		func(s *mqlGcpProjectComputeService) *plugin.TValue[[]any] { return s.GetRoutes() },
		func(r *mqlGcpProjectComputeServiceRoute) string { return r.cacheNetworkUrl })
}

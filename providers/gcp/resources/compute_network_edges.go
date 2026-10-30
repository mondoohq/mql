// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

type mqlGcpProjectComputeServiceBackendServiceBackendInternal struct {
	cacheGroupUrl string
}

type mqlGcpProjectComputeServiceForwardingRuleInternal struct {
	cacheBackendServiceUrl string
	cacheNetworkUrl        string
	cacheRegionUrl         string
	cacheSubnetworkUrl     string
}

type mqlGcpProjectComputeServiceRouteInternal struct {
	cacheNetworkUrl string
}

type mqlGcpProjectComputeServiceTargetPoolInternal struct {
	cacheBackupPoolUrl     string
	cacheRegionUrl         string
	cacheSecurityPolicyUrl string
}

// ---------------------------------------------------------------
// Shared URL helpers
// ---------------------------------------------------------------

// computeURLCollection returns the collection segment (the plural resource kind)
// of a GCP compute self-link, e.g. "instanceGroups" for
// ".../zones/{zone}/instanceGroups/{name}" or "networkEndpointGroups" for
// ".../zones/{zone}/networkEndpointGroups/{name}". It is the path segment
// immediately before the resource name. Returns "" when the URL does not have
// the expected .../{collection}/{name} shape. It lets a single raw reference
// that may point at more than one resource kind (a forwarding rule's target, a
// backend's group) be dispatched to the right typed accessor without a lookup.
func computeURLCollection(url string) string {
	u := strings.TrimRight(strings.TrimSpace(url), "/")
	if u == "" {
		return ""
	}
	parts := strings.Split(u, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
}

// findComputeBySelfLink returns the resource in items whose self-link matches
// url, or nil when none matches. Both sides are normalized with trimComputeURL
// so the www.googleapis.com and compute.googleapis.com prefixes compare equal.
// It relies on every compute resource that carries a selfLink exposing a
// generated GetSelfLink() accessor.
func findComputeBySelfLink(items []any, url string) any {
	if url == "" {
		return nil
	}
	target := trimComputeURL(url)
	for _, it := range items {
		sl, ok := it.(interface {
			GetSelfLink() *plugin.TValue[string]
		})
		if !ok {
			continue
		}
		if trimComputeURL(sl.GetSelfLink().Data) == target {
			return it
		}
	}
	return nil
}

// computeServiceForUrl resolves the gcp.project.computeService resource for the
// project named in a compute self-link, so a by-URL lookup can reach that
// project's cached resource lists.
func computeServiceForUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeService, error) {
	parts := strings.Split(trimComputeURL(url), "/")
	if len(parts) < 2 || parts[0] != "projects" {
		return nil, nil
	}
	res, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(parts[1]),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectComputeService), nil
}

// ---------------------------------------------------------------
// By-URL resolvers (match against the project's cached lists)
// ---------------------------------------------------------------

func getBackendServiceByUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceBackendService, error) {
	if url == "" {
		return nil, nil
	}
	svc, err := computeServiceForUrl(url, runtime)
	if err != nil || svc == nil {
		return nil, err
	}
	list := svc.GetBackendServices()
	if list.Error != nil {
		return nil, list.Error
	}
	if m := findComputeBySelfLink(list.Data, url); m != nil {
		return m.(*mqlGcpProjectComputeServiceBackendService), nil
	}
	return nil, nil
}

func getHealthCheckByUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceHealthCheck, error) {
	if url == "" {
		return nil, nil
	}
	svc, err := computeServiceForUrl(url, runtime)
	if err != nil || svc == nil {
		return nil, err
	}
	list := svc.GetHealthChecks()
	if list.Error != nil {
		return nil, list.Error
	}
	if m := findComputeBySelfLink(list.Data, url); m != nil {
		return m.(*mqlGcpProjectComputeServiceHealthCheck), nil
	}
	return nil, nil
}

func getTargetPoolByUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceTargetPool, error) {
	if url == "" {
		return nil, nil
	}
	svc, err := computeServiceForUrl(url, runtime)
	if err != nil || svc == nil {
		return nil, err
	}
	list := svc.GetTargetPools()
	if list.Error != nil {
		return nil, list.Error
	}
	if m := findComputeBySelfLink(list.Data, url); m != nil {
		return m.(*mqlGcpProjectComputeServiceTargetPool), nil
	}
	return nil, nil
}

func getInstanceGroupByUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceInstanceGroup, error) {
	if url == "" {
		return nil, nil
	}
	svc, err := computeServiceForUrl(url, runtime)
	if err != nil || svc == nil {
		return nil, err
	}
	list := svc.GetInstanceGroups()
	if list.Error != nil {
		return nil, list.Error
	}
	if m := findComputeBySelfLink(list.Data, url); m != nil {
		return m.(*mqlGcpProjectComputeServiceInstanceGroup), nil
	}
	return nil, nil
}

func getNetworkEndpointGroupByUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceNetworkEndpointGroup, error) {
	if url == "" {
		return nil, nil
	}
	svc, err := computeServiceForUrl(url, runtime)
	if err != nil || svc == nil {
		return nil, err
	}
	list := svc.GetNetworkEndpointGroups()
	if list.Error != nil {
		return nil, list.Error
	}
	if m := findComputeBySelfLink(list.Data, url); m != nil {
		return m.(*mqlGcpProjectComputeServiceNetworkEndpointGroup), nil
	}
	return nil, nil
}

func getInstanceByUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceInstance, error) {
	if url == "" {
		return nil, nil
	}
	svc, err := computeServiceForUrl(url, runtime)
	if err != nil || svc == nil {
		return nil, err
	}
	list := svc.GetInstances()
	if list.Error != nil {
		return nil, list.Error
	}
	if m := findComputeBySelfLink(list.Data, url); m != nil {
		return m.(*mqlGcpProjectComputeServiceInstance), nil
	}
	return nil, nil
}

func getForwardingRuleByUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceForwardingRule, error) {
	if url == "" {
		return nil, nil
	}
	svc, err := computeServiceForUrl(url, runtime)
	if err != nil || svc == nil {
		return nil, err
	}
	list := svc.GetForwardingRules()
	if list.Error != nil {
		return nil, list.Error
	}
	if m := findComputeBySelfLink(list.Data, url); m != nil {
		return m.(*mqlGcpProjectComputeServiceForwardingRule), nil
	}
	return nil, nil
}

func getVpnTunnelByUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceVpnTunnel, error) {
	if url == "" {
		return nil, nil
	}
	svc, err := computeServiceForUrl(url, runtime)
	if err != nil || svc == nil {
		return nil, err
	}
	list := svc.GetVpnTunnels()
	if list.Error != nil {
		return nil, list.Error
	}
	if m := findComputeBySelfLink(list.Data, url); m != nil {
		return m.(*mqlGcpProjectComputeServiceVpnTunnel), nil
	}
	return nil, nil
}

func getTargetHttpProxyByUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceTargetHttpProxy, error) {
	if url == "" {
		return nil, nil
	}
	svc, err := computeServiceForUrl(url, runtime)
	if err != nil || svc == nil {
		return nil, err
	}
	list := svc.GetTargetHttpProxies()
	if list.Error != nil {
		return nil, list.Error
	}
	if m := findComputeBySelfLink(list.Data, url); m != nil {
		return m.(*mqlGcpProjectComputeServiceTargetHttpProxy), nil
	}
	return nil, nil
}

func getTargetHttpsProxyByUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceTargetHttpsProxy, error) {
	if url == "" {
		return nil, nil
	}
	svc, err := computeServiceForUrl(url, runtime)
	if err != nil || svc == nil {
		return nil, err
	}
	list := svc.GetTargetHttpsProxies()
	if list.Error != nil {
		return nil, list.Error
	}
	if m := findComputeBySelfLink(list.Data, url); m != nil {
		return m.(*mqlGcpProjectComputeServiceTargetHttpsProxy), nil
	}
	return nil, nil
}

func getTargetTcpProxyByUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceTargetTcpProxy, error) {
	if url == "" {
		return nil, nil
	}
	svc, err := computeServiceForUrl(url, runtime)
	if err != nil || svc == nil {
		return nil, err
	}
	list := svc.GetTargetTcpProxies()
	if list.Error != nil {
		return nil, list.Error
	}
	if m := findComputeBySelfLink(list.Data, url); m != nil {
		return m.(*mqlGcpProjectComputeServiceTargetTcpProxy), nil
	}
	return nil, nil
}

func getTargetSslProxyByUrl(url string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceTargetSslProxy, error) {
	if url == "" {
		return nil, nil
	}
	svc, err := computeServiceForUrl(url, runtime)
	if err != nil || svc == nil {
		return nil, err
	}
	list := svc.GetTargetSslProxies()
	if list.Error != nil {
		return nil, list.Error
	}
	if m := findComputeBySelfLink(list.Data, url); m != nil {
		return m.(*mqlGcpProjectComputeServiceTargetSslProxy), nil
	}
	return nil, nil
}

// resolveComputeRefs maps a slice of compute self-link URLs to their typed
// resources, dropping any that don't resolve. Used by the list-valued *Refs
// accessors (health checks, instances).
func resolveComputeRefs(urls plugin.TValue[[]any], runtime *plugin.Runtime, resolve func(string, *plugin.Runtime) (plugin.Resource, error)) ([]any, error) {
	if urls.Error != nil {
		return nil, urls.Error
	}
	res := make([]any, 0, len(urls.Data))
	for _, raw := range urls.Data {
		url, ok := raw.(string)
		if !ok || url == "" {
			continue
		}
		r, err := resolve(url, runtime)
		if err != nil {
			return nil, err
		}
		if r != nil {
			res = append(res, r)
		}
	}
	return res, nil
}

// ---------------------------------------------------------------
// forwardingRule edges
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceForwardingRule) backendService() (*mqlGcpProjectComputeServiceBackendService, error) {
	bs, err := getBackendServiceByUrl(g.cacheBackendServiceUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if bs == nil {
		g.BackendService.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return bs, nil
}

func (g *mqlGcpProjectComputeServiceForwardingRule) targetPool() (*mqlGcpProjectComputeServiceTargetPool, error) {
	if g.TargetUrl.Error != nil {
		return nil, g.TargetUrl.Error
	}
	if computeURLCollection(g.TargetUrl.Data) != "targetPools" {
		g.TargetPool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	tp, err := getTargetPoolByUrl(g.TargetUrl.Data, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if tp == nil {
		g.TargetPool.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return tp, nil
}

func (g *mqlGcpProjectComputeServiceForwardingRule) targetHttpProxy() (*mqlGcpProjectComputeServiceTargetHttpProxy, error) {
	if g.TargetUrl.Error != nil {
		return nil, g.TargetUrl.Error
	}
	if computeURLCollection(g.TargetUrl.Data) != "targetHttpProxies" {
		g.TargetHttpProxy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	p, err := getTargetHttpProxyByUrl(g.TargetUrl.Data, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if p == nil {
		g.TargetHttpProxy.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return p, nil
}

func (g *mqlGcpProjectComputeServiceForwardingRule) targetHttpsProxy() (*mqlGcpProjectComputeServiceTargetHttpsProxy, error) {
	if g.TargetUrl.Error != nil {
		return nil, g.TargetUrl.Error
	}
	if computeURLCollection(g.TargetUrl.Data) != "targetHttpsProxies" {
		g.TargetHttpsProxy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	p, err := getTargetHttpsProxyByUrl(g.TargetUrl.Data, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if p == nil {
		g.TargetHttpsProxy.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return p, nil
}

func (g *mqlGcpProjectComputeServiceForwardingRule) targetTcpProxy() (*mqlGcpProjectComputeServiceTargetTcpProxy, error) {
	if g.TargetUrl.Error != nil {
		return nil, g.TargetUrl.Error
	}
	if computeURLCollection(g.TargetUrl.Data) != "targetTcpProxies" {
		g.TargetTcpProxy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	p, err := getTargetTcpProxyByUrl(g.TargetUrl.Data, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if p == nil {
		g.TargetTcpProxy.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return p, nil
}

func (g *mqlGcpProjectComputeServiceForwardingRule) targetSslProxy() (*mqlGcpProjectComputeServiceTargetSslProxy, error) {
	if g.TargetUrl.Error != nil {
		return nil, g.TargetUrl.Error
	}
	if computeURLCollection(g.TargetUrl.Data) != "targetSslProxies" {
		g.TargetSslProxy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	p, err := getTargetSslProxyByUrl(g.TargetUrl.Data, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if p == nil {
		g.TargetSslProxy.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return p, nil
}

// ---------------------------------------------------------------
// backendService edges
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceBackendService) edgeSecurityPolicy() (*mqlGcpProjectComputeServiceSecurityPolicy, error) {
	sp, err := getSecurityPolicyByUrl(g.cacheEdgeSecurityPolicyUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if sp == nil {
		g.EdgeSecurityPolicy.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sp, nil
}

func (g *mqlGcpProjectComputeServiceBackendService) healthCheckRefs() ([]any, error) {
	return resolveComputeRefs(g.HealthChecks, g.MqlRuntime, func(url string, rt *plugin.Runtime) (plugin.Resource, error) {
		hc, err := getHealthCheckByUrl(url, rt)
		if hc == nil {
			return nil, err
		}
		return hc, err
	})
}

func (g *mqlGcpProjectComputeServiceBackendServiceBackend) instanceGroup() (*mqlGcpProjectComputeServiceInstanceGroup, error) {
	if computeURLCollection(g.cacheGroupUrl) != "instanceGroups" {
		g.InstanceGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ig, err := getInstanceGroupByUrl(g.cacheGroupUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if ig == nil {
		g.InstanceGroup.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return ig, nil
}

func (g *mqlGcpProjectComputeServiceBackendServiceBackend) networkEndpointGroup() (*mqlGcpProjectComputeServiceNetworkEndpointGroup, error) {
	if computeURLCollection(g.cacheGroupUrl) != "networkEndpointGroups" {
		g.NetworkEndpointGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	neg, err := getNetworkEndpointGroupByUrl(g.cacheGroupUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if neg == nil {
		g.NetworkEndpointGroup.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return neg, nil
}

// ---------------------------------------------------------------
// urlMap + target proxy edges
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceUrlMap) defaultService() (*mqlGcpProjectComputeServiceBackendService, error) {
	bs, err := getBackendServiceByUrl(g.cacheDefaultServiceUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if bs == nil {
		g.DefaultService.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return bs, nil
}

func (g *mqlGcpProjectComputeServiceTargetTcpProxy) service() (*mqlGcpProjectComputeServiceBackendService, error) {
	bs, err := getBackendServiceByUrl(g.cacheServiceUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if bs == nil {
		g.Service.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return bs, nil
}

func (g *mqlGcpProjectComputeServiceTargetSslProxy) service() (*mqlGcpProjectComputeServiceBackendService, error) {
	bs, err := getBackendServiceByUrl(g.cacheServiceUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if bs == nil {
		g.Service.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return bs, nil
}

// ---------------------------------------------------------------
// targetPool edges
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceTargetPool) backupPool() (*mqlGcpProjectComputeServiceTargetPool, error) {
	tp, err := getTargetPoolByUrl(g.cacheBackupPoolUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if tp == nil {
		g.BackupPool.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return tp, nil
}

func (g *mqlGcpProjectComputeServiceTargetPool) securityPolicy() (*mqlGcpProjectComputeServiceSecurityPolicy, error) {
	sp, err := getSecurityPolicyByUrl(g.cacheSecurityPolicyUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if sp == nil {
		g.SecurityPolicy.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sp, nil
}

func (g *mqlGcpProjectComputeServiceTargetPool) healthCheckRefs() ([]any, error) {
	return resolveComputeRefs(g.HealthCheckUrls, g.MqlRuntime, func(url string, rt *plugin.Runtime) (plugin.Resource, error) {
		hc, err := getHealthCheckByUrl(url, rt)
		if hc == nil {
			return nil, err
		}
		return hc, err
	})
}

func (g *mqlGcpProjectComputeServiceTargetPool) instanceRefs() ([]any, error) {
	return resolveComputeRefs(g.InstanceUrls, g.MqlRuntime, func(url string, rt *plugin.Runtime) (plugin.Resource, error) {
		inst, err := getInstanceByUrl(url, rt)
		if inst == nil {
			return nil, err
		}
		return inst, err
	})
}

// ---------------------------------------------------------------
// route next-hop edges
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceRoute) nextHopInstanceRef() (*mqlGcpProjectComputeServiceInstance, error) {
	if g.NextHopInstance.Error != nil {
		return nil, g.NextHopInstance.Error
	}
	inst, err := getInstanceByUrl(g.NextHopInstance.Data, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if inst == nil {
		g.NextHopInstanceRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return inst, nil
}

func (g *mqlGcpProjectComputeServiceRoute) nextHopVpnTunnelRef() (*mqlGcpProjectComputeServiceVpnTunnel, error) {
	if g.NextHopVpnTunnel.Error != nil {
		return nil, g.NextHopVpnTunnel.Error
	}
	vt, err := getVpnTunnelByUrl(g.NextHopVpnTunnel.Data, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if vt == nil {
		g.NextHopVpnTunnelRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return vt, nil
}

func (g *mqlGcpProjectComputeServiceRoute) nextHopNetworkRef() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.NextHopNetwork.Error != nil {
		return nil, g.NextHopNetwork.Error
	}
	net, err := getNetworkByUrl(g.NextHopNetwork.Data, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if net == nil {
		g.NextHopNetworkRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return net, nil
}

func (g *mqlGcpProjectComputeServiceRoute) nextHopIlbRef() (*mqlGcpProjectComputeServiceForwardingRule, error) {
	if g.NextHopIlb.Error != nil {
		return nil, g.NextHopIlb.Error
	}
	// nextHopIlb may be a forwarding-rule self-link or a bare internal IP; only
	// the self-link form resolves to a forwarding rule.
	if computeURLCollection(g.NextHopIlb.Data) != "forwardingRules" {
		g.NextHopIlbRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	fr, err := getForwardingRuleByUrl(g.NextHopIlb.Data, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if fr == nil {
		g.NextHopIlbRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return fr, nil
}

// ---------------------------------------------------------------
// instanceGroup member instances
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceInstanceGroup) instances() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	if g.SelfLink.Error != nil {
		return nil, g.SelfLink.Error
	}
	projectId := g.ProjectId.Data
	name := g.Name.Data

	// Derive the location (zone or region) from the self-link:
	// .../zones/{zone}/instanceGroups/{name} or .../regions/{region}/instanceGroups/{name}
	parts := strings.Split(trimComputeURL(g.SelfLink.Data), "/")
	var zone, region string
	for i := 0; i+1 < len(parts); i++ {
		switch parts[i] {
		case "zones":
			zone = parts[i+1]
		case "regions":
			region = parts[i+1]
		}
	}
	if zone == "" && region == "" {
		return nil, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var instanceUrls []string
	if zone != "" {
		req := computeSvc.InstanceGroups.ListInstances(projectId, zone, name, &compute.InstanceGroupsListInstancesRequest{})
		if err := req.Pages(ctx, func(page *compute.InstanceGroupsListInstances) error {
			for _, item := range page.Items {
				if item != nil && item.Instance != "" {
					instanceUrls = append(instanceUrls, item.Instance)
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	} else {
		req := computeSvc.RegionInstanceGroups.ListInstances(projectId, region, name, &compute.RegionInstanceGroupsListInstancesRequest{})
		if err := req.Pages(ctx, func(page *compute.RegionInstanceGroupsListInstances) error {
			for _, item := range page.Items {
				if item != nil && item.Instance != "" {
					instanceUrls = append(instanceUrls, item.Instance)
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	res := make([]any, 0, len(instanceUrls))
	for _, url := range instanceUrls {
		inst, err := getInstanceByUrl(url, g.MqlRuntime)
		if err != nil {
			return nil, err
		}
		if inst != nil {
			res = append(res, inst)
		}
	}
	return res, nil
}

// ---------------------------------------------------------------
// instance network interfaces
// ---------------------------------------------------------------

type mqlGcpProjectComputeServiceInstanceNetworkInterfaceInternal struct {
	cacheNetworkUrl        string
	cacheSubnetworkUrl     string
	cacheAccessConfigs     []*compute.AccessConfig
	cacheIpv6AccessConfigs []*compute.AccessConfig
}

// newMqlComputeNetworkInterface builds a typed network-interface resource for a
// single NIC of a Compute Engine instance. The network/subnetwork references
// are resolved lazily from the cached self-links.
func newMqlComputeNetworkInterface(runtime *plugin.Runtime, instanceID uint64, ni *compute.NetworkInterface) (*mqlGcpProjectComputeServiceInstanceNetworkInterface, error) {
	accessConfigs, err := convert.JsonToDictSlice(ni.AccessConfigs)
	if err != nil {
		return nil, err
	}
	ipv6AccessConfigs, err := convert.JsonToDictSlice(ni.Ipv6AccessConfigs)
	if err != nil {
		return nil, err
	}
	aliasIpRanges, err := convert.JsonToDictSlice(ni.AliasIpRanges)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "gcp.project.computeService.instance.networkInterface", map[string]*llx.RawData{
		"__id":              llx.StringData("gcp.project.computeService.instance.networkInterface/" + strconv.FormatUint(instanceID, 10) + "/" + ni.Name),
		"name":              llx.StringData(ni.Name),
		"networkIP":         llx.StringData(ni.NetworkIP),
		"ipv6Address":       llx.StringData(ni.Ipv6Address),
		"stackType":         llx.StringData(ni.StackType),
		"nicType":           llx.StringData(ni.NicType),
		"queueCount":        llx.IntData(ni.QueueCount),
		"accessConfigs":     llx.ArrayData(accessConfigs, types.Dict),
		"ipv6AccessConfigs": llx.ArrayData(ipv6AccessConfigs, types.Dict),
		"aliasIpRanges":     llx.ArrayData(aliasIpRanges, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	nic := res.(*mqlGcpProjectComputeServiceInstanceNetworkInterface)
	nic.cacheNetworkUrl = ni.Network
	nic.cacheSubnetworkUrl = ni.Subnetwork
	nic.cacheAccessConfigs = ni.AccessConfigs
	nic.cacheIpv6AccessConfigs = ni.Ipv6AccessConfigs
	return nic, nil
}

func (g *mqlGcpProjectComputeServiceInstanceNetworkInterface) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	net, err := getNetworkByUrl(g.cacheNetworkUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if net == nil {
		g.Network.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return net, nil
}

func (g *mqlGcpProjectComputeServiceInstanceNetworkInterface) subnetwork() (*mqlGcpProjectComputeServiceSubnetwork, error) {
	subnet, err := getSubnetworkByUrl(g.cacheSubnetworkUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if subnet == nil {
		g.Subnetwork.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return subnet, nil
}

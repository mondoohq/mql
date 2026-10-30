// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/l7policies"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/listeners"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/loadbalancers"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/monitors"
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/pools"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// barbicanRefIsContainer reports whether a Barbican ref URL points at a
// container (vs a bare secret). Octavia accepts either; resolution to a typed
// resource depends on which it is.
func barbicanRefIsContainer(ref string) bool {
	return strings.Contains(ref, "/containers/")
}

// newKeymanagerContainerByRef resolves a Barbican container ref URL to an
// openstack.keymanager.container resource. Returns (nil, nil) when ref is
// empty or points at a bare secret (not a container) — callers MUST set
// `<field>.State = StateIsSet | StateIsNull` before returning, otherwise the
// runtime keeps the field unresolved.
func newKeymanagerContainerByRef(runtime *plugin.Runtime, ref string) (*mqlOpenstackKeymanagerContainer, error) {
	if !barbicanRefIsContainer(ref) {
		return nil, nil
	}
	id := barbicanRefID(ref)
	if id == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "openstack.keymanager.container", map[string]*llx.RawData{
		"id":           llx.StringData(id),
		"containerRef": llx.StringData(ref),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackKeymanagerContainer), nil
}

// barbicanRefIsSecret reports whether a Barbican ref URL points at a bare
// secret (vs a container). Octavia accepts either for its TLS refs, and a
// PKCS12 bundle stored as a single secret is the common form on modern
// clouds. A ref that matches neither shape is left unresolved rather than
// guessed at.
func barbicanRefIsSecret(ref string) bool {
	return strings.Contains(ref, "/secrets/")
}

// newKeymanagerSecretByRef resolves a Barbican secret ref URL to an
// openstack.keymanager.secret resource. Returns (nil, nil) when ref is empty
// or points at a container (not a bare secret) — callers MUST set
// `<field>.State = StateIsSet | StateIsNull` before returning, otherwise the
// runtime keeps the field unresolved.
func newKeymanagerSecretByRef(runtime *plugin.Runtime, ref string) (*mqlOpenstackKeymanagerSecret, error) {
	if !barbicanRefIsSecret(ref) {
		return nil, nil
	}
	id := barbicanRefID(ref)
	if id == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "openstack.keymanager.secret", map[string]*llx.RawData{
		"id":        llx.StringData(id),
		"secretRef": llx.StringData(ref),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackKeymanagerSecret), nil
}

// ---- openstack.octavia.loadBalancer ----

type mqlOpenstackOctaviaLoadBalancerInternal struct {
	cacheProjectID    string
	cacheVipPortID    string
	cacheVipNetworkID string
	cacheVipSubnetID  string
	cacheListenerIDs  []string
	cachePoolIDs      []string
}

func (r *mqlOpenstackOctaviaLoadBalancer) id() (string, error) {
	return "openstack.octavia.loadBalancer/" + r.Id.Data, nil
}

func initOpenstackOctaviaLoadBalancer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Skip the per-ID Get when the caller already supplied populated
	// fields. provisioningStatus is mandatory in every Octavia API
	// response, so its presence reliably distinguishes a fully-populated
	// resource from one created with just {__id, id}.
	if _, ok := args["provisioningStatus"]; ok {
		return args, nil, nil
	}
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}

	c := conn(runtime)
	client, err := c.LoadBalancerClient()
	if err != nil {
		return nil, nil, err
	}
	lb, err := loadbalancers.Get(ctx(), client, id).Extract()
	if err != nil {
		if translateGetError(err) == nil {
			return args, nil, nil
		}
		return nil, nil, err
	}
	mqlLb, err := newMqlOpenstackOctaviaLoadBalancer(runtime, lb)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlLb, nil
}

func newMqlOpenstackOctaviaLoadBalancer(runtime *plugin.Runtime, lb *loadbalancers.LoadBalancer) (*mqlOpenstackOctaviaLoadBalancer, error) {
	res, err := CreateResource(runtime, "openstack.octavia.loadBalancer", map[string]*llx.RawData{
		"__id":               llx.StringData("openstack.octavia.loadBalancer/" + lb.ID),
		"id":                 llx.StringData(lb.ID),
		"name":               llx.StringData(lb.Name),
		"description":        llx.StringData(lb.Description),
		"adminStateUp":       llx.BoolData(lb.AdminStateUp),
		"provisioningStatus": llx.StringData(lb.ProvisioningStatus),
		"operatingStatus":    llx.StringData(lb.OperatingStatus),
		"vipAddress":         llx.StringData(lb.VipAddress),
		"provider":           llx.StringData(lb.Provider),
		"flavorId":           llx.StringData(lb.FlavorID),
		"availabilityZone":   llx.StringData(lb.AvailabilityZone),
		"additionalVips":     dictSliceData(additionalVipsToDict(lb.AdditionalVips)),
		"tags":               stringSliceData(lb.Tags),
		"createdAt":          llx.TimeDataPtr(timePtr(lb.CreatedAt)),
		"updatedAt":          llx.TimeDataPtr(timePtr(lb.UpdatedAt)),
	})
	if err != nil {
		return nil, err
	}
	mqlLb := res.(*mqlOpenstackOctaviaLoadBalancer)
	mqlLb.cacheProjectID = lb.ProjectID
	mqlLb.cacheVipPortID = lb.VipPortID
	mqlLb.cacheVipNetworkID = lb.VipNetworkID
	mqlLb.cacheVipSubnetID = lb.VipSubnetID
	mqlLb.cacheListenerIDs = listenerIDsFromLB(lb.Listeners)
	mqlLb.cachePoolIDs = poolIDsFromLB(lb.Pools)
	return mqlLb, nil
}

func (o *mqlOpenstack) loadBalancers() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.LoadBalancerClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := loadbalancers.List(client, loadbalancers.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := loadbalancers.ExtractLoadBalancers(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		mqlLb, err := newMqlOpenstackOctaviaLoadBalancer(o.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, mqlLb)
	}
	return out, nil
}

func (r *mqlOpenstackOctaviaLoadBalancer) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackOctaviaLoadBalancer) vipPort() (*mqlOpenstackPort, error) {
	if r.cacheVipPortID == "" {
		r.VipPort.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.port", map[string]*llx.RawData{"id": llx.StringData(r.cacheVipPortID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackPort), nil
}

func (r *mqlOpenstackOctaviaLoadBalancer) vipNetwork() (*mqlOpenstackNetwork, error) {
	if r.cacheVipNetworkID == "" {
		r.VipNetwork.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.network", map[string]*llx.RawData{"id": llx.StringData(r.cacheVipNetworkID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackNetwork), nil
}

func (r *mqlOpenstackOctaviaLoadBalancer) vipSubnet() (*mqlOpenstackSubnet, error) {
	if r.cacheVipSubnetID == "" {
		r.VipSubnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.subnet", map[string]*llx.RawData{"id": llx.StringData(r.cacheVipSubnetID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackSubnet), nil
}

func (r *mqlOpenstackOctaviaLoadBalancer) listeners() ([]any, error) {
	out := make([]any, 0, len(r.cacheListenerIDs))
	for _, id := range r.cacheListenerIDs {
		if id == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "openstack.octavia.listener", map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlOpenstackOctaviaLoadBalancer) pools() ([]any, error) {
	out := make([]any, 0, len(r.cachePoolIDs))
	for _, id := range r.cachePoolIDs {
		if id == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "openstack.octavia.pool", map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func additionalVipsToDict(in []loadbalancers.AdditionalVip) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		out = append(out, map[string]any{
			"subnet_id":  v.SubnetID,
			"ip_address": v.IPAddress,
		})
	}
	return out
}

func listenerIDsFromLB(in []listeners.Listener) []string {
	out := make([]string, 0, len(in))
	for _, l := range in {
		if l.ID != "" {
			out = append(out, l.ID)
		}
	}
	return out
}

func poolIDsFromLB(in []pools.Pool) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p.ID != "" {
			out = append(out, p.ID)
		}
	}
	return out
}

// ---- openstack.octavia.listener ----

type mqlOpenstackOctaviaListenerInternal struct {
	cacheProjectID               string
	cacheLoadBalancerID          string
	cacheDefaultPoolID           string
	cacheDefaultTlsContainerRef  string
	cacheSniContainerRefs        []string
	cacheClientCATlsContainerRef string
	cacheClientCRLContainerRef   string
	cacheL7PolicyIDs             []string
}

func (r *mqlOpenstackOctaviaListener) id() (string, error) {
	return "openstack.octavia.listener/" + r.Id.Data, nil
}

func initOpenstackOctaviaListener(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetListeners()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		l := raw.(*mqlOpenstackOctaviaListener)
		if l.Id.Data == id {
			return args, l, nil
		}
	}
	initSyntheticID("openstack.octavia.listener", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) listeners() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.LoadBalancerClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := listeners.List(client, listeners.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := listeners.ExtractListeners(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		l := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.octavia.listener", map[string]*llx.RawData{
			"__id":                  llx.StringData("openstack.octavia.listener/" + l.ID),
			"id":                    llx.StringData(l.ID),
			"name":                  llx.StringData(l.Name),
			"description":           llx.StringData(l.Description),
			"adminStateUp":          llx.BoolData(l.AdminStateUp),
			"protocol":              llx.StringData(l.Protocol),
			"protocolPort":          llx.IntData(int64(l.ProtocolPort)),
			"connectionLimit":       llx.IntData(int64(l.ConnLimit)),
			"provisioningStatus":    llx.StringData(l.ProvisioningStatus),
			"tlsCiphers":            llx.StringData(l.TLSCiphers),
			"tlsVersions":           stringSliceData(l.TLSVersions),
			"alpnProtocols":         stringSliceData(l.ALPNProtocols),
			"clientAuthentication":  llx.StringData(l.ClientAuthentication),
			"allowedCidrs":          stringSliceData(l.AllowedCIDRs),
			"insertHeaders":         stringMapData(l.InsertHeaders),
			"timeoutClientData":     llx.IntData(int64(l.TimeoutClientData)),
			"timeoutMemberData":     llx.IntData(int64(l.TimeoutMemberData)),
			"timeoutMemberConnect":  llx.IntData(int64(l.TimeoutMemberConnect)),
			"timeoutTcpInspect":     llx.IntData(int64(l.TimeoutTCPInspect)),
			"hstsIncludeSubdomains": llx.BoolData(l.HSTSIncludeSubdomains),
			"hstsMaxAge":            llx.IntData(int64(l.HSTSMaxAge)),
			"hstsPreload":           llx.BoolData(l.HSTSPreload),
			"tags":                  stringSliceData(l.Tags),
		})
		if err != nil {
			return nil, err
		}
		mqlL := res.(*mqlOpenstackOctaviaListener)
		mqlL.cacheProjectID = l.ProjectID
		if len(l.Loadbalancers) > 0 {
			mqlL.cacheLoadBalancerID = l.Loadbalancers[0].ID
			if len(l.Loadbalancers) > 1 {
				log.Warn().
					Str("listenerId", l.ID).
					Int("loadBalancerCount", len(l.Loadbalancers)).
					Msg("openstack: listener references multiple load balancers; exposing only the first")
			}
		}
		mqlL.cacheDefaultPoolID = l.DefaultPoolID
		mqlL.cacheDefaultTlsContainerRef = l.DefaultTlsContainerRef
		mqlL.cacheSniContainerRefs = l.SniContainerRefs
		mqlL.cacheClientCATlsContainerRef = l.ClientCATLSContainerRef
		mqlL.cacheClientCRLContainerRef = l.ClientCRLContainerRef
		mqlL.cacheL7PolicyIDs = l7PolicyIDs(l.L7Policies)
		out = append(out, mqlL)
	}
	return out, nil
}

func (r *mqlOpenstackOctaviaListener) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackOctaviaListener) loadBalancer() (*mqlOpenstackOctaviaLoadBalancer, error) {
	if r.cacheLoadBalancerID == "" {
		r.LoadBalancer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.octavia.loadBalancer", map[string]*llx.RawData{"id": llx.StringData(r.cacheLoadBalancerID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackOctaviaLoadBalancer), nil
}

func (r *mqlOpenstackOctaviaListener) defaultPool() (*mqlOpenstackOctaviaPool, error) {
	if r.cacheDefaultPoolID == "" {
		r.DefaultPool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.octavia.pool", map[string]*llx.RawData{"id": llx.StringData(r.cacheDefaultPoolID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackOctaviaPool), nil
}

func (r *mqlOpenstackOctaviaListener) defaultTlsContainer() (*mqlOpenstackKeymanagerContainer, error) {
	res, err := newKeymanagerContainerByRef(r.MqlRuntime, r.cacheDefaultTlsContainerRef)
	if err != nil {
		return nil, err
	}
	if res == nil {
		r.DefaultTlsContainer.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (r *mqlOpenstackOctaviaListener) defaultTlsSecret() (*mqlOpenstackKeymanagerSecret, error) {
	res, err := newKeymanagerSecretByRef(r.MqlRuntime, r.cacheDefaultTlsContainerRef)
	if err != nil {
		return nil, err
	}
	if res == nil {
		r.DefaultTlsSecret.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (r *mqlOpenstackOctaviaListener) sniContainers() ([]any, error) {
	out := make([]any, 0, len(r.cacheSniContainerRefs))
	for _, ref := range r.cacheSniContainerRefs {
		c, err := newKeymanagerContainerByRef(r.MqlRuntime, ref)
		if err != nil {
			return nil, err
		}
		if c != nil {
			out = append(out, c)
		}
	}
	return out, nil
}

func (r *mqlOpenstackOctaviaListener) sniSecrets() ([]any, error) {
	out := make([]any, 0, len(r.cacheSniContainerRefs))
	for _, ref := range r.cacheSniContainerRefs {
		s, err := newKeymanagerSecretByRef(r.MqlRuntime, ref)
		if err != nil {
			return nil, err
		}
		if s != nil {
			out = append(out, s)
		}
	}
	return out, nil
}

func (r *mqlOpenstackOctaviaListener) clientCATlsContainer() (*mqlOpenstackKeymanagerContainer, error) {
	res, err := newKeymanagerContainerByRef(r.MqlRuntime, r.cacheClientCATlsContainerRef)
	if err != nil {
		return nil, err
	}
	if res == nil {
		r.ClientCATlsContainer.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (r *mqlOpenstackOctaviaListener) clientCATlsSecret() (*mqlOpenstackKeymanagerSecret, error) {
	res, err := newKeymanagerSecretByRef(r.MqlRuntime, r.cacheClientCATlsContainerRef)
	if err != nil {
		return nil, err
	}
	if res == nil {
		r.ClientCATlsSecret.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (r *mqlOpenstackOctaviaListener) clientCRLContainer() (*mqlOpenstackKeymanagerContainer, error) {
	res, err := newKeymanagerContainerByRef(r.MqlRuntime, r.cacheClientCRLContainerRef)
	if err != nil {
		return nil, err
	}
	if res == nil {
		r.ClientCRLContainer.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (r *mqlOpenstackOctaviaListener) clientCRLSecret() (*mqlOpenstackKeymanagerSecret, error) {
	res, err := newKeymanagerSecretByRef(r.MqlRuntime, r.cacheClientCRLContainerRef)
	if err != nil {
		return nil, err
	}
	if res == nil {
		r.ClientCRLSecret.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (r *mqlOpenstackOctaviaListener) l7Policies() ([]any, error) {
	out := make([]any, 0, len(r.cacheL7PolicyIDs))
	for _, id := range r.cacheL7PolicyIDs {
		if id == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "openstack.octavia.l7Policy", map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func l7PolicyIDs(in []l7policies.L7Policy) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p.ID != "" {
			out = append(out, p.ID)
		}
	}
	return out
}

// ---- openstack.octavia.pool ----

type mqlOpenstackOctaviaPoolInternal struct {
	cacheProjectID             string
	cacheLoadBalancerID        string
	cacheListenerIDs           []string
	cacheHealthMonitorID       string
	cacheSubnetID              string
	cacheCATlsContainerRef     string
	cacheCRLContainerRef       string
	cacheClientTlsContainerRef string
	cacheMembers               []pools.Member
}

func (r *mqlOpenstackOctaviaPool) id() (string, error) {
	return "openstack.octavia.pool/" + r.Id.Data, nil
}

func initOpenstackOctaviaPool(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetPools()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		p := raw.(*mqlOpenstackOctaviaPool)
		if p.Id.Data == id {
			return args, p, nil
		}
	}
	initSyntheticID("openstack.octavia.pool", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) pools() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.LoadBalancerClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := pools.List(client, pools.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := pools.ExtractPools(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		p := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.octavia.pool", map[string]*llx.RawData{
			"__id":               llx.StringData("openstack.octavia.pool/" + p.ID),
			"id":                 llx.StringData(p.ID),
			"name":               llx.StringData(p.Name),
			"description":        llx.StringData(p.Description),
			"adminStateUp":       llx.BoolData(p.AdminStateUp),
			"lbAlgorithm":        llx.StringData(p.LBMethod),
			"protocol":           llx.StringData(p.Protocol),
			"provisioningStatus": llx.StringData(p.ProvisioningStatus),
			"operatingStatus":    llx.StringData(p.OperatingStatus),
			"provider":           llx.StringData(p.Provider),
			"persistence":        llx.DictData(persistenceToDict(p.Persistence)),
			"tlsEnabled":         llx.BoolData(p.TLSEnabled),
			"tlsCiphers":         llx.StringData(p.TLSCiphers),
			"tlsVersions":        stringSliceData(p.TLSVersions),
			"alpnProtocols":      stringSliceData(p.ALPNProtocols),
			"tags":               stringSliceData(p.Tags),
		})
		if err != nil {
			return nil, err
		}
		mqlP := res.(*mqlOpenstackOctaviaPool)
		mqlP.cacheProjectID = p.ProjectID
		if len(p.Loadbalancers) > 0 {
			mqlP.cacheLoadBalancerID = p.Loadbalancers[0].ID
			if len(p.Loadbalancers) > 1 {
				log.Warn().
					Str("poolId", p.ID).
					Int("loadBalancerCount", len(p.Loadbalancers)).
					Msg("openstack: pool references multiple load balancers; exposing only the first")
			}
		}
		mqlP.cacheListenerIDs = listenerIDsFromPoolListeners(p.Listeners)
		mqlP.cacheHealthMonitorID = p.MonitorID
		mqlP.cacheSubnetID = p.SubnetID
		mqlP.cacheCATlsContainerRef = p.CATLSContainerRef
		mqlP.cacheCRLContainerRef = p.CRLContainerRef
		mqlP.cacheClientTlsContainerRef = p.TLSContainerRef
		mqlP.cacheMembers = p.Members
		out = append(out, mqlP)
	}
	return out, nil
}

func (r *mqlOpenstackOctaviaPool) members() ([]any, error) {
	return buildOctaviaMembers(r.MqlRuntime, r.cacheMembers)
}

func (r *mqlOpenstackOctaviaPool) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackOctaviaPool) loadBalancer() (*mqlOpenstackOctaviaLoadBalancer, error) {
	if r.cacheLoadBalancerID == "" {
		r.LoadBalancer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.octavia.loadBalancer", map[string]*llx.RawData{"id": llx.StringData(r.cacheLoadBalancerID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackOctaviaLoadBalancer), nil
}

func (r *mqlOpenstackOctaviaPool) listeners() ([]any, error) {
	out := make([]any, 0, len(r.cacheListenerIDs))
	for _, id := range r.cacheListenerIDs {
		if id == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "openstack.octavia.listener", map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlOpenstackOctaviaPool) healthMonitor() (*mqlOpenstackOctaviaHealthMonitor, error) {
	if r.cacheHealthMonitorID == "" {
		r.HealthMonitor.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.octavia.healthMonitor", map[string]*llx.RawData{"id": llx.StringData(r.cacheHealthMonitorID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackOctaviaHealthMonitor), nil
}

func (r *mqlOpenstackOctaviaPool) subnet() (*mqlOpenstackSubnet, error) {
	if r.cacheSubnetID == "" {
		r.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.subnet", map[string]*llx.RawData{"id": llx.StringData(r.cacheSubnetID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackSubnet), nil
}

func (r *mqlOpenstackOctaviaPool) caTlsContainer() (*mqlOpenstackKeymanagerContainer, error) {
	res, err := newKeymanagerContainerByRef(r.MqlRuntime, r.cacheCATlsContainerRef)
	if err != nil {
		return nil, err
	}
	if res == nil {
		r.CaTlsContainer.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (r *mqlOpenstackOctaviaPool) caTlsSecret() (*mqlOpenstackKeymanagerSecret, error) {
	res, err := newKeymanagerSecretByRef(r.MqlRuntime, r.cacheCATlsContainerRef)
	if err != nil {
		return nil, err
	}
	if res == nil {
		r.CaTlsSecret.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (r *mqlOpenstackOctaviaPool) crlContainer() (*mqlOpenstackKeymanagerContainer, error) {
	res, err := newKeymanagerContainerByRef(r.MqlRuntime, r.cacheCRLContainerRef)
	if err != nil {
		return nil, err
	}
	if res == nil {
		r.CrlContainer.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (r *mqlOpenstackOctaviaPool) crlSecret() (*mqlOpenstackKeymanagerSecret, error) {
	res, err := newKeymanagerSecretByRef(r.MqlRuntime, r.cacheCRLContainerRef)
	if err != nil {
		return nil, err
	}
	if res == nil {
		r.CrlSecret.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (r *mqlOpenstackOctaviaPool) clientTlsContainer() (*mqlOpenstackKeymanagerContainer, error) {
	res, err := newKeymanagerContainerByRef(r.MqlRuntime, r.cacheClientTlsContainerRef)
	if err != nil {
		return nil, err
	}
	if res == nil {
		r.ClientTlsContainer.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func (r *mqlOpenstackOctaviaPool) clientTlsSecret() (*mqlOpenstackKeymanagerSecret, error) {
	res, err := newKeymanagerSecretByRef(r.MqlRuntime, r.cacheClientTlsContainerRef)
	if err != nil {
		return nil, err
	}
	if res == nil {
		r.ClientTlsSecret.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return res, nil
}

func persistenceToDict(p pools.SessionPersistence) map[string]any {
	if p.Type == "" {
		return nil
	}
	out := map[string]any{"type": p.Type}
	if p.CookieName != "" {
		out["cookie_name"] = p.CookieName
	}
	return out
}

func listenerIDsFromPoolListeners(in []pools.ListenerID) []string {
	out := make([]string, 0, len(in))
	for _, l := range in {
		if l.ID != "" {
			out = append(out, l.ID)
		}
	}
	return out
}

// ---- openstack.octavia.member ----

type mqlOpenstackOctaviaMemberInternal struct {
	cacheProjectID string
	cachePoolID    string
	cacheSubnetID  string
}

func (r *mqlOpenstackOctaviaMember) id() (string, error) {
	return "openstack.octavia.member/" + r.Id.Data, nil
}

func buildOctaviaMembers(runtime *plugin.Runtime, members []pools.Member) ([]any, error) {
	out := make([]any, 0, len(members))
	for i := range members {
		m := &members[i]
		res, err := CreateResource(runtime, "openstack.octavia.member", map[string]*llx.RawData{
			"__id":               llx.StringData("openstack.octavia.member/" + m.ID),
			"id":                 llx.StringData(m.ID),
			"name":               llx.StringData(m.Name),
			"adminStateUp":       llx.BoolData(m.AdminStateUp),
			"address":            llx.StringData(m.Address),
			"protocolPort":       llx.IntData(int64(m.ProtocolPort)),
			"weight":             llx.IntData(int64(m.Weight)),
			"backup":             llx.BoolData(m.Backup),
			"monitorAddress":     llx.StringData(m.MonitorAddress),
			"monitorPort":        llx.IntData(int64(m.MonitorPort)),
			"provisioningStatus": llx.StringData(m.ProvisioningStatus),
			"operatingStatus":    llx.StringData(m.OperatingStatus),
			"tags":               stringSliceData(m.Tags),
			"createdAt":          llx.TimeDataPtr(timePtr(m.CreatedAt)),
			"updatedAt":          llx.TimeDataPtr(timePtr(m.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlM := res.(*mqlOpenstackOctaviaMember)
		mqlM.cacheProjectID = m.ProjectID
		mqlM.cachePoolID = m.PoolID
		mqlM.cacheSubnetID = m.SubnetID
		out = append(out, mqlM)
	}
	return out, nil
}

func (r *mqlOpenstackOctaviaMember) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackOctaviaMember) pool() (*mqlOpenstackOctaviaPool, error) {
	if r.cachePoolID == "" {
		r.Pool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.octavia.pool", map[string]*llx.RawData{"id": llx.StringData(r.cachePoolID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackOctaviaPool), nil
}

func (r *mqlOpenstackOctaviaMember) subnet() (*mqlOpenstackSubnet, error) {
	if r.cacheSubnetID == "" {
		r.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.subnet", map[string]*llx.RawData{"id": llx.StringData(r.cacheSubnetID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackSubnet), nil
}

// ---- openstack.octavia.healthMonitor ----

type mqlOpenstackOctaviaHealthMonitorInternal struct {
	cacheProjectID string
	cachePoolIDs   []string
}

func (r *mqlOpenstackOctaviaHealthMonitor) id() (string, error) {
	return "openstack.octavia.healthMonitor/" + r.Id.Data, nil
}

func initOpenstackOctaviaHealthMonitor(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetHealthMonitors()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		h := raw.(*mqlOpenstackOctaviaHealthMonitor)
		if h.Id.Data == id {
			return args, h, nil
		}
	}
	initSyntheticID("openstack.octavia.healthMonitor", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) healthMonitors() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.LoadBalancerClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := monitors.List(client, monitors.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := monitors.ExtractMonitors(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		m := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.octavia.healthMonitor", map[string]*llx.RawData{
			"__id":               llx.StringData("openstack.octavia.healthMonitor/" + m.ID),
			"id":                 llx.StringData(m.ID),
			"name":               llx.StringData(m.Name),
			"adminStateUp":       llx.BoolData(m.AdminStateUp),
			"type":               llx.StringData(m.Type),
			"delay":              llx.IntData(int64(m.Delay)),
			"timeout":            llx.IntData(int64(m.Timeout)),
			"maxRetries":         llx.IntData(int64(m.MaxRetries)),
			"maxRetriesDown":     llx.IntData(int64(m.MaxRetriesDown)),
			"httpMethod":         llx.StringData(m.HTTPMethod),
			"httpVersion":        llx.StringData(m.HTTPVersion),
			"urlPath":            llx.StringData(m.URLPath),
			"expectedCodes":      llx.StringData(m.ExpectedCodes),
			"domainName":         llx.StringData(m.DomainName),
			"status":             llx.StringData(m.Status),
			"provisioningStatus": llx.StringData(m.ProvisioningStatus),
			"operatingStatus":    llx.StringData(m.OperatingStatus),
			"tags":               stringSliceData(m.Tags),
		})
		if err != nil {
			return nil, err
		}
		mqlM := res.(*mqlOpenstackOctaviaHealthMonitor)
		mqlM.cacheProjectID = m.ProjectID
		mqlM.cachePoolIDs = monitorPoolIDs(m.Pools)
		out = append(out, mqlM)
	}
	return out, nil
}

func (r *mqlOpenstackOctaviaHealthMonitor) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackOctaviaHealthMonitor) pools() ([]any, error) {
	out := make([]any, 0, len(r.cachePoolIDs))
	for _, id := range r.cachePoolIDs {
		if id == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "openstack.octavia.pool", map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func monitorPoolIDs(in []monitors.PoolID) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p.ID != "" {
			out = append(out, p.ID)
		}
	}
	return out
}

// ---- openstack.octavia.l7Policy ----

type mqlOpenstackOctaviaL7PolicyInternal struct {
	cacheProjectID      string
	cacheListenerID     string
	cacheRedirectPoolID string
	cacheRules          []l7policies.Rule
}

func (r *mqlOpenstackOctaviaL7Policy) id() (string, error) {
	return "openstack.octavia.l7Policy/" + r.Id.Data, nil
}

func initOpenstackOctaviaL7Policy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetL7Policies()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		p := raw.(*mqlOpenstackOctaviaL7Policy)
		if p.Id.Data == id {
			return args, p, nil
		}
	}
	initSyntheticID("openstack.octavia.l7Policy", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) l7Policies() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.LoadBalancerClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := l7policies.List(client, l7policies.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := l7policies.ExtractL7Policies(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		p := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.octavia.l7Policy", map[string]*llx.RawData{
			"__id":               llx.StringData("openstack.octavia.l7Policy/" + p.ID),
			"id":                 llx.StringData(p.ID),
			"name":               llx.StringData(p.Name),
			"description":        llx.StringData(p.Description),
			"adminStateUp":       llx.BoolData(p.AdminStateUp),
			"action":             llx.StringData(p.Action),
			"position":           llx.IntData(int64(p.Position)),
			"redirectPrefix":     llx.StringData(p.RedirectPrefix),
			"redirectUrl":        llx.StringData(p.RedirectURL),
			"redirectHttpCode":   llx.IntData(int64(p.RedirectHttpCode)),
			"provisioningStatus": llx.StringData(p.ProvisioningStatus),
			"operatingStatus":    llx.StringData(p.OperatingStatus),
			"tags":               stringSliceData(p.Tags),
		})
		if err != nil {
			return nil, err
		}
		mqlP := res.(*mqlOpenstackOctaviaL7Policy)
		mqlP.cacheProjectID = p.ProjectID
		mqlP.cacheListenerID = p.ListenerID
		mqlP.cacheRedirectPoolID = p.RedirectPoolID
		mqlP.cacheRules = p.Rules
		out = append(out, mqlP)
	}
	return out, nil
}

func (r *mqlOpenstackOctaviaL7Policy) rules() ([]any, error) {
	return buildOctaviaL7Rules(r.MqlRuntime, r.Id.Data, r.cacheRules)
}

func (r *mqlOpenstackOctaviaL7Policy) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackOctaviaL7Policy) listener() (*mqlOpenstackOctaviaListener, error) {
	if r.cacheListenerID == "" {
		r.Listener.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.octavia.listener", map[string]*llx.RawData{"id": llx.StringData(r.cacheListenerID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackOctaviaListener), nil
}

func (r *mqlOpenstackOctaviaL7Policy) redirectPool() (*mqlOpenstackOctaviaPool, error) {
	if r.cacheRedirectPoolID == "" {
		r.RedirectPool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.octavia.pool", map[string]*llx.RawData{"id": llx.StringData(r.cacheRedirectPoolID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackOctaviaPool), nil
}

// ---- openstack.octavia.l7Rule ----

type mqlOpenstackOctaviaL7RuleInternal struct {
	cacheProjectID  string
	cacheL7PolicyID string
}

func (r *mqlOpenstackOctaviaL7Rule) id() (string, error) {
	return "openstack.octavia.l7Rule/" + r.Id.Data, nil
}

func buildOctaviaL7Rules(runtime *plugin.Runtime, policyID string, rules []l7policies.Rule) ([]any, error) {
	out := make([]any, 0, len(rules))
	for i := range rules {
		rule := &rules[i]
		res, err := CreateResource(runtime, "openstack.octavia.l7Rule", map[string]*llx.RawData{
			"__id":               llx.StringData("openstack.octavia.l7Rule/" + rule.ID),
			"id":                 llx.StringData(rule.ID),
			"ruleType":           llx.StringData(rule.RuleType),
			"compareType":        llx.StringData(rule.CompareType),
			"value":              llx.StringData(rule.Value),
			"key":                llx.StringData(rule.Key),
			"invert":             llx.BoolData(rule.Invert),
			"adminStateUp":       llx.BoolData(rule.AdminStateUp),
			"provisioningStatus": llx.StringData(rule.ProvisioningStatus),
			"operatingStatus":    llx.StringData(rule.OperatingStatus),
			"tags":               stringSliceData(rule.Tags),
		})
		if err != nil {
			return nil, err
		}
		mqlR := res.(*mqlOpenstackOctaviaL7Rule)
		mqlR.cacheProjectID = rule.ProjectID
		mqlR.cacheL7PolicyID = policyID
		out = append(out, mqlR)
	}
	return out, nil
}

func (r *mqlOpenstackOctaviaL7Rule) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackOctaviaL7Rule) l7Policy() (*mqlOpenstackOctaviaL7Policy, error) {
	if r.cacheL7PolicyID == "" {
		r.L7Policy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.octavia.l7Policy", map[string]*llx.RawData{"id": llx.StringData(r.cacheL7PolicyID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackOctaviaL7Policy), nil
}

// resolveProject is a shared helper for the many octavia accessors that
// resolve a cached project ID into a typed openstack.project. Returns
// (nil, nil) when the cache is empty after marking the field null.
// hstsEnabledForMaxAge reports whether an HSTS max-age turns the header on.
// Octavia emits Strict-Transport-Security only for a positive max-age; the
// includeSubDomains and preload directives do nothing on their own, so reading
// either of them as "HSTS is configured" is a false positive.
func hstsEnabledForMaxAge(maxAge int64) bool {
	return maxAge > 0
}

func (r *mqlOpenstackOctaviaListener) hstsEnabled() (bool, error) {
	maxAge := r.GetHstsMaxAge()
	if maxAge.Error != nil {
		return false, maxAge.Error
	}
	return hstsEnabledForMaxAge(maxAge.Data), nil
}

func resolveProject(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOpenstackProject]) (*mqlOpenstackProject, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "openstack.project", map[string]*llx.RawData{"id": llx.StringData(id)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackProject), nil
}

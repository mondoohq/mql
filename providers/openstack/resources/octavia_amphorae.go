// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/gophercloud/gophercloud/v2/openstack/loadbalancer/v2/amphorae"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlOpenstackOctaviaAmphoraInternal struct {
	cacheLoadBalancerID string
	cacheComputeID      string
	cacheImageID        string
	cacheHAPortID       string
	cacheVRRPPortID     string
}

func (r *mqlOpenstackOctaviaAmphora) id() (string, error) {
	return "openstack.octavia.amphora/" + r.Id.Data, nil
}

func (o *mqlOpenstack) amphorae() ([]any, error) {
	client, err := conn(o.MqlRuntime).LoadBalancerClient()
	if err != nil {
		return nil, err
	}
	pages, err := amphorae.List(client, amphorae.ListOpts{}).AllPages(ctx())
	if err != nil {
		// Listing amphorae is admin-only in most deployments, so a scoped user
		// simply sees none.
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := amphorae.ExtractAmphorae(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, a := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.octavia.amphora", map[string]*llx.RawData{
			"__id":           llx.StringData("openstack.octavia.amphora/" + a.ID),
			"id":             llx.StringData(a.ID),
			"role":           llx.StringData(a.Role),
			"status":         llx.StringData(a.Status),
			"certExpiration": llx.TimeDataPtr(timePtr(a.CertExpiration)),
			"certBusy":       llx.BoolData(a.CertBusy),
			"cachedZone":     llx.StringData(a.CachedZone),
			"lbNetworkIp":    llx.StringData(a.LBNetworkIP),
			"haIp":           llx.StringData(a.HAIP),
			"vrrpIp":         llx.StringData(a.VRRPIP),
			"vrrpInterface":  llx.StringData(a.VRRPInterface),
			"vrrpId":         llx.IntData(int64(a.VRRPID)),
			"vrrpPriority":   llx.IntData(int64(a.VRRPPriority)),
			"createdAt":      llx.TimeDataPtr(timePtr(a.CreatedAt)),
			"updatedAt":      llx.TimeDataPtr(timePtr(a.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlA := res.(*mqlOpenstackOctaviaAmphora)
		mqlA.cacheLoadBalancerID = a.LoadbalancerID
		mqlA.cacheComputeID = a.ComputeID
		mqlA.cacheImageID = a.ImageID
		mqlA.cacheHAPortID = a.HAPortID
		mqlA.cacheVRRPPortID = a.VRRPPortID
		out = append(out, mqlA)
	}
	return out, nil
}

func (r *mqlOpenstackOctaviaAmphora) loadBalancer() (*mqlOpenstackOctaviaLoadBalancer, error) {
	if r.cacheLoadBalancerID == "" {
		r.LoadBalancer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.octavia.loadBalancer", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheLoadBalancerID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackOctaviaLoadBalancer), nil
}

func (r *mqlOpenstackOctaviaAmphora) server() (*mqlOpenstackComputeServer, error) {
	if r.cacheComputeID == "" {
		r.Server.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.compute.server", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheComputeID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackComputeServer), nil
}

func (r *mqlOpenstackOctaviaAmphora) image() (*mqlOpenstackImage, error) {
	return resolveImage(r.MqlRuntime, r.cacheImageID, &r.Image)
}

func (r *mqlOpenstackOctaviaAmphora) haPort() (*mqlOpenstackPort, error) {
	return resolvePort(r.MqlRuntime, r.cacheHAPortID, &r.HaPort)
}

func (r *mqlOpenstackOctaviaAmphora) vrrpPort() (*mqlOpenstackPort, error) {
	return resolvePort(r.MqlRuntime, r.cacheVRRPPortID, &r.VrrpPort)
}

// resolveImage resolves an image id to the image resource, leaving the field
// null when no image is named.
func resolveImage(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOpenstackImage]) (*mqlOpenstackImage, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "openstack.image", map[string]*llx.RawData{"id": llx.StringData(id)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackImage), nil
}

// resolvePort resolves a port id to the port resource, leaving the field null
// when no port is named.
func resolvePort(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOpenstackPort]) (*mqlOpenstackPort, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "openstack.port", map[string]*llx.RawData{"id": llx.StringData(id)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackPort), nil
}

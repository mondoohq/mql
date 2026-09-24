// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlHetznerFloatingIpInternal struct {
	cacheHomeLocation *hcloud.Location
	cacheServer       *hcloud.Server
}

func (r *mqlHetznerFloatingIp) id() (string, error) {
	return fmt.Sprintf("hetzner.floatingIp/%d", r.Id.Data), nil
}

func (h *mqlHetzner) floatingIps() ([]any, error) {
	items, err := h.allFloatingIPs()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, f := range items {
		res, err := newMqlHetznerFloatingIp(h.MqlRuntime, f)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerFloatingIp(runtime *plugin.Runtime, f *hcloud.FloatingIP) (*mqlHetznerFloatingIp, error) {
	ipStr := ipString(f.IP)
	if f.Network != nil {
		ipStr = ipNetString(f.Network)
	}
	res, err := CreateResource(runtime, "hetzner.floatingIp", map[string]*llx.RawData{
		"__id":        llx.StringData(fmt.Sprintf("hetzner.floatingIp/%d", f.ID)),
		"id":          llx.IntData(f.ID),
		"type":        llx.StringData(string(f.Type)),
		"ip":          llx.StringData(ipStr),
		"name":        llx.StringData(f.Name),
		"description": llx.StringData(f.Description),
		"blocked":     llx.BoolData(f.Blocked),
		"dnsPtr":      dictArrayData(dnsPtrSliceFromMap(f.DNSPtr)),
		"protection":  llx.DictData(protectionDict(f.Protection.Delete)),
		"labels":      labelData(f.Labels),
		"created":     llx.TimeDataPtr(timePtr(f.Created)),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerFloatingIp)
	m.cacheHomeLocation = f.HomeLocation
	m.cacheServer = f.Server
	return m, nil
}

func initHetznerFloatingIp(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "floatingIp")
	if err != nil {
		return nil, nil, err
	}
	f, _, err := conn(runtime).Client().FloatingIP.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if f == nil {
		return nil, nil, notFoundErr("floatingIp", id)
	}
	res, err := newMqlHetznerFloatingIp(runtime, f)
	return args, res, err
}

func (m *mqlHetznerFloatingIp) homeLocation() (*mqlHetznerLocation, error) {
	return resolveTypedResource(&m.HomeLocation, m.cacheHomeLocation, func(loc *hcloud.Location) (*mqlHetznerLocation, error) {
		return newMqlHetznerLocation(m.MqlRuntime, loc)
	})
}

func (m *mqlHetznerFloatingIp) server() (*mqlHetznerServer, error) {
	if m.cacheServer == nil {
		m.Server.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// FloatingIP only carries a partial Server (ID); resolve via init.
	ref, err := NewResource(m.MqlRuntime, "hetzner.server", map[string]*llx.RawData{
		"id": llx.IntData(m.cacheServer.ID),
	})
	if err != nil {
		return nil, err
	}
	return ref.(*mqlHetznerServer), nil
}

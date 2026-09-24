// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlHetznerPrimaryIpInternal struct {
	cacheLocation *hcloud.Location
	cacheServerID int64
}

func (r *mqlHetznerPrimaryIp) id() (string, error) {
	return fmt.Sprintf("hetzner.primaryIp/%d", r.Id.Data), nil
}

func (h *mqlHetzner) primaryIps() ([]any, error) {
	items, err := h.allPrimaryIPs()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, p := range items {
		res, err := newMqlHetznerPrimaryIp(h.MqlRuntime, p)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerPrimaryIp(runtime *plugin.Runtime, p *hcloud.PrimaryIP) (*mqlHetznerPrimaryIp, error) {
	ipStr := ipString(p.IP)
	if p.Network != nil {
		ipStr = ipNetString(p.Network)
	}
	res, err := CreateResource(runtime, "hetzner.primaryIp", map[string]*llx.RawData{
		"__id":         llx.StringData(fmt.Sprintf("hetzner.primaryIp/%d", p.ID)),
		"id":           llx.IntData(p.ID),
		"type":         llx.StringData(string(p.Type)),
		"ip":           llx.StringData(ipStr),
		"name":         llx.StringData(p.Name),
		"assigneeType": llx.StringData(p.AssigneeType),
		"assigneeId":   llx.IntData(p.AssigneeID),
		"autoDelete":   llx.BoolData(p.AutoDelete),
		"blocked":      llx.BoolData(p.Blocked),
		"dnsPtr":       dictArrayData(dnsPtrSliceFromMap(p.DNSPtr)),
		"protection":   llx.DictData(protectionDict(p.Protection.Delete)),
		"labels":       labelData(p.Labels),
		"created":      llx.TimeDataPtr(timePtr(p.Created)),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerPrimaryIp)
	m.cacheLocation = p.Location
	if p.AssigneeType == "server" {
		m.cacheServerID = p.AssigneeID
	}
	return m, nil
}

func initHetznerPrimaryIp(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "primaryIp")
	if err != nil {
		return nil, nil, err
	}
	p, _, err := conn(runtime).Client().PrimaryIP.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if p == nil {
		return nil, nil, notFoundErr("primaryIp", id)
	}
	res, err := newMqlHetznerPrimaryIp(runtime, p)
	return args, res, err
}

func (m *mqlHetznerPrimaryIp) location() (*mqlHetznerLocation, error) {
	return resolveTypedResource(&m.Location, m.cacheLocation, func(l *hcloud.Location) (*mqlHetznerLocation, error) {
		return newMqlHetznerLocation(m.MqlRuntime, l)
	})
}

func (m *mqlHetznerPrimaryIp) server() (*mqlHetznerServer, error) {
	if m.cacheServerID == 0 {
		m.Server.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ref, err := NewResource(m.MqlRuntime, "hetzner.server", map[string]*llx.RawData{
		"id": llx.IntData(m.cacheServerID),
	})
	if err != nil {
		return nil, err
	}
	return ref.(*mqlHetznerServer), nil
}

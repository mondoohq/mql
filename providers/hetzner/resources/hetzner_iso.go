// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (r *mqlHetznerIso) id() (string, error) {
	return fmt.Sprintf("hetzner.iso/%d", r.Id.Data), nil
}

func (h *mqlHetzner) isos() ([]any, error) {
	c := conn(h.MqlRuntime)
	items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.ISO, *hcloud.Response, error) {
		return c.Client().ISO.List(ctx(), hcloud.ISOListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, iso := range items {
		res, err := newMqlHetznerIso(h.MqlRuntime, iso)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerIso(runtime *plugin.Runtime, iso *hcloud.ISO) (*mqlHetznerIso, error) {
	dep := deprecationDict(iso.Deprecation)
	arch := ""
	if iso.Architecture != nil {
		arch = string(*iso.Architecture)
	}
	res, err := CreateResource(runtime, "hetzner.iso", map[string]*llx.RawData{
		"__id":         llx.StringData(fmt.Sprintf("hetzner.iso/%d", iso.ID)),
		"id":           llx.IntData(iso.ID),
		"name":         llx.StringData(iso.Name),
		"description":  llx.StringData(iso.Description),
		"type":         llx.StringData(string(iso.Type)),
		"deprecation":  llx.DictData(dep),
		"architecture": llx.StringData(arch),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHetznerIso), nil
}

func initHetznerIso(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "iso")
	if err != nil {
		return nil, nil, err
	}
	iso, _, err := conn(runtime).Client().ISO.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if iso == nil {
		return nil, nil, notFoundErr("iso", id)
	}
	res, err := newMqlHetznerIso(runtime, iso)
	return args, res, err
}

// serverHasISO reports whether the server currently boots from the given ISO.
//
// A server with an ISO attached can boot outside its installed operating
// system, which bypasses every control that lives on the disk, so this is the
// reverse of the server.iso edge rather than a convenience.
func serverHasISO(s *hcloud.Server, isoID int64) bool {
	return s != nil && s.ISO != nil && s.ISO.ID == isoID
}

func (m *mqlHetznerIso) servers() ([]any, error) {
	isoID := m.Id.Data
	return serversMatching(m.MqlRuntime, func(s *hcloud.Server) bool {
		return serverHasISO(s, isoID)
	})
}

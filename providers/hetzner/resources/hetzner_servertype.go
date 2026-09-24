// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlHetznerServerTypeInternal struct {
	cacheLocations []hcloud.ServerTypeLocation
}

func (r *mqlHetznerServerType) id() (string, error) {
	return fmt.Sprintf("hetzner.serverType/%d", r.Id.Data), nil
}

func (h *mqlHetzner) serverTypes() ([]any, error) {
	c := conn(h.MqlRuntime)
	items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.ServerType, *hcloud.Response, error) {
		return c.Client().ServerType.List(ctx(), hcloud.ServerTypeListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, t := range items {
		res, err := newMqlHetznerServerType(h.MqlRuntime, t)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerServerType(runtime *plugin.Runtime, t *hcloud.ServerType) (*mqlHetznerServerType, error) {
	res, err := CreateResource(runtime, "hetzner.serverType", map[string]*llx.RawData{
		"__id":         llx.StringData(fmt.Sprintf("hetzner.serverType/%d", t.ID)),
		"id":           llx.IntData(t.ID),
		"name":         llx.StringData(t.Name),
		"description":  llx.StringData(t.Description),
		"cores":        llx.IntData(int64(t.Cores)),
		"memory":       llx.FloatData(float64(t.Memory)),
		"disk":         llx.IntData(int64(t.Disk)),
		"storageType":  llx.StringData(string(t.StorageType)),
		"cpuType":      llx.StringData(string(t.CPUType)),
		"category":     llx.StringData(t.Category),
		"architecture": llx.StringData(string(t.Architecture)),
		"deprecated":   llx.BoolData(t.IsDeprecated()),
		// hcloud marks ServerType.DeprecatableResource as phasing out in
		// favour of the per-location schedule, which locations() already
		// carries. The type-wide schedule is kept because the shipped
		// `deprecated` bool reads from the same struct and says only that a
		// type is going away, never by when.
		"deprecation": llx.DictData(deprecationDict(t.Deprecation)),
		// Deprecated in the SDK and reports 0 after 2024-08-05, when Hetzner
		// moved the traffic allowance into per-location pricing. Carried so
		// the inventory matches what the API returns.
		"includedTraffic": llx.IntData(t.IncludedTraffic),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerServerType)
	m.cacheLocations = t.Locations
	return m, nil
}

func (m *mqlHetznerServerType) locations() ([]any, error) {
	out := make([]any, 0, len(m.cacheLocations))
	for _, loc := range m.cacheLocations {
		res, err := newMqlHetznerServerTypeLocation(m.MqlRuntime, m.Id.Data, loc)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// --- serverType.location sub-resource ---

// mqlHetznerServerTypeLocationInternal holds the server type and location the
// availability entry joins, which the serverType and location accessors
// resolve.
type mqlHetznerServerTypeLocationInternal struct {
	cacheServerTypeID int64
	cacheLocationID   int64
}

func (r *mqlHetznerServerTypeLocation) id() (string, error) {
	return fmt.Sprintf("hetzner.serverType.location/%d/%d", r.cacheServerTypeID, r.cacheLocationID), nil
}

func newMqlHetznerServerTypeLocation(runtime *plugin.Runtime, serverTypeID int64, stl hcloud.ServerTypeLocation) (*mqlHetznerServerTypeLocation, error) {
	var locationID int64
	if stl.Location != nil {
		locationID = stl.Location.ID
	}
	dep := deprecationDict(stl.Deprecation)
	res, err := CreateResource(runtime, "hetzner.serverType.location", map[string]*llx.RawData{
		"__id":        llx.StringData(fmt.Sprintf("hetzner.serverType.location/%d/%d", serverTypeID, locationID)),
		"available":   llx.BoolData(stl.Available),
		"recommended": llx.BoolData(stl.Recommended),
		"deprecation": llx.DictData(dep),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerServerTypeLocation)
	m.cacheServerTypeID = serverTypeID
	m.cacheLocationID = locationID
	return m, nil
}

func (m *mqlHetznerServerTypeLocation) serverType() (*mqlHetznerServerType, error) {
	if m.cacheServerTypeID == 0 {
		m.ServerType.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ref, err := NewResource(m.MqlRuntime, "hetzner.serverType", map[string]*llx.RawData{
		"id": llx.IntData(m.cacheServerTypeID),
	})
	if err != nil {
		return nil, err
	}
	return ref.(*mqlHetznerServerType), nil
}

func (m *mqlHetznerServerTypeLocation) location() (*mqlHetznerLocation, error) {
	if m.cacheLocationID == 0 {
		m.Location.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ref, err := NewResource(m.MqlRuntime, "hetzner.location", map[string]*llx.RawData{
		"id": llx.IntData(m.cacheLocationID),
	})
	if err != nil {
		return nil, err
	}
	return ref.(*mqlHetznerLocation), nil
}

func initHetznerServerType(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "serverType")
	if err != nil {
		return nil, nil, err
	}
	t, _, err := conn(runtime).Client().ServerType.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if t == nil {
		return nil, nil, notFoundErr("serverType", id)
	}
	res, err := newMqlHetznerServerType(runtime, t)
	return args, res, err
}

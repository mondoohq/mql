// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/agents"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/taas/tapmirrors"
	"go.mondoo.com/mql/llx"
)

// ---- openstack.network.agent ----

func (r *mqlOpenstackNetworkAgent) id() (string, error) {
	return "openstack.network.agent/" + r.Id.Data, nil
}

func (o *mqlOpenstack) networkAgents() ([]any, error) {
	client, err := conn(o.MqlRuntime).NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := agents.List(client, agents.ListOpts{}).AllPages(ctx())
	if err != nil {
		// Listing agents is admin-only in most deployments, so a scoped user
		// simply sees none.
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := agents.ExtractAgents(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, a := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.network.agent", map[string]*llx.RawData{
			"__id":               llx.StringData("openstack.network.agent/" + a.ID),
			"id":                 llx.StringData(a.ID),
			"agentType":          llx.StringData(a.AgentType),
			"binary":             llx.StringData(a.Binary),
			"host":               llx.StringData(a.Host),
			"topic":              llx.StringData(a.Topic),
			"alive":              llx.BoolData(a.Alive),
			"adminStateUp":       llx.BoolData(a.AdminStateUp),
			"resourcesSynced":    llx.BoolData(a.ResourcesSynced),
			"availabilityZone":   llx.StringData(a.AvailabilityZone),
			"description":        llx.StringData(a.Description),
			"configurations":     llx.DictData(toDict(a.Configurations)),
			"heartbeatTimestamp": llx.TimeDataPtr(timePtr(a.HeartbeatTimestamp)),
			"createdAt":          llx.TimeDataPtr(timePtr(a.CreatedAt)),
			"startedAt":          llx.TimeDataPtr(timePtr(a.StartedAt)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- openstack.network.tapMirror ----

type mqlOpenstackNetworkTapMirrorInternal struct {
	cachePortID    string
	cacheProjectID string
}

func (r *mqlOpenstackNetworkTapMirror) id() (string, error) {
	return "openstack.network.tapMirror/" + r.Id.Data, nil
}

func (o *mqlOpenstack) tapMirrors() ([]any, error) {
	client, err := conn(o.MqlRuntime).NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := tapmirrors.List(client, tapmirrors.ListOpts{}).AllPages(ctx())
	if err != nil {
		// A cloud without the tap-as-a-service extension mirrors nothing.
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := tapmirrors.ExtractTapMirrors(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, m := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.network.tapMirror", map[string]*llx.RawData{
			"__id":         llx.StringData("openstack.network.tapMirror/" + m.ID),
			"id":           llx.StringData(m.ID),
			"name":         llx.StringData(m.Name),
			"description":  llx.StringData(m.Description),
			"mirrorType":   llx.StringData(m.MirrorType),
			"remoteIp":     llx.StringData(m.RemoteIP),
			"directionIn":  llx.IntData(int64(m.Directions.In)),
			"directionOut": llx.IntData(int64(m.Directions.Out)),
		})
		if err != nil {
			return nil, err
		}
		mqlM := res.(*mqlOpenstackNetworkTapMirror)
		mqlM.cachePortID = m.PortID
		// ProjectID is the owner; fall back to the legacy TenantID alias.
		owner := m.ProjectID
		if owner == "" {
			owner = m.TenantID
		}
		mqlM.cacheProjectID = owner
		out = append(out, mqlM)
	}
	return out, nil
}

func (r *mqlOpenstackNetworkTapMirror) port() (*mqlOpenstackPort, error) {
	return resolvePort(r.MqlRuntime, r.cachePortID, &r.Port)
}

func (r *mqlOpenstackNetworkTapMirror) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

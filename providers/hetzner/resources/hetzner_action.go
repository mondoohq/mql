// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// actionListOpts is the paging window every per-resource action listing uses.
// 50 is hcloud's maximum page size, matching the paginate helper.
func actionListOpts() hcloud.ActionListOpts {
	return hcloud.ActionListOpts{PerPage: 50}
}

func (r *mqlHetznerAction) id() (string, error) {
	return fmt.Sprintf("hetzner.action/%d", r.Id.Data), nil
}

// actionResourceDicts renders the resources an action ran against. IDs are
// widened to int64 because the dict-to-primitive converter only accepts
// int64; a raw int fails serialization when the field is queried.
func actionResourceDicts(resources []*hcloud.ActionResource) []any {
	out := make([]any, 0, len(resources))
	for _, r := range resources {
		if r == nil {
			continue
		}
		out = append(out, map[string]any{
			"id":   r.ID,
			"type": string(r.Type),
		})
	}
	return out
}

func newMqlHetznerAction(runtime *plugin.Runtime, a *hcloud.Action) (*mqlHetznerAction, error) {
	res, err := CreateResource(runtime, "hetzner.action", map[string]*llx.RawData{
		"__id":         llx.StringData(fmt.Sprintf("hetzner.action/%d", a.ID)),
		"id":           llx.IntData(a.ID),
		"command":      llx.StringData(a.Command),
		"status":       llx.StringData(string(a.Status)),
		"progress":     llx.IntData(int64(a.Progress)),
		"started":      llx.TimeDataPtr(timePtr(a.Started)),
		"finished":     llx.TimeDataPtr(timePtr(a.Finished)),
		"errorCode":    llx.StringData(a.ErrorCode),
		"errorMessage": llx.StringData(a.ErrorMessage),
		"resources":    dictArrayData(actionResourceDicts(a.Resources)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHetznerAction), nil
}

// actionsFrom builds the action resources for one project resource.
//
// The list closure always calls a per-resource action client
// (client.Server.Action, client.Firewall.Action, ...) rather than the global
// ActionClient. /actions has required an explicit list of action IDs since
// 2025-01-30, and hcloud marks ActionClient.All deprecated for that reason,
// so the only way to read the history of a single resource is the resource's
// own /<resource>/<id>/actions endpoint.
//
// A 404 here means the resource is gone, which is the same "nothing to list"
// answer paginate gives a missing collection. Everything else propagates: a
// denial establishes nothing about what happened to the resource, and
// reporting it as no history would assert an audit trail we never read.
func actionsFrom(runtime *plugin.Runtime, list func() ([]*hcloud.Action, error)) ([]any, error) {
	items, err := list()
	if err != nil {
		if translateHcloudError(err) != nil {
			return nil, err
		}
		return []any{}, nil
	}
	out := make([]any, 0, len(items))
	for _, a := range items {
		if a == nil {
			continue
		}
		res, err := newMqlHetznerAction(runtime, a)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (m *mqlHetznerServer) actions() ([]any, error) {
	c := conn(m.MqlRuntime)
	return actionsFrom(m.MqlRuntime, func() ([]*hcloud.Action, error) {
		return c.Client().Server.Action.AllFor(ctx(), &hcloud.Server{ID: m.Id.Data}, actionListOpts())
	})
}

func (m *mqlHetznerFirewall) actions() ([]any, error) {
	c := conn(m.MqlRuntime)
	return actionsFrom(m.MqlRuntime, func() ([]*hcloud.Action, error) {
		return c.Client().Firewall.Action.AllFor(ctx(), &hcloud.Firewall{ID: m.Id.Data}, actionListOpts())
	})
}

func (m *mqlHetznerLoadBalancer) actions() ([]any, error) {
	c := conn(m.MqlRuntime)
	return actionsFrom(m.MqlRuntime, func() ([]*hcloud.Action, error) {
		return c.Client().LoadBalancer.Action.AllFor(ctx(), &hcloud.LoadBalancer{ID: m.Id.Data}, actionListOpts())
	})
}

func (m *mqlHetznerVolume) actions() ([]any, error) {
	c := conn(m.MqlRuntime)
	return actionsFrom(m.MqlRuntime, func() ([]*hcloud.Action, error) {
		return c.Client().Volume.Action.AllFor(ctx(), &hcloud.Volume{ID: m.Id.Data}, actionListOpts())
	})
}

func (m *mqlHetznerCertificate) actions() ([]any, error) {
	c := conn(m.MqlRuntime)
	return actionsFrom(m.MqlRuntime, func() ([]*hcloud.Action, error) {
		return c.Client().Certificate.Action.AllFor(ctx(), &hcloud.Certificate{ID: m.Id.Data}, actionListOpts())
	})
}

func (m *mqlHetznerNetwork) actions() ([]any, error) {
	c := conn(m.MqlRuntime)
	return actionsFrom(m.MqlRuntime, func() ([]*hcloud.Action, error) {
		return c.Client().Network.Action.AllFor(ctx(), &hcloud.Network{ID: m.Id.Data}, actionListOpts())
	})
}

func (m *mqlHetznerPrimaryIp) actions() ([]any, error) {
	c := conn(m.MqlRuntime)
	return actionsFrom(m.MqlRuntime, func() ([]*hcloud.Action, error) {
		return c.Client().PrimaryIP.Action.AllFor(ctx(), &hcloud.PrimaryIP{ID: m.Id.Data}, actionListOpts())
	})
}

func (m *mqlHetznerFloatingIp) actions() ([]any, error) {
	c := conn(m.MqlRuntime)
	return actionsFrom(m.MqlRuntime, func() ([]*hcloud.Action, error) {
		return c.Client().FloatingIP.Action.AllFor(ctx(), &hcloud.FloatingIP{ID: m.Id.Data}, actionListOpts())
	})
}

func (m *mqlHetznerImage) actions() ([]any, error) {
	c := conn(m.MqlRuntime)
	return actionsFrom(m.MqlRuntime, func() ([]*hcloud.Action, error) {
		return c.Client().Image.Action.AllFor(ctx(), &hcloud.Image{ID: m.Id.Data}, actionListOpts())
	})
}

func (m *mqlHetznerZone) actions() ([]any, error) {
	c := conn(m.MqlRuntime)
	return actionsFrom(m.MqlRuntime, func() ([]*hcloud.Action, error) {
		return c.Client().Zone.Action.AllFor(ctx(), &hcloud.Zone{ID: m.Id.Data}, actionListOpts())
	})
}

func (m *mqlHetznerStorageBox) actions() ([]any, error) {
	c := conn(m.MqlRuntime)
	return actionsFrom(m.MqlRuntime, func() ([]*hcloud.Action, error) {
		return c.Client().StorageBox.Action.AllFor(ctx(), &hcloud.StorageBox{ID: m.Id.Data}, actionListOpts())
	})
}

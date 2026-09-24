// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlHetznerImageInternal struct {
	cacheBoundServerID int64
	cacheCreatedFromID int64
}

func (r *mqlHetznerImage) id() (string, error) {
	return fmt.Sprintf("hetzner.image/%d", r.Id.Data), nil
}

func (h *mqlHetzner) images() ([]any, error) {
	c := conn(h.MqlRuntime)
	items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.Image, *hcloud.Response, error) {
		return c.Client().Image.List(ctx(), hcloud.ImageListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, img := range items {
		res, err := newMqlHetznerImage(h.MqlRuntime, img)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerImage(runtime *plugin.Runtime, img *hcloud.Image) (*mqlHetznerImage, error) {
	res, err := CreateResource(runtime, "hetzner.image", map[string]*llx.RawData{
		"__id":         llx.StringData(fmt.Sprintf("hetzner.image/%d", img.ID)),
		"id":           llx.IntData(img.ID),
		"type":         llx.StringData(string(img.Type)),
		"status":       llx.StringData(string(img.Status)),
		"name":         llx.StringData(img.Name),
		"description":  llx.StringData(img.Description),
		"imageSize":    llx.FloatData(float64(img.ImageSize)),
		"diskSize":     llx.FloatData(float64(img.DiskSize)),
		"created":      llx.TimeDataPtr(timePtr(img.Created)),
		"osFlavor":     llx.StringData(img.OSFlavor),
		"osVersion":    llx.StringData(img.OSVersion),
		"architecture": llx.StringData(string(img.Architecture)),
		"rapidDeploy":  llx.BoolData(img.RapidDeploy),
		"protection":   llx.DictData(protectionDict(img.Protection.Delete)),
		"deprecated":   llx.TimeDataPtr(timePtr(img.Deprecated)),
		"deprecation":  llx.DictData(deprecationDict(img.Deprecation)),
		"deleted":      llx.TimeDataPtr(timePtr(img.Deleted)),
		"labels":       labelData(img.Labels),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerImage)
	if img.BoundTo != nil {
		m.cacheBoundServerID = img.BoundTo.ID
	}
	if img.CreatedFrom != nil {
		m.cacheCreatedFromID = img.CreatedFrom.ID
	}
	return m, nil
}

func initHetznerImage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "image")
	if err != nil {
		return nil, nil, err
	}
	img, _, err := conn(runtime).Client().Image.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if img == nil {
		return nil, nil, notFoundErr("image", id)
	}
	res, err := newMqlHetznerImage(runtime, img)
	return args, res, err
}

func (m *mqlHetznerImage) boundServer() (*mqlHetznerServer, error) {
	return serverRefByID(m.MqlRuntime, &m.BoundServer, m.cacheBoundServerID)
}

func (m *mqlHetznerImage) createdFrom() (*mqlHetznerServer, error) {
	return serverRefByID(m.MqlRuntime, &m.CreatedFrom, m.cacheCreatedFromID)
}

// serverRefByID resolves a single typed server reference via NewResource so
// the runtime fetches a full server (via init) on first access. Avoids
// cache-poisoning a server entry with a partial stub from a parent API
// response that only carries (ID, Name).
func serverRefByID(runtime *plugin.Runtime, field *plugin.TValue[*mqlHetznerServer], id int64) (*mqlHetznerServer, error) {
	if id == 0 {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ref, err := NewResource(runtime, "hetzner.server", map[string]*llx.RawData{
		"id": llx.IntData(id),
	})
	if err != nil {
		return nil, err
	}
	return ref.(*mqlHetznerServer), nil
}

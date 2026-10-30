// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
)

// --- Sizes (droplet size catalog) ---

// newMqlDigitaloceanSize builds a digitalocean.size resource from a godo size.
// It is shared by the sizes() catalog collection and the droplet/nodePool
// dropletSize() accessors.
func newMqlDigitaloceanSize(runtime *plugin.Runtime, size godo.Size) (*mqlDigitaloceanSize, error) {
	regions := make([]any, len(size.Regions))
	for i, rg := range size.Regions {
		regions[i] = rg
	}

	var gpuInfo any
	if size.GPUInfo != nil {
		gi := map[string]any{
			"count": int64(size.GPUInfo.Count),
			"model": size.GPUInfo.Model,
		}
		if size.GPUInfo.VRAM != nil {
			gi["vram"] = map[string]any{
				"amount": int64(size.GPUInfo.VRAM.Amount),
				"unit":   size.GPUInfo.VRAM.Unit,
			}
		}
		if len(size.GPUInfo.SupportedPartitionModes) > 0 {
			modes := make([]any, len(size.GPUInfo.SupportedPartitionModes))
			for i, m := range size.GPUInfo.SupportedPartitionModes {
				modes[i] = m
			}
			gi["supportedPartitionModes"] = modes
		}
		gpuInfo = gi
	}

	res, err := CreateResource(runtime, "digitalocean.size", map[string]*llx.RawData{
		"slug":         llx.StringData(size.Slug),
		"memory":       llx.IntData(int64(size.Memory)),
		"vcpus":        llx.IntData(int64(size.Vcpus)),
		"disk":         llx.IntData(int64(size.Disk)),
		"priceMonthly": llx.FloatData(size.PriceMonthly),
		"priceHourly":  llx.FloatData(size.PriceHourly),
		"transfer":     llx.FloatData(size.Transfer),
		"available":    llx.BoolData(size.Available),
		"regions":      llx.ArrayData(regions, "\x02"),
		"description":  llx.StringData(size.Description),
		"gpuInfo":      llx.DictData(gpuInfo),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanSize), nil
}

// sizes lists the DigitalOcean droplet size catalog — the hardware tiers a
// droplet or Kubernetes worker node can run on.
func (r *mqlDigitalocean) sizes() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	sizes, err := paginate(context.Background(), client.Sizes.List)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(sizes))
	for _, s := range sizes {
		res, err := newMqlDigitaloceanSize(r.MqlRuntime, s)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanSize) id() (string, error) {
	return "digitalocean.size/" + r.Slug.Data, nil
}

// sizeBySlug resolves a size by its slug from the account-wide catalog,
// caching the index so repeated node-pool lookups do not re-list the catalog.
func (r *mqlDigitalocean) sizeBySlug(slug string) (*mqlDigitaloceanSize, error) {
	r.sizeIndexOnce.Do(func() {
		sizes := r.GetSizes()
		if sizes.Error != nil {
			r.sizeIndexErr = sizes.Error
			return
		}
		idx := make(map[string]*mqlDigitaloceanSize, len(sizes.Data))
		for _, s := range sizes.Data {
			ms := s.(*mqlDigitaloceanSize)
			idx[ms.Slug.Data] = ms
		}
		r.sizeIndex = idx
	})
	if r.sizeIndexErr != nil {
		return nil, r.sizeIndexErr
	}
	return r.sizeIndex[slug], nil
}

// initDigitaloceanSize resolves a size requested by slug (for example
// digitalocean.size(slug: "s-1vcpu-1gb")) against the catalog. Fully-populated
// args from the sizes() collection take the fast path.
func initDigitaloceanSize(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	slugRaw, ok := args["slug"]
	if !ok {
		return nil, nil, errors.New("digitalocean.size requires a slug")
	}
	slug, ok := slugRaw.Value.(string)
	if !ok || slug == "" {
		return nil, nil, errors.New("digitalocean.size slug must be a non-empty string")
	}

	parent, err := parentDigitalocean(runtime)
	if err != nil {
		return nil, nil, err
	}
	size, err := parent.sizeBySlug(slug)
	if err != nil {
		return nil, nil, err
	}
	if size == nil {
		return nil, nil, fmt.Errorf("digitalocean.size with slug %q not found", slug)
	}
	return nil, size, nil
}

// dropletSize resolves the droplet's hardware tier to a typed digitalocean.size.
// The godo size is embedded in the droplet list response, so no refetch happens.
func (r *mqlDigitaloceanDroplet) dropletSize() (*mqlDigitaloceanSize, error) {
	if r.size == nil || r.size.Slug == "" {
		r.DropletSize.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlDigitaloceanSize(r.MqlRuntime, *r.size)
}

// dropletSize resolves the node pool's droplet hardware tier to a typed
// digitalocean.size. The pool carries only the size slug, so it is resolved
// against the account-wide catalog (cached after the first lookup).
func (r *mqlDigitaloceanKubernetesNodePool) dropletSize() (*mqlDigitaloceanSize, error) {
	if r.Size.Data == "" {
		r.DropletSize.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	size, err := parent.sizeBySlug(r.Size.Data)
	if err != nil {
		return nil, err
	}
	if size == nil {
		r.DropletSize.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return size, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package recording

import (
	"context"
	"errors"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

var _ llx.Recording = &Upstream{}

type Upstream struct {
	ctx            context.Context
	service        ResourcesExplorer
	asset          *inventory.Asset
	lock           sync.Mutex
	resourcesCache map[string]resourceCache
}

func NewUpstreamRecording(ctx context.Context, service ResourcesExplorer, assetMrn string) (*Upstream, error) {
	recording := &Upstream{
		ctx:     ctx,
		service: service,
		asset: &inventory.Asset{
			Mrn: assetMrn,
		},
		resourcesCache: map[string]resourceCache{},
	}

	raw, ok := recording.GetResource(llx.AssetRecordingLookup{Mrn: assetMrn}, "asset", "")
	if !ok {
		return nil, errors.New("failed to get asset info for " + assetMrn)
	}

	asset := rawdata2assetinfo(raw)
	asset.Mrn = assetMrn
	recording.asset = asset

	return recording, nil
}

func rawdata2assetinfo(fields map[string]*llx.RawData) *inventory.Asset {
	ids := rawValue[[]any](fields["ids"])
	sids := make([]string, len(ids))
	for i := range ids {
		sids[i] = ids[i].(string)
	}

	return &inventory.Asset{
		Name:        rawValue[string](fields["name"]),
		PlatformIds: sids,
		Platform: &inventory.Platform{
			Version: rawValue[string](fields["version"]),
			Arch:    rawValue[string](fields["arch"]),
			Title:   rawValue[string](fields["title"]),
			Runtime: rawValue[string](fields["runtime"]),
			Kind:    rawValue[string](fields["kind"]),
			Name:    rawValue[string](fields["platform"]),
			Build:   rawValue[string](fields["build"]),
		},
	}
}

func rawValue[T any](field *llx.RawData) T {
	var empty T
	if field == nil || field.Value == nil {
		return empty
	}
	res, ok := field.Value.(T)
	if !ok {
		return empty
	}
	return res
}

type resourceCache struct {
	fields map[string]*llx.RawData
	err    error
}

func (n *Upstream) Asset() *inventory.Asset {
	return n.asset
}

func (n *Upstream) EnsureAsset(asset *inventory.Asset, provider string, connectionID uint32, conf *inventory.Config) {
	// We don't sync assets with upstream, we only read at this time
}

func (n *Upstream) AddData(req llx.AddDataReq) {
	// We don't store asset data this way, we use StoreResults for now.
	// We will expand this method to handle more ad-hoc data methods in the
	// future. (e.g. for shell)
}

func (n *Upstream) GetData(lookup llx.AssetRecordingLookup, resource string, id string, field string) (*llx.RawData, bool) {
	fields, ok := n.GetResource(lookup, resource, id)
	if !ok || len(fields) == 0 {
		return nil, false
	}
	res, ok := fields[field]
	return res, ok
}

func (n *Upstream) GetResource(_ llx.AssetRecordingLookup, resource string, id string) (map[string]*llx.RawData, bool) {
	n.lock.Lock()
	defer n.lock.Unlock()

	cacheID := resource + keySep + id
	if exist, ok := n.resourcesCache[cacheID]; ok {
		return exist.fields, true
	}

	res, err := n.service.GetResourcesData(n.ctx, &EntityResourcesReq{
		EntityMrn: n.asset.Mrn,
		Resources: []*ResourceDataReq{{
			Resource: resource,
			Id:       id,
		}},
	})
	if err != nil {
		n.resourcesCache[cacheID] = resourceCache{err: err}
		return nil, false
	}

	if len(res.Resources) == 0 {
		n.resourcesCache[cacheID] = resourceCache{}
		return nil, false
	} else if len(res.Resources) != 1 {
		log.Warn().Str("asset", n.asset.Mrn).Str("resource", resource).Msg("too many resources returned for asset request")
	}

	fields := make(map[string]*llx.RawData, len(res.Resources[0].Fields))
	for k, v := range res.Resources[0].Fields {
		fields[k] = v.RawData()
	}
	n.resourcesCache[cacheID] = resourceCache{fields: fields}

	return fields, true
}

func (n *Upstream) GetAssetData(assetMrn string) (map[string]*llx.ResourceRecording, bool) {
	// We currently don't dump entire upstream asset data.
	return nil, false
}

func (n *Upstream) GetAssetRecordings() []llx.Recording {
	return nil
}

func (n *Upstream) GetAssets() []*inventory.Asset {
	return []*inventory.Asset{n.asset}
}

func (n *Upstream) Save() error {
	// No need to save anything with upstream recordings for now. We will make
	// use of this once we use AddData with upstream.
	return nil
}

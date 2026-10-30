// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package recording

import (
	"fmt"
	"maps"
	"sort"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func NewAssetRecording(asset *inventory.Asset) *Asset {
	return &Asset{
		Asset:       asset,
		connections: map[string]*connection{},
		resources:   map[string]*Resource{},
		IdsLookup:   map[string]string{},
	}
}

type Asset struct {
	Asset       *inventory.Asset `json:"asset"`
	Connections []connection     `json:"connections"`
	Resources   []Resource       `json:"resources"`
	// A lookup of requested resources to their actual ID.
	// This is required to resolve cases where a resource is requested by one ID (usually empty ID)
	// and the connection responds with another (resolved) ID. This mapping allows us to mimic
	// the same behavior when reading/replaying recordings.
	//
	// The key is the resource name + request ID, e.g.
	// "aws.ec2.instance\x1e123": "i-1234567890abcdef0"
	// "azure.subscription\x1e1": "/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	IdsLookup map[string]string `json:"idsLookup,omitempty"`

	connections map[string]*connection `json:"-"`
	resources   map[string]*Resource   `json:"-"`

	// mu guards concurrent access to the connections, resources, and IdsLookup
	// maps. During a parallel scan multiple assets share one recording: one
	// asset closing triggers Save (which finalizes every asset by iterating its
	// resources map) while other assets are still fetching data via AddData
	// (which writes those maps). Go maps are not safe for concurrent use.
	mu sync.Mutex `json:"-"`
}

type connection struct {
	Url        string `json:"url"`
	ProviderID string `json:"provider"`
	Connector  string `json:"connector"`
	Version    string `json:"version"`
	Id         uint32 `json:"id"`
}

type Resource struct {
	Resource string
	ID       string
	Fields   map[string]*llx.RawData
}

func (asset *Asset) finalize() {
	asset.mu.Lock()
	defer asset.mu.Unlock()

	asset.Resources = make([]Resource, len(asset.resources))
	asset.Connections = make([]connection, len(asset.connections))

	i := 0
	for _, v := range asset.resources {
		asset.Resources[i] = *v
		i++
	}

	sort.Slice(asset.Resources, func(i, j int) bool {
		a := asset.Resources[i]
		b := asset.Resources[j]
		if a.Resource == b.Resource {
			return a.ID < b.ID
		}
		return a.Resource < b.Resource
	})

	i = 0
	for _, v := range asset.connections {
		asset.Connections[i] = *v
		i++
	}
}

func (asset *Asset) GetResource(name string, id string) (*Resource, bool) {
	asset.mu.Lock()
	defer asset.mu.Unlock()

	r, ok := asset.resources[name+keySep+id]
	if !ok {
		return nil, false
	}

	// Return a snapshot: callers iterate the Fields map after we release the
	// lock, while AddData may still be inserting into the live map.
	clone := &Resource{
		Resource: r.Resource,
		ID:       r.ID,
		Fields:   make(map[string]*llx.RawData, len(r.Fields)),
	}
	maps.Copy(clone.Fields, r.Fields)
	return clone, true
}

func (asset *Asset) RefreshCache() {
	asset.mu.Lock()
	defer asset.mu.Unlock()

	asset.resources = make(map[string]*Resource, len(asset.Resources))
	asset.connections = make(map[string]*connection, len(asset.Connections))

	for _, resource := range asset.Resources {
		asset.resources[resource.Resource+keySep+resource.ID] = &resource
	}

	for _, conn := range asset.Connections {
		asset.connections[fmt.Sprintf("%d", conn.Id)] = &conn
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"sync"

	"go.mondoo.com/mql/llx"
)

// fieldCache holds every field answer a runtime received from its providers,
// so a field read by many queries crosses the plugin boundary once. The
// executor's own cache lives only as long as one query; without this one,
// every query that walks a large list asks the provider again for each
// element's fields.
//
// Providers already cache their field values, so answering from here returns
// what the provider would have returned; it only saves the round-trip. It is
// independent of the recording, which captures data for upload or --record.
//
// A nil *fieldCache is valid: it never hits and drops every write.
type fieldCache struct {
	mu   sync.RWMutex
	data map[fieldCacheKey]*llx.RawData
}

type fieldCacheKey struct {
	connection uint32
	resource   string
	id         string
	field      string
}

func newFieldCache() *fieldCache {
	return &fieldCache{data: map[fieldCacheKey]*llx.RawData{}}
}

func (c *fieldCache) get(connection uint32, resource string, id string, field string) (*llx.RawData, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	raw, ok := c.data[fieldCacheKey{connection: connection, resource: resource, id: id, field: field}]
	return raw, ok
}

func (c *fieldCache) set(connection uint32, resource string, id string, field string, raw *llx.RawData) {
	if c == nil || raw == nil {
		return
	}
	c.mu.Lock()
	c.data[fieldCacheKey{connection: connection, resource: resource, id: id, field: field}] = raw
	c.mu.Unlock()
}

// clear drops every entry, so a closed runtime releases what it held.
func (c *fieldCache) clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	clear(c.data)
	c.mu.Unlock()
}

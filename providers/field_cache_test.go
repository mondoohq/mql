// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
)

// Synthetic: runtimes built as struct literals carry no cache; it must behave
// as an empty one, not panic.
func TestFieldCache_Nil(t *testing.T) {
	var c *fieldCache
	c.set(1, "r", "id", "f", &llx.RawData{Value: "v"})
	_, ok := c.get(1, "r", "id", "f")
	assert.False(t, ok)
	c.clear()
}

// Synthetic: every part of the key separates entries, so two connections (or
// two resources sharing an id) never answer for each other.
func TestFieldCache_Key(t *testing.T) {
	c := newFieldCache()
	c.set(1, "r", "id", "f", &llx.RawData{Value: "v"})

	raw, ok := c.get(1, "r", "id", "f")
	assert.True(t, ok)
	assert.Equal(t, "v", raw.Value)

	for _, miss := range []struct {
		conn             uint32
		resource, id, fd string
	}{
		{2, "r", "id", "f"},
		{1, "other", "id", "f"},
		{1, "r", "other", "f"},
		{1, "r", "id", "other"},
	} {
		_, ok := c.get(miss.conn, miss.resource, miss.id, miss.fd)
		assert.False(t, ok, "%+v", miss)
	}

	c.set(1, "r", "id", "nil-answer", nil)
	_, ok = c.get(1, "r", "id", "nil-answer")
	assert.False(t, ok, "a nil answer is not a cached answer")

	c.clear()
	_, ok = c.get(1, "r", "id", "f")
	assert.False(t, ok, "clear drops every entry")
}

// Synthetic: dropping a resource forgets all of its fields and nothing else.
func TestFieldCache_DropResource(t *testing.T) {
	c := newFieldCache()
	c.set(1, "r", "id", "f", &llx.RawData{Value: "v"})
	c.set(1, "r", "id", "g", &llx.RawData{Value: "w"})
	c.set(1, "r", "other", "f", &llx.RawData{Value: "x"})
	c.set(2, "r", "id", "f", &llx.RawData{Value: "y"})

	c.dropResource(1, "r", "id")

	_, ok := c.get(1, "r", "id", "f")
	assert.False(t, ok)
	_, ok = c.get(1, "r", "id", "g")
	assert.False(t, ok)
	raw, ok := c.get(1, "r", "other", "f")
	assert.True(t, ok)
	assert.Equal(t, "x", raw.Value)
	raw, ok = c.get(2, "r", "id", "f")
	assert.True(t, ok)
	assert.Equal(t, "y", raw.Value)

	var nilCache *fieldCache
	nilCache.dropResource(1, "r", "id")
}

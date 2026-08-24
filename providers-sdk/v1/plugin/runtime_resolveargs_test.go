// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// fakeResource is a minimal plugin.Resource for the cache.
type fakeResource struct {
	id   string
	name string
}

func (f *fakeResource) MqlID() string   { return f.id }
func (f *fakeResource) MqlName() string { return f.name }

// mapResources is an in-memory Resources[Resource].
type mapResources map[string]Resource

func (m mapResources) Get(key string) (Resource, bool) {
	v, ok := m[key]
	return v, ok
}
func (m mapResources) Set(key string, value Resource) { m[key] = value }

func resourceArg(name, id string) *llx.RawData {
	return &llx.RawData{
		Type:  types.Resource(name),
		Value: &llx.MockResource{Name: name, ID: id},
	}
}

// A reference present in the cache is swapped for the real resource, which is
// what the generated resource-typed setters require.
func TestResolveResourceArgsResolvesACachedReference(t *testing.T) {
	want := &fakeResource{id: "/etc/passwd", name: "file"}
	runtime := &Runtime{Resources: mapResources{"file\x00/etc/passwd": want}}

	args := map[string]*llx.RawData{"file": resourceArg("file", "/etc/passwd")}
	ResolveResourceArgs(args, runtime)

	require.Equal(t, want, args["file"].Value, "the cached resource replaces the MockResource")
}

// A reference the cache does not hold is left alone rather than dropped or
// replaced with a nil resource. The downstream SetData is what reports it.
func TestResolveResourceArgsLeavesAnUncachedReference(t *testing.T) {
	runtime := &Runtime{Resources: mapResources{}}

	args := map[string]*llx.RawData{"file": resourceArg("file", "/etc/shadow")}
	ResolveResourceArgs(args, runtime)

	mock, ok := args["file"].Value.(*llx.MockResource)
	require.True(t, ok, "an unresolvable reference keeps its MockResource")
	assert.Equal(t, "/etc/shadow", mock.ID)
}

// A miss on one reference must not stop the others from resolving.
func TestResolveResourceArgsResolvesAroundAMiss(t *testing.T) {
	hit := &fakeResource{id: "/etc/passwd", name: "file"}
	runtime := &Runtime{Resources: mapResources{"file\x00/etc/passwd": hit}}

	args := map[string]*llx.RawData{
		"present": resourceArg("file", "/etc/passwd"),
		"missing": resourceArg("file", "/etc/shadow"),
	}
	ResolveResourceArgs(args, runtime)

	assert.Equal(t, hit, args["present"].Value)
	_, stillMock := args["missing"].Value.(*llx.MockResource)
	assert.True(t, stillMock)
}

// A nil runtime, a nil arg, and a non-resource arg are all no-ops.
func TestResolveResourceArgsIgnoresWhatItCannotResolve(t *testing.T) {
	str := llx.StringData("plain")
	args := map[string]*llx.RawData{"s": str, "nil": nil}

	ResolveResourceArgs(args, nil)
	assert.Equal(t, str, args["s"])

	ResolveResourceArgs(args, &Runtime{Resources: mapResources{}})
	assert.Equal(t, str, args["s"], "a non-resource arg is untouched")
}

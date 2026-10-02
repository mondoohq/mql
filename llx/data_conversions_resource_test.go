// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/types"
)

// nilProneResource is shaped like a generated MQL resource: MqlID reads a
// field through a pointer receiver, so calling it on a nil pointer panics.
type nilProneResource struct {
	id string
}

func (r *nilProneResource) MqlName() string { return "test.resource" }
func (r *nilProneResource) MqlID() string   { return r.id }

// A provider that resolves a resource field to no resource hands back a nil
// pointer of the resource's own type. Stored in the Resource interface that
// pointer is not == nil, so the interface is non-nil and the conversion used
// to call MqlID on it and take the process down with a nil dereference -- a
// panic in a provider fails the whole scan, not just the field.
//
// raw2primitive already answers NilPrimitive for a value that is nil, and a
// typed nil resource is the same absence wearing an interface.
func TestResourceConversionWithTypedNilResource(t *testing.T) {
	var missing *nilProneResource

	raw := &RawData{
		Type:  types.Resource("test.resource"),
		Value: missing,
	}

	var res *Result
	require.NotPanics(t, func() { res = raw.Result() }, "a nil resource must not panic")
	require.NotNil(t, res)
	assert.Empty(t, res.Error)
	assert.Equal(t, string(types.Nil), res.Data.Type,
		"a nil resource serializes as nil, the way any other nil value does")
}

// A resource that is actually there still serializes to its id.
func TestResourceConversionWithResource(t *testing.T) {
	raw := &RawData{
		Type:  types.Resource("test.resource"),
		Value: &nilProneResource{id: "some-id"},
	}

	res := raw.Result()
	require.NotNil(t, res)
	assert.Empty(t, res.Error)
	assert.Equal(t, "some-id", string(res.Data.Value))
	assert.Equal(t, string(types.Resource("test.resource")), res.Data.Type)
}

// A value that is not a resource at all is still a conversion error rather
// than a nil.
func TestResourceConversionWithNonResource(t *testing.T) {
	raw := &RawData{
		Type:  types.Resource("test.resource"),
		Value: "not a resource",
	}

	res := raw.Result()
	require.NotNil(t, res)
	assert.NotEmpty(t, res.Error, "a non-resource value must not pass as one")
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func TestVersion_Conversions(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		sv := llx.StringPrimitive("1.2.3")
		sv.Type = string(types.Version)
		rd := sv.RawData()
		require.NoError(t, rd.Error, "no error converting version to raw data")
		require.Equal(t, "1.2.3", rd.Value, "version to raw data is the same")
	})
}

func TestResultNotPanicsOnBareTypes(t *testing.T) {
	t.Run("bare ArrayLike with elements", func(t *testing.T) {
		rd := &llx.RawData{Type: types.ArrayLike, Value: []any{"hello"}}
		require.NotPanics(t, func() { rd.Result() })
	})

	t.Run("bare ArrayLike empty", func(t *testing.T) {
		rd := &llx.RawData{Type: types.ArrayLike, Value: []any{}}
		require.NotPanics(t, func() { rd.Result() })
	})

	t.Run("bare MapLike with entries", func(t *testing.T) {
		rd := &llx.RawData{Type: types.MapLike, Value: map[string]any{"k": "v"}}
		require.NotPanics(t, func() { rd.Result() })
	})

	t.Run("Primitive round-trip with bare ArrayLike", func(t *testing.T) {
		p := &llx.Primitive{
			Type:  string(types.ArrayLike),
			Array: []*llx.Primitive{llx.StringPrimitive("hello")},
		}
		require.NotPanics(t, func() {
			raw := p.RawData()
			raw.Result()
		})
	})
}

func TestResultRawConversions(t *testing.T) {
	tests := []struct {
		raw *llx.RawData
	}{
		{raw: llx.VersionData("1.2.3")},
		{raw: llx.IPData(llx.ParseIP("192.168.0.1/27"))},
	}
	for i := range tests {
		cur := tests[i]
		t.Run(cur.raw.String(), func(t *testing.T) {
			require.NotContains(t, cur.raw.String(), llx.UNKNOWN_VALUE, fmt.Sprintf("implement String() for %#v", cur.raw))

			res := cur.raw.Result()
			require.NotNil(t, res)
			raw := res.RawData()
			require.NotNil(t, raw)
			assert.Equal(t, cur.raw.Type, raw.Type)
			assert.Equal(t, cur.raw.Value, raw.Value)
			res2 := raw.Result()
			require.NotNil(t, res2)
			assert.Equal(t, res, res2)
		})
	}
}

// TestEmptyTypePrimitiveConvertsToNil ensures a malformed (no-type) primitive is
// coerced to a Nil value instead of returning an error (loud-and-narrow: it is
// also logged). A no-type primitive only appears via an upstream bug (compiler
// value-field binding, or an unset provider field); erroring here used to abort
// conversion of the whole surrounding array/map (see
// TestEmptyTypePrimitiveKeepsCollection).
func TestEmptyTypePrimitiveConvertsToNil(t *testing.T) {
	rd := (&llx.Primitive{}).RawData()
	require.NoError(t, rd.Error)
	assert.Equal(t, types.Nil, rd.Type)
	assert.Nil(t, rd.Value)
}

// TestNilPrimitiveConvertsToNil is a regression test for a nil-receiver panic.
// providers.Runtime watchAndUpdate calls data.Data.RawData() unconditionally,
// and a provider that answers with neither data nor an error leaves data.Data
// nil — so RawData must tolerate a nil *Primitive. Probing the husk with the
// bare fields (p.Value) instead of the nil-safe generated getters crashes the
// whole scan here, because the executor runs blocks in goroutines.
func TestNilPrimitiveConvertsToNil(t *testing.T) {
	var p *llx.Primitive
	require.NotPanics(t, func() {
		rd := p.RawData()
		require.NoError(t, rd.Error)
		assert.Equal(t, types.Nil, rd.Type)
		assert.Nil(t, rd.Value)
	})
}

// TestErroredUntypedRawDataRoundTrip: an errored RawData without type info
// (e.g. a provider error wrapped as a bare &RawData{Error: ...} at the plugin
// boundary) serializes with a typeless data primitive next to the error;
// reading it back must yield a clean typed null carrying the error.
func TestErroredUntypedRawDataRoundTrip(t *testing.T) {
	rd := &llx.RawData{Error: errors.New("field failed")}
	res := rd.Result()
	require.NotNil(t, res)
	assert.Equal(t, "field failed", res.Error)
	require.NotNil(t, res.Data)
	assert.Equal(t, "", res.Data.Type)

	back := res.RawData()
	assert.Equal(t, types.Nil, back.Type)
	assert.EqualError(t, back.Error, "field failed")
}

// An errored RawData that does carry type info must keep it.
func TestErroredTypedRawDataResultKeepsType(t *testing.T) {
	rd := &llx.RawData{Type: types.Bool, Error: errors.New("field failed")}
	res := rd.Result()
	require.NotNil(t, res)
	assert.Equal(t, string(types.Bool), res.Data.Type)
	assert.Equal(t, "field failed", res.Error)
}

// TestBlockWithErroredFieldReadsBackAsNull mirrors a `ports { ... process }`
// block where one field errored: block2result keeps only Result().Data for
// nested fields (the error is carried by the query score instead), leaving a
// typeless empty husk behind. Reading the block back must coerce the husk to
// a clean null and must not error or drop the surrounding block.
func TestBlockWithErroredFieldReadsBackAsNull(t *testing.T) {
	blk := &llx.RawData{
		Type: types.Block,
		Value: map[string]any{
			"ok":  llx.StringData("fine"),
			"bad": &llx.RawData{Error: errors.New("no process for this port")},
		},
	}
	res := blk.Result()
	require.NotNil(t, res)
	require.NotNil(t, res.Data)
	m := res.Data.Map
	require.NotNil(t, m)
	require.Contains(t, m, "bad")
	assert.Equal(t, "", m["bad"].Type,
		"the nested errored field serializes as a typeless husk (Primitive cannot carry the error)")
	assert.Equal(t, string(types.String), m["ok"].Type)

	back := res.RawData()
	require.NoError(t, back.Error)
	backMap, ok := back.Value.(map[string]any)
	require.True(t, ok)
	badBack, ok := backMap["bad"].(*llx.RawData)
	require.True(t, ok)
	assert.Equal(t, types.Nil, badBack.Type)
	assert.Nil(t, badBack.Value)
}

// TestEmptyTypePrimitiveKeepsCollection is a regression test for empty
// assessments: a single untyped nested field (e.g. an unset sub-field of a
// resource's @context block) must not discard the entire surrounding array.
// Previously RawData() errored on the untyped field and primitive2array /
// primitive2rawdataMapV2 propagated that error, returning an empty slice — so
// `list.all(...)` over @context resources rendered no failing resources at all.
func TestEmptyTypePrimitiveKeepsCollection(t *testing.T) {
	// A resource block whose nested context block carries an unset (untyped) field.
	contextBlock := &llx.Primitive{
		Type: string(types.Block),
		Map: map[string]*llx.Primitive{
			"path":  llx.StringPrimitive("main.tf"),
			"range": {}, // untyped/null sub-field — the trigger
		},
	}
	element := &llx.Primitive{
		Type: string(types.Block),
		Map: map[string]*llx.Primitive{
			"name":    llx.StringPrimitive("resource"),
			"context": contextBlock,
		},
	}
	arr := llx.ArrayPrimitive([]*llx.Primitive{element, element, element}, types.Block)

	rd := arr.RawData()
	require.NoError(t, rd.Error)
	got, ok := rd.Value.([]any)
	require.True(t, ok, "expected the array to survive conversion")
	assert.Len(t, got, 3, "the whole collection must be preserved, not emptied")
}

// TestMalformedElementKeepsCollection covers the converter-hardening half of
// loud-and-narrow: during late value extraction, an element whose RawData()
// genuinely errors (here an unregistered type) must not discard the surrounding
// array or map. The bad element is nulled out (and logged); its siblings
// survive. types.Any has no primitive converter, so it errors at conversion.
func TestMalformedElementKeepsCollection(t *testing.T) {
	bad := &llx.Primitive{Type: string(types.Any), Value: []byte{0x1}}
	// sanity: the element really does error on its own
	require.Error(t, bad.RawData().Error)

	t.Run("array", func(t *testing.T) {
		arr := llx.ArrayPrimitive([]*llx.Primitive{
			llx.StringPrimitive("ok"), bad, llx.StringPrimitive("also-ok"),
		}, types.String)

		rd := arr.RawData()
		require.NoError(t, rd.Error, "one bad element must not error the array")
		got, ok := rd.Value.([]any)
		require.True(t, ok)
		require.Len(t, got, 3, "the whole collection must be preserved")
		assert.Equal(t, "ok", got[0])
		assert.Nil(t, got[1], "the malformed element is nulled out")
		assert.Equal(t, "also-ok", got[2])
	})

	t.Run("map", func(t *testing.T) {
		m := &llx.Primitive{
			Type: string(types.MapLike),
			Map: map[string]*llx.Primitive{
				"good": llx.StringPrimitive("ok"),
				"bad":  bad,
			},
		}

		rd := m.RawData()
		require.NoError(t, rd.Error, "one bad element must not error the map")
		got, ok := rd.Value.(map[string]any)
		require.True(t, ok)
		require.Len(t, got, 2, "the whole map must be preserved")
		assert.Equal(t, "ok", got["good"])
		assert.Nil(t, got["bad"], "the malformed element is nulled out")
	})
}

// TestAssetValueRoundTrip proves the native `asset` primitive payload survives
// the RawData -> Primitive -> RawData (gRPC-boundary) encoding, and that the
// root the type is parameterized with survives with it: a value that arrives as
// a bare `asset` cannot be chained off, so dropping the root anywhere along this
// path would silently disable cross-asset traversal for every provider-supplied
// value. See ADR 030 and ADR 031.
func TestAssetValueRoundTrip(t *testing.T) {
	t.Run("populated", func(t *testing.T) {
		rd := llx.AssetData(&llx.AssetValue{
			ResourceType: "claude.code.mcpServer",
			ResourceId:   "claude.code.mcpServer/context7",
		}, "mcp")
		assert.Equal(t, types.Asset("mcp"), rd.Type)

		prim := rd.Result().Data
		require.Equal(t, string(types.Asset("mcp")), prim.Type)

		back := prim.RawData()
		require.NoError(t, back.Error)
		assert.Equal(t, types.Asset("mcp"), back.Type)
		assert.Equal(t, "mcp", back.Type.AssetRootName())
		av, ok := back.Value.(*llx.AssetValue)
		require.True(t, ok)
		require.NotNil(t, av)
		assert.Equal(t, "claude.code.mcpServer", av.ResourceType)
		assert.Equal(t, "claude.code.mcpServer/context7", av.ResourceId)
	})

	t.Run("nil value keeps its root", func(t *testing.T) {
		prim := llx.AssetData(nil, "mcp").Result().Data
		require.Equal(t, string(types.Asset("mcp")), prim.Type)
		back := prim.RawData()
		require.NoError(t, back.Error)
		assert.Equal(t, types.Asset("mcp"), back.Type)
		av, _ := back.Value.(*llx.AssetValue)
		assert.Nil(t, av)
	})

	t.Run("no root", func(t *testing.T) {
		rd := llx.AssetData(&llx.AssetValue{ResourceType: "muser", ResourceId: "u1"}, "")
		assert.Equal(t, types.AssetLike, rd.Type)
		back := rd.Result().Data.RawData()
		require.NoError(t, back.Error)
		assert.Equal(t, "", back.Type.AssetRootName())
	})
}

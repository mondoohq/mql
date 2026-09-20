// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/types"
)

func newTestBlockExecutor() *blockExecutor {
	return &blockExecutor{
		ctx: &MQLExecutorV2{code: &CodeV2{}},
	}
}

func newStringKeyChunk() *Chunk {
	return &Chunk{
		Function: &Function{
			Args: []*Primitive{{Value: []byte("key"), Type: string(types.String)}},
		},
	}
}

func runIndexHandler(t *testing.T, bind *RawData, operator string) (*RawData, uint64, error) {
	t.Helper()

	handler, err := BuiltinFunctionV2(bind.Type, operator)
	require.NoError(t, err)

	return handler.f(newTestBlockExecutor(), bind, newStringKeyChunk(), 0)
}

// A null map receiver must not error when the all/any/none/one assertion
// builtins are called on it; it propagates as a null bool so the check fails
// cleanly instead of crashing the scan. Mirrors the array variants.
func TestMapAssertions_NullReceiver(t *testing.T) {
	cases := []struct {
		name string
		fn   func(*blockExecutor, *RawData, *Chunk, uint64) (*RawData, uint64, error)
	}{
		{"all", mapAll},
		{"any", mapAny},
		{"none", mapNone},
		{"one", mapOne},
	}
	for _, c := range cases {
		t.Run(c.name+" on null map returns null bool, no error", func(t *testing.T) {
			res, ref, err := c.fn(nil, &RawData{Type: types.Map(types.String, types.String), Value: nil}, nil, 0)
			require.NoError(t, err)
			require.Equal(t, uint64(0), ref)
			require.NotNil(t, res)
			require.Equal(t, types.Bool, res.Type)
			require.Nil(t, res.Value)
			require.NoError(t, res.Error)
		})

		t.Run(c.name+" preserves a genuine upstream error", func(t *testing.T) {
			boom := errors.New("upstream boom")
			res, _, err := c.fn(nil, &RawData{Type: types.Map(types.String, types.String), Value: nil, Error: boom}, nil, 0)
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, boom, res.Error)
		})
	}
}

// The dict assertion variants behave the same as the array/map ones on a null
// receiver: a graceful null bool, with any genuine upstream error preserved.
func TestDictAssertions_NullReceiver(t *testing.T) {
	cases := []struct {
		name string
		fn   func(*blockExecutor, *RawData, *Chunk, uint64) (*RawData, uint64, error)
	}{
		{"all", dictAllV2},
		{"any", dictAnyV2},
		{"none", dictNoneV2},
		{"one", dictOneV2},
	}
	for _, c := range cases {
		t.Run(c.name+" on null dict returns null bool, no error", func(t *testing.T) {
			res, ref, err := c.fn(nil, &RawData{Type: types.Dict, Value: nil}, nil, 0)
			require.NoError(t, err)
			require.Equal(t, uint64(0), ref)
			require.NotNil(t, res)
			require.Equal(t, types.Bool, res.Type)
			require.Nil(t, res.Value)
			require.NoError(t, res.Error)
		})

		t.Run(c.name+" preserves a genuine upstream error", func(t *testing.T) {
			boom := errors.New("upstream boom")
			res, _, err := c.fn(nil, &RawData{Type: types.Dict, Value: nil, Error: boom}, nil, 0)
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, boom, res.Error)
		})
	}
}

func TestDictGetIndex_NilValue(t *testing.T) {
	for _, operator := range []string{"[]", "[]?"} {
		t.Run(operator+" returns typed null when parent dict is nil", func(t *testing.T) {
			bind := &RawData{Type: types.Dict, Value: nil}

			res, ref, err := runIndexHandler(t, bind, operator)
			require.NoError(t, err)
			assert.Equal(t, uint64(0), ref)
			assert.Equal(t, types.Dict, res.Type)
			assert.Nil(t, res.Value, "null dict access should propagate null, not error")
		})
	}
}

func newArrayArgChunk(elems []*Primitive, elemType types.Type) *Chunk {
	return &Chunk{
		Function: &Function{
			Args: []*Primitive{ArrayPrimitive(elems, elemType)},
		},
	}
}

func runDictInHandler(t *testing.T, bind *RawData, chunk *Chunk, operator string) (*RawData, uint64, error) {
	t.Helper()

	handler, err := BuiltinFunctionV2(bind.Type, operator)
	require.NoError(t, err)

	return handler.f(newTestBlockExecutor(), bind, chunk, 0)
}

func TestDictIn_ScalarValues(t *testing.T) {
	intArr := newArrayArgChunk([]*Primitive{IntPrimitive(1), IntPrimitive(2)}, types.Int)
	strArr := newArrayArgChunk([]*Primitive{StringPrimitive("1"), StringPrimitive("2")}, types.String)

	cases := []struct {
		name  string
		bind  any
		chunk *Chunk
		op    string
		want  *RawData
	}{
		// CIS-style: DWORD (int64) against numeric array — used to error
		{"int64 bind in int array match", int64(2), intArr, "in", BoolTrue},
		{"int64 bind in int array miss", int64(3), intArr, "in", BoolFalse},
		{"int64 bind notIn int array match", int64(2), intArr, "notIn", BoolFalse},
		{"int64 bind notIn int array miss", int64(3), intArr, "notIn", BoolTrue},

		// Cross-type: DWORD against string array (matches the literal CIS check shape)
		{"int64 bind in string array match", int64(2), strArr, "in", BoolTrue},
		{"int64 bind in string array miss", int64(3), strArr, "in", BoolFalse},

		// Existing string-bind path still works through the unified helper
		{"string bind in string array match", "1", strArr, "in", BoolTrue},
		{"string bind in string array miss", "9", strArr, "in", BoolFalse},

		// Bool bind
		{"bool bind in bool array",
			true,
			newArrayArgChunk([]*Primitive{BoolPrimitive(false), BoolPrimitive(true)}, types.Bool),
			"in", BoolTrue},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bind := &RawData{Type: types.Dict, Value: tc.bind}
			res, ref, err := runDictInHandler(t, bind, tc.chunk, tc.op)
			require.NoError(t, err)
			assert.Equal(t, uint64(0), ref)
			assert.Equal(t, tc.want, res)
		})
	}
}

func TestDictIn_NilBindAndArg(t *testing.T) {
	intArr := newArrayArgChunk([]*Primitive{IntPrimitive(1)}, types.Int)

	t.Run("nil dict bind", func(t *testing.T) {
		bind := &RawData{Type: types.Dict, Value: nil}
		res, _, err := runDictInHandler(t, bind, intArr, "in")
		require.NoError(t, err)
		assert.Equal(t, BoolFalse, res)
	})
}

func TestMapGetIndex_NilValue(t *testing.T) {
	for _, operator := range []string{"[]", "[]?"} {
		t.Run(operator+" returns typed null when parent map is nil", func(t *testing.T) {
			mapType := types.Map(types.String, types.String)
			bind := &RawData{Type: mapType, Value: nil}

			res, ref, err := runIndexHandler(t, bind, operator)
			require.NoError(t, err)
			assert.Equal(t, uint64(0), ref)
			assert.Equal(t, types.String, res.Type)
			assert.Nil(t, res.Value, "null map access should propagate null, not error")
		})
	}
}

// walkChain replays what a compiled dot chain does at runtime: a block of one
// `[]` chunk per segment, each binding to the one before, executed in order.
// The shape matters as much as the values - whether a link is the last one in
// the chain is exactly what dictWalk reads to decide if a key is missing.
func walkChain(t *testing.T, doc map[string]any, nullability Function_Nullability, segments ...string) (*RawData, error) {
	t.Helper()

	block := &Block{}
	for i, seg := range segments {
		block.Chunks = append(block.Chunks, &Chunk{
			Id: "[]",
			Function: &Function{
				Binding:     uint64(i), // the chunk before it; 0 for the first
				Args:        []*Primitive{StringPrimitive(seg)},
				Nullability: nullability,
			},
		})
	}
	e := &blockExecutor{block: block}

	// Mirrors how dictGetIndex actually calls in: a walk under way is consulted
	// before anything else, and otherwise only once the plain key has missed.
	bind := &RawData{Type: types.Dict, Value: doc}
	for i, seg := range segments {
		ref := uint64(i + 1)
		chunk := block.Chunks[i]

		walk := func() (*RawData, error, bool) {
			return dictWalk(e, bind, chunk, ref, seg, types.Dict)
		}

		if bind.dictPath != nil {
			res, err, handled := walk()
			if err != nil {
				return nil, err
			}
			if handled {
				bind = res
				continue
			}
		}

		m, ok := bind.Value.(map[string]any)
		if !ok {
			return &RawData{Type: types.Dict}, nil
		}
		if v, present := m[seg]; present {
			bind = &RawData{Type: types.Dict, Value: v}
			continue
		}

		res, err, handled := walk()
		if err != nil {
			return nil, err
		}
		if handled {
			bind = res
			continue
		}

		r, _, err := missingKey(chunk, seg, types.Dict)
		if err != nil {
			return nil, err
		}
		return r, nil
	}
	return bind, nil
}

func chainValue(t *testing.T, doc map[string]any, segments ...string) any {
	t.Helper()
	res, err := walkChain(t, doc, Function_NULLABILITY_UNSPECIFIED, segments...)
	require.NoError(t, err)
	return res.Value
}

// Modelled on /Library/Managed Preferences/<user>/complete.plist: settings keyed
// by preference domain, sibling domains where one is a prefix of another, and a
// domain whose own keys are dotted too.
func managedPrefsDoc() map[string]any {
	return map[string]any{
		"com.apple.security.firewall": map[string]any{
			"EnableFirewall": map[string]any{"value": true},
		},
		"com.apple.MCX": map[string]any{
			"dontAllowFDEDisable":                   map[string]any{"value": true},
			"com.apple.EnergySaver.desktop.ACPower": map[string]any{"value": "on"},
		},
		"com.apple.MCX.FileVault2": map[string]any{
			"Enable": map[string]any{"value": "On"},
		},
		"plain": map[string]any{"nested": map[string]any{"leaf": 7}},
	}
}

// Every profile-managed CIS macOS check read null here, because the chain walked
// a "com" that the document does not contain.
func TestDictWalk(t *testing.T) {
	doc := managedPrefsDoc()

	cases := []struct {
		name     string
		segments []string
		want     any
	}{
		{
			name:     "dotted domain then plain keys",
			segments: []string{"com", "apple", "security", "firewall", "EnableFirewall", "value"},
			want:     true,
		},
		{
			// "com.apple.MCX" matches first and holds no "FileVault2", so the
			// walk has to abandon it and come back for the longer sibling.
			name:     "backtracks past a shorter sibling domain",
			segments: []string{"com", "apple", "MCX", "FileVault2", "Enable", "value"},
			want:     "On",
		},
		{
			name:     "dotted key nested inside a dotted domain",
			segments: []string{"com", "apple", "MCX", "com", "apple", "EnergySaver", "desktop", "ACPower", "value"},
			want:     "on",
		},
		{
			name:     "undotted path resolves as it always did",
			segments: []string{"plain", "nested", "leaf"},
			want:     7,
		},
		{
			name:     "a setting the document does not carry stays absent",
			segments: []string{"com", "apple", "MCX", "DisableGuestAccount", "value"},
			want:     nil,
		},
		{
			name:     "no domain begins with this segment",
			segments: []string{"org", "example", "thing"},
			want:     nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, chainValue(t, doc, tc.segments...))
		})
	}
}

// Production reaches dictWalk only once a plain lookup has missed or a walk is
// already under way, and the cheap answer must stay cheap: nothing built, and
// the caller left to report the key exactly as it always did.
func TestDictWalk_MissingKeyAtTheEndOfAChainBuildsNothing(t *testing.T) {
	doc := map[string]any{"a": 1}
	bind := &RawData{Type: types.Dict, Value: doc}
	chunk := &Chunk{Id: "[]", Function: &Function{}}

	// e is nil, so nothing follows this link: the chain ends here.
	res, err, handled := dictWalk(nil, bind, chunk, 0, "NOPE", types.Dict)
	require.NoError(t, err)
	assert.False(t, handled, "a missing key with nothing after it has no walk to start")
	assert.Nil(t, res)

	allocs := testing.AllocsPerRun(200, func() {
		_, _, _ = dictWalk(nil, bind, chunk, 0, "NOPE", types.Dict)
	})
	assert.Zero(t, allocs, "and it must not build walk state on the way to that answer")
}

// A value the walk resolved carries the walk on only while another key lookup
// is waiting to read it. Otherwise `params.a.b` keeps an anchor into the whole
// document, and a block or a variable reading from it resolves sibling keys
// that `params["a.b"]` does not contain and that the value's own `keys` does not
// list - the same value answering differently depending on how it was reached.
func TestDictWalk_ResolvedValueDropsTheWalkWhenTheChainEnds(t *testing.T) {
	doc := map[string]any{
		"a.b":        map[string]any{"x": 1},
		"a.b.secret": "do not leak",
	}

	res, err := walkChain(t, doc, Function_NULLABILITY_UNSPECIFIED, "a", "b")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"x": 1}, res.Value)
	assert.Nil(t, res.dictPath, "the chain ended, so the value must not keep an anchor")
}

// The compiler never splits a key, so a dot inside one was written by the author
// and has to keep meaning the key spelled that way.
func TestDictWalk_ExplicitKeyIsNotAPath(t *testing.T) {
	doc := map[string]any{"a": map[string]any{"b": "nested"}}

	assert.Nil(t, chainValue(t, doc, "a.b"), `params["a.b"] must not walk into a -> b`)
	// ...while the same document reached one segment at a time still resolves.
	assert.Equal(t, "nested", chainValue(t, doc, "a", "b"))
}

// A literal dotted key must not shadow a nested path that already resolved,
// because the plain key is what the chain has always read first.
func TestDictWalk_NestedPathWinsOverLiteralKey(t *testing.T) {
	doc := map[string]any{
		"a.b": map[string]any{"c": 99},
		"a":   map[string]any{"b": map[string]any{"c": 1}},
	}
	assert.Equal(t, 1, chainValue(t, doc, "a", "b", "c"))
}

// Where the chain ends is what tells a missing key from a half-walked path, and
// strict mode is where the difference is visible (ADR 043). Kubernetes labels
// are the case that forces it: "app.kubernetes.io/name" continues the text of
// `labels.app`, so a walk that judged itself by the document's keys would treat
// a plainly missing "app" as unfinished business.
func TestDictWalk_StrictReportsAKeyTheChainEndsOn(t *testing.T) {
	labels := map[string]any{"app.kubernetes.io/name": "web"}

	_, err := walkChain(t, labels, Function_NULLABILITY_REQUIRED, "app")
	require.Error(t, err, "the chain ends on a key the document does not have")
	assert.ErrorIs(t, err, ErrStrict)

	// Mid-chain the same miss says nothing, because the path is what resolves.
	doc := managedPrefsDoc()
	res, err := walkChain(t, doc, Function_NULLABILITY_REQUIRED,
		"com", "apple", "security", "firewall", "EnableFirewall", "value")
	require.NoError(t, err)
	assert.Equal(t, true, res.Value)
}

// A key the chain ends on comes back as the plain null it always was, carrying
// no walk - so a RawData still compares equal to one produced before any of this
// existed.
func TestDictWalk_DeadEndCarriesNoWalk(t *testing.T) {
	doc := map[string]any{"app.kubernetes.io/name": "web", "other": 1}

	res, err := walkChain(t, doc, Function_NULLABILITY_UNSPECIFIED, "app")
	require.NoError(t, err)
	assert.Nil(t, res.Value)
	assert.Nil(t, res.dictPath, "a dead end must not leave walk state on the result")
}

// A document crafted so that every prefix of the path is a live branch makes the
// walk exponential, so the budget has to cut it off. The trade it makes is
// deliberate: past the ceiling the walk reports absence rather than running to
// completion, which is the right way to lose - a query that reads null beats a
// scan that hangs on a file it found on the host.
func TestResolveDictPath_ProbeBudget(t *testing.T) {
	// At every level the keys "a", "a.a", "a.a.a" and "a.a.a.a" all exist, so
	// each of the four splits is a live branch and the search fans out. Four
	// levels is already far more than the budget allows the walk to explore -
	// deeper trees only cost the test memory - so absence here is the budget
	// doing its job.
	var build func(depth int) map[string]any
	build = func(depth int) map[string]any {
		m := map[string]any{}
		if depth == 0 {
			return m
		}
		key := "a"
		for i := 0; i < 4; i++ {
			m[key] = build(depth - 1)
			key += ".a"
		}
		return m
	}

	segments := make([]string, 40)
	for i := range segments {
		segments[i] = "a"
	}

	done := make(chan struct{})
	var found bool
	go func() {
		defer close(done)
		probes := maxDictPathProbes
		_, found, _ = resolveDictPath(build(4), segments, &probes)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("resolveDictPath did not terminate; the probe budget is not bounding the search")
	}
	assert.False(t, found)
}

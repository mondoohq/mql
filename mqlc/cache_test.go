// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
	"google.golang.org/protobuf/proto"
)

// versioned is a schema that says which version of itself it is.
type versioned struct {
	resources.ResourcesSchema
	version uint64
}

func (v *versioned) SchemaVersion() (uintptr, uint64) { return 1, v.version }

// noTranslations is a source of translations that has none.
type noTranslations struct{}

func (noTranslations) TranslationsFor(string) []*llx.TranslationStep { return nil }

// countingProps counts how often properties are asked for.
type countingProps struct {
	SimpleProps
	asked int
}

func (p *countingProps) Get(name string) *llx.Primitive {
	p.asked++
	return p.SimpleProps.Get(name)
}

func TestCompileCache(t *testing.T) {
	enabled, shared := compileCacheEnabled, compileCacheShared
	compileCacheEnabled, compileCacheShared, compileCache.entries = true, false, nil
	t.Cleanup(func() { compileCacheEnabled, compileCacheShared, compileCache.entries = enabled, shared, nil })

	plain := &resources.Schema{Resources: map[string]*resources.ResourceInfo{
		"mondoo": {Id: "mondoo", Name: "mondoo", Global: true, Fields: map[string]*resources.Field{
			"version": {Name: "version", Type: string(types.String)},
			"build":   {Name: "build", Type: string(types.String)},
			"uptime":  {Name: "uptime", Type: string(types.Int)},
		}},
	}}
	schema := &versioned{ResourcesSchema: plain}
	cached := NewConfig(schema, mql.DefaultFeatures)
	const query = `mondoo.version == "x" && mondoo.uptime > props.limit`
	props := func() *countingProps {
		return &countingProps{SimpleProps: SimpleProps{"limit": {Type: string(types.Int)}}}
	}

	first, err := Compile(query, props(), cached)
	require.NoError(t, err)
	want, err := Compile(query, props(), NewConfig(plain, mql.DefaultFeatures))
	require.NoError(t, err)
	require.True(t, proto.Equal(want, first), "a compile through the cache gives what a compile gives")
	require.Len(t, compileCache.entries, 1)

	t.Run("the second compile is a copy of the first", func(t *testing.T) {
		p := props()
		second, err := Compile(query, p, cached)
		require.NoError(t, err)
		assert.True(t, proto.Equal(first, second))
		assert.NotSame(t, first, second, "whoever gets a bundle owns it")
		assert.Len(t, compileCache.entries, 1)
		assert.Equal(t, 1, p.asked, "the property is asked for, as the compiler asks")

		second.CodeV2.Id = "changed"
		third, err := Compile(query, props(), cached)
		require.NoError(t, err)
		assert.Equal(t, first.CodeV2.Id, third.CodeV2.Id, "changing a copy changes nothing else")
	})

	t.Run("not with a property of another type, or without it", func(t *testing.T) {
		other, err := Compile(query, SimpleProps{"limit": {Type: string(types.String)}}, cached)
		require.NoError(t, err)
		assert.Equal(t, string(types.String), other.Props["limit"], "compiled again, for the type it has now")
		assert.NotEqual(t, first.CodeV2.Id, other.CodeV2.Id)
		_, err = Compile(query, nil, cached)
		assert.Error(t, err)
	})

	t.Run("not against another version of the schema, or another configuration", func(t *testing.T) {
		schema.version++
		_, err := Compile(query, props(), cached)
		require.NoError(t, err)
		assert.Len(t, compileCache.entries, 2)

		strict := cached
		strict.Strict = true
		_, err = Compile(query, props(), strict)
		require.NoError(t, err)
		assert.Len(t, compileCache.entries, 3)

		// Two configurations that differ only in where one root ends and
		// the next begins are two configurations.
		one, other := cached, cached
		one.AssetRoot, one.DeclaredAssetRoot = "a|b", "c"
		other.AssetRoot, other.DeclaredAssetRoot = "a", "b|c"
		first, ok := compileCacheKey(query, one)
		require.True(t, ok)
		second, ok := compileCacheKey(query, other)
		require.True(t, ok)
		assert.NotEqual(t, first, second)
	})

	t.Run("not with statistics or translations, and not for a schema without versions", func(t *testing.T) {
		before := len(compileCache.entries)
		stats := cached
		stats.EnableStats()
		_, err := Compile(query, props(), stats)
		require.NoError(t, err)
		translated := cached
		translated.Translations = noTranslations{}
		_, err = Compile(`mondoo.build`, nil, translated)
		require.NoError(t, err)
		_, err = Compile(`mondoo.build`, nil, NewConfig(plain, mql.DefaultFeatures))
		require.NoError(t, err)
		assert.Len(t, compileCache.entries, before)
	})

	t.Run("shared, every compile gets the same bundle", func(t *testing.T) {
		compileCacheShared, compileCache.entries = true, nil
		defer func() { compileCacheShared = false }()
		one, err := Compile(query, props(), cached)
		require.NoError(t, err)
		p := props()
		two, err := Compile(query, p, cached)
		require.NoError(t, err)
		assert.Same(t, one, two)
		assert.Equal(t, 1, p.asked)
	})

	t.Run("checked, a caller that changes a shared bundle is found", func(t *testing.T) {
		compileCacheShared, compileCacheVerify, compileCache.entries = true, true, nil
		defer func() { compileCacheShared, compileCacheVerify = false, false }()
		found := compileCacheChanged.Load()

		one, err := Compile(query, props(), cached)
		require.NoError(t, err)
		two, err := Compile(query, props(), cached)
		require.NoError(t, err)
		assert.Same(t, one, two)
		assert.Equal(t, found, compileCacheChanged.Load(), "nobody changed it")

		id := one.CodeV2.Id
		one.CodeV2.Id = "changed"
		three, err := Compile(query, props(), cached)
		require.NoError(t, err)
		assert.Equal(t, found+1, compileCacheChanged.Load())
		assert.Equal(t, id, three.CodeV2.Id, "what is handed out is the bundle as it was compiled")
		four, err := Compile(query, props(), cached)
		require.NoError(t, err)
		assert.Same(t, three, four)
		assert.Equal(t, found+1, compileCacheChanged.Load(), "and it is found once")
	})

	t.Run("a query that does not compile is not kept", func(t *testing.T) {
		before := len(compileCache.entries)
		_, err := Compile(`mondoo.nosuchfield`, nil, cached)
		require.Error(t, err)
		assert.Len(t, compileCache.entries, before)
	})
}

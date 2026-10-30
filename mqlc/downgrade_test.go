// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/types"
)

// writerWithField returns the os schema plus one field the older provider never
// had, so a compile against it is a compile against a newer release.
func writerWithField(t *testing.T, field string, typ types.Type, since string) *resources.Schema {
	t.Helper()
	schema := &resources.Schema{
		Resources:    map[string]*resources.ResourceInfo{},
		Dependencies: map[string]*resources.ProviderInfo{},
	}
	schema.Add(testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "os"}))
	cfg := schema.Resources["sshd.config"]
	require.NotNil(t, cfg)
	cfg.Fields[field] = &resources.Field{
		Name: field, Type: string(typ),
		Provider: osProviderID, MinProviderVersion: since,
	}
	return schema
}

// authored builds a translation exactly the way a provider author would, then
// converts it into what the caller hands the compiler.
// fakeSource answers downgrade lookups from a fixed list, standing in for the
// provider binary a real compile would ask.
type fakeSource struct {
	provider string
	steps    []*llx.TranslationStep
	// asked records which providers were looked up, so a test can show the
	// lookup is lazy rather than eager.
	asked []string
}

func (f *fakeSource) TranslationsFor(provider string) []*llx.TranslationStep {
	f.asked = append(f.asked, provider)
	if provider != f.provider {
		return nil
	}
	return f.steps
}

func authored(t *testing.T, field string, changedIn string, build func(*plugin.TranslationBuilder)) *fakeSource {
	t.Helper()
	tr := plugin.Translate("sshd.config", field, changedIn, build)
	require.NotNil(t, tr)
	return &fakeSource{
		provider: "os",
		steps: []*llx.TranslationStep{{
			Resource: tr.Resource, Field: tr.Field, ChangedIn: tr.ChangedIn, Block: tr.Block,
		}},
	}
}

func configFor(schema *resources.Schema, catalog llx.TranslationSource, floor string) mqlc.CompilerConfig {
	conf := mqlc.NewConfig(schema, mql.Features{})
	conf.Translations = catalog
	if floor != "" {
		conf.DowngradeFloor = map[string]string{"os": floor}
	}
	return conf
}

// The whole producer path: a provider authors a rebuild in Go, the compiler
// relocates it into the bundle, and the bundle ships knowing how to serve a
// reader that predates the field.
func TestCompilerEmitsProviderTranslation(t *testing.T) {
	schema := writerWithField(t, "cipherCount", types.Int, "14.5.0")
	catalog := authored(t, "cipherCount", "14.5.0", func(b *plugin.TranslationBuilder) {
		b.Return(b.Call(b.Field("ciphers", types.Array(types.String)), "length", types.Int))
	})

	bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, configFor(schema, catalog, "13.0.0"))
	require.NoError(t, err)

	require.Len(t, bundle.Translations, 1)
	tr := bundle.Translations[0]
	assert.Equal(t, "os", tr.Provider)
	assert.Equal(t, "14.5.0", tr.BelowVersion)

	// The ref points at the cipherCount chunk, and the block at a real block.
	require.NotZero(t, tr.BlockRef)
	blockIdx := int(tr.BlockRef>>32) - 1
	require.Less(t, blockIdx, len(bundle.CodeV2.Blocks))

	// Relocation rebased the template's bindings onto the block's real ref and
	// checksummed each chunk at its final position.
	block := bundle.CodeV2.Blocks[blockIdx]
	require.Len(t, block.Chunks, 3) // binding, ciphers, length
	assert.Equal(t, tr.BlockRef|1, block.Chunks[1].Function.Binding)
	assert.Equal(t, tr.BlockRef|2, block.Chunks[2].Function.Binding)
	assert.Equal(t, []uint64{tr.BlockRef | 3}, block.Entrypoints)
	for i := range block.Chunks {
		ref := tr.BlockRef | uint64(i+1)
		assert.NotEmpty(t, bundle.CodeV2.Checksums[ref], "chunk %d has no checksum", i+1)
	}
}

// Nothing is emitted when there is no floor to serve, which is the default and
// keeps every existing compile byte-identical.
func TestCompilerEmitsNothingWithoutAFloor(t *testing.T) {
	schema := writerWithField(t, "cipherCount", types.Int, "14.5.0")
	catalog := authored(t, "cipherCount", "14.5.0", func(b *plugin.TranslationBuilder) {
		b.Return(b.Call(b.Field("ciphers", types.Array(types.String)), "length", types.Int))
	})

	bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, configFor(schema, catalog, ""))
	require.NoError(t, err)
	assert.Empty(t, bundle.Translations)
}

// A field that already existed at the floor needs no fallback.
func TestCompilerSkipsTranslationBelowTheFloor(t *testing.T) {
	schema := writerWithField(t, "cipherCount", types.Int, "12.0.0")
	catalog := authored(t, "cipherCount", "12.0.0", func(b *plugin.TranslationBuilder) {
		b.Return(b.Call(b.Field("ciphers", types.Array(types.String)), "length", types.Int))
	})

	bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, configFor(schema, catalog, "13.0.0"))
	require.NoError(t, err)
	assert.Empty(t, bundle.Translations, "every supported reader already has this field")
}

// A translation whose result is not the field's declared type would leave every
// chunk downstream compiled against something the substitute never produces.
func TestCompilerRejectsTypeMismatchedTranslation(t *testing.T) {
	schema := writerWithField(t, "cipherCount", types.Int, "14.5.0")
	catalog := authored(t, "cipherCount", "14.5.0", func(b *plugin.TranslationBuilder) {
		// yields []string where the field is an int
		b.Return(b.Field("ciphers", types.Array(types.String)))
	})

	bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, configFor(schema, catalog, "13.0.0"))
	require.NoError(t, err)
	assert.Empty(t, bundle.Translations)
}

// A translation that rebuilds a field out of something its own readers do not
// have swaps one unrunnable call for another. min_provider_version is what lets
// us catch that here rather than in the field.
func TestCompilerRejectsTranslationNeedingTooNewAField(t *testing.T) {
	schema := writerWithField(t, "cipherCount", types.Int, "14.5.0")
	// effectiveCiphers landed in 13.16.9, so a translation serving readers below
	// 13.5.0 cannot use it.
	schema.Resources["sshd.config"].Fields["effectiveCiphers"].MinProviderVersion = "13.16.9"
	catalog := authored(t, "cipherCount", "13.5.0", func(b *plugin.TranslationBuilder) {
		b.Return(b.Call(b.Field("effectiveCiphers", types.Array(types.String)), "length", types.Int))
	})

	bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, configFor(schema, catalog, "13.0.0"))
	require.NoError(t, err)
	assert.Empty(t, bundle.Translations)
}

// End to end: author, compile, then execute on a reader that predates the field.
func TestProviderTranslationRunsOnAnOlderReader(t *testing.T) {
	runtime := testutils.LinuxMock()
	schema := writerWithField(t, "cipherCount", types.Int, "14.5.0")
	catalog := authored(t, "cipherCount", "14.5.0", func(b *plugin.TranslationBuilder) {
		b.Return(b.Call(b.Field("ciphers", types.Array(types.String)), "length", types.Int))
	})

	bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, configFor(schema, catalog, "13.0.0"))
	require.NoError(t, err)
	require.Len(t, bundle.Translations, 1)

	patched, installed := llx.Patch(bundle.CodeV2, bundle.Translations,
		map[string]string{osProviderID: "13.2.0"})
	require.Len(t, installed, 1)
	bundle.CodeV2 = patched

	raw, err := exec.ExecuteCode(runtime, bundle, nil, mql.Features{})
	require.NoError(t, err)
	results := llx.ReturnValuesV2(bundle, func(checksum string) (*llx.RawResult, bool) {
		res, ok := raw[checksum]
		return res, ok
	})
	require.Len(t, results, 1)
	assert.NoError(t, results[0].Data.Error)
	assert.Equal(t, int64(6), results[0].Data.Value,
		"a reader without the field computed it from what it does have")
	assert.True(t, results[0].Data.Translated)
}

// A field read in several places shares one translation block. Emitting a copy
// per read would multiply the bundle by how often a translated field is
// mentioned, which in a policy is a lot.
func TestCompilerReusesOneTranslationBlockPerField(t *testing.T) {
	schema := writerWithField(t, "cipherCount", types.Int, "14.5.0")
	catalog := authored(t, "cipherCount", "14.5.0", func(b *plugin.TranslationBuilder) {
		b.Return(b.Call(b.Field("ciphers", types.Array(types.String)), "length", types.Int))
	})

	bundle, err := mqlc.Compile(
		`sshd.config.cipherCount > 0 && sshd.config.cipherCount != 3 && sshd.config.cipherCount < 50`,
		nil, configFor(schema, catalog, "13.0.0"))
	require.NoError(t, err)

	require.Len(t, bundle.Translations, 3, "each read needs its own entry")

	blocks := map[uint64]bool{}
	refs := map[uint64]bool{}
	for _, tr := range bundle.Translations {
		blocks[tr.BlockRef] = true
		refs[tr.Ref] = true
	}
	assert.Len(t, blocks, 1, "but all three entries point at one block")
	assert.Len(t, refs, 3, "and each entry patches a different chunk")
}

// The block computes on the field's binding, so its parameter placeholder has to
// be checksummed against that binding - the same thing an ordinary block does.
// Getting this wrong is invisible in a simple query and wrong in a nested one.
func TestTranslationBlockIsBoundToTheFieldsBinding(t *testing.T) {
	schema := writerWithField(t, "cipherCount", types.Int, "14.5.0")
	catalog := authored(t, "cipherCount", "14.5.0", func(b *plugin.TranslationBuilder) {
		b.Return(b.Call(b.Field("ciphers", types.Array(types.String)), "length", types.Int))
	})

	bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, configFor(schema, catalog, "13.0.0"))
	require.NoError(t, err)
	require.Len(t, bundle.Translations, 1)

	tr := bundle.Translations[0]
	patchedChunk := bundle.CodeV2.Chunk(tr.Ref)
	require.NotNil(t, patchedChunk.Function)

	bindingChecksum := bundle.CodeV2.Checksums[patchedChunk.Function.Binding]
	require.NotEmpty(t, bindingChecksum)
	assert.Equal(t, bindingChecksum, bundle.CodeV2.Checksums[tr.BlockRef|1],
		"the block parameter must carry the binding's checksum")
}

// The catalog is asked for lazily, per provider the query actually touches.
//
// This is the whole reason the compiler takes a lookup instead of a prepared
// map: which providers a query reaches is only known while compiling it, so a
// map would force the caller to guess or to start every installed provider just
// in case - and reading a catalog means running the provider.
func TestTranslationLookupIsLazyAndScoped(t *testing.T) {
	schema := writerWithField(t, "cipherCount", types.Int, "14.5.0")

	t.Run("nothing is asked without a floor", func(t *testing.T) {
		src := authored(t, "cipherCount", "14.5.0", func(b *plugin.TranslationBuilder) {
			b.Return(b.Call(b.Field("ciphers", types.Array(types.String)), "length", types.Int))
		})
		_, err := mqlc.Compile(`sshd.config.cipherCount`, nil, configFor(schema, src, ""))
		require.NoError(t, err)
		assert.Empty(t, src.asked, "a compile that emits no fallbacks must start no providers")
	})

	t.Run("only the providers the query touches are asked", func(t *testing.T) {
		src := authored(t, "cipherCount", "14.5.0", func(b *plugin.TranslationBuilder) {
			b.Return(b.Call(b.Field("ciphers", types.Array(types.String)), "length", types.Int))
		})
		_, err := mqlc.Compile(`sshd.config.cipherCount`, nil, configFor(schema, src, "13.0.0"))
		require.NoError(t, err)

		require.NotEmpty(t, src.asked)
		for _, provider := range src.asked {
			assert.Equal(t, "os", provider, "no provider outside the query should be consulted")
		}
	})

	t.Run("a source that answers nothing is not an error", func(t *testing.T) {
		empty := &fakeSource{provider: "nobody"}
		bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, configFor(schema, empty, "13.0.0"))
		require.NoError(t, err)
		assert.Empty(t, bundle.Translations)
	})
}

// A runtime that can supply a catalog is picked up automatically, so no caller
// has to assemble this by hand.
func TestNewConfigFromPicksUpTheRuntimeCatalog(t *testing.T) {
	runtime := testutils.LinuxMock()
	conf := mqlc.NewConfigFrom(runtime, mql.Features{})
	assert.NotNil(t, conf.Schema)
	// LinuxMock's runtime is a providers.Runtime, which implements the source.
	assert.NotNil(t, conf.Translations,
		"a runtime that can answer downgrade lookups must be wired in without help")
}

// The default window applies without anyone opting in, and today every provider
// is still on major 13 - below the stop floor - so it comes out empty and no
// catalog is fetched. That changes on its own when providers reach 14.
func TestNewConfigFromAppliesTheDefaultFloor(t *testing.T) {
	runtime := testutils.LinuxMock()
	conf := mqlc.NewConfigFrom(runtime, mql.Features{})

	for provider, floor := range conf.DowngradeFloor {
		assert.Equal(t, mqlc.DefaultDowngradeFloor(
			runtime.Schema().AllProviderVersions())[provider], floor)
	}
}

// End to end with a provider past the stop floor: the default window alone is
// enough to get a fallback emitted, with no floor configured by hand.
func TestDefaultFloorAloneEmitsATranslation(t *testing.T) {
	schema := writerWithField(t, "cipherCount", types.Int, "16.1.0")
	schema.ProviderVersions = map[string]string{osProviderID: "16.1.0"}
	src := authored(t, "cipherCount", "16.1.0", func(b *plugin.TranslationBuilder) {
		b.Return(b.Call(b.Field("ciphers", types.Array(types.String)), "length", types.Int))
	})

	conf := mqlc.NewConfig(schema, mql.Features{})
	conf.Translations = src
	conf.DowngradeFloor = mqlc.DefaultDowngradeFloor(schema.AllProviderVersions())
	require.Equal(t, map[string]string{"os": "14.0.0"}, conf.DowngradeFloor)

	bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, conf)
	require.NoError(t, err)
	require.Len(t, bundle.Translations, 1)
	assert.Equal(t, "16.1.0", bundle.Translations[0].BelowVersion,
		"readers below the version that introduced the field get the fallback")
}

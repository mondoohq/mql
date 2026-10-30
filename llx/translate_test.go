// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/types"
)

// translatable builds the writer's view: sshd.config gains a cipherCount field
// the reader has never had, which the reader can nonetheless compute from
// vocabulary it does have.
func translatable(t *testing.T, runtime llx.Runtime) *resources.Schema {
	t.Helper()
	schema := &resources.Schema{
		Resources:    map[string]*resources.ResourceInfo{},
		Dependencies: map[string]*resources.ProviderInfo{},
	}
	schema.Add(runtime.Schema())
	cfg := schema.Resources["sshd.config"]
	require.NotNil(t, cfg)
	cfg.Fields["cipherCount"] = &resources.Field{
		Name: "cipherCount", Type: string(types.Int),
		Provider: osProviderID, MinProviderVersion: "99.0.0",
	}
	return schema
}

// findChunk locates a chunk by id and returns its ref.
func findChunk(t *testing.T, code *llx.CodeV2, id string) (uint64, *llx.Chunk) {
	t.Helper()
	for bi, block := range code.Blocks {
		for ci, chunk := range block.Chunks {
			if chunk.Id == id && chunk.Function != nil {
				return (uint64(bi+1) << 32) | uint64(ci+1), chunk
			}
		}
	}
	t.Fatalf("no chunk %q in code", id)
	return 0, nil
}

// addTranslationBlock builds "<binding>.ciphers.length" as a block the producer
// would have shipped alongside the primary code, and returns its ref.
func addTranslationBlock(code *llx.CodeV2, binding uint64) uint64 {
	block, blockRef := code.AddBlock()
	block.SingleValue = true
	block.AddArgumentPlaceholder(code, blockRef, types.Resource("sshd.config"), code.Checksums[binding])
	block.AddChunk(code, blockRef, &llx.Chunk{
		Call: llx.Chunk_FUNCTION, Id: "ciphers",
		Function: &llx.Function{Type: string(types.Array(types.String)), Binding: blockRef | 1},
	})
	block.AddChunk(code, blockRef, &llx.Chunk{
		Call: llx.Chunk_FUNCTION, Id: "length",
		Function: &llx.Function{Type: string(types.Int), Binding: blockRef | 2},
	})
	block.Entrypoints = []uint64{blockRef | 3}
	return blockRef
}

// The load-bearing claims of the downgrade design, against the real VM:
// a field the reader does not have still produces the right value, the reported
// identity is the one the producer shipped, and nothing downstream notices.
func TestDowngradePatchRunsTranslationAndKeepsIdentity(t *testing.T) {
	runtime := testutils.LinuxMock()
	writer := translatable(t, runtime)

	bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, mqlc.NewConfig(writer, mql.Features{}))
	require.NoError(t, err)

	targetRef, target := findChunk(t, bundle.CodeV2, "cipherCount")
	declaredType := target.Function.Type
	shipped := bundle.CodeV2.Checksums[targetRef]

	blockRef := addTranslationBlock(bundle.CodeV2, target.Function.Binding)
	translations := []*llx.TranslationRef{{
		Ref: targetRef, Provider: osProviderID, BelowVersion: "99.0.0", BlockRef: blockRef,
	}}

	patched, installed := llx.Patch(bundle.CodeV2, translations, map[string]string{osProviderID: "13.0.0"})
	require.Len(t, installed, 1)

	// The original is untouched: patching hands back a private copy so one
	// bundle stays safe to execute against many assets concurrently.
	assert.Equal(t, "cipherCount", target.Id, "Patch must not edit the code it is given")

	// The patched chunk keeps the type it was compiled with, so every chunk
	// downstream stays valid.
	_, patchedChunk := findChunk(t, patched, llx.TranslateChunkID)
	assert.Equal(t, declaredType, patchedChunk.Function.Type)

	bundle.CodeV2 = patched
	raw, err := exec.ExecuteCode(runtime, bundle, nil, mql.Features{})
	require.NoError(t, err)
	results := llx.ReturnValuesV2(bundle, func(checksum string) (*llx.RawResult, bool) {
		res, ok := raw[checksum]
		return res, ok
	})
	require.Len(t, results, 1)

	assert.NoError(t, results[0].Data.Error)
	assert.Equal(t, types.Int, results[0].Data.Type)
	assert.Equal(t, int64(6), results[0].Data.Value,
		"the reader computed the new field out of vocabulary it already had")
	assert.Equal(t, shipped, results[0].CodeID,
		"a patched reader must report under the checksum the producer shipped, or scoring forks")
}

// A reader new enough to run the primary code takes no patch at all. The
// translation block ships with the bundle either way and is simply never
// reached, which is what keeps the cost off current readers.
func TestDowngradePatchSkippedWhenReaderIsCurrent(t *testing.T) {
	runtime := testutils.LinuxMock()
	writer := translatable(t, runtime)

	bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, mqlc.NewConfig(writer, mql.Features{}))
	require.NoError(t, err)

	targetRef, target := findChunk(t, bundle.CodeV2, "cipherCount")
	blockRef := addTranslationBlock(bundle.CodeV2, target.Function.Binding)
	translations := []*llx.TranslationRef{{
		Ref: targetRef, Provider: osProviderID, BelowVersion: "99.0.0", BlockRef: blockRef,
	}}

	for _, tc := range []struct {
		name    string
		readers map[string]string
	}{
		{"reader is newer", map[string]string{osProviderID: "99.0.1"}},
		{"reader is exactly at the change", map[string]string{osProviderID: "99.0.0"}},
		// A source build of the line that introduced the field has the field.
		// It satisfies a floor of 99.0.0, so it must not also be told it is
		// below 99.0.0 and handed the downgrade path.
		{"reader is a source build of that version", map[string]string{osProviderID: "v99.0.0+rolling"}},
		// Not knowing a version is not evidence a translation applies. Guessing
		// would rewrite code that was going to run correctly.
		{"reader version unknown", map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, chunk := findChunk(t, bundle.CodeV2, "cipherCount")
			code, installed := llx.Patch(bundle.CodeV2, translations, tc.readers)
			assert.Empty(t, installed)
			assert.Same(t, bundle.CodeV2, code, "no translation means no copy")
			assert.Equal(t, "cipherCount", chunk.Id, "the primary code must be left pristine")
		})
	}
}

// A sidecar naming a block that was never shipped must be ignored, not allowed
// to rewrite a working chunk into a dangling call.
func TestDowngradePatchIgnoresDanglingTranslation(t *testing.T) {
	runtime := testutils.LinuxMock()
	writer := translatable(t, runtime)

	bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, mqlc.NewConfig(writer, mql.Features{}))
	require.NoError(t, err)
	targetRef, target := findChunk(t, bundle.CodeV2, "cipherCount")

	for _, bad := range []*llx.TranslationRef{
		{Ref: targetRef, Provider: osProviderID, BelowVersion: "99.0.0", BlockRef: uint64(999) << 32},
		{Ref: uint64(999) << 32, Provider: osProviderID, BelowVersion: "99.0.0", BlockRef: uint64(1) << 32},
		{Ref: targetRef, Provider: osProviderID, BelowVersion: "not-a-version", BlockRef: uint64(1) << 32},
	} {
		_, installed := llx.Patch(bundle.CodeV2, []*llx.TranslationRef{bad},
			map[string]string{osProviderID: "13.0.0"})
		assert.Empty(t, installed)
		assert.Equal(t, "cipherCount", target.Id)
	}
}

// The bundle carries its translations on the wire, so execution installs them
// with no caller involvement - and a bundle is executed once per asset, so the
// same bundle passing through repeatedly must keep working and must never be
// edited. Patch returning a private copy is what makes that safe; this pins it.
//
// Deliberately sequential. Executing one bundle against a shared runtime
// concurrently races inside the os provider's lazy field cache
// (providers/os/resources/sshd.go parse/GetOrCompute), which reproduces with no
// translations involved at all and is not this code's to assert on.
func TestDowngradePatchViaBundleRepeatsWithoutEditingIt(t *testing.T) {
	runtime := testutils.LinuxMock()
	providers.Coordinator.Schema().(providers.ExtensibleSchema).Add("translate-test-repeat", &resources.Schema{
		Resources:        map[string]*resources.ResourceInfo{},
		Dependencies:     map[string]*resources.ProviderInfo{},
		ProviderVersions: map[string]string{osProviderID: "13.0.0"},
	})
	writer := translatable(t, runtime)

	bundle, err := mqlc.Compile(`sshd.config.cipherCount`, nil, mqlc.NewConfig(writer, mql.Features{}))
	require.NoError(t, err)

	targetRef, target := findChunk(t, bundle.CodeV2, "cipherCount")
	shipped := bundle.CodeV2.Checksums[targetRef]
	blockRef := addTranslationBlock(bundle.CodeV2, target.Function.Binding)
	bundle.Translations = []*llx.TranslationRef{{
		Ref: targetRef, Provider: osProviderID, BelowVersion: "99.0.0", BlockRef: blockRef,
	}}
	originalCode := bundle.CodeV2

	for range 3 {
		raw, err := exec.ExecuteCode(runtime, bundle, nil, mql.Features{})
		require.NoError(t, err)
		results := llx.ReturnValuesV2(bundle, func(checksum string) (*llx.RawResult, bool) {
			res, ok := raw[checksum]
			return res, ok
		})
		require.Len(t, results, 1)
		assert.NoError(t, results[0].Data.Error)
		assert.Equal(t, int64(6), results[0].Data.Value)
		assert.Equal(t, shipped, results[0].CodeID)
		assert.True(t, results[0].Data.Translated, "a value a translation produced has to say so")
	}

	assert.Same(t, originalCode, bundle.CodeV2, "the shared bundle must never be swapped out")
	assert.Equal(t, "cipherCount", target.Id,
		"the shared bundle is never edited, however many executions it serves")
}

// An untranslated value must not claim to be translated.
func TestUntranslatedValuesAreNotMarked(t *testing.T) {
	runtime := testutils.LinuxMock()
	bundle, err := mqlc.Compile(`sshd.config.ciphers.length`, nil,
		mqlc.NewConfig(runtime.Schema(), mql.Features{}))
	require.NoError(t, err)

	raw, err := exec.ExecuteCode(runtime, bundle, nil, mql.Features{})
	require.NoError(t, err)
	results := llx.ReturnValuesV2(bundle, func(checksum string) (*llx.RawResult, bool) {
		res, ok := raw[checksum]
		return res, ok
	})
	require.Len(t, results, 1)
	assert.Equal(t, int64(6), results[0].Data.Value)
	assert.False(t, results[0].Data.Translated)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/core/resources/versions/semver"
)

// A downgrade patch replaces calls the reader cannot make with translation
// blocks that produce the same value out of the vocabulary it does have.
//
// The bundle is compiled once, canonically, against the newest schema. The
// translations ride alongside as a sidecar rather than as branches in the
// primary code, which buys three properties:
//
//   - A current reader executes pristine bytecode. It walks the sidecar, finds
//     nothing that applies, and pays nothing - no branches it can never take.
//   - Patching does not move anything. The translation blocks ship inside
//     CodeV2 as ordinary blocks, with their checksums already in the map, and
//     nothing points at them until a patch does - so a current reader carries
//     them as dead weight and never executes them. Patching rewrites one chunk
//     in place at its own index. Nothing is appended, nothing renumbers, and
//     the checksum map is never written to at all.
//   - Reported identity is untouched. The executor reads `code.Checksums[ref]`
//     rather than recomputing, so a patched reader runs different chunks and
//     still reports under the checksums the producer shipped. Scoring does not
//     fork across versions.
//
// The patched chunk keeps its original Function.Type, so every chunk downstream
// stays compiled against the type it already expected.

// Patch returns the code this reader should execute, and the translations it
// installed. A reader current enough to need none gets the original code back.
//
// It never mutates the code it is given. The alternative - rewriting chunks in
// place - looks cheaper but is unsound: one CodeBundle is executed against many
// assets, queries run in goroutines, and a lock around the patch does nothing
// about a goroutine *reading* a chunk while another rewrites it. Copying is
// what makes the patched code private to this execution.
//
// The copy is shallow and narrow: only the blocks that actually contain a
// patched chunk are cloned, and within them only the patched chunks. Everything
// else - every other block, every other chunk, and the whole checksum map - is
// shared read-only. A current reader copies nothing at all.
//
// Translations are selected against readerVersions, keyed the same way
// everything else keys providers, so a legacy module-path id still matches.
func Patch(code *CodeV2, translations []*TranslationRef, readerVersions map[string]string) (*CodeV2, []*TranslationRef) {
	if code == nil || len(translations) == 0 {
		return code, nil
	}

	applicable := []*TranslationRef{}
	for _, t := range translations {
		if t == nil || t.BlockRef == 0 || !needsTranslation(t, readerVersions) {
			continue
		}
		if target := chunkAt(code, t.Ref); target != nil && target.Function != nil && blockExists(code, t.BlockRef) {
			applicable = append(applicable, t)
		}
	}
	if len(applicable) == 0 {
		return code, nil
	}

	patched := &CodeV2{
		Id:         code.Id,
		Blocks:     make([]*Block, len(code.Blocks)),
		Checksums:  code.Checksums,
		Assertions: code.Assertions,
	}
	copy(patched.Blocks, code.Blocks)

	installed := []*TranslationRef{}
	for _, t := range applicable {
		if patchOne(patched, t) {
			installed = append(installed, t)
		}
	}
	return patched, installed
}

// blockExists guards against a sidecar naming a block that was never shipped,
// which would rewrite a working chunk into a dangling call.
func blockExists(code *CodeV2, blockRef uint64) bool {
	idx := int(blockRef>>32) - 1
	return idx >= 0 && idx < len(code.Blocks) && code.Blocks[idx] != nil
}

// needsTranslation reports whether this reader is old enough to need it. A
// reader whose version we cannot establish is left alone: not knowing a version
// is not evidence that a translation applies, and guessing would rewrite code
// that was going to run correctly.
func needsTranslation(t *TranslationRef, readerVersions map[string]string) bool {
	if t.Provider == "" || t.BelowVersion == "" {
		return false
	}
	schema := &resources.Schema{ProviderVersions: readerVersions}
	installed, ok := schema.ProviderVersion(t.Provider)
	if !ok {
		return false
	}
	diff, err := (semver.Parser{}).Compare(installed, t.BelowVersion)
	if err != nil {
		return false
	}
	return diff < 0
}

// patchOne redirects one chunk at its translation block.
// patchOne clones the one block and the one chunk it touches, then redirects
// that clone at the translation block. The original stays untouched so other
// executions of the same bundle are unaffected.
func patchOne(code *CodeV2, t *TranslationRef) bool {
	blockIdx := int(t.Ref>>32) - 1
	chunkIdx := int(uint32(t.Ref)) - 1
	if blockIdx < 0 || blockIdx >= len(code.Blocks) {
		return false
	}
	original := code.Blocks[blockIdx]
	if original == nil || chunkIdx < 0 || chunkIdx >= len(original.Chunks) {
		return false
	}
	target := original.Chunks[chunkIdx]
	if target == nil || target.Function == nil || target.Id == TranslateChunkID {
		return false
	}

	block := cloneBlockShallow(original)
	// The type and the binding carry over untouched: the type is what
	// downstream was compiled against, and the binding is the parent the
	// translation computes from.
	block.Chunks[chunkIdx] = &Chunk{
		Call: target.Call,
		Id:   TranslateChunkID,
		Function: &Function{
			Type:    target.Function.Type,
			Binding: target.Function.Binding,
			Args:    []*Primitive{FunctionPrimitive(t.BlockRef)},
		},
	}
	code.Blocks[blockIdx] = block
	return true
}

// cloneBlockShallow copies a block's chunk list so one entry can be replaced
// without disturbing the original. The chunks themselves are shared; only the
// one being patched is replaced, with a fresh Chunk.
func cloneBlockShallow(b *Block) *Block {
	nu := &Block{
		Chunks:      make([]*Chunk, len(b.Chunks)),
		Entrypoints: b.Entrypoints,
		Datapoints:  b.Datapoints,
		Parameters:  b.Parameters,
		SingleValue: b.SingleValue,
	}
	copy(nu.Chunks, b.Chunks)
	return nu
}

// chunkAt resolves a ref without the panic CodeV2.Chunk raises on a bad one. A
// malformed sidecar must not be able to crash execution.
func chunkAt(code *CodeV2, ref uint64) *Chunk {
	blockIdx := int(ref>>32) - 1
	chunkIdx := int(uint32(ref)) - 1
	if blockIdx < 0 || blockIdx >= len(code.Blocks) {
		return nil
	}
	block := code.Blocks[blockIdx]
	if block == nil || chunkIdx < 0 || chunkIdx >= len(block.Chunks) {
		return nil
	}
	return block.Chunks[chunkIdx]
}

// TranslationStep is one provider-authored rebuild of a field, between adjacent
// releases (ADR 040 part 6).
//
// It lives here rather than in the compiler because what it carries is bytecode,
// and because both the compiler that emits it and the provider layer that
// supplies it need to name the type without depending on each other.
type TranslationStep struct {
	Resource string
	Field    string
	// ChangedIn is the version that introduced the change. Readers older than
	// this need the step; readers at or above it run the field directly.
	ChangedIn string
	// Block computes the field from vocabulary that predates ChangedIn. Its refs
	// are block-relative: chunk 1 is the binding.
	Block *Block
}

// TranslationSource supplies downgrade steps on demand.
//
// It is a lookup rather than a prepared map because which providers a query
// touches is only known while compiling it. Handing the compiler a map would
// mean the caller either guessing, or starting every installed provider just in
// case - and reading a catalog means running the provider, so "just in case" is
// expensive. Asked lazily, only the providers a query actually reaches are
// consulted.
//
// A source that cannot answer returns nil, which is not an error: the compile
// continues with no fallbacks for that provider.
type TranslationSource interface {
	// TranslationsFor returns the steps a provider offers, keyed by the stable
	// provider name.
	TranslationsFor(provider string) []*TranslationStep
}

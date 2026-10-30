// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"sort"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/core/resources/versions/semver"
	"go.mondoo.com/mql/types"
)

// Downgrade emission (ADR 040 part 6).
//
// A bundle is compiled once, against the newest schema, for every client that
// will ever run it. Where a provider knows how to express a new field in the
// vocabulary of an older release, that knowledge is compiled in as a block the
// older reader runs instead - so one artifact serves every supported version
// and the compiling side never needs to know who it is compiling for.

// emitTranslations attaches downgrade fallbacks for one field access.
//
// It is called after the field chunk is emitted, with that chunk's ref. For
// every era between the configured floor and the version that introduced the
// field, it relocates the matching step into this bundle and records a
// TranslationRef pointing at it.
func (c *compiler) emitTranslations(resource string, field string, ref uint64, fieldType types.Type) {
	if c.Translations == nil || len(c.DowngradeFloor) == 0 {
		return
	}

	info := c.Schema.Lookup(resource)
	if info == nil {
		return
	}
	provider := resources.ProviderKey(info.Provider)

	floor, ok := c.DowngradeFloor[provider]
	if !ok || floor == "" {
		return
	}

	// The block reads from the field's own binding, so the binding is what the
	// parameter placeholder has to be checksummed against - the same thing
	// blockcompileOnResource does for an ordinary block.
	chunk := c.Result.CodeV2.Chunk(ref)
	if chunk == nil || chunk.Function == nil {
		return
	}
	bindingChecksum := c.Result.CodeV2.Checksums[chunk.Function.Binding]

	steps := c.stepsFor(provider, resource, field, floor)
	for _, step := range steps {
		blockRef, ok := c.translationBlock(step, resource, fieldType, bindingChecksum)
		if !ok {
			continue
		}
		c.Result.Translations = append(c.Result.Translations, &llx.TranslationRef{
			Ref:          ref,
			Provider:     provider,
			BelowVersion: step.ChangedIn,
			BlockRef:     blockRef,
		})
	}
}

// translationBlock returns the block for this step, relocating it on first use
// and reusing it afterwards.
//
// A field read in three places gets three TranslationRef entries pointing at one
// block, not three copies of it. Reuse is keyed on the binding's checksum as well
// as the step, because the block computes on that binding: two reads of the same
// field off the same binding are the same computation and share, while two reads
// off genuinely different bindings are not and must not.
func (c *compiler) translationBlock(step *llx.TranslationStep, resource string, fieldType types.Type, bindingChecksum string) (uint64, bool) {
	key := step.Resource + "\x00" + step.Field + "\x00" + step.ChangedIn + "\x00" + bindingChecksum
	if blockRef, ok := c.translationBlocks[key]; ok {
		return blockRef, true
	}

	blockRef, ok := c.relocate(step, resource, fieldType, bindingChecksum)
	if !ok {
		return 0, false
	}
	if c.translationBlocks == nil {
		c.translationBlocks = map[string]uint64{}
	}
	c.translationBlocks[key] = blockRef
	return blockRef, true
}

// stepsFor returns the steps that apply to this field for readers at or above
// the floor, newest first.
//
// Providers author one step per adjacent release, which is what keeps their
// maintenance linear and lets a shipped step stay frozen. Emitting one
// TranslationRef per step is the other half of that bargain: the reader picks
// the single entry matching its era and never composes anything at runtime.
func (c *compiler) stepsFor(provider string, resource string, field string, floor string) []*llx.TranslationStep {
	parser := semver.Parser{}
	var res []*llx.TranslationStep

	for _, step := range c.Translations.TranslationsFor(provider) {
		if step == nil || step.Block == nil {
			continue
		}
		if step.Resource != resource || step.Field != field {
			continue
		}
		// A step older than the floor helps nobody we still support.
		diff, err := parser.Compare(step.ChangedIn, floor)
		if err != nil || diff <= 0 {
			continue
		}
		res = append(res, step)
	}

	sort.Slice(res, func(i, j int) bool {
		diff, err := parser.Compare(res[i].ChangedIn, res[j].ChangedIn)
		return err == nil && diff > 0
	})
	return res
}

// relocate copies a provider's block template into this bundle.
//
// The template's refs are block-relative - chunk 1 is the binding - so every
// binding has to be rebased onto the block's real ref here. Chunks are re-added
// through Block.AddChunk rather than copied wholesale, because that is what
// computes each checksum against its final position.
//
// It refuses a template whose result type disagrees with the field's declared
// type: the whole point of the patch is that downstream bytecode stays valid,
// and it only stays valid if the substitute yields what the original promised.
func (c *compiler) relocate(step *llx.TranslationStep, resource string, fieldType types.Type, bindingChecksum string) (uint64, bool) {
	src := step.Block
	if len(src.Chunks) < 2 || len(src.Entrypoints) != 1 {
		log.Warn().Str("resource", resource).Str("field", step.Field).
			Msg("skipping a downgrade translation that computes no single value")
		return 0, false
	}

	last := src.Chunks[len(src.Chunks)-1]
	if last.Function == nil || types.Type(last.Function.Type) != fieldType {
		log.Warn().Str("resource", resource).Str("field", step.Field).
			Str("declared", fieldType.Label()).
			Msg("skipping a downgrade translation whose result type does not match the field")
		return 0, false
	}

	if !c.floorValid(step, resource) {
		return 0, false
	}

	block, blockRef := c.Result.CodeV2.AddBlock()
	block.SingleValue = true
	block.AddArgumentPlaceholder(c.Result.CodeV2, blockRef,
		types.Resource(resource), bindingChecksum)

	for i := 1; i < len(src.Chunks); i++ {
		chunk := src.Chunks[i]
		if chunk.Function == nil {
			log.Warn().Str("field", step.Field).Msg("skipping a downgrade translation with a malformed chunk")
			return 0, false
		}
		block.AddChunk(c.Result.CodeV2, blockRef, &llx.Chunk{
			Call: chunk.Call,
			Id:   chunk.Id,
			Function: &llx.Function{
				Type: chunk.Function.Type,
				// Rebase: a template binding of N means "chunk N of this block".
				Binding: blockRef | chunk.Function.Binding,
				Args:    chunk.Function.Args,
			},
		})
	}
	block.Entrypoints = []uint64{blockRef | uint64(len(src.Chunks))}
	return blockRef, true
}

// floorValid checks that a translation only uses vocabulary the readers it
// targets actually have.
//
// A step that rebuilds a field using something introduced *after* the era it
// serves swaps one unrunnable call for another, and the failure surfaces deep
// in execution with nothing pointing back here. The check is possible because
// every field and resource carries min_provider_version, the same data the
// build-time schema gate reads.
func (c *compiler) floorValid(step *llx.TranslationStep, resource string) bool {
	parser := semver.Parser{}
	info := c.Schema.Lookup(resource)
	if info == nil {
		return false
	}

	for i := 1; i < len(step.Block.Chunks); i++ {
		chunk := step.Block.Chunks[i]
		if chunk.Function == nil {
			return false
		}
		_, field := c.Schema.LookupField(resource, chunk.Id)
		if field == nil {
			// Not a field of this resource (a builtin like `length`), so it is
			// not versioned and cannot be too new.
			continue
		}
		if field.MinProviderVersion == "" {
			continue
		}
		diff, err := parser.Compare(field.MinProviderVersion, step.ChangedIn)
		if err != nil {
			continue
		}
		if diff >= 0 {
			log.Warn().
				Str("resource", resource).Str("field", step.Field).
				Str("uses", chunk.Id).Str("introduced", field.MinProviderVersion).
				Str("serves_readers_below", step.ChangedIn).
				Msg("rejecting a downgrade translation that needs a field its readers do not have")
			return false
		}
	}
	return true
}

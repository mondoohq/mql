// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// Translations answers the downgrade catalog with nothing (ADR 040 part 6).
//
// Every provider embeds *plugin.Service, so this default is what makes the
// capability opt-in: a provider with no shape changes to bridge needs no code,
// and adding the RPC did not touch a single provider.
//
// A provider that does have translations overrides this and builds them with
// Translate.
func (s *Service) Translations(req *TranslationsReq) (*TranslationsRes, error) {
	return &TranslationsRes{}, nil
}

// Translate declares how to rebuild one field for a reader that predates it.
//
// The build function receives a builder bound to the parent resource, not to
// the old value of the field: the field being rebuilt often does not exist on
// the older provider at all, so there is nothing of it to transform. A field
// promoted from a sibling - `process.file` out of `process.executable` - is the
// normal case, not the exception.
//
// Steps are written between adjacent releases. Author one when you make the
// change, and never revise it again: the compiler folds a run of steps into a
// single block per era, so old steps stay frozen as new ones land.
func Translate(resource string, field string, changedIn string, build func(*TranslationBuilder)) *Translation {
	b := newTranslationBuilder(resource)
	build(b)
	if b.result == 0 {
		return nil
	}
	b.block.Entrypoints = []uint64{b.result}
	return &Translation{
		Resource:  resource,
		Field:     field,
		ChangedIn: changedIn,
		Block:     b.block,
	}
}

// Translations collects declared translations, dropping any that produced no
// value. A malformed entry is left out rather than shipped: a translation that
// computes nothing would replace a working failure with a silent one.
func Translations(list ...*Translation) (*TranslationsRes, error) {
	res := &TranslationsRes{}
	for _, t := range list {
		if t != nil {
			res.Translations = append(res.Translations, t)
		}
	}
	return res, nil
}

// TranslationBuilder emits the bytecode for one translation.
//
// Refs it produces are block-relative: chunk 1 is always the binding. The
// compiler relocates the finished block into a bundle, remapping bindings and
// recomputing checksums, so a provider never needs to know where its block
// lands.
type TranslationBuilder struct {
	block *llx.Block
	// relRef is the block-relative ref of the last chunk added. The real block
	// ref is unknown here and gets applied during relocation.
	relRef uint64
	result uint64
}

func newTranslationBuilder(resource string) *TranslationBuilder {
	b := &TranslationBuilder{
		block: &llx.Block{SingleValue: true, Parameters: 1},
	}
	// Chunk 1 is the binding placeholder: the parent resource the translation
	// computes from.
	b.block.Chunks = []*llx.Chunk{{
		Call:      llx.Chunk_PRIMITIVE,
		Primitive: &llx.Primitive{Type: string(types.Resource(resource))},
	}}
	b.relRef = 1
	return b
}

// Binding is the parent resource the translation reads from.
func (b *TranslationBuilder) Binding() uint64 { return 1 }

// Field reads a field off the binding.
func (b *TranslationBuilder) Field(name string, typ types.Type) uint64 {
	return b.Call(b.Binding(), name, typ)
}

// Call invokes a field or function on an earlier result.
func (b *TranslationBuilder) Call(on uint64, name string, typ types.Type) uint64 {
	b.block.Chunks = append(b.block.Chunks, &llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   name,
		Function: &llx.Function{
			Type:    string(typ),
			Binding: on,
		},
	})
	b.relRef++
	return b.relRef
}

// Return marks which result is the field's value.
func (b *TranslationBuilder) Return(ref uint64) { b.result = ref }

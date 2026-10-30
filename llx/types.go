// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"go.mondoo.com/mql/types"
)

// Type of this chunk, by looking at either the primitive or function.
// The type is not be dereferenced! (i.e. ref's remain)
func (c *Chunk) Type() types.Type {
	// call: primitive
	if c.Call == Chunk_PRIMITIVE {
		return types.Type(c.Primitive.Type)
	}

	// call: function
	if c.Function != nil {
		return types.Type(c.Function.Type)
	}

	// call: property
	if c.Primitive != nil {
		return types.Type(c.Primitive.Type)
	}

	// Chunks that don't have a function call but do have an ID are resources.
	// They are bound globally (because otherwise they'd have a function) and
	// they are not primitive (we eliminate those above). They could still be
	// global non-functions, but we need to investigate that case.
	if c.Id != "" {
		return types.Resource(c.Id)
	}

	return types.Any
}

// DereferencedType of this chunk, resolved if it is a reference to anything.
func (c *Chunk) DereferencedTypeV2(stack *CodeV2) types.Type {
	if c.Call == Chunk_PRIMITIVE {
		return c.Primitive.dereferenceTypeV2(types.Type(c.Primitive.Type), stack)
	}

	if c.Function != nil {
		return types.Type(c.Function.Type)
	}

	if c.Primitive != nil {
		return c.Primitive.dereferenceTypeV2(types.Type(c.Primitive.Type), stack)
	}

	// Chunks that don't have a function call but do have an ID are resources.
	// They are bound globally (because otherwise they'd have a function) and
	// they are not primitive (we eliminate those above). They could still be
	// global non-functions, but we need to investigate that case.
	if c.Id != "" {
		return types.Resource(c.Id)
	}

	return types.Any
}

func (p *Primitive) typeStringV1(typ types.Type, stack *CodeV1) string {
	switch typ.Underlying() {
	case types.Ref:
		idx := bytes2int(p.Value)
		ref := stack.Code[idx-1]
		return ref.Primitive.typeStringV1(ref.Type(), stack)
	case types.ArrayLike:
		return "[]" + p.typeStringV1(typ.Child(), stack)
	case types.MapLike:
		return "map[" + p.typeStringV1(typ.Key(), stack) + "]" + p.typeStringV1(typ.Child(), stack)
	default:
		return typ.Label()
	}
}

// TypeString for the dereferenced type label of this primitive
func (p *Primitive) TypeStringV1(stack *CodeV1) string {
	return p.typeStringV1(types.Type(p.Type), stack)
}

// turns any "ref" types into whatever they are referencing
func (p *Primitive) dereferenceTypeV1(typ types.Type, stack *CodeV1) types.Type {
	switch typ.Underlying() {
	case types.Ref:
		idx := bytes2int(p.Value)
		ref := stack.Code[idx-1]
		return ref.Primitive.dereferenceTypeV1(ref.Type(), stack)
	case types.ArrayLike:
		k := p.dereferenceTypeV1(typ.Child(), stack)
		return types.Array(k)
	case types.MapLike:
		k := p.dereferenceTypeV1(typ.Key(), stack)
		v := p.dereferenceTypeV1(typ.Child(), stack)
		return types.Map(k, v)
	default:
		return typ
	}
}

// DereferencedType of this chunk, resolved if it is a reference to anything.
func (c *Chunk) DereferencedTypeV1(stack *CodeV1) types.Type {
	if c.Call == Chunk_PRIMITIVE {
		return c.Primitive.dereferenceTypeV1(types.Type(c.Primitive.Type), stack)
	}

	if c.Function != nil {
		return types.Type(c.Function.Type)
	}

	if c.Primitive != nil {
		return c.Primitive.dereferenceTypeV1(types.Type(c.Primitive.Type), stack)
	}

	return types.Any
}

// ArrayType for the given list of primitives
func ArrayTypeV1(arr []*Primitive, stack *CodeV1) types.Type {
	if len(arr) == 0 {
		return types.Array(types.Unset)
	}

	sharedType := arr[0].dereferenceTypeV1(types.Type(arr[0].Type), stack)
	for i := 1; i < len(arr); i++ {
		// we are done if not all elements have the same type
		ct := arr[i].dereferenceTypeV1(types.Type(arr[i].Type), stack)
		if ct != sharedType {
			return types.Array(types.Any)
		}
	}

	return types.Array(sharedType)
}

// turns any "ref" types into whatever they are referencing
func (p *Primitive) dereferenceTypeV2(typ types.Type, stack *CodeV2) types.Type {
	switch typ.Underlying() {
	case types.Ref:
		ref := uint64(bytes2int(p.Value))
		chunk := stack.Chunk(ref)
		return chunk.Primitive.dereferenceTypeV2(chunk.Type(), stack)
	case types.ArrayLike:
		k := p.dereferenceTypeV2(typ.Child(), stack)
		return types.Array(k)
	case types.MapLike:
		k := p.dereferenceTypeV2(typ.Key(), stack)
		v := p.dereferenceTypeV2(typ.Child(), stack)
		return types.Map(k, v)
	default:
		return typ
	}
}

// ArrayType for the given list of primitives
func ArrayTypeV2(arr []*Primitive, stack *CodeV2) types.Type {
	if len(arr) == 0 {
		return types.Array(types.Unset)
	}

	sharedType := arr[0].dereferenceTypeV2(types.Type(arr[0].Type), stack)
	for i := 1; i < len(arr); i++ {
		// we are done if not all elements have the same type
		ct := arr[i].dereferenceTypeV2(types.Type(arr[i].Type), stack)
		if ct != sharedType {
			return types.Array(types.Any)
		}
	}

	return types.Array(sharedType)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc/parser"
	"go.mondoo.com/mql/types"
)

func compileArrayWhere(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	if call == nil {
		return types.Nil, errors.New("missing filter argument for calling '" + id + "'")
	}
	if len(call.Function) > 1 {
		return types.Nil, errors.New("too many arguments when calling '" + id + "', only 1 is supported")
	}

	// if the where function is called without arguments, we don't have to do anything
	// so we just return the caller type as no additional step in the compiler is necessary
	if len(call.Function) == 0 {
		return typ, nil
	}

	arg := call.Function[0]
	bindingName := "_"
	if arg.Name != "" {
		bindingName = arg.Name
	}

	refs, err := c.blockExpressions([]*parser.Expression{arg.Value}, typ, ref, bindingName)
	if err != nil {
		return types.Nil, err
	}
	if refs.block == 0 {
		return types.Nil, errors.New("called '" + id + "' without a function block")
	}
	ref = refs.binding

	argExpectation := llx.FunctionPrimitive(refs.block)

	// if we have a standalone body in the where clause, then we need to check if
	// it's a value, in which case we need to compare the array value to it
	if refs.isStandalone {
		block := c.Result.CodeV2.Block(refs.block)

		if block == nil {
			return types.Nil, errors.New("cannot find block for standalone compilation of array.where")
		}
		blockValueRef := block.TailRef(refs.block)

		blockTyp := c.Result.CodeV2.DereferencedBlockType(block)
		childType := typ.Child()
		chunkId := "==" + string(childType)
		if blockTyp != childType {
			chunkId = "==" + string(blockTyp)
			_, err := llx.BuiltinFunctionV2(childType, chunkId)
			if err != nil {
				return types.Nil, errors.New("called '" + id + "' with wrong type; either provide a type " + childType.Label() + " value or write it as an expression (e.g. \"_ == 123\")")
			}
		}

		block.AddChunk(c.Result.CodeV2, refs.block, &llx.Chunk{
			Call: llx.Chunk_FUNCTION,
			Id:   chunkId,
			Function: &llx.Function{
				Type:    string(types.Bool),
				Binding: refs.block | 1,
				Args:    []*llx.Primitive{llx.RefPrimitiveV2(blockValueRef)},
			},
		})

		block.Entrypoints = []uint64{block.TailRef(refs.block)}
	}

	args := []*llx.Primitive{
		llx.RefPrimitiveV2(ref),
		argExpectation,
	}
	for _, v := range refs.deps {
		if c.isInMyBlock(v) {
			args = append(args, llx.RefPrimitiveV2(v))
		}
	}
	c.blockDeps = append(c.blockDeps, refs.deps...)

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type:    string(typ),
			Binding: ref,
			Args:    args,
		},
	})
	return typ, nil
}

func compileArrayDuplicates(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	if call != nil && len(call.Function) > 1 {
		return types.Nil, errors.New("too many arguments when calling '" + id + "'")
	} else if call != nil && len(call.Function) == 1 {
		arg := call.Function[0]
		bindingName := "_"
		if arg.Name != "" {
			bindingName = arg.Name
		}

		refs, err := c.blockExpressions([]*parser.Expression{arg.Value}, typ, ref, bindingName)
		if err != nil {
			return types.Nil, err
		}
		if refs.block == 0 {
			return types.Nil, errors.New("called '" + id + "' without a function block")
		}
		ref = refs.binding
		argExpectation := llx.FunctionPrimitive(refs.block)

		if refs.isStandalone {
			return typ, errors.New("called duplicates with a field name on an invalid type")
		}

		args := []*llx.Primitive{
			llx.RefPrimitiveV2(ref),
			argExpectation,
		}

		for _, v := range refs.deps {
			if c.isInMyBlock(v) {
				args = append(args, llx.RefPrimitiveV2(v))
			}
		}
		c.blockDeps = append(c.blockDeps, refs.deps...)

		c.addChunk(&llx.Chunk{
			Call: llx.Chunk_FUNCTION,
			Id:   "fieldDuplicates",
			Function: &llx.Function{
				Type:    string(typ),
				Binding: ref,
				Args:    args,
			},
		})
		return typ, nil
	}

	// Duplicates is being called with 0 arguments, which means it should be on an
	// array of basic types
	ct := typ.Child()
	_, ok := types.Equal[ct]
	if !ok {
		return typ, errors.New("cannot extract duplicates from array, must be a basic type; try using a field argument")
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type:    string(typ),
			Binding: ref,
		},
	})
	return typ, nil
}

func compileArrayUnique(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	if call != nil && len(call.Function) > 0 {
		return types.Nil, errors.New("too many arguments when calling '" + id + "'")
	}

	ct := typ.Child()
	_, ok := types.Equal[ct]
	if !ok {
		return typ, errors.New("cannot extract uniques from array, don't know how to compare entries")
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type:    string(typ),
			Binding: ref,
		},
	})
	return typ, nil
}

func compileArrayContains(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileArrayWhere(c, typ, ref, "where", call)
	if err != nil {
		return types.Nil, err
	}

	// .length
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "length",
		Function: &llx.Function{
			Type:    string(types.Int),
			Binding: c.tailRef(),
		},
	})

	// > 0
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   string(">" + types.Int),
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: c.tailRef(),
			Args: []*llx.Primitive{
				llx.IntPrimitive(0),
			},
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = "[].contains()"

	return types.Bool, nil
}

func compileArrayContainsOnly(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	if call == nil || len(call.Function) != 1 {
		return types.Nil, errors.New("function " + id + " needs one argument (array)")
	}

	f := call.Function[0]
	if f.Value == nil || f.Value.Operand == nil {
		return types.Nil, errors.New("function " + id + " needs one argument (array)")
	}

	val, err := c.compileOperand(f.Value.Operand)
	if err != nil {
		return types.Nil, err
	}

	valType, err := c.dereferenceType(val)
	if err != nil {
		return types.Nil, err
	}

	if valType != typ {
		return types.Nil, errors.New("types don't match for calling contains (got: " + valType.Label() + ", expected: " + typ.Label() + ")")
	}

	// .difference
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "difference",
		Function: &llx.Function{
			Type:    string(typ),
			Binding: ref,
			Args: []*llx.Primitive{
				val,
			},
		},
	})

	// == []
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   string("=="),
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: c.tailRef(),
			Args: []*llx.Primitive{
				llx.ArrayPrimitive([]*llx.Primitive{}, typ.Child()),
			},
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = "[].containsOnly()"

	return types.Bool, nil
}

func compileArrayContainsEq(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call, method string) (types.Type, error) {
	if call == nil || len(call.Function) != 1 {
		return types.Nil, errors.New("function " + id + " needs one argument (array)")
	}

	f := call.Function[0]
	if f.Value == nil || f.Value.Operand == nil {
		return types.Nil, errors.New("function " + id + " needs one argument")
	}

	val, err := c.compileOperand(f.Value.Operand)
	if err != nil {
		return types.Nil, err
	}

	valType, err := c.dereferenceType(val)
	if err != nil {
		return types.Nil, err
	}

	if valType != typ {
		return types.Nil, errors.New("types don't match for calling contains (got: " + valType.Label() + ", expected: " + typ.Label() + ")")
	}

	// .containsNone
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   method,
		Function: &llx.Function{
			Type:    string(typ),
			Binding: ref,
			Args: []*llx.Primitive{
				val,
			},
		},
	})

	// == []
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   string("=="),
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: c.tailRef(),
			Args: []*llx.Primitive{
				llx.ArrayPrimitive([]*llx.Primitive{}, typ.Child()),
			},
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = "[]." + method + "()"

	return types.Bool, nil
}

func compileArrayContainsAll(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	return compileArrayContainsEq(c, typ, ref, id, call, "containsAll")
}

func compileArrayContainsNone(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	return compileArrayContainsEq(c, typ, ref, id, call, "containsNone")
}

func compileArrayAll(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileArrayWhere(c, typ, ref, "$whereNot", call)
	if err != nil {
		return types.Nil, err
	}
	listRef := c.tailRef()

	if err := compileListAssertionMsg(c, typ, ref, listRef, listRef); err != nil {
		return types.Nil, err
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "$all",
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: listRef,
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = "[].all()"

	return types.Bool, nil
}

func compileArrayAny(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileArrayWhere(c, typ, ref, "where", call)
	if err != nil {
		return types.Nil, err
	}
	listRef := c.tailRef()

	if err := compileListAssertionMsg(c, typ, ref, ref, listRef); err != nil {
		return types.Nil, err
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "$any",
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: listRef,
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = "[].any()"

	return types.Bool, nil
}

func compileArrayOne(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileArrayWhere(c, typ, ref, "where", call)
	if err != nil {
		return types.Nil, err
	}
	listRef := c.tailRef()

	if err := compileListAssertionMsg(c, typ, ref, listRef, listRef); err != nil {
		return types.Nil, err
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "$one",
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: listRef,
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = "[].one()"

	return types.Bool, nil
}

func compileArrayNone(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileArrayWhere(c, typ, ref, "where", call)
	if err != nil {
		return types.Nil, err
	}
	listRef := c.tailRef()

	if err := compileListAssertionMsg(c, typ, ref, listRef, listRef); err != nil {
		return types.Nil, err
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "$none",
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: listRef,
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = "[].none()"

	return types.Bool, nil
}

func compileArrayHaving(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileArrayWhere(c, typ, ref, "where", call)
	if err != nil {
		return types.Nil, err
	}
	whereRef := c.tailRef()

	if err := compileListAssertionMsg(c, typ, ref, ref, whereRef); err != nil {
		return types.Nil, err
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "$any",
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: whereRef,
		},
	})
	anyRef := c.tailRef()

	checksum := c.Result.CodeV2.Checksums[anyRef]
	c.Result.Labels.Labels[checksum] = "[].having()"

	c.block.Entrypoints = append(c.block.Entrypoints, anyRef)
	c.block.Datapoints = append(c.block.Datapoints, whereRef)

	c.overrideTailDataRef = whereRef

	return typ, nil
}

func compileArrayMap(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	if call == nil {
		return types.Nil, errors.New("missing filter argument for calling '" + id + "'")
	}
	if len(call.Function) > 1 {
		return types.Nil, errors.New("too many arguments when calling '" + id + "', only 1 is supported")
	}

	// if the map function is called without arguments, we don't have to do anything
	// so we just return the caller type as no additional step in the compiler is necessary
	if len(call.Function) == 0 {
		return typ, nil
	}

	arg := call.Function[0]
	bindingName := "_"
	if arg.Name != "" {
		bindingName = arg.Name
	}

	refs, err := c.blockExpressions([]*parser.Expression{arg.Value}, typ, ref, bindingName)
	if err != nil {
		return types.Nil, err
	}
	if refs.block == 0 {
		return types.Nil, errors.New("called '" + id + "' without a function block")
	}
	ref = refs.binding
	argExpectation := llx.FunctionPrimitive(refs.block)

	block := c.Result.CodeV2.Block(refs.block)
	if len(block.Entrypoints) != 1 {
		return types.Nil, errors.New("called '" + id + "' with a bad function block, you can only return 1 value")
	}
	mappedType := c.Result.CodeV2.DereferencedBlockType(block)

	// The map body's entrypoint is the value this map collects, not something
	// that gets rendered on its own. Mark the block so postCompile won't
	// display-expand a resource(-list) entrypoint into an anonymous `{}` block,
	// which would otherwise make the mapped elements lose their resource type.
	// See https://github.com/mondoohq/mql/issues/8474
	c.valueBodyBlocks[refs.block] = struct{}{}

	args := []*llx.Primitive{
		llx.RefPrimitiveV2(ref),
		argExpectation,
	}
	for _, v := range refs.deps {
		if c.isInMyBlock(v) {
			args = append(args, llx.RefPrimitiveV2(v))
		}
	}
	c.blockDeps = append(c.blockDeps, refs.deps...)

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type:    string(types.Array(mappedType)),
			Binding: ref,
			Args:    args,
		},
	})
	return types.Array(mappedType), nil
}

func compileArrayFlat(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	if call != nil && len(call.Function) > 0 {
		return types.Nil, errors.New("no arguments supported for '" + id + "'")
	}

	for typ.IsArray() {
		typ = typ.Child()
	}
	typ = types.Array(typ)

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type:    string(typ),
			Binding: ref,
		},
	})
	return typ, nil
}

func compileArrayJoin(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	switch typ.Child() {
	case types.String, types.Dict, types.Float, types.Int, types.Bool, types.Nil, types.Regex, types.Version, types.Time, types.Score, types.IP, types.Unset:
	default:
		return types.Nil, errors.New("can only call join() on arrays with elements that can be turned into strings")
	}

	var args []*llx.Primitive = nil
	if call != nil {
		if len(call.Function) > 1 {
			return types.Nil, errors.New("called join() with too many arguments, at most one supported")
		}
		prim, err := callArgTypeIs(c, call, id, "separator", 0, types.String, types.Dict)
		if err != nil {
			return types.Nil, err
		}
		args = []*llx.Primitive{prim}
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type:    string(types.String),
			Binding: ref,
			Args:    args,
		},
	})

	return types.String, nil
}

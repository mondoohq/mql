// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc/parser"
	"go.mondoo.com/mql/types"
)

func compileDictQuery(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
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

	keyType := types.Dict
	valueType := types.Dict
	bindingChecksum := c.Result.CodeV2.Checksums[c.tailRef()]

	blockCompiler := c.newBlockCompiler(&variable{
		typ: typ,
		ref: ref,
	})

	blockCompiler.addArgumentPlaceholder(keyType, bindingChecksum)
	blockCompiler.vars.add("key", variable{
		ref: blockCompiler.tailRef(),
		typ: keyType,
		callback: func() {
			blockCompiler.standalone = false
		},
	})

	blockCompiler.addArgumentPlaceholder(valueType, bindingChecksum)
	blockCompiler.vars.add("value", variable{
		ref: blockCompiler.tailRef(),
		typ: valueType,
		callback: func() {
			blockCompiler.standalone = false
		},
	})

	// we want to make sure the `_` points to the value, which is useful when dealing
	// with arrays and the default in maps
	blockCompiler.Binding.ref = blockCompiler.tailRef()
	if bindingName != "_" {
		blockCompiler.vars.add(bindingName, variable{
			ref: blockCompiler.Binding.ref,
			typ: valueType,
		})
		blockCompiler.bindingIsExplicit = true
	}

	err := blockCompiler.compileExpressions([]*parser.Expression{arg.Value})
	c.Result.Suggestions = append(c.Result.Suggestions, blockCompiler.Result.Suggestions...)
	if err != nil {
		return typ, err
	}

	// if we have a standalone body in the where clause, then we need to check if
	// it's a value, in which case we need to compare the array value to it
	if blockCompiler.standalone {
		block := blockCompiler.block
		blockValueRef := block.TailRef(blockCompiler.blockRef)

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

		block.AddChunk(c.Result.CodeV2, blockCompiler.blockRef, &llx.Chunk{
			Call: llx.Chunk_FUNCTION,
			Id:   chunkId,
			Function: &llx.Function{
				Type:    string(types.Bool),
				Binding: blockCompiler.blockRef | 2,
				Args:    []*llx.Primitive{llx.RefPrimitiveV2(blockValueRef)},
			},
		})

		block.Entrypoints = []uint64{block.TailRef(blockCompiler.blockRef)}
	}

	argExpectation := llx.FunctionPrimitive(blockCompiler.blockRef)

	args := []*llx.Primitive{
		llx.RefPrimitiveV2(ref),
		argExpectation,
	}
	for _, v := range blockCompiler.blockDeps {
		if c.isInMyBlock(v) {
			args = append(args, llx.RefPrimitiveV2(v))
		}
	}
	c.blockDeps = append(c.blockDeps, blockCompiler.blockDeps...)

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

func compileDictWhere(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	return compileDictQuery(c, typ, ref, id, call)
}

func compileDictRecurse(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	return compileDictQuery(c, typ, ref, "recurse", call)
}

func compileDictContains(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileDictQuery(c, typ, ref, "where", call)
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
	lengthRef := c.tailRef()

	// FIXME: DEPRECATED, replace in v12.0 with the use of != empty vv
	// != 0
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   string("!=" + types.Int),
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: lengthRef,
			Args: []*llx.Primitive{
				llx.IntPrimitive(0),
			},
		},
	})
	neq0Ref := c.tailRef()

	// != null
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   string("!=" + types.Nil),
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: ref,
			Args: []*llx.Primitive{
				// Note: we need this for backwards compatibility because labels
				// require 1 argument on < v9.1
				llx.NilPrimitive,
			},
		},
	})
	neqNullRef := c.tailRef()

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   string("&&" + types.Bool),
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: neqNullRef,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2(neq0Ref),
			},
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = "[].contains()"

	return types.Bool, nil
}

func compileDictContainsOnly(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	if call == nil || len(call.Function) != 1 {
		return types.Nil, errors.New("function " + id + " needs one argument (dict)")
	}

	f := call.Function[0]
	if f.Value == nil || f.Value.Operand == nil {
		return types.Nil, errors.New("function " + id + " needs one argument (dict)")
	}

	val, err := c.compileOperand(f.Value.Operand)
	if err != nil {
		return types.Nil, err
	}

	valType, err := c.dereferenceType(val)
	if err != nil {
		return types.Nil, err
	}

	chunkId := "==" + string(typ)
	if valType != typ {
		chunkId = "==" + string(valType)
		_, err := llx.BuiltinFunctionV2(typ, chunkId)
		if err != nil {
			return types.Nil, errors.New("called '" + id + "' with wrong type; either provide a type " + typ.Label() + " value or write it as an expression (e.g. \"_ == 123\")")
		}
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
		Id:   chunkId,
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

func compileDictContainsEq(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call, method string) (types.Type, error) {
	if call == nil || len(call.Function) != 1 {
		return types.Nil, errors.New("function " + id + " needs one argument (dict)")
	}

	f := call.Function[0]
	if f.Value == nil || f.Value.Operand == nil {
		return types.Nil, errors.New("function " + id + " needs one argument (dict)")
	}

	val, err := c.compileOperand(f.Value.Operand)
	if err != nil {
		return types.Nil, err
	}

	valType, err := c.dereferenceType(val)
	if err != nil {
		return types.Nil, err
	}

	chunkId := "==" + string(typ)
	if valType != typ {
		chunkId = "==" + string(valType)
		_, err := llx.BuiltinFunctionV2(typ, chunkId)
		if err != nil {
			return types.Nil, errors.New("called '" + id + "' with wrong type; either provide a type " + typ.Label() + " value or write it as an expression (e.g. \"_ == 123\")")
		}
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
		Id:   chunkId,
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

func compileDictContainsAll(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	return compileDictContainsEq(c, typ, ref, id, call, "containsAll")
}

func compileDictContainsNone(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	return compileDictContainsEq(c, typ, ref, id, call, "containsNone")
}

func compileDictAll(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileDictQuery(c, typ, ref, "$whereNot", call)
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

func compileDictAny(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileDictQuery(c, typ, ref, "where", call)
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

func compileDictOne(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileDictQuery(c, typ, ref, "where", call)
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

func compileDictNone(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileDictQuery(c, typ, ref, "where", call)
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

func compileDictHaving(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileDictQuery(c, typ, ref, "where", call)
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

func compileDictFlat(c *compiler, _ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	if call != nil && len(call.Function) > 0 {
		return types.Nil, errors.New("no arguments supported for '" + id + "'")
	}

	typ := types.Array(types.Dict)
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

func compileMapValues(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	typ = types.Array(typ.Child())
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

func compileMapWhere(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
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

	keyType := typ.Key()
	valueType := typ.Child()
	bindingChecksum := c.Result.CodeV2.Checksums[c.tailRef()]

	blockCompiler := c.newBlockCompiler(&variable{
		typ: typ,
		ref: ref,
	})

	blockCompiler.addArgumentPlaceholder(keyType, bindingChecksum)
	blockCompiler.vars.add("key", variable{
		ref: blockCompiler.tailRef(),
		typ: keyType,
		callback: func() {
			blockCompiler.standalone = false
		},
	})

	blockCompiler.addArgumentPlaceholder(valueType, bindingChecksum)
	blockCompiler.vars.add("value", variable{
		ref: blockCompiler.tailRef(),
		typ: valueType,
		callback: func() {
			blockCompiler.standalone = false
		},
	})

	// we want to make sure the `_` points to the value, which is useful when dealing
	// with arrays and the default in maps
	blockCompiler.Binding.ref = blockCompiler.tailRef()
	if bindingName != "_" {
		blockCompiler.vars.add(bindingName, variable{
			ref: blockCompiler.Binding.ref,
			typ: valueType,
		})
		blockCompiler.bindingIsExplicit = true
	}

	err := blockCompiler.compileExpressions([]*parser.Expression{arg.Value})
	c.Result.Suggestions = append(c.Result.Suggestions, blockCompiler.Result.Suggestions...)
	if err != nil {
		return typ, err
	}

	argExpectation := llx.FunctionPrimitive(blockCompiler.blockRef)

	args := []*llx.Primitive{
		llx.RefPrimitiveV2(ref),
		argExpectation,
	}
	for _, v := range blockCompiler.blockDeps {
		if c.isInMyBlock(v) {
			args = append(args, llx.RefPrimitiveV2(v))
		}
	}
	c.blockDeps = append(c.blockDeps, blockCompiler.blockDeps...)

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

func compileMapContains(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileMapWhere(c, typ, ref, "where", call)
	if err != nil {
		return types.Nil, err
	}
	listRef := c.tailRef()

	if err := compileListAssertionMsg(c, typ, ref, listRef, listRef); err != nil {
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
	c.Result.Labels.Labels[checksum] = "[].contains()"

	return types.Bool, nil
}

func compileMapAll(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileMapWhere(c, typ, ref, "$whereNot", call)
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

func compileMapOne(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileMapWhere(c, typ, ref, "where", call)
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

func compileMapNone(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileMapWhere(c, typ, ref, "where", call)
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

func compileMapHaving(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	_, err := compileMapWhere(c, typ, ref, "where", call)
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
	c.Result.Labels.Labels[checksum] = "{}.having()"

	c.block.Entrypoints = append(c.block.Entrypoints, anyRef)
	c.block.Datapoints = append(c.block.Datapoints, whereRef)

	c.overrideTailDataRef = whereRef

	return typ, nil
}

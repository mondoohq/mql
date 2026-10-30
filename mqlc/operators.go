// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc/parser"
	"go.mondoo.com/mql/types"
)

type fieldCompiler func(*compiler, string, *parser.Call) (types.Type, error)

var operatorsCompilers map[string]fieldCompiler

func init() {
	operatorsCompilers = map[string]fieldCompiler{
		"==":     compileComparable,
		"=~":     compileComparable,
		"!=":     compileComparable,
		"!~":     compileComparable,
		">=":     compileComparable,
		">":      compileComparable,
		"<=":     compileComparable,
		"<":      compileComparable,
		"+":      compileTransformation,
		"-":      compileTransformation,
		"*":      compileTransformation,
		"/":      compileTransformation,
		"%":      nil,
		"=":      compileAssignment,
		"||":     compileComparable,
		"&&":     compileComparable,
		"{}":     compileBlock,
		"if":     compileIf,
		"else":   compileElse,
		"expect": compileExpect,
		"score":  compileScore,
		"typeof": compileTypeof,
		"switch": compileSwitch,
		"Never":  compileNever,
		"empty":  compileEmpty,
	}
}

func compileEmpty(c *compiler, id string, call *parser.Call) (types.Type, error) {
	c.addChunk(&llx.Chunk{
		Call:      llx.Chunk_PRIMITIVE,
		Primitive: llx.EmptyPrimitive,
	})

	return types.Time, nil
}

// compile the operation between two operands A and B
// examples: A && B, A - B, ...
func compileABOperation(c *compiler, id string, call *parser.Call) (uint64, *llx.Chunk, *llx.Primitive, *llx.AssertionMessage, error) {
	if call == nil {
		return 0, nil, nil, nil, errors.New("operation needs a function call")
	}

	if call.Function == nil {
		return 0, nil, nil, nil, errors.New("operation needs a function call")
	}
	if len(call.Function) != 2 {
		if len(call.Function) < 2 {
			return 0, nil, nil, nil, errors.New("missing arguments")
		}
		return 0, nil, nil, nil, errors.New("too many arguments")
	}

	a := call.Function[0]
	b := call.Function[1]
	if a.Name != "" || b.Name != "" {
		return 0, nil, nil, nil, errors.New("calling operations with named arguments is not supported")
	}

	leftRef, err := c.compileAndAddExpression(a.Value)
	if err != nil {
		return 0, nil, nil, nil, err
	}
	left := c.Result.CodeV2.Chunk(leftRef)

	right, err := c.compileExpression(b.Value)
	if err != nil {
		return 0, nil, nil, nil, err
	}

	if left == nil {
		log.Fatal().Msgf("left is nil: %d", leftRef)
	}

	comments := extractComments(a.Value) + "\n" + extractComments(b.Value)
	msg := extractMsgTag(comments)
	if msg == "" {
		return leftRef, left, right, nil, nil
	}

	// if the right-hand argument is directly provided as a primitive, we don't have a way to
	// ref to it in the chunk stack. Since the message tag **may** end up using it,
	// we have to provide it ref'able. So... bit the bullet (for now... seriously if
	// we could do this simpler that'd be great)
	rightRef, ok := right.RefV2()
	if !ok {
		c.addChunk(&llx.Chunk{
			Call:      llx.Chunk_PRIMITIVE,
			Primitive: right,
		})
		rightRef = c.tailRef()
	}

	// these variables are accessible only to comments
	c.vars.add("$expected", variable{ref: rightRef, typ: types.Type(right.Type)})
	c.vars.add("$actual", variable{ref: leftRef, typ: left.Type()})
	if c.Binding != nil {
		c.vars.add("$binding", variable{ref: c.Binding.ref, typ: c.Binding.typ})
	}

	assertionMsg, err := compileAssertionMsg(msg, c)
	if err != nil {
		return 0, nil, nil, nil, err
	}
	return leftRef, left, right, assertionMsg, nil
}

func compileAssignment(c *compiler, id string, call *parser.Call) (types.Type, error) {
	if call == nil {
		return types.Nil, errors.New("assignment needs a function call")
	}

	if call.Function == nil {
		return types.Nil, errors.New("assignment needs a function call")
	}
	if len(call.Function) != 2 {
		if len(call.Function) < 2 {
			return types.Nil, errors.New("missing arguments")
		}
		return types.Nil, errors.New("too many arguments")
	}

	varIdent := call.Function[0]
	varValue := call.Function[1]
	if varIdent.Name != "" || varValue.Name != "" {
		return types.Nil, errors.New("calling operations with named arguments is not supported")
	}

	if varIdent.Value == nil || varIdent.Value.Operand == nil || varIdent.Value.Operand.Value == nil ||
		varIdent.Value.Operand.Value.Ident == nil {
		return types.Nil, errors.New("variable name is not defined")
	}

	name := *varIdent.Value.Operand.Value.Ident
	if name == "" {
		return types.Nil, errors.New("cannot assign to empty variable name")
	}
	if name[0] == '$' {
		return types.Nil, errors.New("illegal character in variable assignment '$'")
	}

	ref, err := c.compileAndAddExpression(varValue.Value)
	if err != nil {
		return types.Nil, err
	}

	c.vars.assign(name, variable{
		name: name,
		ref:  ref,
		typ:  c.Result.CodeV2.Chunk(ref).Type(),
	})

	return types.Nil, nil
}

func compileComparable(c *compiler, id string, call *parser.Call) (types.Type, error) {
	leftRef, leftOrg, right, assertionMsg, err := compileABOperation(c, id, call)
	if err != nil {
		return types.Nil, errors.New("failed to compile: " + err.Error())
	}

	// find specialized or generalized builtin function
	lt := leftOrg.DereferencedTypeV2(c.Result.CodeV2)
	rtChunk := &llx.Chunk{Primitive: right}
	rt := rtChunk.DereferencedTypeV2(c.Result.CodeV2)

	name := id + string(rt)

	// First we look for special functions in MQLc for operators
	var resType types.Type
	h, _ := builtinFunction(lt, name)
	if h != nil {
		resType, err = h.compile(c, lt, leftRef, name, call)
		if err != nil {
			return resType, err
		}

	} else {
		// If we don't find any special operator functions in MQLc we look at LLX to see if any are defined there
		h, err := llx.BuiltinFunctionV2(lt, name)
		if err != nil {
			h, err = llx.BuiltinFunctionV2(lt, id)
		}
		if err != nil {
			name = id + string(rt.Underlying())
			h, err = llx.BuiltinFunctionV2(lt, name)
		}
		if err != nil {
			return types.Nil, errors.New("cannot find operator handler: " + lt.Label() + " " + id + " " + types.Type(right.Type).Label())
		}
		if h.Compiler != nil {
			name, err = h.Compiler(lt, rt)
			if err != nil {
				return types.Nil, err
			}
		}

		c.addChunk(&llx.Chunk{
			Call: llx.Chunk_FUNCTION,
			Id:   name,
			Function: &llx.Function{
				Type:    string(types.Bool),
				Binding: leftRef,
				Args:    []*llx.Primitive{right},
			},
		})
		resType = types.Bool
	}

	if assertionMsg != nil {
		if c.Result.CodeV2.Assertions == nil {
			c.Result.CodeV2.Assertions = map[uint64]*llx.AssertionMessage{}
		}
		c.Result.CodeV2.Assertions[c.tailRef()] = assertionMsg
	}

	return resType, nil
}

func compileTransformation(c *compiler, id string, call *parser.Call) (types.Type, error) {
	leftRef, left, right, _, err := compileABOperation(c, id, call)
	if err != nil {
		return types.Nil, err
	}

	// find specialized or generalized builtin function
	lt := left.DereferencedTypeV2(c.Result.CodeV2)
	rt := (&llx.Chunk{Primitive: right}).DereferencedTypeV2(c.Result.CodeV2)

	name := id + string(rt)
	h, err := llx.BuiltinFunctionV2(lt, name)
	if err != nil {
		h, err = llx.BuiltinFunctionV2(lt, id)
	}
	if err != nil {
		name = id + string(rt.Underlying())
		h, err = llx.BuiltinFunctionV2(lt, name)
	}
	if err != nil {
		return types.Nil, errors.New("cannot find operator handler: " + lt.Label() + " " + id + " " + types.Type(right.Type).Label())
	}

	if h.Compiler != nil {
		name, err = h.Compiler(lt, rt)
		if err != nil {
			return types.Nil, err
		}
	}

	// An empty array literal carries no element type, so `[] + ["a"]` would
	// otherwise report []unset and break any downstream call that needs a
	// concrete element type. Resolve it from whichever operand knows it. This is
	// done after the handler lookup above so the resolved function is unchanged.
	lt = types.CoalesceArrays(lt, rt)

	returnType := h.Typ
	if returnType == types.NoType {
		returnType = lt
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   name,
		Function: &llx.Function{
			Type:    string(returnType),
			Binding: leftRef,
			Args:    []*llx.Primitive{right},
		},
	})

	return lt, nil
}

func (c *compiler) generateEntrypoints(arg *llx.Primitive) error {
	code := c.Result.CodeV2

	ref, ok := arg.RefV2()
	if !ok {
		return nil
	}

	refobj := code.Chunk(ref)
	if refobj == nil {
		return errors.New("failed to get code reference on expect call, this shouldn't happen")
	}

	reffunc := refobj.Function
	if reffunc == nil {
		return nil
	}

	// if the left argument is not a primitive but a calculated value
	bind := code.Chunk(reffunc.Binding)
	if bind.Primitive == nil {
		c.block.Entrypoints = append(c.block.Entrypoints, reffunc.Binding)
	}

	for i := range reffunc.Args {
		arg := reffunc.Args[i]
		i, ok := arg.RefV2()
		if ok {
			c.block.Entrypoints = append(c.block.Entrypoints, i)
		}
	}
	return nil
}

func compileBlock(c *compiler, id string, call *parser.Call) (types.Type, error) {
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type: string(types.Unset),
			Args: []*llx.Primitive{},
		},
	})
	return types.Unset, nil
}

func compileIf(c *compiler, id string, call *parser.Call) (types.Type, error) {
	if call == nil {
		return types.Nil, errors.New("need conditional arguments for if-clause")
	}
	if len(call.Function) < 1 {
		return types.Nil, errors.New("missing parameters for if-clause, it requires 1")
	}
	arg := call.Function[0]
	if arg.Name != "" {
		return types.Nil, errors.New("called if-clause with a named argument, which is not supported")
	}

	// if we are in a chained if-else call (needs previous if-call)
	if c.prevID == "else" && len(c.block.Chunks) != 0 {
		maxRef := len(c.block.Chunks) - 1
		prev := c.block.Chunks[maxRef]
		if prev.Id == "if" {
			// we need to pop off the last "if" chunk as the new condition needs to
			// be added in front of it
			c.popChunk()

			argValue, err := c.compileExpression(arg.Value)
			if err != nil {
				return types.Nil, err
			}

			// now add back the last chunk and append the newly compiled condition
			c.addChunk(prev)
			// We do not need to add it back as an entrypoint here. It happens below
			// outside this block

			prev.Function.Args = append(prev.Function.Args, argValue)

			c.prevID = "if"
			return types.Nil, nil
		}
	}

	argValue, err := c.compileExpression(arg.Value)
	if err != nil {
		return types.Nil, err
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type: string(types.Unset),
			Args: []*llx.Primitive{argValue},
		},
	})
	c.block.Entrypoints = append(c.block.Entrypoints, c.tailRef())
	c.prevID = "if"

	return types.Nil, nil
}

func compileElse(c *compiler, id string, call *parser.Call) (types.Type, error) {
	if call != nil {
		return types.Nil, errors.New("cannot have conditional arguments for else-clause, use another if-statement")
	}

	if len(c.block.Chunks) == 0 {
		return types.Nil, errors.New("can only use else-statement after a preceding if-statement")
	}

	prev := c.block.Chunks[len(c.block.Chunks)-1]
	if prev.Id != "if" {
		return types.Nil, errors.New("can only use else-statement after a preceding if-statement")
	}

	if c.prevID != "if" {
		return types.Nil, errors.New("can only use else-statement after a preceding if-statement (internal reference is wrong)")
	}

	c.prevID = "else"

	return types.Nil, nil
}

func compileExpect(c *compiler, id string, call *parser.Call) (types.Type, error) {
	if call == nil || len(call.Function) < 1 {
		return types.Nil, errors.New("missing parameter for '" + id + "', it requires 1")
	}
	if len(call.Function) > 1 {
		return types.Nil, errors.New("called '" + id + "' with too many arguments, it requires 1")
	}

	arg := call.Function[0]
	if arg.Name != "" {
		return types.Nil, errors.New("called '" + id + "' with a named argument, which is not supported")
	}

	argValue, err := c.compileExpression(arg.Value)
	if err != nil {
		return types.Nil, err
	}

	if err = c.generateEntrypoints(argValue); err != nil {
		return types.Nil, err
	}

	typ := types.Bool
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type: string(typ),
			Args: []*llx.Primitive{argValue},
		},
	})
	c.block.Entrypoints = append(c.block.Entrypoints, c.tailRef())

	return typ, nil
}

func compileScore(c *compiler, id string, call *parser.Call) (types.Type, error) {
	if call == nil || len(call.Function) < 1 {
		return types.Nil, errors.New("missing parameter for '" + id + "', it requires 1")
	}

	arg := call.Function[0]
	if arg == nil || arg.Value == nil || arg.Value.Operand == nil || arg.Value.Operand.Value == nil {
		return types.Nil, errors.New("failed to get parameter for '" + id + "'")
	}

	argValue, err := c.compileExpression(arg.Value)
	if err != nil {
		return types.Nil, err
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "score",
		Function: &llx.Function{
			Type: string(types.Score),
			Args: []*llx.Primitive{argValue},
		},
	})

	return types.Score, nil
}

func compileTypeof(c *compiler, id string, call *parser.Call) (types.Type, error) {
	if call == nil || len(call.Function) < 1 {
		return types.Nil, errors.New("missing parameter for '" + id + "', it requires 1")
	}

	arg := call.Function[0]
	if arg == nil || arg.Value == nil || arg.Value.Operand == nil || arg.Value.Operand.Value == nil {
		return types.Nil, errors.New("failed to get parameter for '" + id + "'")
	}

	argValue, err := c.compileExpression(arg.Value)
	if err != nil {
		return types.Nil, err
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "typeof",
		Function: &llx.Function{
			Type: string(types.String),
			Args: []*llx.Primitive{argValue},
		},
	})

	return types.String, nil
}

func compileSwitch(c *compiler, id string, call *parser.Call) (types.Type, error) {
	var ref *llx.Primitive

	if call != nil && len(call.Function) != 0 {
		arg := call.Function[0]
		if arg.Name != "" {
			return types.Nil, errors.New("called `" + id + "` with a named argument, which is not supported")
		}

		argValue, err := c.compileExpression(arg.Value)
		if err != nil {
			return types.Nil, err
		}

		ref = argValue
	} else {
		ref = &llx.Primitive{Type: string(types.Unset)}
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type: string(types.Unset),
			Args: []*llx.Primitive{ref},
		},
	})
	c.prevID = "switch"

	return types.Nil, nil
}

func compileNever(c *compiler, id string, call *parser.Call) (types.Type, error) {
	c.addChunk(&llx.Chunk{
		Call:      llx.Chunk_PRIMITIVE,
		Primitive: llx.NeverFuturePrimitive,
	})

	return types.Time, nil
}

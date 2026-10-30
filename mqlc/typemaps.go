// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc/parser"
	"go.mondoo.com/mql/types"
)

var typeConversions map[string]fieldCompiler

func init() {
	typeConversions = map[string]fieldCompiler{
		"bool":    compileTypeConversion("bool", types.Bool),
		"int":     compileTypeConversion("int", types.Int),
		"float":   compileTypeConversion("float", types.Float),
		"string":  compileTypeConversion("string", types.String),
		"regex":   compileTypeConversion("$regex", types.Regex),
		"dict":    compileTypeConversion("dict", types.Dict),
		"version": compileTypeConversion("version", types.Version),
		"ip":      compileTypeConversion("ip", types.IP),
		// FIXME: DEPRECATED, remove in v13.0 vv
		"semver": compileTypeConversion("semver", types.Version), // deprecated
		//
	}
}

var errNotConversion = errors.New("not a type-conversion")

func compileTypeConversion(llxID string, typ types.Type) fieldCompiler {
	return func(c *compiler, id string, call *parser.Call) (types.Type, error) {
		if call == nil || len(call.Function) < 1 {
			return types.Nil, errNotConversion
		}

		otherMap := map[string]*llx.Primitive{}
		args := []*llx.Primitive{}
		for i := range call.Function {
			arg := call.Function[i]
			if arg == nil || arg.Value == nil || arg.Value.Operand == nil || arg.Value.Operand.Value == nil {
				return types.Nil, errors.New("failed to get parameter for '" + id + "'")
			}

			argValue, err := c.compileExpression(arg.Value)
			if err != nil {
				return types.Nil, err
			}
			if arg.Name != "" {
				otherMap[arg.Name] = argValue
			} else {
				args = append(args, argValue)
			}
		}

		if len(otherMap) != 0 {
			args = append(args, llx.MapPrimitive(otherMap, types.Any))
		}

		c.addChunk(&llx.Chunk{
			Call: llx.Chunk_FUNCTION,
			Id:   llxID,
			Function: &llx.Function{
				Type: string(typ),
				Args: args,
			},
		})

		return typ, nil
	}
}

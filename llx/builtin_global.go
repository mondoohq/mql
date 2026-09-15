// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"strconv"
	"strings"

	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/versionx"
)

// handleGlobal takes a global function and returns a handler if found.
// this is not exported as it is only used internally. it exposes everything
// below this function
func handleGlobalV2(op string) (handleFunctionV2, bool) {
	f, ok := globalFunctionsV2[op]
	if !ok {
		return nil, false
	}
	return f, true
}

// DEFINITIONS

type handleFunctionV2 func(*blockExecutor, *Function, uint64) (*RawData, uint64, error)

var globalFunctionsV2 map[string]handleFunctionV2

func init() {
	globalFunctionsV2 = map[string]handleFunctionV2{
		"expect":         expectV2,
		"if":             ifCallV2,
		"switch":         switchCallV2,
		"score":          scoreCallV2,
		"typeof":         typeofCallV2,
		"{}":             blockV2,
		"return":         returnCallV2,
		"createResource": globalCreateResource,
		// type-conversions
		"string":  stringCall,
		"$regex":  regexCall, // TODO: support both the regex resource and the internal typemap!
		"float":   floatCall,
		"int":     intCall,
		"bool":    boolCall,
		"dict":    dictCall,
		"version": versionCall,
		"ip":      ipCall,
		// FIXME: DEPRECATED, remove in v13.0 vv
		"semver": versionCall, // deprecated
		// ^^
	}
}

func globalCreateResource(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if l := len(f.Args); l%2 != 1 || l == 0 {
		return nil, 0, errors.New("called `createResource` with invalid number of arguments")
	}

	binding, ok := f.Args[0].RefV2()
	if !ok {
		return nil, 0, errors.New("called `createResource` with invalid arguments: expected ref")
	}

	t := types.Type(f.Type)
	return e.createResource(t.ResourceName(), binding, &Function{
		Type: f.Type,
		Args: f.Args[1:],
	}, ref)
}

func ifCallV2(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if len(f.Args) < 3 {
		return nil, 0, errors.New("Called if with " + strconv.Itoa(len(f.Args)) + " arguments, expected at least 3")
	}

	var idx int
	max := len(f.Args)
	for idx+2 < max {
		res, dref, err := e.resolveValue(f.Args[idx], ref)
		if dref != 0 || (err != nil && res == nil) {
			return res, dref, err
		}
		if res.Error != nil {
			return NilData, 0, res.Error
		}

		if truthy, _ := res.IsTruthy(); truthy {
			depArgs := f.Args[idx+2]
			res, dref, err = e.runBlock(nil, f.Args[idx+1], depArgs.Array, ref)
			return res, dref, err
		}

		idx += 3
	}

	if idx < max {
		depArgs := f.Args[idx+1]
		res, dref, err := e.runBlock(nil, f.Args[idx], depArgs.Array, ref)
		return res, dref, err
	}

	return NilData, 0, nil
}

func switchCallV2(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	// very similar to the if-call above; minor differences:
	// - we have an optional reference value (which is in the function call)
	// - default is translated to `true` in its condition; everything else is a function

	if len(f.Args) < 2 {
		return nil, 0, errors.New("called switch with no arguments, expected at least one case statement")
	}

	var bind *RawData
	if types.Type(f.Args[0].Type) != types.Unset {
		var dref uint64
		var err error
		bind, dref, err = e.resolveValue(f.Args[0], ref)
		if err != nil || dref != 0 || bind == nil {
			return bind, dref, err
		}
	}

	// ignore the first argument, it's just the reference value
	idx := 1
	max := len(f.Args)
	defaultCaseIdx := -1
	for idx+2 < max {
		// the default case is marked with an unset condition primitive by the
		// compiler, so it can be told apart from a real case with a constant
		// boolean condition (`case true:` / `case false:`). See mondoohq/mql#1174.
		if types.Type(f.Args[idx].Type) == types.Unset {
			defaultCaseIdx = idx
			idx += 3
			continue
		}

		res, dref, err := e.resolveValue(f.Args[idx], ref)
		if err != nil || dref != 0 || res == nil {
			return res, dref, err
		}

		if truthy, _ := res.IsTruthy(); truthy {
			depArgs := f.Args[idx+2]
			res, dref, err = e.runBlock(bind, f.Args[idx+1], depArgs.Array, ref)
			return res, dref, err
		}

		idx += 3
	}

	if defaultCaseIdx != -1 {
		res, dref, err := e.runBlock(nil, f.Args[defaultCaseIdx+1], f.Args[defaultCaseIdx+2].Array, ref)
		return res, dref, err
	}

	return NilData, 0, nil
}

func scoreCallV2(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if len(f.Args) != 1 {
		return nil, 0, errors.New("Called `score` with " + strconv.Itoa(len(f.Args)) + " arguments, expected one")
	}

	res, dref, err := e.resolveValue(f.Args[0], ref)
	if err != nil || dref != 0 || res == nil {
		return res, dref, err
	}

	var b []byte
	switch res.Type {
	case types.Int:
		b, err = scoreVector(int32(res.Value.(int64)))

	case types.Float:
		b, err = scoreVector(int32(res.Value.(float64)))

	case types.String:
		b, err = scoreString(res.Value.(string))
	}

	if err != nil {
		return nil, 0, err
	}

	return ScoreData(b), 0, nil
}

func typeofCallV2(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if len(f.Args) != 1 {
		return nil, 0, errors.New("Called `typeof` with " + strconv.Itoa(len(f.Args)) + " arguments, expected one")
	}

	res, dref, err := e.resolveValue(f.Args[0], ref)
	if err != nil || dref != 0 || res == nil {
		return res, dref, err
	}

	return StringData(res.Type.Label()), 0, nil
}

func versionCall(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if len(f.Args) == 0 {
		return nil, 0, errors.New("called `version` with no arguments, expected one")
	}

	arg := f.Args[0]
	res, dref, err := e.resolveValue(arg, ref)
	if err != nil || dref != 0 || res == nil {
		return res, dref, err
	}

	raw, ok := res.Value.(string)
	if !ok {
		return nil, 0, errors.New("called `version` with unsupported type (expected string)")
	}

	version := versionx.Parse(raw)

	for i := 1; i < len(f.Args); i++ {
		arg := f.Args[i]
		if !types.Type(arg.Type).IsMap() {
			return nil, 0, errors.New("called `version` with unknown argument, expected one string")
		}
		for k, v := range arg.Map {
			switch k {
			case "type":
				t, ok := v.RawData().Value.(string)
				if !ok {
					return nil, 0, errors.New("unsupported `type` value in `version` call")
				}
				typ := strings.ToLower(t)
				switch typ {
				case "semver":
					if version.Kind() != versionx.KindSemver {
						return &RawData{Error: errors.New("version '" + raw + "' is not a semantic version"), Value: raw, Type: types.Version}, 0, nil
					}
				case "debian":
					// KindGeneric counts: the debian format is upstream + revision with
					// no constraint on the upstream part, so "1.1.1k-12.el8" is a debian
					// version even though it is not a semantic one. It used to be
					// rejected here only because the parser underneath was semver-only.
					switch version.Kind() {
					case versionx.KindSemver, versionx.KindDebian, versionx.KindGeneric:
					default:
						return &RawData{Error: errors.New("version '" + raw + "' is not a debian version"), Value: raw, Type: types.Version}, 0, nil
					}
				case "python":
					if version.Kind() != versionx.KindSemver && version.Kind() != versionx.KindPython {
						return &RawData{Error: errors.New("version '" + raw + "' is not a python version"), Value: raw, Type: types.Version}, 0, nil
					}
				case "all":
					break
				default:
					return nil, 0, errors.New("unsupported `type=" + t + "` in `version` call")
				}
			}
		}
	}

	return &RawData{Type: types.Version, Value: res.Value}, 0, nil
}

func ipCall(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if len(f.Args) == 0 {
		return nil, 0, errors.New("called `ip` with no arguments, expected one")
	}

	arg := f.Args[0]

	var (
		res  *RawData
		dref uint64
		err  error
	)

	switch arg.Type {
	case string(types.String), string(types.Int), string(types.Dict):
		res, dref, err = e.resolveValue(arg, ref)
	case string(types.Ref):
		srcRef, _ := arg.RefV2()
		res, dref, err = e.resolveRef(srcRef, ref)
	default:
		return nil, 0, errors.New("called `ip` with incorrect argument type, expected string or int")
	}

	if err != nil || dref != 0 || res == nil {
		return res, dref, err
	}

	ip, ok := any2ip(res.Value)
	if !ok {
		return nil, 0, errors.New("called `ip` with unsupported type (expected string, int or IP)")
	}
	return IPData(ip), 0, nil
}

func stringCall(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if len(f.Args) != 1 {
		return nil, 0, errors.New("Called `string` with " + strconv.Itoa(len(f.Args)) + " arguments, expected one")
	}

	res, dref, err := e.resolveValue(f.Args[0], ref)
	if err != nil || dref != 0 || res == nil {
		return res, dref, err
	}

	switch v := res.Value.(type) {
	case string:
		return StringData(v), 0, nil
	case int64:
		i := strconv.FormatInt(v, 10)
		return StringData(i), 0, nil
	case float64:
		f := strconv.FormatFloat(v, 'f', 2, 64)
		return StringData(f), 0, nil
	case bool:
		if v {
			return StringData("true"), 0, nil
		}
		return StringData("false"), 0, nil
	default:
		return NilData, 0, nil
	}
}

func regexCall(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if len(f.Args) != 1 {
		return nil, 0, errors.New("Called `regex` with " + strconv.Itoa(len(f.Args)) + " arguments, expected one")
	}

	res, dref, err := e.resolveValue(f.Args[0], ref)
	if err != nil || dref != 0 || res == nil {
		return res, dref, err
	}

	switch v := res.Value.(type) {
	case string:
		return RegexData(v), 0, nil
	case int64:
		i := strconv.FormatInt(v, 10)
		return RegexData(i), 0, nil
	case float64:
		f := strconv.FormatFloat(v, 'f', 2, 64)
		return RegexData(f), 0, nil
	case bool:
		if v {
			return RegexData("true"), 0, nil
		}
		return RegexData("false"), 0, nil
	default:
		return NilData, 0, nil
	}
}

func intCall(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if len(f.Args) != 1 {
		return nil, 0, errors.New("Called `int` with " + strconv.Itoa(len(f.Args)) + " arguments, expected one")
	}

	res, dref, err := e.resolveValue(f.Args[0], ref)
	if err != nil || dref != 0 || res == nil {
		return res, dref, err
	}

	switch v := res.Value.(type) {
	case string:
		i, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, 0, err
		}
		return IntData(i), 0, nil
	case int64:
		return IntData(v), 0, nil
	case float64:
		return IntData(int64(v)), 0, nil
	case bool:
		if v {
			return IntData(1), 0, nil
		}
		return IntData(0), 0, nil
	default:
		return NilData, 0, nil
	}
}

func floatCall(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if len(f.Args) != 1 {
		return nil, 0, errors.New("Called `float` with " + strconv.Itoa(len(f.Args)) + " arguments, expected one")
	}

	res, dref, err := e.resolveValue(f.Args[0], ref)
	if err != nil || dref != 0 || res == nil {
		return res, dref, err
	}

	switch v := res.Value.(type) {
	case string:
		i, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, 0, err
		}
		return FloatData(i), 0, nil
	case int64:
		return FloatData(float64(v)), 0, nil
	case float64:
		return FloatData(v), 0, nil
	case bool:
		if v {
			return FloatData(1), 0, nil
		}
		return FloatData(0), 0, nil
	default:
		return NilData, 0, nil
	}
}

func boolCall(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if len(f.Args) != 1 {
		return nil, 0, errors.New("Called `bool` with " + strconv.Itoa(len(f.Args)) + " arguments, expected one")
	}

	res, dref, err := e.resolveValue(f.Args[0], ref)
	if err != nil || dref != 0 || res == nil {
		return res, dref, err
	}

	switch v := res.Value.(type) {
	case string:
		return BoolData(v == "true"), 0, nil
	case int64:
		return BoolData(v != 0), 0, nil
	case float64:
		return BoolData(v != 0), 0, nil
	case bool:
		return BoolData(v), 0, nil
	default:
		return NilData, 0, nil
	}
}

func dictCall(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if len(f.Args) != 1 {
		return nil, 0, errors.New("Called `dict` with " + strconv.Itoa(len(f.Args)) + " arguments, expected one")
	}

	res, dref, err := e.resolveValue(f.Args[0], ref)
	if err != nil || dref != 0 || res == nil {
		return res, dref, err
	}

	switch v := res.Value.(type) {
	case string, int64, float64, bool, []any, map[string]any:
		return DictData(v), 0, nil
	default:
		return NilData, 0, nil
	}
}

func expectV2(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if len(f.Args) != 1 {
		return nil, 0, errors.New("Called expect with " + strconv.Itoa(len(f.Args)) + " arguments, expected 1")
	}
	res, dref, err := e.resolveValue(f.Args[0], ref)
	if res != nil && res.Type != types.Bool {
		return nil, 0, errors.New("called expect body with wrong type, it should be a boolean (type mismatch)")
	}
	return res, dref, err
}

func blockV2(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	if len(f.Args) != 1 {
		return nil, 0, errors.New("Called block with " + strconv.Itoa(len(f.Args)) + " arguments, expected 1")
	}
	// This handler is registered for "{}" but was never implemented. Return a
	// contextual error instead of panicking so a query that reaches it fails
	// gracefully and identifiably rather than crashing the executor.
	return nil, 0, errors.New("block call is not implemented: " + e.refContext(ref))
}

func returnCallV2(e *blockExecutor, f *Function, ref uint64) (*RawData, uint64, error) {
	arg := f.Args[0]
	return e.resolveValue(arg, ref)
}

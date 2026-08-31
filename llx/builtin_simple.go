// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"go.mondoo.com/mql/types"
)

// run an operation that returns true/false on a bind data vs a chunk call.
// Unlike boolOp we don't check if either side is nil
func rawboolOpV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, f func(*RawData, *RawData) bool) (*RawData, uint64, error) {
	v, dref, err := e.resolveValue(chunk.Function.Args[0], ref)
	if err != nil {
		return nil, 0, err
	}
	if dref != 0 {
		return nil, dref, nil
	}
	return BoolData(f(bind, v)), 0, nil
}

// run an operation that returns true/false on a bind data vs a chunk call.
// Unlike boolOp we don't check if either side is nil. It inverts the
// returned boolean from the child function.
func rawboolNotOpV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, f func(*RawData, *RawData) bool) (*RawData, uint64, error) {
	v, dref, err := e.resolveValue(chunk.Function.Args[0], ref)
	if err != nil {
		return nil, 0, err
	}
	if dref != 0 {
		return nil, dref, nil
	}
	return BoolData(!f(bind, v)), 0, nil
}

// run an operation that returns true/false on a bind data vs a chunk call.
// this includes handling for the case where either side is nil, i.e.
// - if both sides are nil we return true
// - if either side is nil but not the other we return false
func boolOpV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, f func(any, any) bool) (*RawData, uint64, error) {
	v, dref, err := e.resolveValue(chunk.Function.Args[0], ref)
	if err != nil {
		return nil, 0, err
	}
	if dref != 0 {
		return nil, dref, nil
	}

	if bind.Value == nil {
		return BoolData(v.Value == nil), 0, nil
	}
	if v == nil || v.Value == nil {
		return BoolData(false), 0, nil
	}

	return BoolData(f(bind.Value, v.Value)), 0, nil
}

// boolOrOp behaves like boolOp, but checks if the left argument is true first
// (and stop if it is). Only then proceeds to check the right argument.
func boolOrOpV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, fLeft func(any) bool, fRight func(any) bool) (*RawData, uint64, error) {
	if bind.Value != nil && fLeft(bind.Value) {
		return BoolData(true), 0, nil
	}

	v, dref, err := e.resolveValue(chunk.Function.Args[0], ref)
	if err != nil {
		return nil, 0, err
	}
	if dref != 0 {
		return nil, dref, nil
	}

	// A null left side is falsy, so the result is whatever the right side says -
	// exactly what a false left side does. This branch used to carry the AND
	// rule verbatim (`v.Value == nil`), which made `null || true` return false:
	// wrong under three-valued logic, wrong under null-as-false, and wrong under
	// null-as-true. Falling through to the shared tail is the whole fix.
	if v == nil || v.Value == nil {
		return BoolData(false), 0, nil
	}

	return BoolData(fRight(v.Value)), 0, nil
}

// boolAndOp behaves like boolOp, but checks if the left argument is falsy first
// (and stops if it is). Only then proceeds to check the right argument.
//
// A null operand is falsy. It used to be its own case, returning true when the
// other side was also null, which made `a && b` pass when neither a nor b could
// be read - an assertion reporting success over two values it never measured.
// Nine providers grew regression tests to keep their resources from tripping it.
// Treating null as falsy removes the case rather than special-casing it: null
// now takes the identical path false takes, including the short circuit.
//
// Comparison stays untouched. `null == null` is still true, because asking
// whether two absent values are equal is a different question from asking
// whether an absent value satisfies a check.
func boolAndOpV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, fLeft func(any) bool, fRight func(any) bool) (*RawData, uint64, error) {
	arg := chunk.Function.Args[0]

	if bind.Value == nil || !fLeft(bind.Value) {
		// if the left side is falsy, we can return false immediately
		// We need to write a nil result for the right side to avoid
		// it being executed, for example to get its data for the
		// datapoints
		typ := types.Type(arg.Type)
		switch typ.Underlying() {
		case types.Ref:
			rRef := uint64(bytes2int(arg.Value))
			e.cache.Store(rRef, &stepCache{
				Result: &RawData{
					Type:  typ,
					Value: nil,
				},
			})
		}
		return BoolData(false), 0, nil
	}

	v, dref, err := e.resolveValue(arg, ref)
	if err != nil {
		return nil, 0, err
	}
	if dref != 0 {
		return nil, dref, nil
	}

	if v == nil || v.Value == nil {
		return BoolData(false), 0, nil
	}
	return BoolData(fRight(v.Value)), 0, nil
}

func boolNotOpV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, f func(any, any) bool) (*RawData, uint64, error) {
	v, dref, err := e.resolveValue(chunk.Function.Args[0], ref)
	if err != nil {
		return nil, 0, err
	}
	if dref != 0 {
		return nil, dref, nil
	}

	if bind.Value == nil {
		return BoolData(v.Value != nil), 0, nil
	}
	if v == nil || v.Value == nil {
		return BoolData(true), 0, nil
	}

	return BoolData(!f(bind.Value, v.Value)), 0, nil
}

func dataOpV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, typ types.Type, f func(any, any) *RawData) (*RawData, uint64, error) {
	v, dref, err := e.resolveValue(chunk.Function.Args[0], ref)
	if err != nil {
		return nil, 0, err
	}
	if dref != 0 {
		return nil, dref, nil
	}

	if bind.Value == nil {
		return &RawData{Type: typ}, 0, nil
	}
	if v == nil || v.Value == nil {
		return &RawData{Type: typ}, 0, nil
	}

	return f(bind.Value, v.Value), 0, nil
}

func nonNilDataOpV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, typ types.Type, f func(any, any) *RawData) (*RawData, uint64, error) {
	if bind.Value == nil {
		// For comparison operations, a null operand means the comparison
		// is undefined and evaluates to false (e.g. a missing config param
		// is not <= 4). This intentionally departs from SQL NULL semantics
		// (which would return NULL/unknown); we return false so that policy
		// checks against absent values fail rather than error.
		return BoolData(false), 0, nil
	}

	v, dref, err := e.resolveValue(chunk.Function.Args[0], ref)
	if err != nil {
		return nil, 0, err
	}
	if dref != 0 {
		return nil, dref, nil
	}

	if v == nil || v.Value == nil {
		return BoolData(false), 0, nil
	}

	return f(bind.Value, v.Value), 0, nil
}

func nonNilDataOpT[T any](e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, typ types.Type, f func(T, T) *RawData) (*RawData, uint64, error) {
	if bind.Value == nil {
		// Null operand: comparison is undefined, return false. See nonNilDataOpV2.
		return BoolData(false), 0, nil
	}

	v, dref, err := e.resolveValue(chunk.Function.Args[0], ref)
	if err != nil {
		return nil, 0, err
	}
	if dref != 0 {
		return nil, dref, nil
	}

	if v == nil || v.Value == nil {
		return BoolData(false), 0, nil
	}

	l, ok := bind.Value.(T)
	if !ok {
		return nil, 0, errors.New("incorrect internal data type for left operand, expected " + typ.Label())
	}
	r, ok := v.Value.(T)
	if !ok {
		return nil, 0, errors.New("incorrect internal data type for right operand, expected " + typ.Label())
	}

	return f(l, r), 0, nil
}

// for equality and inequality checks that are pre-determined
// we need to catch the case where both values end up nil

func chunkEqTrueV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, func(a any, b any) bool {
		return true
	})
}

func chunkEqFalseV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, func(a any, b any) bool {
		return false
	})
}

func chunkNeqFalseV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, func(a any, b any) bool {
		return true
	})
}

func chunkNeqTrueV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, func(a any, b any) bool {
		return false
	})
}

func bindingEqNil(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolData(bind.Value == nil), 0, nil
}

func bindingNeqNil(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolData(bind.Value != nil), 0, nil
}

// raw operator handling
// ==   !=

func opBoolCmpBool(left any, right any) bool {
	return left.(bool) == right.(bool)
}

func opIntCmpInt(left any, right any) bool {
	return left.(int64) == right.(int64)
}

func opFloatCmpFloat(left any, right any) bool {
	return left.(float64) == right.(float64)
}

func opStringCmpString(left any, right any) bool {
	return left.(string) == right.(string)
}

func opTimeCmpTime(left any, right any) bool {
	l := left.(*time.Time)
	r := right.(*time.Time)
	if l == nil {
		return r == nil
	}
	if r == nil {
		return false
	}

	if (l.Equal(NeverPastTime) || l.Equal(NeverFutureTime)) && (r.Equal(NeverPastTime) || r.Equal(NeverFutureTime)) {
		return true
	}

	return (*l).Equal(*r)
}

func opStringCmpInt(left any, right any) bool {
	return left.(string) == strconv.FormatInt(right.(int64), 10)
}

func opIntCmpString(left any, right any) bool {
	return right.(string) == strconv.FormatInt(left.(int64), 10)
}

func opStringCmpFloat(left any, right any) bool {
	return left.(string) == strconv.FormatFloat(right.(float64), 'f', -1, 64)
}

func opFloatCmpString(left any, right any) bool {
	return right.(string) == strconv.FormatFloat(left.(float64), 'f', -1, 64)
}

func opStringCmpRegex(left any, right any) bool {
	return compiledRegex(right.(string)).MatchString(left.(string))
}

func opRegexCmpString(left any, right any) bool {
	return compiledRegex(left.(string)).MatchString(right.(string))
}

func opRegexCmpInt(left any, right any) bool {
	return opStringCmpRegex(strconv.FormatInt(right.(int64), 10), left.(string))
}

func opIntCmpRegex(left any, right any) bool {
	return opStringCmpRegex(strconv.FormatInt(left.(int64), 10), right.(string))
}

func opRegexCmpFloat(left any, right any) bool {
	return opStringCmpRegex(strconv.FormatFloat(right.(float64), 'f', -1, 64), left.(string))
}

func opFloatCmpRegex(left any, right any) bool {
	return opStringCmpRegex(strconv.FormatFloat(left.(float64), 'f', -1, 64), right.(string))
}

// same operator types
// ==   !=

func boolCmpBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opBoolCmpBool)
}

func boolNotBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opBoolCmpBool)
}

func intCmpIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntCmpInt)
}

func intNotIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opIntCmpInt)
}

func floatCmpFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatCmpFloat)
}

func floatNotFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opFloatCmpFloat)
}

func stringCmpStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringCmpString)
}

func stringNotStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opStringCmpString)
}

func timeCmpTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opTimeCmpTime)
}

func timeNotTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opTimeCmpTime)
}

func stringCmpEmptyV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolTrue, 0, nil
	}
	return BoolData(bind.Value.(string) == ""), 0, nil
}

func stringNotEmptyV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}
	return BoolData(bind.Value.(string) != ""), 0, nil
}

// int arithmetic

func intPlusIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Int, func(left any, right any) *RawData {
		res := left.(int64) + right.(int64)
		return IntData(res)
	})
}

func intMinusIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Int, func(left any, right any) *RawData {
		res := left.(int64) - right.(int64)
		return IntData(res)
	})
}

func intTimesIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Int, func(left any, right any) *RawData {
		res := left.(int64) * right.(int64)
		return IntData(res)
	})
}

func intDividedIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Int, func(left any, right any) *RawData {
		res := left.(int64) / right.(int64)
		return IntData(res)
	})
}

func intPlusFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Float, func(left any, right any) *RawData {
		res := float64(left.(int64)) + right.(float64)
		return FloatData(res)
	})
}

func intMinusFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Float, func(left any, right any) *RawData {
		res := float64(left.(int64)) - right.(float64)
		return FloatData(res)
	})
}

func intTimesFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Float, func(left any, right any) *RawData {
		res := float64(left.(int64)) * right.(float64)
		return FloatData(res)
	})
}

func intDividedFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Float, func(left any, right any) *RawData {
		res := float64(left.(int64)) / right.(float64)
		return FloatData(res)
	})
}

// float arithmetic

func floatPlusIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Float, func(left any, right any) *RawData {
		res := left.(float64) + float64(right.(int64))
		return FloatData(res)
	})
}

func floatMinusIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Float, func(left any, right any) *RawData {
		res := left.(float64) - float64(right.(int64))
		return FloatData(res)
	})
}

func floatTimesIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Float, func(left any, right any) *RawData {
		res := left.(float64) * float64(right.(int64))
		return FloatData(res)
	})
}

func floatDividedIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Float, func(left any, right any) *RawData {
		res := left.(float64) / float64(right.(int64))
		return FloatData(res)
	})
}

func floatPlusFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Float, func(left any, right any) *RawData {
		res := left.(float64) + right.(float64)
		return FloatData(res)
	})
}

func floatMinusFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Float, func(left any, right any) *RawData {
		res := left.(float64) - right.(float64)
		return FloatData(res)
	})
}

func floatTimesFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Float, func(left any, right any) *RawData {
		res := left.(float64) * right.(float64)
		return FloatData(res)
	})
}

func floatDividedFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Float, func(left any, right any) *RawData {
		res := left.(float64) / right.(float64)
		return FloatData(res)
	})
}

// int vs float
// int ==/!= float

func opIntCmpFloat(left any, right any) bool {
	return float64(left.(int64)) == right.(float64)
}

func opFloatCmpInt(left any, right any) bool {
	return left.(float64) == float64(right.(int64))
}

func intCmpFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntCmpFloat)
}

func intNotFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opIntCmpFloat)
}

func floatCmpIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatCmpInt)
}

func floatNotIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opFloatCmpInt)
}

// string vs other types
// string ==/!= nil

func opStringCmpNil(left any, right any) bool {
	return left == nil
}

func stringCmpNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringCmpNil)
}

func stringNotNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opStringCmpNil)
}

// string ==/!= bool

func opStringCmpBool(left any, right any) bool {
	if right.(bool) {
		return left.(string) == "true"
	}
	return left.(string) == "false"
}

func opBoolCmpString(left any, right any) bool {
	if left.(bool) {
		return right.(string) == "true"
	}
	return right.(string) == "false"
}

func stringCmpBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringCmpBool)
}

func stringNotBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opStringCmpBool)
}

func boolCmpStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opBoolCmpString)
}

func boolNotStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opBoolCmpString)
}

// string ==/!= int

func stringCmpIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringCmpInt)
}

func stringNotIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opStringCmpInt)
}

func intCmpStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntCmpString)
}

func intNotStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opIntCmpString)
}

// string ==/!= float

func stringCmpFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringCmpFloat)
}

func stringNotFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opStringCmpFloat)
}

func floatCmpStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatCmpString)
}

func floatNotStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opFloatCmpString)
}

// string ==/!= regex

func stringCmpRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringCmpRegex)
}

func stringNotRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opStringCmpRegex)
}

func regexCmpStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opRegexCmpString)
}

func regexNotStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opRegexCmpString)
}

// regex vs other types
// int ==/!= regex

func intCmpRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntCmpRegex)
}

func intNotRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opIntCmpRegex)
}

func regexCmpIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opRegexCmpInt)
}

func regexNotIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opRegexCmpInt)
}

// float ==/!= regex

func floatCmpRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatCmpRegex)
}

func floatNotRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opFloatCmpRegex)
}

func regexCmpFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opRegexCmpFloat)
}

func regexNotFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opRegexCmpFloat)
}

// null vs other types
// bool ==/!= nil

func opBoolCmpNil(left any, right any) bool {
	return left == nil
}

func boolCmpNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opBoolCmpNil)
}

func boolNotNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opBoolCmpNil)
}

// int ==/!= nil

func opIntCmpNil(left any, right any) bool {
	return left == nil
}

func intCmpNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntCmpNil)
}

func intNotNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opIntCmpNil)
}

// float ==/!= nil

func opFloatCmpNil(left any, right any) bool {
	return left == nil
}

func floatCmpNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatCmpNil)
}

func floatNotNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opFloatCmpNil)
}

// time ==/!= nil

func opTimeCmpNil(left *RawData, right *RawData) bool {
	return left.Value == nil || left.Value.(*time.Time) == nil
}

func timeCmpNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, opTimeCmpNil)
}

func timeNotNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, opTimeCmpNil)
}

// The native `asset` primitive (types.Asset) carries an *AssetValue payload with
// the anchor (resourceType, resourceId) that points at another asset. The anchor
// is not introspectable from MQL; it is serialized out for the platform to
// correlate against the separately-discovered asset. The only MQL-facing builtins
// are nil comparisons. See ADR 030.

func opAssetCmpNil(left *RawData, right *RawData) bool {
	if left.Value == nil {
		return true
	}
	v, ok := left.Value.(*AssetValue)
	return !ok || v == nil
}

func assetCmpNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, opAssetCmpNil)
}

func assetNotNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, opAssetCmpNil)
}

// string </>/<=/>= string

func stringLTStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(string) < right.(string))
	})
}

func stringLTEStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(string) <= right.(string))
	})
}

func stringGTStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(string) > right.(string))
	})
}

func stringGTEStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(string) >= right.(string))
	})
}

// int </>/<=/>= int

func intLTIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(int64) < right.(int64))
	})
}

func intLTEIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(int64) <= right.(int64))
	})
}

func intGTIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(int64) > right.(int64))
	})
}

func intGTEIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(int64) >= right.(int64))
	})
}

// float </>/<=/>= float

func floatLTFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(float64) < right.(float64))
	})
}

func floatLTEFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(float64) <= right.(float64))
	})
}

func floatGTFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(float64) > right.(float64))
	})
}

func floatGTEFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(float64) >= right.(float64))
	})
}

// time </>/<=/>= time

func timeLTTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		l := left.(*time.Time)
		if l == nil {
			return BoolData(false)
		}
		r := right.(*time.Time)
		if r == nil {
			return BoolData(false)
		}

		return BoolData((*l).Before(*r))
	})
}

func timeLTETimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		l := left.(*time.Time)
		if l == nil {
			return BoolData(false)
		}
		r := right.(*time.Time)
		if r == nil {
			return BoolData(false)
		}

		return BoolData((*l).Before(*r) || (*l).Equal(*r))
	})
}

func timeGTTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		l := left.(*time.Time)
		if l == nil {
			return BoolData(false)
		}
		r := right.(*time.Time)
		if r == nil {
			return BoolData(false)
		}

		return BoolData((*l).After(*r))
	})
}

func timeGTETimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		l := left.(*time.Time)
		if l == nil {
			return BoolData(false)
		}
		r := right.(*time.Time)
		if r == nil {
			return BoolData(false)
		}

		return BoolData((*l).After(*r) || (*l).Equal(*r))
	})
}

// time arithmetic

func timeMinusTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		l := left.(*time.Time)
		r := right.(*time.Time)
		if l == nil || r == nil {
			return &RawData{Type: types.Time}
		}

		if r.Equal(NeverPastTime) {
			return NeverFuturePrimitive.RawData()
		}
		if r.Equal(NeverFutureTime) {
			return NeverPastPrimitive.RawData()
		}
		if l.Equal(NeverPastTime) {
			return NeverPastPrimitive.RawData()
		}
		if l.Equal(NeverFutureTime) {
			return NeverFuturePrimitive.RawData()
		}

		diff := l.Unix() - r.Unix()
		res := DurationToTime(diff)
		return TimeData(res)
	})
}

func timePlusTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		l := left.(*time.Time)
		r := right.(*time.Time)
		if l == nil || r == nil {
			return &RawData{Type: types.Time}
		}

		if r.Equal(NeverPastTime) {
			return NeverFuturePrimitive.RawData()
		}
		if r.Equal(NeverFutureTime) {
			return NeverPastPrimitive.RawData()
		}
		if l.Equal(NeverPastTime) {
			return NeverPastPrimitive.RawData()
		}
		if l.Equal(NeverFutureTime) {
			return NeverFuturePrimitive.RawData()
		}

		lt := l.Unix()
		rt := r.Unix()

		// the breakpoint for time and duration is the unix time of zero
		bothDuration := false
		if lt < 0 {
			lt = TimeToDuration(l)
			if rt < 0 {
				bothDuration = true
			}
		}
		if rt < 0 {
			rt = TimeToDuration(r)
		}

		sum := lt + rt
		if bothDuration {
			return TimeData(DurationToTime(sum))
		}

		return TimeData(time.Unix(sum, 0))
	})
}

func opTimeTimesInt(left any, right any) *RawData {
	l := left.(*time.Time)
	if l == nil {
		return &RawData{Type: types.Time}
	}

	if l.Equal(NeverPastTime) {
		return NeverPastPrimitive.RawData()
	}
	if l.Equal(NeverFutureTime) {
		return NeverFuturePrimitive.RawData()
	}

	diff := TimeToDuration(l) * right.(int64)
	res := DurationToTime(diff)
	return TimeData(res)
}

func opTimeTimesFloat(left any, right any) *RawData {
	l := left.(*time.Time)
	if l == nil {
		return &RawData{Type: types.Time}
	}

	if l.Equal(NeverPastTime) {
		return NeverPastPrimitive.RawData()
	}
	if l.Equal(NeverFutureTime) {
		return NeverFuturePrimitive.RawData()
	}

	diff := float64(TimeToDuration(l)) * right.(float64)
	res := DurationToTime(int64(diff))
	return TimeData(res)
}

func timeTimesIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, opTimeTimesInt)
}

func intTimesTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		return opTimeTimesInt(right, left)
	})
}

func timeTimesFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, opTimeTimesFloat)
}

func floatTimesTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		return opTimeTimesFloat(right, left)
	})
}

// int </>/<=/>= float

func intLTFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(float64(left.(int64)) < right.(float64))
	})
}

func intLTEFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(float64(left.(int64)) <= right.(float64))
	})
}

func intGTFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(float64(left.(int64)) > right.(float64))
	})
}

func intGTEFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(float64(left.(int64)) >= right.(float64))
	})
}

// float </>/<=/>= int

func floatLTIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(float64) < float64(right.(int64)))
	})
}

func floatLTEIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(float64) <= float64(right.(int64)))
	})
}

func floatGTIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(float64) > float64(right.(int64)))
	})
}

func floatGTEIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		return BoolData(left.(float64) >= float64(right.(int64)))
	})
}

// float </>/<=/>= string

func floatLTStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseFloat(right.(string), 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to float")}
		}
		return BoolData(left.(float64) < f)
	})
}

func floatLTEStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseFloat(right.(string), 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to float")}
		}
		return BoolData(left.(float64) <= f)
	})
}

func floatGTStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseFloat(right.(string), 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to float")}
		}
		return BoolData(left.(float64) > f)
	})
}

func floatGTEStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseFloat(right.(string), 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to float")}
		}
		return BoolData(left.(float64) >= f)
	})
}

// string </>/<=/>= float

func stringLTFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseFloat(left.(string), 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to float")}
		}
		return BoolData(f < right.(float64))
	})
}

func stringLTEFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseFloat(left.(string), 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to float")}
		}
		return BoolData(f <= right.(float64))
	})
}

func stringGTFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseFloat(left.(string), 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to float")}
		}
		return BoolData(f > right.(float64))
	})
}

func stringGTEFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseFloat(left.(string), 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to float")}
		}
		return BoolData(f >= right.(float64))
	})
}

// int </>/<=/>= string

func intLTStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseInt(right.(string), 10, 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to int")}
		}
		return BoolData(left.(int64) < f)
	})
}

func intLTEStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseInt(right.(string), 10, 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to int")}
		}
		return BoolData(left.(int64) <= f)
	})
}

func intGTStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseInt(right.(string), 10, 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to int")}
		}
		return BoolData(left.(int64) > f)
	})
}

func intGTEStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseInt(right.(string), 10, 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to int")}
		}
		return BoolData(left.(int64) >= f)
	})
}

// string </>/<=/>= int

func stringLTIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseInt(left.(string), 10, 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to int")}
		}
		return BoolData(f < right.(int64))
	})
}

func stringLTEIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseInt(left.(string), 10, 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to int")}
		}
		return BoolData(f <= right.(int64))
	})
}

func stringGTIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseInt(left.(string), 10, 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to int")}
		}
		return BoolData(f > right.(int64))
	})
}

func stringGTEIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		f, err := strconv.ParseInt(left.(string), 10, 64)
		if err != nil {
			return &RawData{Type: types.Bool, Error: errors.New("failed to convert string to int")}
		}
		return BoolData(f >= right.(int64))
	})
}

// ---------------------------------
//       &&  AND        ||  OR
// ---------------------------------

// T &&/|| T

func truthyBool(val any) bool {
	return val.(bool)
}

func truthyInt(val any) bool {
	return val.(int64) != 0
}

func truthyFloat(val any) bool {
	return val.(float64) != 0
}

func truthyString(val any) bool {
	return val.(string) != ""
}

func truthyArray(val any) bool {
	return true
}

func boolAndBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyBool, truthyBool)
}

func boolOrBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyBool, truthyBool)
}

func intAndIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyInt, truthyInt)
}

func intOrIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyInt, truthyInt)
}

func floatAndFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyFloat, truthyFloat)
}

func floatOrFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyFloat, truthyFloat)
}

func stringAndStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyString, truthyString)
}

func stringOrStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyString, truthyString)
}

func regexAndRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyString, truthyString)
}

func regexOrRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyString, truthyString)
}

func arrayAndArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyArray, truthyArray)
}

func arrayOrArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyArray, truthyArray)
}

// bool &&/|| T

func boolAndIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyBool, truthyInt)
}

func boolOrIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyBool, truthyInt)
}

func intAndBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyInt, truthyBool)
}

func intOrBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyInt, truthyBool)
}

func boolAndFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyBool, truthyFloat)
}

func boolOrFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyBool, truthyFloat)
}

func floatAndBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyFloat, truthyBool)
}

func floatOrBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyFloat, truthyBool)
}

func boolAndStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyBool, truthyString)
}

func boolOrStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyBool, truthyString)
}

func stringAndBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyString, truthyBool)
}

func stringOrBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyString, truthyBool)
}

func boolAndRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyBool, truthyString)
}

func boolOrRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyBool, truthyString)
}

func regexAndBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyString, truthyBool)
}

func regexOrBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyString, truthyBool)
}

func boolAndArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyBool, truthyArray)
}

func boolOrArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyBool, truthyArray)
}

func arrayAndBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyArray, truthyBool)
}

func arrayOrBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyArray, truthyBool)
}

func opBoolAndMap(left any, right any) bool {
	return left.(bool) && (len(right.([]any)) != 0)
}

func opBoolOrMap(left any, right any) bool {
	return left.(bool) || (len(right.([]any)) != 0)
}

func boolAndMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opBoolAndMap)
}

func boolOrMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opBoolOrMap)
}

// int &&/|| T

func opIntAndFloat(left any, right any) bool {
	return (left.(int64) != 0) && (right.(float64) != 0)
}

func opFloatAndInt(left any, right any) bool {
	return (right.(int64) != 0) && (left.(float64) != 0)
}

func opIntOrFloat(left any, right any) bool {
	return (left.(int64) != 0) || (right.(float64) != 0)
}

func opFloatOrInt(left any, right any) bool {
	return (right.(int64) != 0) || (left.(float64) != 0)
}

func intAndFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntAndFloat)
}

func intOrFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntOrFloat)
}

func floatAndIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatAndInt)
}

func floatOrIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatOrInt)
}

func opIntAndString(left any, right any) bool {
	return (left.(int64) != 0) && (right.(string) != "")
}

func opStringAndInt(left any, right any) bool {
	return (right.(int64) != 0) && (left.(string) != "")
}

func opIntOrString(left any, right any) bool {
	return (left.(int64) != 0) || (right.(string) != "")
}

func opStringOrInt(left any, right any) bool {
	return (right.(int64) != 0) || (left.(string) != "")
}

func intAndStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntAndString)
}

func intOrStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntOrString)
}

func stringAndIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringAndInt)
}

func stringOrIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringOrInt)
}

func intAndRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntAndString)
}

func intOrRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntOrString)
}

func regexAndIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringAndInt)
}

func regexOrIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringOrInt)
}

func opIntAndArray(left any, right any) bool {
	return (left.(int64) != 0) && (len(right.([]any)) != 0)
}

func opArrayAndInt(left any, right any) bool {
	return (right.(int64) != 0) && (len(left.([]any)) != 0)
}

func opIntOrArray(left any, right any) bool {
	return (left.(int64) != 0) || (len(right.([]any)) != 0)
}

func opArrayOrInt(left any, right any) bool {
	return (right.(int64) != 0) || (len(left.([]any)) != 0)
}

func intAndArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntAndArray)
}

func intOrArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntOrArray)
}

func arrayAndIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opArrayAndInt)
}

func arrayOrIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opArrayOrInt)
}

func opIntAndMap(left any, right any) bool {
	return (left.(int64) != 0) && (len(right.(map[string]any)) != 0)
}

func opMapAndInt(left any, right any) bool {
	return (right.(int64) != 0) && (len(left.(map[string]any)) != 0)
}

func opIntOrMap(left any, right any) bool {
	return (left.(int64) != 0) || (len(right.(map[string]any)) != 0)
}

func opMapOrInt(left any, right any) bool {
	return (right.(int64) != 0) || (len(left.(map[string]any)) != 0)
}

func intAndMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntAndMap)
}

func intOrMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntOrMap)
}

func mapAndIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapAndInt)
}

func mapOrIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapOrInt)
}

func int64InRange(e *blockExecutor, val int64, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	minRef := chunk.Function.Args[0]
	min, rref, err := e.resolveValue(minRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	switch minval := min.Value.(type) {
	case int64:
		if val < minval {
			return BoolFalse, 0, nil
		}
	case float64:
		if float64(val) < minval {
			return BoolFalse, 0, nil
		}
	case string:
		f, err := strconv.ParseInt(minval, 10, 64)
		if err == nil {
			if val < f {
				return BoolFalse, 0, nil
			}
		} else {
			f, err := strconv.ParseFloat(minval, 64)
			if err != nil {
				return &RawData{Type: types.Bool, Error: errors.New("failed to parse minimum value of inRange as a number")}, 0, nil
			}
			if float64(val) < f {
				return BoolFalse, 0, nil
			}
		}
	}

	maxRef := chunk.Function.Args[1]
	max, rref, err := e.resolveValue(maxRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	switch maxval := max.Value.(type) {
	case int64:
		if val > maxval {
			return BoolFalse, 0, nil
		}
	case float64:
		if float64(val) > maxval {
			return BoolFalse, 0, nil
		}
	case string:
		max, err := strconv.ParseInt(maxval, 10, 64)
		if err == nil {
			if val > max {
				return BoolFalse, 0, nil
			}
		} else {
			max, err := strconv.ParseFloat(maxval, 64)
			if err != nil {
				return &RawData{Type: types.Bool, Error: errors.New("failed to parse maximum value of inRange as a number")}, 0, nil
			}
			if float64(val) > max {
				return BoolFalse, 0, nil
			}
		}
	}

	return BoolTrue, 0, nil
}

func float64InRange(e *blockExecutor, val float64, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	minRef := chunk.Function.Args[0]
	min, rref, err := e.resolveValue(minRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	switch minval := min.Value.(type) {
	case int64:
		if val < float64(minval) {
			return BoolFalse, 0, nil
		}
	case float64:
		if val < minval {
			return BoolFalse, 0, nil
		}
	}

	maxRef := chunk.Function.Args[1]
	max, rref, err := e.resolveValue(maxRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	switch maxval := max.Value.(type) {
	case int64:
		if val > float64(maxval) {
			return BoolFalse, 0, nil
		}
	case float64:
		if val > maxval {
			return BoolFalse, 0, nil
		}
	case string:
		max, err := strconv.ParseInt(maxval, 10, 64)
		if err == nil {
			if val > float64(max) {
				return BoolFalse, 0, nil
			}
		} else {
			max, err := strconv.ParseFloat(maxval, 64)
			if err != nil {
				return &RawData{Type: types.Bool, Error: errors.New("failed to parse maximum value of inRange as a number")}, 0, nil
			}
			if float64(val) > max {
				return BoolFalse, 0, nil
			}
		}
	}

	return BoolTrue, 0, nil
}

func intInRange(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}
	val := bind.Value.(int64)
	return int64InRange(e, val, chunk, ref)
}

func floatInRange(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}
	val := bind.Value.(float64)
	return float64InRange(e, val, chunk, ref)
}

func stringInRange(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}

	val := bind.Value.(string)

	i, err := strconv.ParseInt(val, 10, 64)
	if err == nil {
		return int64InRange(e, i, chunk, ref)
	}

	f, err := strconv.ParseFloat(val, 64)
	if err == nil {
		return float64InRange(e, f, chunk, ref)
	}

	return &RawData{Type: types.Bool, Error: errors.New("can only check `inRange` on numbers")}, 0, nil
}

// float &&/|| T

func opFloatAndString(left any, right any) bool {
	return (left.(float64) != 0) && (right.(string) != "")
}

func opStringAndFloat(left any, right any) bool {
	return (right.(float64) != 0) && (left.(string) != "")
}

func opFloatOrString(left any, right any) bool {
	return (left.(float64) != 0) || (right.(string) != "")
}

func opStringOrFloat(left any, right any) bool {
	return (right.(float64) != 0) || (left.(string) != "")
}

func floatAndStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatAndString)
}

func floatOrStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatOrString)
}

func stringAndFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringAndFloat)
}

func stringOrFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringOrFloat)
}

func floatAndRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatAndString)
}

func floatOrRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatOrString)
}

func regexAndFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringAndFloat)
}

func regexOrFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringOrFloat)
}

func opFloatAndArray(left any, right any) bool {
	return (left.(float64) != 0) && (len(right.([]any)) != 0)
}

func opArrayAndFloat(left any, right any) bool {
	return (right.(float64) != 0) && (len(left.([]any)) != 0)
}

func opFloatOrArray(left any, right any) bool {
	return (left.(float64) != 0) || (len(right.([]any)) != 0)
}

func opArrayOrFloat(left any, right any) bool {
	return (right.(float64) != 0) || (len(left.([]any)) != 0)
}

func floatAndArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatAndArray)
}

func floatOrArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatOrArray)
}

func arrayAndFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opArrayAndFloat)
}

func arrayOrFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opArrayOrFloat)
}

func opFloatAndMap(left any, right any) bool {
	return (left.(float64) != 0) && (len(right.(map[string]any)) != 0)
}

func opMapAndFloat(left any, right any) bool {
	return (right.(float64) != 0) && (len(left.(map[string]any)) != 0)
}

func opFloatOrMap(left any, right any) bool {
	return (left.(float64) != 0) || (len(right.(map[string]any)) != 0)
}

func opMapOrFloat(left any, right any) bool {
	return (right.(float64) != 0) || (len(left.(map[string]any)) != 0)
}

func floatAndMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatAndMap)
}

func floatOrMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatOrMap)
}

func mapAndFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapAndFloat)
}

func mapOrFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapOrFloat)
}

// string &&/|| T

func stringAndRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyString, truthyString)
}

func stringOrRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyString, truthyString)
}

func regexAndStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolAndOpV2(e, bind, chunk, ref, truthyString, truthyString)
}

func regexOrStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOrOpV2(e, bind, chunk, ref, truthyString, truthyString)
}

func opStringAndArray(left any, right any) bool {
	return (left.(float64) != 0) && (len(right.([]any)) != 0)
}

func opArrayAndString(left any, right any) bool {
	return (right.(float64) != 0) && (len(left.([]any)) != 0)
}

func opStringOrArray(left any, right any) bool {
	return (left.(float64) != 0) || (len(right.([]any)) != 0)
}

func opArrayOrString(left any, right any) bool {
	return (right.(float64) != 0) || (len(left.([]any)) != 0)
}

func stringAndArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringAndArray)
}

func stringOrArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringOrArray)
}

func arrayAndStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opArrayAndString)
}

func arrayOrStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opArrayOrString)
}

func opStringAndMap(left any, right any) bool {
	return (left.(float64) != 0) && (len(right.(map[string]any)) != 0)
}

func opMapAndString(left any, right any) bool {
	return (right.(float64) != 0) && (len(left.(map[string]any)) != 0)
}

func opStringOrMap(left any, right any) bool {
	return (left.(float64) != 0) || (len(right.(map[string]any)) != 0)
}

func opMapOrString(left any, right any) bool {
	return (right.(float64) != 0) || (len(left.(map[string]any)) != 0)
}

func stringAndMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringAndMap)
}

func stringOrMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringOrMap)
}

func mapAndStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapAndString)
}

func mapOrStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapOrString)
}

// string + T

func stringPlusStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		l := left.(string)
		r := right.(string)

		return StringData(l + r)
	})
}

// regex &&/|| array

func regexAndArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringAndArray)
}

func regexOrArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringOrArray)
}

func arrayAndRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opArrayAndString)
}

func arrayOrRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opArrayOrString)
}

// regex &&/|| map

func regexAndMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringAndMap)
}

func regexOrMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringOrMap)
}

func mapAndRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapAndString)
}

func mapOrRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapOrString)
}

// time &&/|| T
// note: time is always truthy

func opBoolAndTime(left any, right any) bool {
	return left.(bool)
}

func opTimeAndBool(left any, right any) bool {
	return right.(bool)
}

func boolAndTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opBoolAndTime)
}

func boolOrTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func timeAndBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opTimeAndBool)
}

func timeOrBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func opIntAndTime(left any, right any) bool {
	return left.(int64) != 0
}

func opTimeAndInt(left any, right any) bool {
	return right.(int64) != 0
}

func intAndTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntAndTime)
}

func intOrTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func timeAndIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opTimeAndInt)
}

func timeOrIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func opFloatAndTime(left any, right any) bool {
	return left.(float64) != 0
}

func opTimeAndFloat(left any, right any) bool {
	return right.(float64) != 0
}

func floatAndTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatAndTime)
}

func floatOrTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func timeAndFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opTimeAndFloat)
}

func timeOrFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func opStringAndTime(left any, right any) bool {
	return left.(string) != ""
}

func opTimeAndString(left any, right any) bool {
	return right.(string) != ""
}

func stringAndTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringAndTime)
}

func stringOrTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func timeAndStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opTimeAndString)
}

func timeOrStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func opRegexAndTime(left any, right any) bool {
	return left.(string) != ""
}

func opTimeAndRegex(left any, right any) bool {
	return right.(string) != ""
}

func regexAndTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opRegexAndTime)
}

func regexOrTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func timeAndRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opTimeAndRegex)
}

func timeOrRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func timeAndTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func timeOrTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func opTimeAndArray(left any, right any) bool {
	return len(right.([]any)) != 0
}

func timeAndArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opTimeAndArray)
}

func timeOrArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func opTimeAndMap(left any, right any) bool {
	return len(right.(map[string]any)) != 0
}

func opMapAndTime(left any, right any) bool {
	return len(left.(map[string]any)) != 0
}

func timeAndMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opTimeAndMap)
}

func timeOrMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

func mapAndTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapAndTime)
}

func mapOrTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return BoolTrue, 0, nil
}

// string methods

func opStringContainsDict(left string, right any) (bool, error) {
	switch x := right.(type) {
	case string:
		return strings.Contains(left, x), nil
	case int64:
		val := strconv.FormatInt(x, 10)
		return strings.Contains(left, val), nil
	case float64:
		val := strconv.FormatFloat(x, 'f', -1, 64)
		return strings.Contains(left, val), nil
	default:
		return false, nil
	}
}

func opStringContainsString(left string, right any) (bool, error) {
	v, ok := right.(string)
	if !ok {
		return false, nil
	}
	return strings.Contains(left, v), nil
}

func opStringContainsInt(left string, right any) (bool, error) {
	val := strconv.FormatInt(right.(int64), 10)
	return strings.Contains(left, val), nil
}

func opStringContainsRegex(left string, right any) (bool, error) {
	reContent, ok := right.(string)
	if !ok {
		return false, nil
	}

	re, err := regexp.Compile(right.(string))
	if err != nil {
		return false, errors.New("Failed to compile regular expression: " + reContent)
	}

	return re.MatchString(left), nil
}

func stringContainsOther(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, cmp func(left string, right any) (bool, error)) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}

	argRef := chunk.Function.Args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if arg.Value == nil {
		return BoolFalse, 0, nil
	}

	left := bind.Value.(string)
	res, err := cmp(left, arg.Value)
	if err != nil {
		return nil, 0, err
	}
	return BoolData(res), 0, nil
}

func stringContainsArrayOther(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, cmp func(left string, right any) (bool, error)) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}

	argRef := chunk.Function.Args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if arg.Value == nil {
		return BoolFalse, 0, nil
	}

	arr := arg.Value.([]any)
	for i := range arr {
		found, err := cmp(bind.Value.(string), arr[i])
		if err != nil {
			return nil, 0, err
		}
		if found {
			return BoolData(true), 0, nil
		}
	}

	return BoolData(false), 0, nil
}

func stringContainsString(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return stringContainsOther(e, bind, chunk, ref, opStringContainsString)
}

func stringContainsDict(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return stringContainsOther(e, bind, chunk, ref, opStringContainsDict)
}

func stringContainsInt(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return stringContainsOther(e, bind, chunk, ref, opStringContainsInt)
}

func stringContainsRegex(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return stringContainsOther(e, bind, chunk, ref, opStringContainsRegex)
}

func stringContainsArrayString(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return stringContainsArrayOther(e, bind, chunk, ref, opStringContainsString)
}

func stringContainsArrayDict(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return stringContainsArrayOther(e, bind, chunk, ref, opStringContainsDict)
}

func stringContainsArrayInt(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return stringContainsArrayOther(e, bind, chunk, ref, opStringContainsInt)
}

func stringContainsArrayRegex(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return stringContainsArrayOther(e, bind, chunk, ref, opStringContainsRegex)
}

func stringInArray(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}

	argRef := chunk.Function.Args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if arg.Value == nil {
		return BoolFalse, 0, nil
	}

	arr := arg.Value.([]any)
	for i := range arr {
		v, ok := arr[i].(string)
		if !ok {
			return nil, 0, errors.New("invalid type in array")
		}

		if v == bind.Value.(string) {
			return BoolTrue, 0, nil
		}
	}
	return BoolFalse, 0, nil
}

func stringNotInArray(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolTrue, 0, nil
	}

	argRef := chunk.Function.Args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if arg.Value == nil {
		return BoolTrue, 0, nil
	}

	arr := arg.Value.([]any)
	for i := range arr {
		v, ok := arr[i].(string)
		if !ok {
			return nil, 0, errors.New("invalid type in array")
		}

		if v == bind.Value.(string) {
			return BoolFalse, 0, nil
		}
	}
	return BoolTrue, 0, nil
}

func stringFindV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return ArrayData([]any{}, types.String), 0, nil
	}

	argRef := chunk.Function.Args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if arg.Value == nil {
		return ArrayData([]any{}, types.String), 0, nil
	}

	reContent := arg.Value.(string)
	re, err := regexp.Compile(reContent)
	if err != nil {
		return nil, 0, errors.New("Failed to compile regular expression: " + reContent)
	}

	list := re.FindAllString(bind.Value.(string), -1)
	res := make([]any, len(list))
	for i := range list {
		res[i] = list[i]
	}

	return ArrayData(res, types.String), 0, nil
}

func stringDowncaseV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type}, 0, nil
	}

	res := strings.ToLower(bind.Value.(string))
	return StringData(res), 0, nil
}

var camelCaseRe = regexp.MustCompile(`([[:punct:]]|\s)+[\p{L}]`)

func stringCamelcaseV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type}, 0, nil
	}

	res := camelCaseRe.ReplaceAllStringFunc(bind.Value.(string), func(in string) string {
		reader := strings.NewReader(in)
		var last rune
		for {
			r, _, err := reader.ReadRune()
			if err == io.EOF {
				break
			}
			if err != nil {
				return in
			}
			last = r
		}

		return string(unicode.ToTitle(last))
	})

	return StringData(res), 0, nil
}

func stringUpcaseV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type}, 0, nil
	}

	res := strings.ToUpper(bind.Value.(string))
	return StringData(res), 0, nil
}

func stringLengthV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Int}, 0, nil
	}

	l := len(bind.Value.(string))
	return IntData(int64(l)), 0, nil
}

func stringLinesV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Array(types.String)}, 0, nil
	}

	s := bind.Value.(string)
	lines := strings.Split(s, "\n")
	res := make([]any, len(lines))
	for i := range lines {
		res[i] = lines[i]
	}

	return ArrayData(res, types.String), 0, nil
}

func stringSplitV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Array(types.String)}, 0, nil
	}

	argRef := chunk.Function.Args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if arg.Value == nil {
		return &RawData{
			Type:  types.Array(types.String),
			Value: nil,
			Error: errors.New("failed to split string, separator was null"),
		}, 0, nil
	}

	splits := strings.Split(bind.Value.(string), arg.Value.(string))
	res := make([]any, len(splits))
	for i := range splits {
		res[i] = splits[i]
	}

	return ArrayData(res, types.String), 0, nil
}

func stringTrimV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type}, 0, nil
	}

	cutset := " \t\n\r"

	if len(chunk.Function.Args) != 0 {
		argRef := chunk.Function.Args[0]
		arg, rref, err := e.resolveValue(argRef, ref)
		if err != nil || rref > 0 {
			return nil, rref, err
		}

		if arg.Value == nil {
			return &RawData{
				Type:  bind.Type,
				Value: nil,
				Error: errors.New("failed to trim string, cutset was null"),
			}, 0, nil
		}

		cutset = arg.Value.(string)
	}

	res := strings.Trim(bind.Value.(string), cutset)

	return StringData(res), 0, nil
}

// time methods

// zeroTimeOffset to help convert unix times into base times that start at the year 0
const zeroTimeOffset int64 = -62167219200

// TimeToDuration takes a regular time object and treats it as a duration and gets the duration in seconds
func TimeToDuration(t *time.Time) int64 {
	return t.Unix() - zeroTimeOffset
}

// DurationToTime takes a duration in seconds and turns it into a time object
func DurationToTime(i int64) time.Time {
	return time.Unix(i+zeroTimeOffset, 0)
}

func timeSecondsV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Int}, 0, nil
	}
	t := bind.Value.(*time.Time)
	if t == nil {
		return &RawData{Type: types.Int}, 0, nil
	}

	if t.Equal(NeverPastTime) {
		return MinIntPrimitive.RawData(), 0, nil
	}
	if t.Equal(NeverFutureTime) {
		return MaxIntPrimitive.RawData(), 0, nil
	}

	raw := TimeToDuration(t)
	return IntData(int64(raw)), 0, nil
}

func timeMinutesV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Int}, 0, nil
	}
	t := bind.Value.(*time.Time)
	if t == nil {
		return &RawData{Type: types.Int}, 0, nil
	}

	if t.Equal(NeverPastTime) {
		return MinIntPrimitive.RawData(), 0, nil
	}
	if t.Equal(NeverFutureTime) {
		return MaxIntPrimitive.RawData(), 0, nil
	}

	raw := TimeToDuration(t) / 60
	return IntData(int64(raw)), 0, nil
}

func timeHoursV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Int}, 0, nil
	}
	t := bind.Value.(*time.Time)
	if t == nil {
		return &RawData{Type: types.Int}, 0, nil
	}

	if t.Equal(NeverPastTime) {
		return MinIntPrimitive.RawData(), 0, nil
	}
	if t.Equal(NeverFutureTime) {
		return MaxIntPrimitive.RawData(), 0, nil
	}

	raw := TimeToDuration(t) / (60 * 60)
	return IntData(int64(raw)), 0, nil
}

func timeDaysV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Int}, 0, nil
	}
	t := bind.Value.(*time.Time)
	if t == nil {
		return &RawData{Type: types.Int}, 0, nil
	}

	if t.Equal(NeverPastTime) {
		return MinIntPrimitive.RawData(), 0, nil
	}
	if t.Equal(NeverFutureTime) {
		return MaxIntPrimitive.RawData(), 0, nil
	}

	raw := TimeToDuration(t) / (60 * 60 * 24)
	return IntData(int64(raw)), 0, nil
}

func timeUnixV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Int}, 0, nil
	}
	t := bind.Value.(*time.Time)
	if t == nil {
		return &RawData{Type: types.Int}, 0, nil
	}

	raw := t.Unix()
	return IntData(int64(raw)), 0, nil
}

func timeInRange(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Bool}, 0, nil
	}
	val := bind.Value.(*time.Time)
	if val == nil {
		return &RawData{Type: types.Bool}, 0, nil
	}

	minRef := chunk.Function.Args[0]
	min, rref, err := e.resolveValue(minRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	switch minval := min.Value.(type) {
	case *time.Time:
		if val.Before(*minval) {
			return BoolFalse, 0, nil
		}
	}

	maxRef := chunk.Function.Args[1]
	max, rref, err := e.resolveValue(maxRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	switch maxval := max.Value.(type) {
	case *time.Time:
		if val.After(*maxval) {
			return BoolFalse, 0, nil
		}
	}

	return BoolTrue, 0, nil
}

// stringslice methods

func stringsliceEqString(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Int, func(left any, right any) *RawData {
		l := left.(string)
		r := right.(string)
		idx := strings.Index(l, r)
		if idx == -1 {
			return StringData("")
		}
		return StringData(r)
	})
}

func stringsliceEqDict(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Int, func(left any, right any) *RawData {
		l := left.(string)
		ok, err := opStringContainsDict(l, right)
		if err != nil {
			return &RawData{Error: err, Type: types.String}
		}
		if !ok {
			return StringData("")
		}
		return StringData(l)
	})
}

func stringsliceEqArrayString(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Int, func(left any, right any) *RawData {
		l := left.(string)
		arr := right.([]any)
		for i := range arr {
			r := arr[i].(string)
			idx := strings.Index(l, r)
			if idx != -1 {
				return StringData(r)
			}
		}

		return StringData("")
	})
}

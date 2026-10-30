// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlx

import (
	"fmt"
	"math"
	"time"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// ToPrimitive converts a Go value into an MQL primitive. Supported types:
// bool, all int/uint kinds, float32/64, string, time.Time, []any,
// map[string]any (recursively), and *llx.Primitive (passed through).
func ToPrimitive(value any) (*llx.Primitive, error) {
	switch v := value.(type) {
	case nil:
		return llx.NilPrimitive, nil
	case *llx.Primitive:
		return v, nil
	case bool:
		return llx.BoolPrimitive(v), nil
	case int:
		return llx.IntPrimitive(int64(v)), nil
	case int8:
		return llx.IntPrimitive(int64(v)), nil
	case int16:
		return llx.IntPrimitive(int64(v)), nil
	case int32:
		return llx.IntPrimitive(int64(v)), nil
	case int64:
		return llx.IntPrimitive(v), nil
	case uint:
		// uint is 64-bit on most platforms, so it can exceed int64.
		if uint64(v) > math.MaxInt64 {
			return nil, errors.New(fmt.Sprintf("uint value %d overflows int64", v))
		}
		return llx.IntPrimitive(int64(v)), nil
	case uint8:
		return llx.IntPrimitive(int64(v)), nil
	case uint16:
		return llx.IntPrimitive(int64(v)), nil
	case uint32:
		return llx.IntPrimitive(int64(v)), nil
	case uint64:
		if v > math.MaxInt64 {
			return nil, errors.New(fmt.Sprintf("uint64 value %d overflows int64", v))
		}
		return llx.IntPrimitive(int64(v)), nil
	case float32:
		return llx.FloatPrimitive(float64(v)), nil
	case float64:
		return llx.FloatPrimitive(v), nil
	case string:
		return llx.StringPrimitive(v), nil
	case time.Time:
		return llx.TimePrimitive(&v), nil
	case *time.Time:
		return llx.TimePrimitive(v), nil
	case []string:
		return llx.ArrayPrimitiveT(v, llx.StringPrimitive, types.String), nil
	case []int:
		return llx.ArrayPrimitiveT(v, func(i int) *llx.Primitive { return llx.IntPrimitive(int64(i)) }, types.Int), nil
	case []int64:
		return llx.ArrayPrimitiveT(v, llx.IntPrimitive, types.Int), nil
	case []float64:
		return llx.ArrayPrimitiveT(v, llx.FloatPrimitive, types.Float), nil
	case []bool:
		return llx.ArrayPrimitiveT(v, llx.BoolPrimitive, types.Bool), nil
	case map[string]string:
		return llx.MapPrimitiveT(v, llx.StringPrimitive, types.String), nil
	case map[string]any, []any:
		// Heterogeneous, JSON-like data is passed as a dict, so queries can
		// navigate it with dot access: props.event.process.binary
		return dictPrimitive(v)
	default:
		return nil, errors.New(fmt.Sprintf("unsupported value type %T", value))
	}
}

func dictPrimitive(value any) (*llx.Primitive, error) {
	res := llx.DictData(value).Result()
	if res.Error != "" {
		return nil, errors.New("failed to convert value to dict: " + res.Error)
	}
	return res.Data, nil
}

// ToPrimitiveMap converts a map of Go values into MQL primitives via
// ToPrimitive.
func ToPrimitiveMap(values map[string]any) (map[string]*llx.Primitive, error) {
	res := make(map[string]*llx.Primitive, len(values))
	for k, v := range values {
		prim, err := ToPrimitive(v)
		if err != nil {
			return nil, errors.Wrap(err, "failed to convert value of '"+k+"'")
		}
		res[k] = prim
	}
	return res, nil
}

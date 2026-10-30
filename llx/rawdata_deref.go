// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"fmt"
	"time"

	"go.mondoo.com/mql/types"
)

func dereferenceDict(raw any) (*RawData, error) {
	switch data := raw.(type) {
	case bool:
		return BoolData(data), nil

	case int64:
		return IntData(data), nil

	case float64:
		return FloatData(data), nil

	case string:
		return StringData(data), nil

	case time.Time:
		return TimeData(data), nil

	case []any:
		// TODO: we'll need to go deeper here to figure out what it really is
		return ArrayData(data, types.Array(types.Any)), nil

	case map[string]any:
		// TODO: we'll need to go deeper here to figure out what it really is
		return MapData(data, types.Map(types.String, types.Any)), nil

	default:
		return AnyData(data), nil
	}
}

func dereferenceBlock(data map[string]any, codeID string, bundle *CodeBundle) (*RawData, error) {
	res := make(map[string]any, len(data))

	for k := range data {
		if k == "_" || k == "__t" || k == "__s" {
			continue
		}

		v := data[k]

		label := label(k, bundle, true)
		val, err := v.(*RawData).Dereference(k, bundle)
		if err != nil {
			return nil, err
		}

		res[label] = val.Value
	}

	return MapData(res, types.Map(types.String, types.Any)), nil
}

func dereferenceArray(typ types.Type, data []any, codeID string, bundle *CodeBundle) (*RawData, error) {
	res := make([]any, len(data))
	childType := typ.Child()

	// TODO: detect any changes to the child type
	for i := range data {
		entry := &RawData{Value: data[i], Type: childType}
		v, err := dereference(entry, codeID, bundle)
		if err != nil {
			return nil, err
		}
		res[i] = v.Value
	}

	return ArrayData(res, childType), nil
}

func dereferenceStringMap(typ types.Type, data map[string]any, codeID string, bundle *CodeBundle) (*RawData, error) {
	res := make(map[string]any, len(data))
	childType := typ.Child()

	// TODO: detect any changes to the child type
	for key := range data {
		entry := &RawData{Value: data[key], Type: childType}
		v, err := dereference(entry, codeID, bundle)
		if err != nil {
			return nil, err
		}
		res[key] = v.Value
	}

	return MapData(res, childType), nil
}

func dereference(raw *RawData, codeID string, bundle *CodeBundle) (*RawData, error) {
	if raw.Type.NotSet() || raw.Value == nil {
		return raw, nil
	}

	typ := raw.Type
	data := raw.Value

	// we only handle types that might have reference data embedded
	switch typ.Underlying() {
	// case types.Ref:
	// 	// TODO: needs work
	case types.Dict:
		return dereferenceDict(data)

	case types.Block:
		return dereferenceBlock(data.(map[string]any), codeID, bundle)

	case types.ArrayLike:
		return dereferenceArray(typ, data.([]any), codeID, bundle)

	case types.MapLike:
		if typ.Key() == types.String {
			return dereferenceStringMap(typ, data.(map[string]any), codeID, bundle)
		}
		// if typ.Key() == types.Int {
		// 	return dereferenceIntMap(typ, data.(map[int]any), codeID, bundle)
		// }
		return nil, errors.New("unable to dereference map, its type is not supported: " + typ.Label() + ", raw: " + fmt.Sprintf("%#v", data))

	default:
		return raw, nil
	}
}

// Dereference takes the raw data provided and finds any code references
// that it might contain. It resolves blocks back into regular string maps
// and converts Dicts into simple data structures.
func (r *RawData) Dereference(codeID string, bundle *CodeBundle) (*RawData, error) {
	return dereference(r, codeID, bundle)
}

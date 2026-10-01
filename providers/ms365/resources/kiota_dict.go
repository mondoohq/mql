// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"

	"github.com/microsoft/kiota-abstractions-go/serialization"
	kjson "github.com/microsoft/kiota-serialization-json-go"
)

// kiotaToDict serializes a Graph model with Kiota's JSON writer and decodes
// the result into a dict. Unlike convert.JsonToDict, which sees an empty
// struct because Kiota keeps values in an unexported backing store, this
// emits every property the concrete type (including a derived type) holds,
// under its Graph property name. Values are JSON-native: integers become
// int64, other numbers float64, enums and timestamps strings.
//
// A nil model returns a nil map.
func kiotaToDict(p serialization.Parsable) (map[string]any, error) {
	if p == nil {
		return nil, nil
	}
	// A non-nil interface can still hold a nil model pointer, which the
	// check above lets through and Serialize would dereference.
	if rv := reflect.ValueOf(p); rv.Kind() == reflect.Ptr && rv.IsNil() {
		return nil, nil
	}

	w := kjson.NewJsonSerializationWriter()
	defer w.Close()
	if err := w.WriteObjectValue("", p); err != nil {
		return nil, err
	}
	content, err := w.GetSerializedContent()
	if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	m, ok := normalizeJSONNumbers(raw).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected a JSON object, got %T", raw)
	}
	return m, nil
}

// normalizeJSONNumbers replaces json.Number values with int64 when they are
// integral and in range, float64 otherwise.
func normalizeJSONNumbers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = normalizeJSONNumbers(e)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = normalizeJSONNumbers(e)
		}
		return t
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, err := t.Float64()
		if err != nil || math.IsInf(f, 0) {
			return t.String()
		}
		return f
	default:
		return v
	}
}

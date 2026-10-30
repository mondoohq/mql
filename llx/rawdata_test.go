// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/types"
)

var testTime = time.Unix(1715874169, 1)

func TestRawData_String(t *testing.T) {
	strVal := "yo"
	intVal := int64(1)
	boolVal := true
	floatVal := 1.5
	float32Val := float32(2.5)
	tests := []struct {
		data *RawData
		res  string
	}{
		{NilData, "<null>"},
		{BoolTrue, "true"},
		{BoolFalse, "false"},
		{BoolDataPtr(&boolVal), "true"},
		{BoolDataPtr(nil), "<null>"},
		{IntData(0), "0"},
		{IntDataPtr(&intVal), "1"},
		{IntDataPtr[int](nil), "<null>"},
		{FloatData(123), "123"},
		{FloatDataPtr(&floatVal), "1.5"},
		{FloatDataPtr[float64](nil), "<null>"},
		{FloatDataPtr(&float32Val), "2.5"},
		{StringData("yo"), "\"yo\""},
		{StringDataPtr(nil), "<null>"},
		{StringDataPtr(&strVal), "\"yo\""},
		{RegexData("ex"), "/ex/"},
		{TimeData(testTime), testTime.String()},
		{TimeDataPtr(nil), "<null>"},
		{TimeDataPtr(&testTime), testTime.String()},
		{DictData(int64(1)), "1"},
		{DictData(float64(1.2)), "1.2"},
		{DictData(string("yo")), "\"yo\""},
		{DictData([]any{int64(1)}), "[1]"},
		{DictData(map[string]any{"a": "b"}), "{\"a\":\"b\"}"},
		{VersionData("1.2.3"), "1.2.3"},
		{ArrayData([]any{"a", "b"}, types.String), "[\"a\",\"b\"]"},
		{MapData(map[string]any{"a": "b"}, types.String), "{\"a\":\"b\"}"},
		{IPData(ParseIP("1.2.3.4")), "1.2.3.4/8"},
		{IPData(ParseIP("")), "<null>"},
		// implicit nil:
		{&RawData{Type: types.String}, "<null>"},
	}

	for i := range tests {
		assert.Equal(t, tests[i].res, tests[i].data.String())
	}
}

func TestTruthy(t *testing.T) {
	strVal := "yo"

	tests := []struct {
		data *RawData
		res  bool
	}{
		{NilData, false},
		{BoolTrue, true},
		{BoolFalse, false},
		{IntData(0), false},
		{IntData(123), true},
		{FloatData(0), false},
		{FloatData(1.23), true},
		{StringData(""), false},
		{StringData("b"), true},
		{StringDataPtr(nil), false},
		{StringDataPtr(&strVal), true},
		{RegexData(""), false},
		{RegexData("r"), true},
		{TimeData(time.Time{}), false},
		{TimeData(testTime), true},
		{TimeDataPtr(nil), false},
		{TimeDataPtr(&testTime), true},
		{VersionData("1.2.3"), true},
		{VersionData(""), false},
		{ArrayData([]any{}, types.Any), false},
		{ArrayData([]any{false}, types.Bool), false},
		{ArrayData([]any{true}, types.Bool), true},
		{MapData(map[string]any{}, types.Any), true},
		{MapData(map[string]any{"a": false}, types.Bool), false},
		{MapData(map[string]any{"a": true}, types.Bool), true},
		{ResourceData(nil, "something"), true},
		// implicit nil:
		{&RawData{Type: types.String}, false},
	}

	for i := range tests {
		o := tests[i]
		t.Run(o.data.String(), func(t *testing.T) {
			is, _ := o.data.IsTruthy()
			assert.Equal(t, o.res, is)
		})
	}
}

// TestTruthyTypeMismatch ensures that a RawData whose declared type disagrees
// with the Go type of its value does not panic in IsTruthy; instead it returns
// (false, false) — "could not determine". See issue #8430.
func TestTruthyTypeMismatch(t *testing.T) {
	tests := []struct {
		name string
		data *RawData
	}{
		{"int type with string value", &RawData{Type: types.Int, Value: "not-an-int"}},
		{"string type with int value", &RawData{Type: types.String, Value: int64(1)}},
		{"bool type with string value", &RawData{Type: types.Bool, Value: "nope"}},
		{"float type with string value", &RawData{Type: types.Float, Value: "nope"}},
		{"regex type with int value", &RawData{Type: types.Regex, Value: int64(1)}},
		{"version type with int value", &RawData{Type: types.Version, Value: int64(1)}},
		{"time type with string value", &RawData{Type: types.Time, Value: "nope"}},
		{"ip type with string value", &RawData{Type: types.IP, Value: "nope"}},
		{"array type with string value", &RawData{Type: types.Array(types.Bool), Value: "nope"}},
		{"map type with string value", &RawData{Type: types.Map(types.String, types.Bool), Value: "nope"}},
		{"block type with string value", &RawData{Type: types.Block, Value: "nope"}},
	}

	for i := range tests {
		o := tests[i]
		t.Run(o.name, func(t *testing.T) {
			var truthy, valid bool
			require.NotPanics(t, func() {
				truthy, valid = o.data.IsTruthy()
			})
			assert.False(t, truthy)
			assert.False(t, valid)
		})
	}
}

func TestSuccess(t *testing.T) {
	tests := []struct {
		data    *RawData
		success bool
		valid   bool
	}{
		{NilData, false, false},
		{BoolTrue, true, true},
		{BoolFalse, false, true},
		{IntData(0), false, false},
		{IntData(123), false, false},
		{FloatData(0), false, false},
		{FloatData(1.23), false, false},
		{StringData(""), false, false},
		{StringData("b"), false, false},
		{RegexData(""), false, false},
		{RegexData("r"), false, false},
		{TimeData(time.Time{}), false, false},
		{TimeDataPtr(nil), false, false},
		{TimeData(testTime), false, false},
		{VersionData("1.2.3"), false, false},
		{IPData(ParseIP("192.168.0.1")), false, false},
		{IPData(ParseIP("")), false, false},
		{ArrayData([]any{}, types.Any), false, false},
		{ArrayData([]any{true, false, true}, types.Bool), false, true},
		{ArrayData([]any{true, true}, types.Bool), true, true},
		{ResourceData(nil, "something"), false, false},
		{
			data: &RawData{
				Type: types.Block,
				Value: map[string]any{
					"__s": BoolData(true),
				},
			},
			success: true,
			valid:   true,
		},
		{
			data: &RawData{
				Type: types.Block,
				Value: map[string]any{
					"__s": BoolData(false),
				},
			},
			success: false,
			valid:   true,
		},
		{
			data: &RawData{
				Type: types.Block,
				Value: map[string]any{
					"__s": NilData,
				},
			},
			success: false,
			valid:   false,
		},
		{
			data: &RawData{
				Type:  types.Block,
				Value: map[string]any{},
			},
			success: false,
			valid:   false,
		},
		// implicit nil:
		{&RawData{Type: types.String}, false, false},
	}

	for i := range tests {
		o := tests[i]
		t.Run(o.data.String(), func(t *testing.T) {
			success, valid := o.data.IsSuccess()
			assert.Equal(t, o.success, success)
			assert.Equal(t, o.valid, valid)
		})
	}
}

func TestRawData_JSON(t *testing.T) {
	tests := []*RawData{
		NilData,
		BoolTrue,
		BoolFalse,
		IntData(0),
		IntData(123),
		FloatData(0),
		FloatData(1.23),
		StringData(""),
		StringData("b"),
		RegexData(""),
		RegexData("r"),
		TimeData(time.Time{}.In(time.Local)),
		TimeData(NeverFutureTime),
		TimeData(NeverPastTime),
		// TODO: the raw comparison here does not come out right, because of nano time
		// TimeData(now),
		VersionData("1.2.3"),
		IPData(ParseIP("192.168.0.1/13")),
		IPData(ParseIP("")),
		IPData(ParseIntIP(0)),
		IPData(ParseIntIP(1<<33 - 1)),
		IPData(ParseIP("2001:db8:3c4d:15::1a2f:1a2b/64")),
		ArrayData([]any{"a", "b"}, types.String),
		MapData(map[string]any{"a": "b"}, types.String),
		{Error: errors.New("test")},
	}

	for i := range tests {
		o := tests[i]
		t.Run(o.String(), func(t *testing.T) {
			out, err := json.Marshal(o)
			require.NoError(t, err)
			var res RawData
			err = json.Unmarshal(out, &res)
			require.NoError(t, err)
			assert.Equal(t, o, &res)
		})
	}
}

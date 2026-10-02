// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/types"
)

func TestRawDataJson_removeUnderscoreKeys(t *testing.T) {
	tests := map[string]struct {
		input []string
		want  []string
	}{
		"no underscores": {
			input: []string{"this", "that"},
			want:  []string{"this", "that"},
		},
		"trailing underscore": {
			input: []string{"this", "that", "_"},
			want:  []string{"this", "that"},
		},
		"leading underscore": {
			input: []string{"_", "this", "that"},
			want:  []string{"this", "that"},
		},
		"alternating underscores": {
			input: []string{"_", "this", "_", "that", "_"},
			want:  []string{"this", "that"},
		},
		"all underscores": {
			input: []string{"_", "_", "_"},
			want:  []string{},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := removeUnderscoreKeys(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRawDataJson_nevertime(t *testing.T) {
	never := NeverPastTime
	var res bytes.Buffer
	require.NoError(t, rawDataJSON(types.Time, &never, "blfbjef", &CodeBundle{}, &res))
	require.Equal(t, res.String(), "\"Never\"")
	require.True(t, json.Valid(res.Bytes()))
}

func TestRawDataJson_duration(t *testing.T) {
	const mins = 60         // 1 minute in seconds
	const hours = 60 * mins // 1 hour in seconds
	const days = 24 * hours // 24 hours in seconds
	dur := DurationToTime(4*days + 13*hours + 42*mins)
	var res bytes.Buffer
	require.NoError(t, rawDataJSON(types.Time, &dur, "", &CodeBundle{}, &res))
	require.Equal(t, res.String(), "\"4 days 13 hours 42 minutes\"")
	require.True(t, json.Valid(res.Bytes()))
}

func TestRawDataJson_Umlauts(t *testing.T) {
	var res bytes.Buffer
	require.NoError(t, rawDataJSON(types.String, "Systemintegrit\x84t", "blfbjef", &CodeBundle{}, &res))
	require.Equal(t, res.String(), "\"Systemintegrit\\ufffdt\"")
	require.True(t, json.Valid(res.Bytes()))
}

// Two block entries can resolve to the same human-readable label (e.g.
// `package("apparmor").installed` and `package("apparmor-utils").installed`
// both label as `package.installed`). The JSON output must still parse — and
// in particular must not contain duplicate map keys, which downstream
// consumers reject when unmarshaling into proto map fields.
func TestRawDataJson_refMapJSON_collidingLabels(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		data   map[string]any
	}{
		{
			name: "two colliding",
			labels: map[string]string{
				"sum-a": "package.installed",
				"sum-b": "package.installed",
			},
			data: map[string]any{
				"sum-a": BoolData(true),
				"sum-b": BoolData(false),
			},
		},
		{
			name: "three colliding",
			labels: map[string]string{
				"sum-a": "package.installed",
				"sum-b": "package.installed",
				"sum-c": "package.installed",
			},
			data: map[string]any{
				"sum-a": BoolData(true),
				"sum-b": BoolData(false),
				"sum-c": BoolData(true),
			},
		},
		{
			name: "mixed collisions and unique",
			labels: map[string]string{
				"sum-a": "package.installed",
				"sum-b": "package.installed",
				"sum-c": "asset.family",
			},
			data: map[string]any{
				"sum-a": BoolData(true),
				"sum-b": BoolData(false),
				"sum-c": StringData("debian"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle := &CodeBundle{Labels: &Labels{Labels: tc.labels}}
			var buf bytes.Buffer
			require.NoError(t, refMapJSON(types.Block, tc.data, "", bundle, &buf))
			require.True(t, json.Valid(buf.Bytes()), "output is not valid JSON: %s", buf.String())

			// json.Unmarshal silently drops duplicate keys, so walk the raw
			// token stream to assert all top-level keys are unique.
			dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
			seen := map[string]struct{}{}
			var depth int
			for {
				tok, err := dec.Token()
				if err != nil {
					break
				}
				switch v := tok.(type) {
				case json.Delim:
					if v == '{' {
						depth++
					}
					if v == '}' {
						depth--
					}
				case string:
					if depth == 1 && dec.More() {
						if _, dup := seen[v]; dup {
							t.Fatalf("duplicate JSON key %q in %s", v, buf.String())
						}
						seen[v] = struct{}{}
					}
				}
			}
			require.Equal(t, len(tc.data), len(seen), "every entry must be present in JSON: %s", buf.String())
		})
	}
}

// An error value used to be written with PrettyPrintString, which un-escapes \n
// and \t back into real control characters. JSON forbids those inside a string
// (RFC 8259 section 7), so any multi-line error made the whole document
// unparseable - and multi-line is the common case, since a multierror renders as
// "N errors occurred:\n\t* ..." whenever more than one element of a collection
// fails.
func TestRawDataJson_errorValuesAreEscaped(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "single line error",
			err:  errors.New("operation error IAM: GetRole, NoSuchEntity"),
		},
		{
			// The shape a multierror produces, which is what broke this.
			name: "multierror with newline and tab",
			err:  errors.New("2 errors occurred:\n\t* subnet not found\n\t* role not found"),
		},
		{
			name: "carriage return",
			err:  errors.New("line one\rline two"),
		},
		{
			name: "embedded quotes and backslashes",
			err:  errors.New(`the role "x\y" cannot be found`),
		},
		{
			name: "other control characters",
			err:  errors.New("bell\x07 and null-ish\x1f"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle := &CodeBundle{Labels: &Labels{Labels: map[string]string{"e": "thing"}}}
			data := map[string]any{"e": &RawData{Type: types.String, Error: tc.err}}

			var buf bytes.Buffer
			require.NoError(t, refMapJSON(types.Block, data, "", bundle, &buf))
			require.True(t, json.Valid(buf.Bytes()),
				"output is not valid JSON: %q", buf.String())

			// the message must survive intact, not just be escaped away
			var out map[string]string
			require.NoError(t, json.Unmarshal(buf.Bytes(), &out))
			require.Equal(t, "Error: "+tc.err.Error(), out["thing"])
		})
	}
}

// Guard the specific byte-level rule: no raw control character may appear in the
// output, whatever the error contains.
func TestRawDataJson_errorValuesCarryNoRawControlBytes(t *testing.T) {
	bundle := &CodeBundle{Labels: &Labels{Labels: map[string]string{"e": "thing"}}}
	data := map[string]any{
		"e": &RawData{Type: types.String, Error: errors.New("a\n\tb\rc")},
	}

	var buf bytes.Buffer
	require.NoError(t, refMapJSON(types.Block, data, "", bundle, &buf))

	for i, b := range buf.Bytes() {
		require.Greater(t, b, byte(0x1f),
			"raw control byte %#x at offset %d in %q", b, i, buf.String())
	}
}

// MQL represents an unbounded int as math.MaxInt64 / math.MinInt64 and an
// unbounded float as ±Inf. JSON has no infinity token, so these are exported
// as strings, the same way an infinite time exports as "Never". Every other
// number stays a bare JSON number.
func TestRawDataJson_numbers(t *testing.T) {
	tests := []struct {
		name string
		typ  types.Type
		data any
		want string
	}{
		{"int", types.Int, int64(99999), "99999"},
		{"negative int", types.Int, int64(-1), "-1"},
		{"zero int", types.Int, int64(0), "0"},
		{"int max-1", types.Int, int64(math.MaxInt64 - 1), "9223372036854775806"},
		{"int infinity", types.Int, int64(math.MaxInt64), `"Inf"`},
		{"int negative infinity", types.Int, int64(math.MinInt64), `"-Inf"`},
		{"float", types.Float, 1.5, "1.5"},
		{"float infinity", types.Float, math.Inf(1), `"Inf"`},
		{"float negative infinity", types.Float, math.Inf(-1), `"-Inf"`},
		{"float NaN", types.Float, math.NaN(), `"NaN"`},
		{"dict int", types.Dict, int64(7), "7"},
		{"dict int infinity", types.Dict, int64(math.MaxInt64), `"Inf"`},
		{"dict float infinity", types.Dict, math.Inf(-1), `"-Inf"`},
		{"dict float NaN", types.Dict, math.NaN(), `"NaN"`},
		{"dict nested infinity", types.Dict, map[string]any{"a": int64(math.MaxInt64), "b": []any{math.Inf(1), 2.5}}, `{"a":"Inf","b":["Inf",2.5]}`},
		{"int array with infinity", types.Array(types.Int), []any{int64(1), int64(math.MaxInt64)}, `[1,"Inf"]`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var res bytes.Buffer
			require.NoError(t, rawDataJSON(tc.typ, tc.data, "", &CodeBundle{}, &res))
			assert.Equal(t, tc.want, res.String())
			assert.True(t, json.Valid(res.Bytes()), "not valid JSON: %s", res.String())
		})
	}
}

// shadow.list { user maxdays inactivedays } on Debian 12, where root's
// /etc/shadow line is `root:...:20719:0:99999:7:::` (inactive field empty).
func TestRawDataJson_shadowEntryBlock(t *testing.T) {
	bundle := &CodeBundle{Labels: &Labels{Labels: map[string]string{
		"u": "user", "m": "maxdays", "i": "inactivedays",
	}}}
	data := map[string]any{
		"u": StringData("root"),
		"m": IntData(99999),
		"i": IntData(math.MaxInt64),
	}
	var res bytes.Buffer
	require.NoError(t, refMapJSON(types.Block, data, "", bundle, &res))
	assert.True(t, json.Valid(res.Bytes()), "not valid JSON: %s", res.String())

	var got map[string]any
	require.NoError(t, json.Unmarshal(res.Bytes(), &got))
	assert.Equal(t, map[string]any{"user": "root", "maxdays": float64(99999), "inactivedays": "Inf"}, got)
}

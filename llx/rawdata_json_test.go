// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"bytes"
	"encoding/json"
	"errors"
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
	require.True(t, json.Valid(res.Bytes()))
	// The invalid byte becomes U+FFFD. Go 1.27's encoding/json writes it as the
	// raw character where earlier releases escaped it as �; both decode to
	// the same string, which is what consumers of the output see.
	var decoded string
	require.NoError(t, json.Unmarshal(res.Bytes(), &decoded))
	require.Equal(t, "Systemintegrit�t", decoded)
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

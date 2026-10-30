// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVersionCount(t *testing.T) {
	// The Packer API encodes the version count as a string; parsing must be
	// lossless for valid values and degrade to zero for missing/garbage ones.
	tests := []struct {
		in   string
		want int64
	}{
		{"", 0},
		{"0", 0},
		{"7", 7},
		{"1024", 1024},
		{"-3", -3},
		{"not-a-number", 0},
		{"12.5", 0},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, parseVersionCount(tt.in), "parseVersionCount(%q)", tt.in)
	}
}

func TestStrfmtTime(t *testing.T) {
	// The zero time must map to nil so it round-trips as null across the plugin
	// boundary, while a real timestamp is preserved.
	assert.Nil(t, strfmtTime(strfmt.DateTime(time.Time{})))

	want := time.Date(2026, 7, 22, 10, 30, 0, 0, time.UTC)
	got := strfmtTime(strfmt.DateTime(want))
	require.NotNil(t, got)
	assert.True(t, got.Equal(want))
}

func TestEnumStr(t *testing.T) {
	type clusterState string
	const running clusterState = "RUNNING"

	assert.Equal(t, "", enumStr[clusterState](nil))
	s := running
	assert.Equal(t, "RUNNING", enumStr(&s))
}

func TestStrSlice(t *testing.T) {
	assert.Equal(t, []any{}, strSlice(nil))
	assert.Equal(t, []any{"aws", "azure"}, strSlice([]string{"aws", "azure"}))
}

func TestToDict(t *testing.T) {
	// A nil pointer marshals to null and must surface as a nil dict value.
	var nilPtr *struct{ A string }
	assert.Nil(t, toDict(nilPtr))

	// A struct becomes a JSON-native map with float64 numbers, matching what
	// llx dict fields accept.
	in := struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}{Name: "datadog", Count: 3}
	out, ok := toDict(in).(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "datadog", out["name"])
	assert.Equal(t, float64(3), out["count"])
}

type codeErr struct{ code int }

func (e codeErr) Error() string { return "boom" }
func (e codeErr) Code() int     { return e.code }

func TestIsServiceUnavailable(t *testing.T) {
	// A product that is not entitled surfaces as a 404, a 403, or an
	// unparseable gateway error; all three must degrade rather than fail.
	assert.True(t, isServiceUnavailable(codeErr{404}))
	assert.True(t, isServiceUnavailable(codeErr{403}))
	assert.True(t, isServiceUnavailable(errors.New(
		"&{0 []  } (*models.GrpcGatewayRuntimeError) is not supported by the TextConsumer, can be resolved by supporting TextUnmarshaler interface")))
	// A real failure (server error, auth) must still propagate.
	assert.False(t, isServiceUnavailable(codeErr{500}))
	assert.False(t, isServiceUnavailable(errors.New("connection refused")))
	assert.False(t, isServiceUnavailable(nil))
}

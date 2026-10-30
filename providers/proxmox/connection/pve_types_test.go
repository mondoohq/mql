// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPveBoolDecodesEveryFormProxmoxSends(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		// the integer form Proxmox actually sends for most flags
		{`1`, true},
		{`0`, false},
		// the boolean form its API schema declares, emitted by some endpoints
		{`true`, true},
		{`false`, false},
		// quoted variants that come back from config-derived values
		{`"1"`, true},
		{`"0"`, false},
		{`"true"`, true},
		{`"false"`, false},
		// an absent flag is not set
		{`null`, false},
		{`""`, false},
		// any non-zero number means set, rather than being rejected
		{`2`, true},
	}

	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			var b PveBool
			require.NoError(t, json.Unmarshal([]byte(tc.raw), &b))
			require.Equal(t, tc.want, b.Bool())
		})
	}
}

func TestPveBoolRejectsNonsense(t *testing.T) {
	var b PveBool
	require.Error(t, json.Unmarshal([]byte(`"maybe"`), &b))
}

// The whole reason PveBool exists: a plain bool field silently reports false
// for the integer form, and a plain int field fails outright on the boolean
// form. Either alone would misreport real Proxmox data.
func TestPveBoolCoversWhatPlainGoTypesCannot(t *testing.T) {
	type withPlainBool struct {
		Protected bool `json:"protected"`
	}
	var plain withPlainBool
	require.Error(t, json.Unmarshal([]byte(`{"protected":1}`), &plain),
		"a plain bool cannot take the integer form Proxmox sends")

	type withPlainInt struct {
		Protected int `json:"protected"`
	}
	var asInt withPlainInt
	require.Error(t, json.Unmarshal([]byte(`{"protected":true}`), &asInt),
		"a plain int cannot take the boolean form the schema declares")

	type withPveBool struct {
		Protected PveBool `json:"protected"`
	}
	for _, raw := range []string{`{"protected":1}`, `{"protected":true}`} {
		var ok withPveBool
		require.NoError(t, json.Unmarshal([]byte(raw), &ok), raw)
		require.True(t, ok.Protected.Bool(), raw)
	}
}

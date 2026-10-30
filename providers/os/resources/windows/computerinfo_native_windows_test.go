// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package windows

import (
	"encoding/json"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NativeComputerInfo must report, for every key it sets, what Get-ComputerInfo
// reports on the same host, in the same JSON shape. A key missing from the
// native map is allowed (the key set is pinned below); a key with a different
// value is not.
func TestNativeComputerInfoMatchesGetComputerInfo(t *testing.T) {
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", PSGetComputerInfo).Output()
	require.NoError(t, err)
	var want map[string]any
	require.NoError(t, json.Unmarshal(out, &want))
	if want["OsProductType"] == nil {
		t.Skip("Get-ComputerInfo returned no OsProductType on this host (the CIM fallback's case)")
	}

	got, err := NativeComputerInfo()
	require.NoError(t, err)

	for _, key := range NativeComputerInfoKeys {
		g, ok := got[key]
		w := want[key]
		if !ok {
			// absent natively is only right where Get-ComputerInfo has nothing either
			assert.Nil(t, w, "%s: not set natively, Get-ComputerInfo has %v", key, w)
			continue
		}
		if key == "CsProcessors" {
			// CurrentClockSpeed is sampled, and may differ between two reads.
			g, w = withoutClockSpeed(g), withoutClockSpeed(w)
		}
		assert.Equal(t, jsonShape(t, w), jsonShape(t, g), key)
	}
	for key := range got {
		assert.Contains(t, NativeComputerInfoKeys, key, "set natively but not in NativeComputerInfoKeys")
	}
}

// jsonShape round-trips a value through JSON, so both sides compare as
// encoding/json decodes them.
func jsonShape(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	var out any
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

func withoutClockSpeed(v any) any {
	list, ok := v.([]any)
	if !ok {
		return v
	}
	out := make([]any, len(list))
	for i, p := range list {
		m, ok := p.(map[string]any)
		if !ok {
			out[i] = p
			continue
		}
		c := map[string]any{}
		for k, val := range m {
			if k != "CurrentClockSpeed" {
				c[k] = val
			}
		}
		out[i] = c
	}
	return out
}

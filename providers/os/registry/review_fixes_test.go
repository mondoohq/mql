// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryKeyItemKindNone(t *testing.T) {
	k := RegistryKeyItem{Value: RegistryKeyValue{Kind: NONE}}
	assert.Equal(t, "none", k.Kind())
}

// The MULTI_SZ array is JSON-decoded, so an element is only a string if
// PowerShell emitted one. A null decodes to nil and a number to float64, and a
// bare type assertion would panic and take the whole scan down with it.
func TestMultiSzNonStringEntryErrorsRatherThanPanics(t *testing.T) {
	for _, bad := range []string{`null`, `42`, `true`, `{"a":1}`} {
		body := []byte(`{"kind":7,"data":["first",` + bad + `]}`)

		require.NotPanics(t, func() {
			var v RegistryKeyValue
			err := json.Unmarshal(body, &v)
			assert.Error(t, err, "a %s entry must be reported, not assumed to be a string", bad)
		}, "decoding a %s MULTI_SZ entry must not panic", bad)
	}
}

func TestMultiSzStringEntriesStillDecode(t *testing.T) {
	var v RegistryKeyValue
	require.NoError(t, json.Unmarshal([]byte(`{"kind":7,"data":["one","two"]}`), &v))
	assert.Equal(t, MULTI_SZ, v.Kind)
	assert.Equal(t, []string{"one", "two"}, v.MultiString)
}

// A registry key may legally contain a single quote. Interpolated raw into the
// script's `$path = '...'` literal it closes the string early, so the script
// stops parsing or runs whatever followed it.
func TestRegistryScriptsEscapeSingleQuotes(t *testing.T) {
	path := `HKLM:\SOFTWARE\O'Brien`

	for name, script := range map[string]string{
		"item":     GetRegistryKeyItemScript(path),
		"children": GetRegistryKeyChildItemsScript(path),
	} {
		t.Run(name, func(t *testing.T) {
			assert.Contains(t, script, `$path = 'HKLM:\SOFTWARE\O''Brien'`,
				"the quote must be doubled, which is PowerShell's escape inside a single-quoted string")
			assert.NotContains(t, script, `$path = 'HKLM:\SOFTWARE\O'Brien'`,
				"an unescaped quote closes the literal early")
		})
	}
}

func TestRegistryScriptsLeaveOrdinaryPathsAlone(t *testing.T) {
	path := `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	assert.True(t, strings.Contains(GetRegistryKeyItemScript(path), `$path = '`+path+`'`))
}

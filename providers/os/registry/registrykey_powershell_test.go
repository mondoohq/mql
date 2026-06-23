// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsRegistryKeyItemParser(t *testing.T) {
	r, err := os.Open("./testdata/registrykey.json")
	require.NoError(t, err)

	items, err := ParsePowershellRegistryKeyItems(r)
	assert.Nil(t, err)
	assert.Equal(t, 10, len(items))
	assert.Equal(t, "ConsentPromptBehaviorAdmin", items[0].Key)
	assert.Equal(t, 4, items[0].Value.Kind)
	assert.Equal(t, int64(5), items[0].Value.Number)
	assert.Equal(t, int64(5), items[0].GetRawValue())
	assert.Equal(t, "5", items[0].String())
}

func TestWindowsRegistryKeyQwordParser(t *testing.T) {
	// kind 11 == REG_QWORD; PowerShell emits the value as a JSON number
	const data = `[{
		"key": "LowMemoryThreshold",
		"value": { "kind": 11, "data": 4294967296 }
	}]`

	items, err := ParsePowershellRegistryKeyItems(strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, 11, items[0].Value.Kind)
	// a QWORD must surface as the integer value, not the float bit-pattern
	assert.Equal(t, int64(4294967296), items[0].Value.Number)
	assert.Equal(t, int64(4294967296), items[0].GetRawValue())
	assert.Equal(t, "4294967296", items[0].String())
}

func TestWindowsRegistryKeyChildParser(t *testing.T) {
	r, err := os.Open("./testdata/registrykey-children.json")
	require.NoError(t, err)

	items, err := ParsePowershellRegistryKeyChildren(r)
	require.NoError(t, err)
	require.Len(t, items, 5)
	// Name carries the child key name; registrykey.children projects it, so a
	// parser that dropped it would silently empty the resource field.
	assert.Equal(t, RegistryKeyChild{
		Name:       "ActiveDesktop",
		Path:       `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop`,
		Properties: []string{"NoAddingComponents", "NoComponents", "NoHTMLWallPaper"},
	}, items[0])
}

// registrykey.children is documented as the immediate children of a key. The
// script is the only thing that bounds the depth, and a recursive enumeration
// both breaks that contract and can return an unbounded JSON document for a
// large hive.
func TestGetRegistryKeyChildItemsScriptEnumeratesOneLevel(t *testing.T) {
	script := GetRegistryKeyChildItemsScript(`HKEY_LOCAL_MACHINE\SOFTWARE\Example`)

	assert.Contains(t, script, `Get-ChildItem -Path ('Registry::' + $path)`)
	assert.NotContains(t, strings.ToLower(script), "-rec")
	assert.Contains(t, script, `"name" = $_.PSChildName`)
}

func TestWindowsRegistryKeyMultiStringParser(t *testing.T) {
	r, err := os.Open("./testdata/registrykey_multistring.json")
	require.NoError(t, err)

	items, err := ParsePowershellRegistryKeyItems(r)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(items))
	assert.Equal(t, "Machine", items[0].Key)
	assert.Equal(t, 7, items[0].Value.Kind)
	assert.Equal(t, []any{
		"Software\\Microsoft\\Windows NT\\CurrentVersion\\Print",
		"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
		"System\\CurrentControlSet\\Control\\Print\\Printers",
	}, items[0].GetRawValue())
}

func TestNormalizeMultiSz(t *testing.T) {
	t.Run("empty MULTI_SZ artifact is normalized to empty slice", func(t *testing.T) {
		// Windows API returns [""] for empty REG_MULTI_SZ (\0\0 bytes)
		result := normalizeMultiSz([]string{""})
		assert.Equal(t, []string{}, result)
	})
	t.Run("nil input stays nil", func(t *testing.T) {
		assert.Nil(t, normalizeMultiSz(nil))
	})
	t.Run("non-empty values are preserved", func(t *testing.T) {
		assert.Equal(t, []string{"foo"}, normalizeMultiSz([]string{"foo"}))
		assert.Equal(t, []string{"foo", "bar"}, normalizeMultiSz([]string{"foo", "bar"}))
	})
	t.Run("multiple empty strings are preserved", func(t *testing.T) {
		// Two empty strings is distinct from the single-empty artifact
		assert.Equal(t, []string{"", ""}, normalizeMultiSz([]string{"", ""}))
	})
}

// TestWindowsRegistryEmptyListParsers covers the shape PowerShell produces for
// a key that exists but has nothing in it. `ConvertTo-Json` writes nothing at
// all for an empty array, so the collection scripts return an empty stream
// rather than `[]`. Decoding that used to fail with "unexpected end of JSON
// input", which turned "this key is present and configures nothing" into an
// unreadable key. The SCHANNEL subtree hits this routinely: the Protocols key
// holds only subkeys and no values, and a protocol's Client subkey can exist
// with neither Enabled nor DisabledByDefault set.
func TestWindowsRegistryEmptyListParsers(t *testing.T) {
	for _, in := range []string{"", "\r\n", "   \n"} {
		items, err := ParsePowershellRegistryKeyItems(strings.NewReader(in))
		require.NoError(t, err)
		assert.Empty(t, items)

		children, err := ParsePowershellRegistryKeyChildren(strings.NewReader(in))
		require.NoError(t, err)
		assert.Empty(t, children)
	}

	// malformed output is still an error, not silently an empty key
	_, err := ParsePowershellRegistryKeyItems(strings.NewReader("{not json"))
	assert.Error(t, err)
	_, err = ParsePowershellRegistryKeyChildren(strings.NewReader("{not json"))
	assert.Error(t, err)
}

// pathAssignment returns the `$path = ...` line of a generated script.
func pathAssignment(t *testing.T, script string) string {
	t.Helper()
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "$path = ") {
			return line
		}
	}
	t.Fatalf("script has no $path assignment:\n%s", script)
	return ""
}

func TestRegistryScriptsQuoteThePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "plain key",
			path:     `HKLM\Software\Mondoo`,
			expected: `$path = 'HKLM\Software\Mondoo'`,
		},
		{
			// subkey names are read off the target and fed back into the
			// next script, and a registry key name may contain a quote
			name:     "key name with a quote",
			path:     `HKLM\Software\od'd`,
			expected: `$path = 'HKLM\Software\od''d'`,
		},
		{
			name:     "quote followed by a statement separator",
			path:     `HKLM\x'; whoami; '`,
			expected: `$path = 'HKLM\x''; whoami; '''`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, pathAssignment(t, GetRegistryKeyItemScript(test.path)))
			assert.Equal(t, test.expected, pathAssignment(t, GetRegistryKeyChildItemsScript(test.path)))
		})
	}
}

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

// TestResolveRegistryValueKind pins the type resolution that decides whether a
// registry value's data is decoded or thrown away.
//
// Under PowerShell Constrained Language Mode (what WDAC and AppLocker put a host
// into) RegistryKey.GetValueKind() cannot be invoked, so the collection script
// reports no numeric kind. That used to decode as NONE, and NONE discards the
// value: every value on a perfectly readable key came back empty while the value
// names still enumerated. reg.exe is an external program that language mode does
// not restrict, so its type name is the source that survives; when neither source
// reports a type the read has to fail rather than report the key as empty.
func TestResolveRegistryValueKind(t *testing.T) {
	kindPtr := func(i int) *int { return &i }

	t.Run("every reg.exe type name maps to a kind", func(t *testing.T) {
		for typeName, expected := range map[string]int{
			"REG_NONE":                       NONE,
			"REG_SZ":                         SZ,
			"REG_EXPAND_SZ":                  EXPAND_SZ,
			"REG_BINARY":                     BINARY,
			"REG_DWORD":                      DWORD,
			"REG_DWORD_LITTLE_ENDIAN":        DWORD,
			"REG_DWORD_BIG_ENDIAN":           DWORD_BIG_ENDIAN,
			"REG_LINK":                       LINK,
			"REG_MULTI_SZ":                   MULTI_SZ,
			"REG_RESOURCE_LIST":              RESOURCE_LIST,
			"REG_FULL_RESOURCE_DESCRIPTOR":   FULL_RESOURCE_DESCRIPTOR,
			"REG_RESOURCE_REQUIREMENTS_LIST": RESOURCE_REQUIREMENTS_LIST,
			"REG_QWORD":                      QWORD,
			"REG_QWORD_LITTLE_ENDIAN":        QWORD,
		} {
			kind, err := resolveRegistryValueKind(typeName, nil)
			require.NoError(t, err, typeName)
			assert.Equal(t, expected, kind, typeName)
		}
	})

	t.Run("type names are matched case-insensitively", func(t *testing.T) {
		kind, err := resolveRegistryValueKind("reg_multi_sz", nil)
		require.NoError(t, err)
		assert.Equal(t, MULTI_SZ, kind)
	})

	t.Run("the reg.exe type wins over the numeric kind", func(t *testing.T) {
		kind, err := resolveRegistryValueKind("REG_QWORD", kindPtr(SZ))
		require.NoError(t, err)
		assert.Equal(t, QWORD, kind)
	})

	t.Run("the numeric kind is used when reg.exe reported no type", func(t *testing.T) {
		kind, err := resolveRegistryValueKind("", kindPtr(DWORD))
		require.NoError(t, err)
		assert.Equal(t, DWORD, kind)

		// an explicit REG_NONE is a real answer, not a missing one
		kind, err = resolveRegistryValueKind("", kindPtr(NONE))
		require.NoError(t, err)
		assert.Equal(t, NONE, kind)
	})

	t.Run("an unrecognized type name is an error, not NONE", func(t *testing.T) {
		_, err := resolveRegistryValueKind("REG_SOMETHING_NEW", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "REG_SOMETHING_NEW")
	})

	t.Run("no type at all is an error, not NONE", func(t *testing.T) {
		_, err := resolveRegistryValueKind("", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Constrained Language Mode")
	})
}

// TestWindowsRegistryKeyItemKinds decodes one value of every registry kind in the
// shape the collection script emits under Constrained Language Mode: a reg.exe
// type name and no numeric kind.
func TestWindowsRegistryKeyItemKinds(t *testing.T) {
	const payload = `[
	  {"key":"ValSz","value":{"data":"hello","type":"REG_SZ","kind":null}},
	  {"key":"ValExpandSz","value":{"data":"C:\\Windows\\temp","type":"REG_EXPAND_SZ","kind":null}},
	  {"key":"ValDword","value":{"data":42,"type":"REG_DWORD","kind":null}},
	  {"key":"ValQword","value":{"data":4294967296,"type":"REG_QWORD","kind":null}},
	  {"key":"ValMultiSz","value":{"data":["alpha","beta","gamma"],"type":"REG_MULTI_SZ","kind":null}},
	  {"key":"ValBinary","value":{"data":[222,173,190,239],"type":"REG_BINARY","kind":null}},
	  {"key":"ValNone","value":{"data":null,"type":"REG_NONE","kind":null}}
	]`

	items, err := ParsePowershellRegistryKeyItems(strings.NewReader(payload))
	require.NoError(t, err)
	require.Len(t, items, 7)

	byName := map[string]RegistryKeyItem{}
	for _, item := range items {
		byName[item.Key] = item
	}

	t.Run("REG_SZ", func(t *testing.T) {
		item := byName["ValSz"]
		assert.Equal(t, SZ, item.Value.Kind)
		assert.Equal(t, "string", item.Kind())
		assert.Equal(t, "hello", item.String())
		assert.Equal(t, "hello", item.GetRawValue())
	})

	t.Run("REG_EXPAND_SZ", func(t *testing.T) {
		item := byName["ValExpandSz"]
		assert.Equal(t, EXPAND_SZ, item.Value.Kind)
		assert.Equal(t, "expandstring", item.Kind())
		assert.Equal(t, `C:\Windows\temp`, item.String())
	})

	t.Run("REG_DWORD", func(t *testing.T) {
		item := byName["ValDword"]
		assert.Equal(t, DWORD, item.Value.Kind)
		assert.Equal(t, "dword", item.Kind())
		assert.Equal(t, int64(42), item.Value.Number)
		assert.Equal(t, "42", item.String())
		assert.Equal(t, int64(42), item.GetRawValue())
	})

	t.Run("REG_QWORD", func(t *testing.T) {
		// a QWORD used to be stuffed into Binary as the IEEE-754 bit pattern of
		// the JSON number, which left Number at zero and String empty: the value
		// read as blank on every host, not just a locked-down one. It decodes
		// like a DWORD now, which is also what the native backend produces.
		item := byName["ValQword"]
		assert.Equal(t, QWORD, item.Value.Kind)
		assert.Equal(t, "qword", item.Kind())
		assert.Equal(t, int64(4294967296), item.Value.Number)
		assert.Equal(t, "4294967296", item.String())
		assert.Equal(t, int64(4294967296), item.GetRawValue())
	})

	t.Run("REG_MULTI_SZ", func(t *testing.T) {
		item := byName["ValMultiSz"]
		assert.Equal(t, MULTI_SZ, item.Value.Kind)
		assert.Equal(t, "multistring", item.Kind())
		assert.Equal(t, []string{"alpha", "beta", "gamma"}, item.Value.MultiString)
		assert.Equal(t, []any{"alpha", "beta", "gamma"}, item.GetRawValue())
	})

	t.Run("REG_BINARY", func(t *testing.T) {
		item := byName["ValBinary"]
		assert.Equal(t, BINARY, item.Value.Kind)
		assert.Equal(t, "binary", item.Kind())
		assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, item.Value.Binary)
		// the raw value has to be JSON-native: an llx dict cannot carry a
		// []byte, and handing it one fails the whole key read rather than the
		// single binary value.
		assert.Equal(t, []any{int64(0xde), int64(0xad), int64(0xbe), int64(0xef)}, item.GetRawValue())
	})

	t.Run("REG_NONE", func(t *testing.T) {
		item := byName["ValNone"]
		assert.Equal(t, NONE, item.Value.Kind)
		assert.Nil(t, item.GetRawValue())
	})
}

// TestWindowsRegistryKeyItemUndeterminedKind covers the failure this fix exists
// for: a value whose type could not be established must fail the read loudly
// instead of decoding as NONE and reporting the value as empty. A key that
// cannot be read must not look like a key that configures nothing.
func TestWindowsRegistryKeyItemUndeterminedKind(t *testing.T) {
	const payload = `[{"key":"ProductPolicy","value":{"data":"something","type":null,"kind":null}}]`

	items, err := ParsePowershellRegistryKeyItems(strings.NewReader(payload))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not determine the registry value type")
	assert.Empty(t, items)
}

// TestWindowsRegistryKeyItemNumericKindOnly keeps the pre-reg.exe output shape
// decoding, so recordings and mock connections captured before this change still
// replay.
func TestWindowsRegistryKeyItemNumericKindOnly(t *testing.T) {
	const payload = `[
	  {"key":"ValSz","value":{"data":"hello","kind":1}},
	  {"key":"ValDword","value":{"data":7,"kind":4}},
	  {"key":"ValMultiSz","value":{"data":["a","b"],"kind":7}}
	]`

	items, err := ParsePowershellRegistryKeyItems(strings.NewReader(payload))
	require.NoError(t, err)
	require.Len(t, items, 3)
	assert.Equal(t, SZ, items[0].Value.Kind)
	assert.Equal(t, "hello", items[0].String())
	assert.Equal(t, DWORD, items[1].Value.Kind)
	assert.Equal(t, int64(7), items[1].Value.Number)
	assert.Equal(t, MULTI_SZ, items[2].Value.Kind)
	assert.Equal(t, []string{"a", "b"}, items[2].Value.MultiString)
}

// TestGetRegistryKeyItemScript checks the collection script keeps the two traits
// the fix depends on: value types are read with reg.exe, an external program that
// Constrained Language Mode does not restrict, while value data still comes from
// Get-ItemProperty, which (unlike reg.exe) expands REG_EXPAND_SZ values.
func TestGetRegistryKeyItemScript(t *testing.T) {
	script := GetRegistryKeyItemScript(`HKEY_LOCAL_MACHINE\SOFTWARE\Example`)

	assert.Contains(t, script, `$path = 'HKEY_LOCAL_MACHINE\SOFTWARE\Example'`)
	assert.Contains(t, script, `reg.exe`)
	assert.Contains(t, script, `Get-ItemProperty`)
	// the default value's row is named in the console locale, so it is read
	// through its own query rather than matched by name
	assert.Contains(t, script, `/ve`)
	// GetValueKind survives only as a fallback, and never uncaught: under
	// Constrained Language Mode invoking it throws
	assert.Contains(t, script, `try { $kind = $reg.GetValueKind($fetchKeyValue) } catch { $kind = $null }`)
}

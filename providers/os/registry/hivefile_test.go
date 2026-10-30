// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// fixtureHive gunzips testdata/fixture.hiv.gz into dir and returns its path.
// The hive was saved on Windows Server 2025 with `reg save` from
// HKLM\SOFTWARE\MondooHiveFixture after a script created the keys and values
// the tests expect, so the hive root is that key.
func fixtureHive(t *testing.T, dir string) string {
	t.Helper()
	in, err := os.Open(filepath.Join("testdata", "fixture.hiv.gz"))
	require.NoError(t, err)
	defer in.Close()
	zr, err := gzip.NewReader(in)
	require.NoError(t, err)
	path := filepath.Join(dir, "fixture.hiv")
	out, err := os.Create(path)
	require.NoError(t, err)
	_, err = io.Copy(out, zr)
	require.NoError(t, err)
	require.NoError(t, out.Close())
	return path
}

func openFixture(t *testing.T) *hiveFile {
	t.Helper()
	h, err := openHiveFile(fixtureHive(t, t.TempDir()))
	require.NoError(t, err)
	t.Cleanup(func() { h.Close() })
	return h
}

func itemByName(t *testing.T, items []RegistryKeyItem, name string) RegistryKeyItem {
	t.Helper()
	for _, i := range items {
		if i.Key == name {
			return i
		}
	}
	require.Failf(t, "value not found", "no value named %q", name)
	return RegistryKeyItem{}
}

func TestHiveFileValues(t *testing.T) {
	h := openFixture(t)
	items, err := h.Items("Values")
	require.NoError(t, err)
	assert.Len(t, items, 15)

	t.Run("sz", func(t *testing.T) {
		v := itemByName(t, items, "Sz").Value
		assert.Equal(t, SZ, v.Kind)
		assert.Equal(t, "hello world", v.String)
	})
	t.Run("sz unicode", func(t *testing.T) {
		assert.Equal(t, "über 日本", itemByName(t, items, "SzUnicode").Value.String)
	})
	t.Run("sz empty", func(t *testing.T) {
		v := itemByName(t, items, "SzEmpty").Value
		assert.Equal(t, SZ, v.Kind)
		assert.Equal(t, "", v.String)
	})
	t.Run("expand sz is not expanded", func(t *testing.T) {
		v := itemByName(t, items, "ExpandSz").Value
		assert.Equal(t, EXPAND_SZ, v.Kind)
		assert.Equal(t, `%SystemRoot%\system32`, v.String)
	})
	t.Run("multi sz", func(t *testing.T) {
		v := itemByName(t, items, "MultiSz").Value
		assert.Equal(t, MULTI_SZ, v.Kind)
		assert.Equal(t, []string{"one", "two", "three"}, v.MultiString)
	})
	t.Run("empty multi sz is an empty list", func(t *testing.T) {
		v := itemByName(t, items, "MultiSzEmpty").Value
		assert.Equal(t, MULTI_SZ, v.Kind)
		assert.NotNil(t, v.MultiString)
		assert.Empty(t, v.MultiString)
	})
	t.Run("dword", func(t *testing.T) {
		v := itemByName(t, items, "Dword").Value
		assert.Equal(t, DWORD, v.Kind)
		assert.Equal(t, int64(112), v.Number)
	})
	t.Run("dword with all bits set is unsigned", func(t *testing.T) {
		assert.Equal(t, int64(0xFFFFFFFF), itemByName(t, items, "DwordMax").Value.Number)
	})
	t.Run("qword", func(t *testing.T) {
		v := itemByName(t, items, "Qword").Value
		assert.Equal(t, QWORD, v.Kind)
		assert.Equal(t, int64(133000000000000000), v.Number)
	})
	t.Run("binary", func(t *testing.T) {
		v := itemByName(t, items, "Binary").Value
		assert.Equal(t, BINARY, v.Kind)
		assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, v.Binary)
	})
	t.Run("big data binary", func(t *testing.T) {
		v := itemByName(t, items, "BinaryBig").Value
		require.Len(t, v.Binary, 20000)
		for i, b := range v.Binary {
			if b != byte(i%251) {
				require.Failf(t, "wrong byte", "byte %d is %d, want %d", i, b, i%251)
			}
		}
	})
	t.Run("big sz", func(t *testing.T) {
		v := itemByName(t, items, "SzBig").Value
		assert.Len(t, v.String, 12000)
		for i := 0; i < len(v.String); i++ {
			if v.String[i] != 'x' {
				require.Failf(t, "wrong char", "char %d is %q", i, v.String[i])
			}
		}
	})
	t.Run("reg none", func(t *testing.T) {
		item := itemByName(t, items, "NoneType")
		assert.Equal(t, NONE, item.Value.Kind)
		assert.Nil(t, item.GetRawValue())
	})
	t.Run("default value has an empty name", func(t *testing.T) {
		v := itemByName(t, items, "").Value
		assert.Equal(t, SZ, v.Kind)
		assert.Equal(t, "default value", v.String)
	})
}

func TestHiveFileCaseInsensitiveLookup(t *testing.T) {
	h := openFixture(t)

	items, err := h.Items("VALUES")
	require.NoError(t, err)
	assert.Len(t, items, 15)

	// the value keeps the case it was created with
	item, err := h.Item("Values", "mixedcasename")
	require.NoError(t, err)
	assert.Equal(t, "MixedCaseName", item.Key)
	assert.Equal(t, "case", item.Value.String)

	assert.True(t, h.Exists("mixedCASE\\subkey"))
	names, err := h.Children("MIXEDCASE")
	require.NoError(t, err)
	assert.Equal(t, []string{"SubKey"}, names)
}

func TestHiveFileKeys(t *testing.T) {
	h := openFixture(t)

	t.Run("root children", func(t *testing.T) {
		names, err := h.Children("")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"Values", "Nested", "MixedCase", "Mime", "Many", "Empty"}, names)
	})
	t.Run("nested key", func(t *testing.T) {
		items, err := h.Items(`Nested\Level2\Level3`)
		require.NoError(t, err)
		require.Len(t, items, 1)
		assert.Equal(t, "Deep", items[0].Key)
		assert.Equal(t, int64(3), items[0].Value.Number)
		// leading and trailing separators do not matter
		assert.True(t, h.Exists(`\Nested\Level2\`))
	})
	t.Run("key name containing a slash", func(t *testing.T) {
		names, err := h.Children("Mime")
		require.NoError(t, err)
		assert.Equal(t, []string{"application/json"}, names)
		items, err := h.Items(`Mime\application/json`)
		require.NoError(t, err)
		require.Len(t, items, 1)
		assert.Equal(t, "Extension", items[0].Key)
		assert.Equal(t, ".json", items[0].Value.String)
		// a slash is not a separator
		assert.False(t, h.Exists("Mime/application/json"))
	})
	t.Run("empty key", func(t *testing.T) {
		assert.True(t, h.Exists("Empty"))
		items, err := h.Items("Empty")
		require.NoError(t, err)
		assert.Empty(t, items)
		names, err := h.Children("Empty")
		require.NoError(t, err)
		assert.Empty(t, names)
	})
	t.Run("many children", func(t *testing.T) {
		names, err := h.Children("Many")
		require.NoError(t, err)
		require.Len(t, names, 1500)
		seen := map[string]bool{}
		for _, n := range names {
			seen[n] = true
		}
		for i := range 1500 {
			name := fmt.Sprintf("Key%04d", i)
			require.True(t, seen[name], "missing %s", name)
			item, err := h.Item("Many\\"+name, "Index")
			require.NoError(t, err)
			require.Equal(t, int64(i), item.Value.Number, name)
		}
	})
	t.Run("missing key", func(t *testing.T) {
		assert.False(t, h.Exists("Nope"))
		assert.False(t, h.Exists(`Nested\Nope`))
		_, err := h.Items("Nope")
		assert.Equal(t, codes.NotFound, status.Code(err))
		_, err = h.Children("Nested\\Nope")
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
	t.Run("missing value", func(t *testing.T) {
		_, err := h.Item("Values", "Nope")
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
}

func TestOpenHiveFileInvalid(t *testing.T) {
	dir := t.TempDir()
	_, err := openHiveFile(filepath.Join(dir, "missing"))
	assert.Error(t, err)

	notAHive := filepath.Join(dir, "junk")
	require.NoError(t, os.WriteFile(notAHive, make([]byte, 8192), 0o600))
	_, err = openHiveFile(notAHive)
	assert.Error(t, err)
}

func TestHiveFileDirtyWithoutLogsReadsAsIs(t *testing.T) {
	path := fixtureHive(t, t.TempDir())
	// make the hive dirty: primary and secondary sequence numbers differ
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte{0x7f, 0x7f, 0x7f, 0x7f}, 4)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	h, err := openHiveFile(path)
	require.NoError(t, err)
	defer h.Close()
	assert.Zero(t, h.recovered, "no logs, so nothing to recover into")
	item, err := h.Item("Values", "Sz")
	require.NoError(t, err)
	assert.Equal(t, "hello world", item.Value.String)
}

func TestDecodeHiveName(t *testing.T) {
	assert.Equal(t, "café", decodeHiveName("caf\xe9", true))
	assert.Equal(t, "ab", decodeHiveName("a\x00b\x00", false))
}

// A DWORD whose data cell lies outside the hive fails that value with an
// error, it does not crash the reader and the other values stay readable.
func TestHiveFileValueWithUnreadableDataFailsAlone(t *testing.T) {
	path := fixtureHive(t, t.TempDir())
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	// find the vk cell of the "Dword" value (name length 5, then "Dword" at +20)
	at := -1
	for i := 0; i+25 < len(raw); i++ {
		if string(raw[i:i+2]) == "vk" && raw[i+2] == 5 && string(raw[i+20:i+25]) == "Dword" {
			at = i
			break
		}
	}
	require.GreaterOrEqual(t, at, 0)
	// 4 bytes of data, stored in a cell, at an offset far beyond the file
	raw[at+4], raw[at+5], raw[at+6], raw[at+7] = 4, 0, 0, 0
	raw[at+8], raw[at+9], raw[at+10], raw[at+11] = 0xF8, 0xFF, 0xFF, 0x7F
	require.NoError(t, os.WriteFile(path, raw, 0o600))

	h, err := openHiveFile(path)
	require.NoError(t, err)
	defer h.Close()
	items, err := h.Items("Values")
	require.NoError(t, err)
	assert.Len(t, items, 15)
	assert.Error(t, itemByName(t, items, "Dword").Value.Err)
	assert.Equal(t, "hello world", itemByName(t, items, "Sz").Value.String)
	item, err := h.Item("Values", "Dword")
	require.NoError(t, err)
	assert.Error(t, item.Value.Err)
}

// Windows images commonly hold empty .LOG1 and .LOG2 files, which are no log.
func TestHiveFileEmptyLogsAreIgnored(t *testing.T) {
	path := fixtureHive(t, t.TempDir())
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte{0x7f, 0x7f, 0x7f, 0x7f}, 4)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.NoError(t, os.WriteFile(path+".LOG1", nil, 0o600))
	require.NoError(t, os.WriteFile(path+".LOG2", nil, 0o600))

	h, err := openHiveFile(path)
	require.NoError(t, err)
	defer h.Close()
	assert.Zero(t, h.recovered)
	assert.Empty(t, h.logs, "log files that were not used are closed")
	item, err := h.Item("Values", "Sz")
	require.NoError(t, err)
	assert.Equal(t, "hello world", item.Value.String)
}

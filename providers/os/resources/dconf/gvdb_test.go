// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dconf

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// compileDir compiles a keyfile directory of testdata as dconf update does.
func compileDir(t *testing.T, dir string) *Database {
	t.Helper()
	names, err := os.ReadDir(dir)
	require.NoError(t, err)
	var files []Keyfile
	for _, n := range names {
		if n.IsDir() || !IsKeyfile(n.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, n.Name()))
		require.NoError(t, err)
		entries, err := ParseKeyfile(n.Name(), bytes.NewReader(data))
		require.NoError(t, err)
		files = append(files, Keyfile{Name: n.Name(), Entries: entries})
	}
	var locks []string
	lockFiles, _ := os.ReadDir(filepath.Join(dir, "locks"))
	for _, n := range lockFiles {
		data, err := os.ReadFile(filepath.Join(dir, "locks", n.Name()))
		require.NoError(t, err)
		l, err := ParseLocks(bytes.NewReader(data))
		require.NoError(t, err)
		locks = append(locks, l...)
	}
	db, _, err := Compile(files, locks)
	require.NoError(t, err)
	return db
}

func readFixture(t *testing.T, name string) *Database {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	db, err := ReadDatabase(data)
	require.NoError(t, err)
	sort.Strings(db.Locks)
	return db
}

// The fixtures were compiled by dconf update from testdata/local.d and
// testdata/site.d: dconf 0.49 on Fedora 43 and dconf 0.26 on Ubuntu 18.04.
func TestReadDatabaseMatchesKeyfiles(t *testing.T) {
	for _, version := range []string{"fedora43", "ubuntu1804"} {
		t.Run(version, func(t *testing.T) {
			local := readFixture(t, version+"-local.gvdb")
			assert.Equal(t, compileDir(t, "testdata/local.d"), local)
			assert.Equal(t, int64(600), local.Values["/org/gnome/desktop/session/idle-delay"], "10-override wins over 00-screensaver")
			assert.Equal(t, []any{[]any{"xkb", "us"}, []any{"xkb", "de"}}, local.Values["/org/gnome/desktop/input-sources/sources"])
			assert.Equal(t, []any{}, local.Values["/org/gnome/desktop/input-sources/xkb-options"])
			assert.Equal(t, []string{"/org/gnome/desktop/session/idle-delay"}, local.Locks, "the indented lock line is ignored")

			site := readFixture(t, version+"-site.gvdb")
			assert.Equal(t, compileDir(t, "testdata/site.d"), site)
			assert.Equal(t, "file:///usr/share/backgrounds/it's.png", site.Values["/org/gnome/desktop/screensaver/picture-uri"])

			gdm := readFixture(t, version+"-gdm.gvdb")
			assert.Equal(t, true, gdm.Values["/org/gnome/login-screen/banner-message-enable"])
			assert.Equal(t, "Authorized uses only. All activity may be monitored and reported.", gdm.Values["/org/gnome/login-screen/banner-message-text"])
			assert.Equal(t, []string{"/org/gnome/login-screen/banner-message-enable"}, gdm.Locks)
		})
	}
}

func TestResolveFixtures(t *testing.T) {
	local := readFixture(t, "fedora43-local.gvdb")
	site := readFixture(t, "fedora43-site.gvdb")
	// user-db:user, system-db:local, system-db:site; `dconf read` gave these
	values, locks := Resolve([]*Database{nil, local, site})
	assert.Equal(t, int64(600), values["/org/gnome/desktop/session/idle-delay"])
	assert.Equal(t, int64(30), values["/org/gnome/desktop/screensaver/lock-delay"], "site locks lock-delay, so its value wins over local's")
	assert.Equal(t, []string{"/org/gnome/desktop/screensaver/lock-delay", "/org/gnome/desktop/session/idle-delay"}, locks)
}

func TestReadDatabaseRejectsInvalidated(t *testing.T) {
	data, err := os.ReadFile("testdata/fedora43-local.gvdb")
	require.NoError(t, err)
	// dconf update overwrites the header of the database it replaces
	copy(data, make([]byte, 8))
	_, err = ReadDatabase(data)
	assert.ErrorIs(t, err, ErrNotDatabase)
	_, err = ReadDatabase([]byte("short"))
	assert.ErrorIs(t, err, ErrNotDatabase)
}

var littleEndian = binary.LittleEndian

func TestDecodeVariantTypes(t *testing.T) {
	le := []byte{0x84, 0x03, 0, 0, 0, 'u'} // uint32 900
	v, err := DecodeVariant(le, littleEndian)
	require.NoError(t, err)
	assert.Equal(t, int64(900), v)

	// a{sv} {'a': <true>}: entry "a\0" + pad + variant (01 00 'b') + framing offset
	entry := []byte{'a', 0, 0, 0, 0, 0, 0, 0, 1, 0, 'b', 2}
	arr := append(append([]byte{}, entry...), byte(len(entry)))
	v, err = DecodeVariant(append(append(arr, 0), []byte("a{sv}")...), littleEndian)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"a": true}, v)
}

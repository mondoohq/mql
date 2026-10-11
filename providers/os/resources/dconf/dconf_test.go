// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dconf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseText(t *testing.T) {
	cases := []struct {
		in   string
		want any
	}{
		{"true", true},
		{"false", false},
		{"uint32 900", int64(900)},
		{"  uint32   5 ", int64(5)},
		{"900", int64(900)},
		{"-1", int64(-1)},
		{"0x1f", int64(31)},
		{"1.5", 1.5},
		{"double 5", float64(5)},
		{"@d 5", float64(5)},
		{"'Authorized uses only.'", "Authorized uses only."},
		{`"it's"`, "it's"},
		{`'a\nb\'cé'`, "a\nb'cé"},
		{"@as []", []any{}},
		{"['a', 'b']", []any{"a", "b"}},
		{"[1, 2.5]", []any{1.0, 2.5}},
		{"[('xkb', 'us'), ('xkb', 'de')]", []any{[]any{"xkb", "us"}, []any{"xkb", "de"}}},
		{"('x',)", []any{"x"}},
		{"{'a': 1, 'b': 2}", map[string]any{"a": int64(1), "b": int64(2)}},
		{"@a{ss} {}", map[string]any{}},
		{"{'a', <true>}", []any{"a", true}},
		{"<uint32 3>", int64(3)},
		{"@ms nothing", nil},
		{"just 'x'", "x"},
		{"b'ab'", []any{int64(97), int64(98), int64(0)}},
		{"objectpath '/org/x'", "/org/x"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := ParseText(c.in)
			require.NoError(t, err)
			assert.Equal(t, c.want, got)
		})
	}

	for _, bad := range []string{"", "'open", "[1, 2", "uint32", "900 seconds", "yes"} {
		_, err := ParseText(bad)
		assert.Error(t, err, bad)
	}
}

func TestParseKeyfile(t *testing.T) {
	entries, err := ParseKeyfile("00-screensaver", strings.NewReader(`# Specify the dconf path
[org/gnome/desktop/session]
idle-delay=uint32 900

  [org/gnome/desktop/screensaver]
lock-delay = uint32 5
lock-enabled=true
lock-enabled=false

[org/gnome/desktop/session]
other='x'
[/]
top=1
`))
	require.NoError(t, err)
	assert.Equal(t, []KeyfileEntry{
		{Path: "/org/gnome/desktop/session/idle-delay", Text: "uint32 900"},
		{Path: "/org/gnome/desktop/session/other", Text: "'x'"},
		{Path: "/org/gnome/desktop/screensaver/lock-delay", Text: "uint32 5"},
		{Path: "/org/gnome/desktop/screensaver/lock-enabled", Text: "false"},
		{Path: "/top", Text: "1"},
	}, entries)

	for _, bad := range []string{
		"idle-delay=1\n",                // before any group
		"[org/gnome]\nidle-delay\n",     // no =
		"[org/gnome] x\nidle-delay=1\n", // text after the group
		"[/org/gnome]\nidle-delay=1\n",  // //org/gnome/idle-delay
		"[org/gnome/]\nidle-delay=1\n",  // org/gnome//idle-delay
		"[org/gnome]\n=1\n",             // empty key
	} {
		_, err := ParseKeyfile("x", strings.NewReader(bad))
		assert.Error(t, err, bad)
	}
}

func TestParseLocks(t *testing.T) {
	locks, err := ParseLocks(strings.NewReader("# locks\n/org/gnome/desktop/session/idle-delay\n  /org/gnome/desktop/screensaver/lock-delay\n/org/gnome/desktop/screensaver/lock-enabled\n"))
	require.NoError(t, err)
	assert.Equal(t, []string{"/org/gnome/desktop/session/idle-delay", "/org/gnome/desktop/screensaver/lock-enabled"}, locks,
		"dconf update takes only lines starting with /")
}

func TestCompile(t *testing.T) {
	db, text, err := Compile([]Keyfile{
		{Name: "90-local", Entries: []KeyfileEntry{{Path: "/a/x", Text: "uint32 300"}}},
		{Name: "00-base", Entries: []KeyfileEntry{{Path: "/a/x", Text: "uint32 900"}, {Path: "/a/y", Text: "true"}}},
	}, []string{"/a/y", "/a/x", "/a/y"})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"/a/x": int64(300), "/a/y": true}, db.Values, "the file that sorts last wins")
	assert.Equal(t, "uint32 300", text["/a/x"])
	assert.Equal(t, []string{"/a/x", "/a/y"}, db.Locks)

	_, _, err = Compile([]Keyfile{{Name: "00-bad", Entries: []KeyfileEntry{{Path: "/a/x", Text: "900 seconds"}}}}, nil)
	assert.ErrorContains(t, err, "00-bad")
}

func TestParseProfile(t *testing.T) {
	sources, err := ParseProfile(strings.NewReader(`user-db:user
  system-db:local   # site settings
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
service-db:x
bogus-db:y
system-db:
`))
	require.NoError(t, err)
	assert.Equal(t, []Source{
		{Type: SourceUser, Name: "user"},
		{Type: SourceSystem, Name: "local"},
		{Type: SourceSystem, Name: "gdm"},
		{Type: SourceFile, Name: "/usr/share/gdm/greeter-dconf-defaults"},
		{Type: SourceService, Name: "x"},
	}, sources)
	assert.Equal(t, "/etc/dconf/db/gdm", sources[2].Path())
	assert.Equal(t, "", sources[0].Path())
}

func TestResolve(t *testing.T) {
	local := &Database{
		Values: map[string]any{"/k/idle": int64(900), "/k/banner": true},
		Locks:  []string{"/k/idle"},
	}
	vendor := &Database{
		Values: map[string]any{"/k/idle": int64(0), "/k/banner": false, "/k/vendor-only": "v"},
		Locks:  []string{"/k/banner"},
	}

	t.Run("first source with the key wins, a lower lock moves the search down", func(t *testing.T) {
		values, locked := Resolve([]*Database{nil, local, vendor})
		assert.Equal(t, int64(900), values["/k/idle"])
		assert.Equal(t, false, values["/k/banner"], "the vendor database locks banner, so its value wins")
		assert.Equal(t, "v", values["/k/vendor-only"])
		assert.Equal(t, []string{"/k/banner", "/k/idle"}, locked)
	})

	t.Run("locks in the first source are ignored", func(t *testing.T) {
		values, locked := Resolve([]*Database{local, vendor})
		assert.Equal(t, int64(900), values["/k/idle"])
		assert.Equal(t, false, values["/k/banner"])
		assert.Equal(t, []string{"/k/banner"}, locked)
	})
}

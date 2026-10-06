// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build unix

package filesfind

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// walkFixture is a small usr-merged tree:
//
//	usr/bin/{su (setuid), ls, sg (setgid), ping.conf}
//	usr/bin/sub/inner.conf
//	bin -> usr/bin                 (start-path link)
//	usr/bin/linkdir -> ../../other (linked directory, never walked)
//	usr/bin/linkfile -> ls         (link to a file: a "file")
//	usr/bin/broken -> nowhere      (broken link: a "link")
//	other/hidden.conf (setuid)
func walkFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "usr", "bin")
	require.NoError(t, os.MkdirAll(filepath.Join(bin, "sub"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "other"), 0o755))
	write := func(p string, mode os.FileMode) {
		require.NoError(t, os.WriteFile(p, nil, 0o644))
		require.NoError(t, os.Chmod(p, mode))
	}
	write(filepath.Join(bin, "su"), 0o755|os.ModeSetuid)
	write(filepath.Join(bin, "sg"), 0o755|os.ModeSetgid)
	write(filepath.Join(bin, "ls"), 0o755)
	write(filepath.Join(bin, "ping.conf"), 0o644)
	write(filepath.Join(bin, "sub", "inner.conf"), 0o600)
	write(filepath.Join(root, "other", "hidden.conf"), 0o755|os.ModeSetuid)
	require.NoError(t, os.Symlink("usr/bin", filepath.Join(root, "bin")))
	require.NoError(t, os.Symlink("../../other", filepath.Join(bin, "linkdir")))
	require.NoError(t, os.Symlink("ls", filepath.Join(bin, "linkfile")))
	require.NoError(t, os.Symlink("nowhere", filepath.Join(bin, "broken")))
	return root
}

func rel(root string, paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		r, _ := filepath.Rel(root, p)
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func depth(d int64) *int64 { return &d }

func walkCases(root string, bin string) map[string]WalkOptions {
	return map[string]WalkOptions{
		"everything from a linked start": {From: bin, Permission: 0o777},
		"setuid files":                   {From: bin, FileType: "file", Permission: 0o4000},
		"setgid":                         {From: bin, Permission: 0o2000},
		"files":                          {From: bin, FileType: "file", Permission: 0o777},
		"directories":                    {From: bin, FileType: "directory", Permission: 0o777},
		"links":                          {From: bin, FileType: "link", Permission: 0o777},
		"name glob":                      {From: bin, Name: "*.conf", Permission: 0o777},
		"regex is anchored":              {From: bin, Regex: ".*/s[ug]", Permission: 0o777},
		"maxdepth 1":                     {From: bin, Depth: depth(1), Permission: 0o777},
		"maxdepth 0":                     {From: bin, Depth: depth(0), Permission: 0o777},
		"real start":                     {From: filepath.Join(root, "usr"), FileType: "file", Permission: 0o777},
		"perm needs every bit":           {From: bin, FileType: "file", Permission: 0o755},
	}
}

func TestWalk(t *testing.T) {
	root := walkFixture(t)
	want := map[string][]string{
		"everything from a linked start": {"bin", "bin/broken", "bin/linkdir", "bin/linkfile", "bin/ls", "bin/ping.conf", "bin/sg", "bin/su", "bin/sub", "bin/sub/inner.conf"},
		"setuid files":                   {"bin/su"},
		"setgid":                         {"bin/sg"},
		"files":                          {"bin/linkfile", "bin/ls", "bin/ping.conf", "bin/sg", "bin/su", "bin/sub/inner.conf"},
		"directories":                    {"bin", "bin/linkdir", "bin/sub"},
		"links":                          {"bin", "bin/broken", "bin/linkdir", "bin/linkfile"},
		"name glob":                      {"bin/ping.conf", "bin/sub/inner.conf"},
		"regex is anchored":              {"bin/sg", "bin/su"},
		"maxdepth 1":                     {"bin", "bin/broken", "bin/linkdir", "bin/linkfile", "bin/ls", "bin/ping.conf", "bin/sg", "bin/su", "bin/sub"},
		"maxdepth 0":                     {"bin"},
		"real start":                     {"usr/bin/linkfile", "usr/bin/ls", "usr/bin/ping.conf", "usr/bin/sg", "usr/bin/su", "usr/bin/sub/inner.conf"},
		"perm needs every bit":           {"bin/linkfile", "bin/ls", "bin/sg", "bin/su"},
	}
	for name, opts := range walkCases(root, filepath.Join(root, "bin")) {
		t.Run(name, func(t *testing.T) {
			got, err := Walk(opts)
			require.NoError(t, err)
			assert.Equal(t, want[name], rel(root, got))
		})
	}
}

// The walk is a stand-in for the find command, so wherever GNU find is
// available the two must agree on every case.
func TestWalkMatchesGNUFind(t *testing.T) {
	out, err := exec.Command("find", "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "GNU findutils") {
		t.Skip("needs GNU find")
	}
	// The start is the real directory: a linked start is pruned by find
	// builds that predate the start-path exemption in BuildFilesFindCmd.
	root := walkFixture(t)
	for name, opts := range walkCases(root, filepath.Join(root, "usr", "bin")) {
		t.Run(name, func(t *testing.T) {
			cmd := BuildFilesFindCmd(opts.From, opts.Xdev, opts.FileType, opts.Regex, opts.Permission, opts.Name, opts.Depth, true)
			raw, err := exec.Command("sh", "-c", cmd).Output()
			require.NoError(t, err, cmd)
			fromFind := strings.Fields(string(raw))

			got, err := Walk(opts)
			require.NoError(t, err)
			assert.Equal(t, rel(root, fromFind), rel(root, got), cmd)
		})
	}
}

func TestWalkErrors(t *testing.T) {
	root := walkFixture(t)

	_, err := Walk(WalkOptions{From: filepath.Join(root, "missing"), Permission: 0o777})
	assert.True(t, os.IsNotExist(err))

	_, err = Walk(WalkOptions{From: root, Name: "[", Permission: 0o777})
	assert.Error(t, err)

	_, err = Walk(WalkOptions{From: root, Regex: "(", Permission: 0o777})
	assert.Error(t, err)
}

func TestWalkUnreadableDirectoryIsPartial(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	root := walkFixture(t)
	locked := filepath.Join(root, "usr", "bin", "sub")
	require.NoError(t, os.Chmod(locked, 0o000))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	got, err := Walk(WalkOptions{From: filepath.Join(root, "bin"), FileType: "file", Permission: 0o4000})
	assert.ErrorIs(t, err, ErrPartialWalk)
	assert.Equal(t, []string{"bin/su"}, rel(root, got))

	_, err = Walk(WalkOptions{From: locked, FileType: "file", Permission: 0o777})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrPartialWalk)
}

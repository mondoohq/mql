// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sshclient

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func osContent(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}

func osGlob(p string) ([]string, error) { return filepath.Glob(p) }

func TestParseConfig(t *testing.T) {
	root := filepath.Join("testdata", "home", ".ssh", "config")
	cfg, err := Parse(root, filepath.Join("testdata", "home"), osContent, osGlob)
	require.NoError(t, err)

	// The settings before any block, then the blocks in the order ssh reads
	// them, with the included file's block where its Include line is.
	assert.Equal(t, map[string]string{"serveraliveinterval": "30"}, cfg.Global())
	require.Len(t, cfg.Blocks, 6)
	kinds := []string{}
	for _, b := range cfg.Blocks[1:] {
		kinds = append(kinds, b.Kind+" "+b.Criteria)
	}
	assert.Equal(t, []string{
		"Host build-01",
		"Host bastion prod-db",
		"Host *.internal !bastion",
		"Host prod-db",
		`Match host build-* exec "true"`,
	}, kinds)

	assert.Equal(t, []string{"bastion", "prod-db"}, cfg.Blocks[2].Patterns)
	assert.Equal(t, "admin", cfg.Blocks[2].Params["user"])
	assert.Equal(t, "no", cfg.Blocks[3].Params["stricthostkeychecking"])
	// A second block for the same host is a separate block, at its own line.
	assert.Equal(t, "other", cfg.Blocks[4].Params["user"])
	assert.NotEqual(t, cfg.Blocks[2].Line, cfg.Blocks[4].Line)
	assert.Equal(t, filepath.Join("testdata", "home", ".ssh", "config.d", "work"), cfg.Blocks[1].Path)

	assert.Equal(t, []string{"build-01", "bastion", "prod-db"}, cfg.LiteralHosts())
	assert.Equal(t, []string{root, filepath.Join("testdata", "home", ".ssh", "config.d", "work")}, cfg.Files)
}

func TestIncludeCycleAndTilde(t *testing.T) {
	files := map[string]string{
		"/home/a/.ssh/config": "Include ~/.ssh/extra\nHost one\n",
		"/home/a/.ssh/extra":  "Include config\nHost two\n",
	}
	content := func(p string) (string, error) { return files[p], nil }
	glob := func(p string) ([]string, error) { return []string{p}, nil }
	cfg, err := Parse("/home/a/.ssh/config", "/home/a", content, glob)
	require.NoError(t, err)
	assert.Equal(t, []string{"two", "one"}, cfg.LiteralHosts())
}

func TestParseKnownHosts(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "home", ".ssh", "known_hosts"))
	require.NoError(t, err)
	res := ParseKnownHosts(string(b))

	require.Len(t, res.Entries, 5)
	assert.Equal(t, 1, res.Unreadable, "a damaged line is counted, not fatal")

	assert.Equal(t, []string{"github.com"}, res.Entries[0].Hosts)
	assert.Equal(t, "ssh-ed25519", res.Entries[0].KeyType)
	assert.True(t, res.Entries[1].Hashed)
	assert.Empty(t, res.Entries[1].Hosts)
	assert.Equal(t, []string{"[git.example.com]:2222", "10.0.0.7"}, res.Entries[2].Hosts)
	assert.Equal(t, "deploy key", res.Entries[2].Comment)
	assert.Equal(t, "cert-authority", res.Entries[3].Marker)
	assert.Equal(t, "revoked", res.Entries[4].Marker)
	assert.Equal(t, 5, res.Entries[4].Line)
}

func TestWindowsPaths(t *testing.T) {
	files := map[string]string{
		`C:\Users\alice\.ssh\config`: "Include extra\nInclude ~/.ssh/more\nInclude C:\\ProgramData\\ssh\\shared\nHost one\n",
		`C:\Users\alice\.ssh\extra`:  "Host two\n",
		`C:\Users\alice\.ssh\more`:   "Host three\n",
		`C:\ProgramData\ssh\shared`:  "Host four\n",
	}
	content := func(p string) (string, error) { return files[p], nil }
	glob := func(p string) ([]string, error) { return []string{p}, nil }
	root := `C:\Users\alice\.ssh\config`
	cfg, err := Parse(root, HomeOf(root), content, glob)
	require.NoError(t, err)
	assert.Equal(t, []string{"two", "three", "four", "one"}, cfg.LiteralHosts())
	assert.Equal(t, `C:\Users\alice`, HomeOf(root))
	assert.Equal(t, "", HomeOf(`C:\ProgramData\ssh\ssh_config`))
	assert.Equal(t, "/home/a", HomeOf("/home/a/.ssh/config"))
	assert.True(t, IsWindowsPath(`C:\x`))
	assert.True(t, IsWindowsPath(`\\server\share`))
	assert.False(t, IsWindowsPath("/etc/ssh/ssh_config"))
}

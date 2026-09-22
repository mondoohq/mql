// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package filesfind

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func ptrInt64(v int64) *int64 { return &v }

func TestUnixFilesCmdGeneration(t *testing.T) {
	tests := []struct {
		From        string
		Xdev        bool
		FileType    string
		Regex       string
		Permission  int64
		Search      string
		Depth       *int64
		HasGNUFind  bool
		ExpectedCmd string
	}{
		{
			From:        "/Users/john/.aws",
			FileType:    "file",
			ExpectedCmd: "find -L \"/Users/john/.aws\" -xdev -type f -perm -0",
		},
		{
			// -maxdepth must be decimal: depth 12 stays 12, not octal 14.
			From:        "/etc",
			FileType:    "file",
			Depth:       ptrInt64(12),
			ExpectedCmd: "find -L \"/etc\" -xdev -type f -perm -0 -maxdepth 12",
		},
		{
			// -name is single-quoted so glob characters reach find instead of being expanded by the shell.
			From:        "/etc",
			FileType:    "file",
			Search:      "*.conf",
			ExpectedCmd: "find -L \"/etc\" -xdev -type f -perm -0 -name '*.conf'",
		},
		{
			// dotfile glob plus depth: the leading-dot pattern must reach find intact alongside -maxdepth.
			From:        "/home/user",
			FileType:    "file",
			Search:      ".*",
			Depth:       ptrInt64(1),
			ExpectedCmd: "find -L \"/home/user\" -xdev -type f -perm -0 -name '.*' -maxdepth 1",
		},
		{
			// single quotes prevent shell variable/command expansion of the name pattern.
			From:        "/etc",
			FileType:    "file",
			Search:      "$HOME*",
			ExpectedCmd: "find -L \"/etc\" -xdev -type f -perm -0 -name '$HOME*'",
		},
		{
			// an embedded single quote is escaped with the '\'' idiom.
			From:        "/etc",
			FileType:    "file",
			Search:      "a'b",
			ExpectedCmd: "find -L \"/etc\" -xdev -type f -perm -0 -name 'a'\\''b'",
		},
		{
			// regex is single-quoted as well (previously an unaddressed TODO).
			From:        "/etc",
			FileType:    "file",
			Regex:       ".*\\.conf$",
			ExpectedCmd: "find -L \"/etc\" -xdev -type f -regex '.*\\.conf$' -perm -0",
		},
		{
			// directory searches don't need symlink resolution: no -L.
			From:        "/",
			FileType:    "directory",
			Permission:  0o002,
			ExpectedCmd: "find -L \"/\" -xdev -type d -perm -2",
		},
		{
			// BSD/macOS: -H follows only command-line symlinks so -type l
			// still works, unlike -L which resolves all links.
			From:        "/home/user",
			FileType:    "link",
			HasGNUFind:  false,
			ExpectedCmd: "find -H \"/home/user\" -xdev -type l -perm -0",
		},
		{
			// GNU/Linux: -L -xtype l follows all symlinks AND finds them.
			From:        "/home/user",
			FileType:    "link",
			HasGNUFind:  true,
			ExpectedCmd: "find -L \"/home/user\" -xdev -xtype l -perm -0",
		},
		{
			// GNU find resolves symlinks with -L so authselect's symlinked
			// /etc/pam.d/system-auth is a "file" (mql#8467), and prunes on
			// -xtype l so it never walks into a symlinked directory.
			From:        "/etc/pam.d",
			FileType:    "file",
			HasGNUFind:  true,
			ExpectedCmd: "find -L \"/etc/pam.d\" -xdev \\( -xtype l -prune -o -true \\) -type f -perm -0 -print",
		},
		{
			// -perm tests the target under -L. Without it, every symlinked
			// directory (/bin, /lib on merged-usr) matched -perm -2, because a
			// symlink's own mode is 0777.
			From:        "/",
			FileType:    "directory",
			Permission:  0o002,
			HasGNUFind:  true,
			ExpectedCmd: "find -L \"/\" -xdev \\( -xtype l -prune -o -true \\) -type d -perm -2 -print",
		},
		{
			From:        "/etc",
			HasGNUFind:  true,
			Search:      "*.conf",
			Depth:       ptrInt64(1),
			ExpectedCmd: "find -L \"/etc\" -xdev \\( -xtype l -prune -o -true \\) -perm -0 -name '*.conf' -maxdepth 1 -print",
		},
	}

	for _, tt := range tests {
		cmd := BuildFilesFindCmd(tt.From, tt.Xdev, tt.FileType, tt.Regex, tt.Permission, tt.Search, tt.Depth, tt.HasGNUFind)
		assert.Equal(t, tt.ExpectedCmd, cmd)
	}
}

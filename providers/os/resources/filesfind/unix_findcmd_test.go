// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package filesfind

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/mount"
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

func readProcMounts(t *testing.T, name string) []mount.MountPoint {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	require.NoError(t, err)
	defer f.Close()
	return mount.ParseLinuxProcMount(f)
}

// /proc/self/mounts of a SLES 16 host, whose root is a Btrfs subvolume with
// eleven more subvolumes mounted below it, and of a SLES 15 SP7 host, whose
// root is XFS. Both carry the same extra mounts under /mnt, /tank and /mpool.
func TestMountPrunes(t *testing.T) {
	sles16 := readProcMounts(t, "sles16-proc-mounts.txt")
	sles15 := readProcMounts(t, "sles15-proc-mounts.txt")

	tests := []struct {
		name   string
		mounts []mount.MountPoint
		from   string
		prunes []string
		ok     bool
	}{
		{
			name: "btrfs root, from /", mounts: sles16, from: "/", ok: true,
			prunes: []string{
				"/.snapshots", "/boot/efi", "/boot/grub2/i386-pc", "/boot/grub2/x86_64-efi", "/boot/writable",
				"/dev", "/home", "/mnt/btr/a", "/mnt/btr/b", "/mnt/btrtop", "/mnt/crypt", "/mnt/lvlin", "/mnt/md",
				"/mnt/nfs3", "/mnt/nfs4", "/mnt/over", "/mnt/ro", "/mnt/sp ace", "/mnt/thin", "/mpool", "/opt",
				"/proc", "/root", "/run", "/srv", "/sys", "/tank", "/tmp", "/usr/local", "/var",
			},
		},
		// The subvolume holding the fixture is mounted at /srv, and the nested
		// subvolume below it is not mounted: nothing is pruned.
		{name: "btrfs, no mount below", mounts: sles16, from: "/srv/g05files", ok: true, prunes: []string{}},
		{name: "trailing slash", mounts: sles16, from: "/srv/g05files/", ok: true, prunes: []string{}},
		{name: "btrfs subvolume mount", mounts: sles16, from: "/var", ok: true, prunes: []string{"/var/lib/nfs/rpc_pipefs"}},
		{name: "directory on btrfs root", mounts: sles16, from: "/mnt/btr", ok: true, prunes: []string{"/mnt/btr/a", "/mnt/btr/b"}},
		{name: "second btrfs filesystem", mounts: sles16, from: "/mnt/btrtop/sub", ok: true, prunes: []string{}},
		// Longest mount wins: tmpfs on a btrfs root is not btrfs.
		{name: "tmpfs with an escaped space", mounts: sles16, from: "/mnt/sp ace", ok: false},
		{name: "zfs", mounts: sles16, from: "/tank", ok: false},
		{name: "ext4", mounts: sles16, from: "/mnt/lvlin/data", ok: false},
		{name: "xfs root", mounts: sles15, from: "/", ok: false},
		{name: "xfs root, /etc", mounts: sles15, from: "/etc", ok: false},
		{name: "relative path", mounts: sles16, from: "etc", ok: false},
		{name: "no mount table", mounts: nil, from: "/etc", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prunes, ok := MountPrunes(tt.from, tt.mounts)
			assert.Equal(t, tt.ok, ok)
			if tt.ok {
				assert.Equal(t, tt.prunes, prunes)
			} else {
				assert.Empty(t, prunes)
			}
		})
	}
}

func TestBuildFilesFindCmdPruningMounts(t *testing.T) {
	// The mount points are matched literally: a space stays inside the quotes
	// and glob characters are escaped. from is cleaned so that the paths find
	// prints line up with the mount points.
	cmd := BuildFilesFindCmdPruningMounts("/srv/", []string{"/srv/a b", "/srv/x*[1]?"}, "file", "", 0o002, "", nil, true)
	assert.Equal(t, `find -L "/srv" \( -type d \( -path '/srv/a b' -o -path '/srv/x\*\[1\]\?' \) -prune -o -true \) \( -xtype l -prune -o -true \) -type f -perm -2 -print`, cmd)

	// no -xdev, and the explicit -print stays when nothing else prunes
	cmd = BuildFilesFindCmdPruningMounts("/", []string{"/proc"}, "link", "", 0o777, "", nil, true)
	assert.Equal(t, `find -L "/" \( -type d \( -path '/proc' \) -prune -o -true \) -xtype l -print`, cmd)

	// with nothing to prune it is a plain search without -xdev
	cmd = BuildFilesFindCmdPruningMounts("/srv/g05files", nil, "file", "", 0o777, "g05-nested-marker", nil, true)
	assert.Equal(t, `find -L "/srv/g05files" \( -xtype l -prune -o -true \) -type f -name 'g05-nested-marker' -print`, cmd)
}

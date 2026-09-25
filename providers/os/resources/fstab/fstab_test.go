// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fstab

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
)

func TestFstabEntries(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		testdata := `# <device>                                <dir> <type> <options> <dump> <fsck>
UUID=0a3407de-014b-458b-b5c1-848e92a327a3 /     ext4   defaults  0      1
UUID=f9fe0b69-a280-415d-a03a-a32752370dee none  swap   defaults  0      0
UUID=b411dc99-f0a0-4c87-9e05-184977be8539 /home ext4   defaults  0      2`

		reader := strings.NewReader(testdata)
		entries, err := Parse(reader)

		require.NoError(t, err)
		require.Len(t, entries, 3)

		require.Equal(t, Entry{
			Device:     "UUID=0a3407de-014b-458b-b5c1-848e92a327a3",
			Mountpoint: "/",
			Fstype:     "ext4",
			Options:    []string{"defaults"},
			Dump:       ptr.To(0),
			Fsck:       ptr.To(1),
		}, entries[0])
		require.Equal(t, Entry{
			Device:     "UUID=f9fe0b69-a280-415d-a03a-a32752370dee",
			Mountpoint: "none",
			Fstype:     "swap",
			Options:    []string{"defaults"},
			Dump:       ptr.To(0),
			Fsck:       ptr.To(0),
		}, entries[1])
		require.Equal(t, Entry{
			Device:     "UUID=b411dc99-f0a0-4c87-9e05-184977be8539",
			Mountpoint: "/home",
			Fstype:     "ext4",
			Options:    []string{"defaults"},
			Dump:       ptr.To(0),
			Fsck:       ptr.To(2),
		}, entries[2])
	})

	t.Run("short", func(t *testing.T) {
		testdata := `# <device>                                <dir> <type> <options>
UUID=0a3407de-014b-458b-b5c1-848e92a327a3 /     ext4   defaults
UUID=f9fe0b69-a280-415d-a03a-a32752370dee none  swap   defaults
UUID=b411dc99-f0a0-4c87-9e05-184977be8539 /home ext4   defaults`

		reader := strings.NewReader(testdata)
		entries, err := Parse(reader)

		require.NoError(t, err)
		require.Len(t, entries, 3)

		require.Equal(t, Entry{
			Device:     "UUID=0a3407de-014b-458b-b5c1-848e92a327a3",
			Mountpoint: "/",
			Fstype:     "ext4",
			Options:    []string{"defaults"},
		}, entries[0])
		require.Equal(t, Entry{
			Device:     "UUID=f9fe0b69-a280-415d-a03a-a32752370dee",
			Mountpoint: "none",
			Fstype:     "swap",
			Options:    []string{"defaults"},
		}, entries[1])
		require.Equal(t, Entry{
			Device:     "UUID=b411dc99-f0a0-4c87-9e05-184977be8539",
			Mountpoint: "/home",
			Fstype:     "ext4",
			Options:    []string{"defaults"},
		}, entries[2])
	})

	t.Run("valid (with tabs)", func(t *testing.T) {
		testdata := `# <device>                                <dir> <type> <options> <dump> <fsck>
LABEL=cloudimg-rootfs	/	 ext4	discard,commit=30,errors=remount-ro	0 1
LABEL=BOOT	/boot	ext4	defaults	0 2
LABEL=UEFI	/boot/efi	vfat	umask=0077	0 1`

		reader := strings.NewReader(testdata)
		entries, err := Parse(reader)

		require.NoError(t, err)
		require.Len(t, entries, 3)

		require.Equal(t, Entry{
			Device:     "LABEL=cloudimg-rootfs",
			Mountpoint: "/",
			Fstype:     "ext4",
			Options:    []string{"discard", "commit=30", "errors=remount-ro"},
			Dump:       ptr.To(0),
			Fsck:       ptr.To(1),
		}, entries[0])
		require.Equal(t, Entry{
			Device:     "LABEL=BOOT",
			Mountpoint: "/boot",
			Fstype:     "ext4",
			Options:    []string{"defaults"},
			Dump:       ptr.To(0),
			Fsck:       ptr.To(2),
		}, entries[1])
		require.Equal(t, Entry{
			Device:     "LABEL=UEFI",
			Mountpoint: "/boot/efi",
			Fstype:     "vfat",
			Options:    []string{"umask=0077"},
			Dump:       ptr.To(0),
			Fsck:       ptr.To(1),
		}, entries[2])
	})

	t.Run("invalid (too short)", func(t *testing.T) {
		testdata := `# <device>                                <dir> <type>
UUID=0a3407de-014b-458b-b5c1-848e92a327a3 /     ext4
UUID=f9fe0b69-a280-415d-a03a-a32752370dee none  swap
UUID=b411dc99-f0a0-4c87-9e05-184977be8539 /home ext4`

		reader := strings.NewReader(testdata)
		entries, err := Parse(reader)

		require.Error(t, err)
		require.Nil(t, entries)
	})

	t.Run("invalid (not numeric dump)", func(t *testing.T) {
		testdata := `# <device>                                <dir> <type> <options> <dump> <fsck>
UUID=0a3407de-014b-458b-b5c1-848e92a327a3 /     ext4   defaults  0      1
UUID=f9fe0b69-a280-415d-a03a-a32752370dee none  swap   defaults  0      0
UUID=b411dc99-f0a0-4c87-9e05-184977be8539 /home ext4   defaults  A      2` // note the 'A' here

		reader := strings.NewReader(testdata)
		entries, err := Parse(reader)

		require.Error(t, err)
		require.Nil(t, entries)
	})

	t.Run("invalid (not numeric fsck)", func(t *testing.T) {
		testdata := `# <device>                                <dir> <type> <options> <dump> <fsck>
UUID=0a3407de-014b-458b-b5c1-848e92a327a3 /     ext4   defaults  0      1
UUID=f9fe0b69-a280-415d-a03a-a32752370dee none  swap   defaults  0      0
UUID=b411dc99-f0a0-4c87-9e05-184977be8539 /home ext4   defaults  0      A` // note the 'A' here

		reader := strings.NewReader(testdata)
		entries, err := Parse(reader)

		require.Error(t, err)
		require.Nil(t, entries)
	})

	t.Run("indented comments and blank lines are skipped", func(t *testing.T) {
		testdata := "# leading comment\n" +
			"\t# indented comment with a tab\n" +
			"   # indented comment with spaces\n" +
			"   \t  \n" + // whitespace-only line
			"\n" + // empty line
			"  UUID=0a3407de-014b-458b-b5c1-848e92a327a3 / ext4 defaults 0 1\n"

		reader := strings.NewReader(testdata)
		entries, err := Parse(reader)

		require.NoError(t, err)
		require.Len(t, entries, 1)
		require.Equal(t, Entry{
			Device:     "UUID=0a3407de-014b-458b-b5c1-848e92a327a3",
			Mountpoint: "/",
			Fstype:     "ext4",
			Options:    []string{"defaults"},
			Dump:       ptr.To(0),
			Fsck:       ptr.To(1),
		}, entries[0])
	})
}

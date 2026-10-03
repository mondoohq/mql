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

	// libmount reads a line of device, mount point and type alone
	t.Run("no options", func(t *testing.T) {
		testdata := `# <device>                                <dir> <type>
UUID=0a3407de-014b-458b-b5c1-848e92a327a3 /     ext4
UUID=f9fe0b69-a280-415d-a03a-a32752370dee none  swap
UUID=b411dc99-f0a0-4c87-9e05-184977be8539 /home ext4`

		reader := strings.NewReader(testdata)
		entries, err := Parse(reader)

		require.NoError(t, err)
		require.Len(t, entries, 3)
		require.Empty(t, entries[2].Options)
	})

	t.Run("invalid (too short)", func(t *testing.T) {
		testdata := `UUID=0a3407de-014b-458b-b5c1-848e92a327a3 /
UUID=b411dc99-f0a0-4c87-9e05-184977be8539 /home ext4 defaults 0 2`

		entries, err := Parse(strings.NewReader(testdata))

		require.NoError(t, err)
		require.Len(t, entries, 1)
		require.Equal(t, "/home", entries[0].Mountpoint)
	})

	t.Run("invalid (not numeric dump)", func(t *testing.T) {
		testdata := `# <device>                                <dir> <type> <options> <dump> <fsck>
UUID=0a3407de-014b-458b-b5c1-848e92a327a3 /     ext4   defaults  0      1
UUID=f9fe0b69-a280-415d-a03a-a32752370dee none  swap   defaults  0      0
UUID=b411dc99-f0a0-4c87-9e05-184977be8539 /home ext4   defaults  A      2` // note the 'A' here

		reader := strings.NewReader(testdata)
		entries, err := Parse(reader)

		// the line is skipped, as util-linux skips it
		require.NoError(t, err)
		require.Len(t, entries, 2)
		require.Equal(t, "none", entries[1].Mountpoint)
	})

	t.Run("invalid (not numeric fsck)", func(t *testing.T) {
		testdata := `# <device>                                <dir> <type> <options> <dump> <fsck>
UUID=0a3407de-014b-458b-b5c1-848e92a327a3 /     ext4   defaults  0      1
UUID=f9fe0b69-a280-415d-a03a-a32752370dee none  swap   defaults  0      0
UUID=b411dc99-f0a0-4c87-9e05-184977be8539 /home ext4   defaults  0      A` // note the 'A' here

		reader := strings.NewReader(testdata)
		entries, err := Parse(reader)

		// the line is skipped, as util-linux skips it
		require.NoError(t, err)
		require.Len(t, entries, 2)
		require.Equal(t, "none", entries[1].Mountpoint)
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

// fstab escapes blanks in its fields as octal (\040 for a space, \011 for a
// tab), which `findmnt --fstab` decodes.
func TestFstabOctalEscapes(t *testing.T) {
	entries, err := Parse(strings.NewReader("/dev/sdx2 /mnt/sp\\040ace ext4 defaults 0 0\nLABEL=x\\040y /m\\011t ext4 defaults 0 0\n"))
	require.NoError(t, err)
	require.Len(t, entries, 2)
	require.Equal(t, "/mnt/sp ace", entries[0].Mountpoint)
	require.Equal(t, "LABEL=x y", entries[1].Device)
	require.Equal(t, "/m\tt", entries[1].Mountpoint)
}

// util-linux skips a line it cannot parse ("parse error at line 1 --
// ignored") and reads the rest of the file. A line needs a device, a mount
// point and a type; options, dump and fsck are optional, but dump and fsck
// must be numbers when present. Checked with findmnt --fstab --tab-file on
// Debian 12 (util-linux 2.38).
func TestFstabSkipsMalformedLines(t *testing.T) {
	input := `/dev/a1
/dev/a2 /m2
/dev/a3 /m3 ext4
/dev/a4 /m4 ext4 defaults
/dev/a5 /m5 ext4 defaults x 0
/dev/sdz1	/no-newline	xfs	defaults 0 0/dev/sdx1 /mnt/x ext4 defaults 0 0
/dev/a7 /m7 ext4 defaults 1
`
	entries, err := Parse(strings.NewReader(input))
	require.NoError(t, err)
	mountpoints := []string{}
	for _, e := range entries {
		mountpoints = append(mountpoints, e.Mountpoint)
	}
	require.Equal(t, []string{"/m3", "/m4", "/m7"}, mountpoints)
	require.Empty(t, entries[0].Options)
	require.Equal(t, ptr.To(1), entries[2].Dump)
	require.Nil(t, entries[2].Fsck)
}

func TestUnescapeOctal(t *testing.T) {
	require.Equal(t, "/mnt/sp ace", UnescapeOctal(`/mnt/sp\040ace`))
	require.Equal(t, "a\\b", UnescapeOctal(`a\134b`))
	// not an escape: kept as written
	require.Equal(t, `a\9b`, UnescapeOctal(`a\9b`))
	require.Equal(t, `end\04`, UnescapeOctal(`end\04`))
	require.Equal(t, "plain", UnescapeOctal("plain"))
}

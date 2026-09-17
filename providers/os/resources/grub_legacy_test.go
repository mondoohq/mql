// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// al1MenuLst is /boot/grub/menu.lst copied verbatim from the Amazon Linux 1
// host the al1 fixture came from. Two kernels are installed and the menu
// offers both, with different arguments.
const al1MenuLst = `# created by imagebuilder
default=0
timeout=0
hiddenmenu

title Amazon Linux 2018.03 (4.14.355-195.591.amzn1.x86_64)
root (hd0,0)
kernel /boot/vmlinuz-4.14.355-195.591.amzn1.x86_64 root=LABEL=/ console=tty1 console=ttyS0 selinux=0 nvme_core.io_timeout=4294967295 LANG=en_US.UTF-8 KEYTABLE=us
initrd /boot/initramfs-4.14.355-195.591.amzn1.x86_64.img

title Amazon Linux 2018.03 (4.14.330-176.540.amzn1.x86_64)
root (hd0,0)
kernel /boot/vmlinuz-4.14.330-176.540.amzn1.x86_64 root=LABEL=/ console=tty1 console=ttyS0 selinux=0 nvme_core.io_timeout=4294967295
initrd /boot/initramfs-4.14.330-176.540.amzn1.x86_64.img
`

func TestParseGrubLegacyEntriesAmazonLinux1(t *testing.T) {
	entries, err := ParseGrubLegacyEntries(strings.NewReader(al1MenuLst))
	require.NoError(t, err)
	finalizeEntries(entries, "/boot/grub/menu.lst", nil)
	require.Len(t, entries, 2)

	// The default entry, which is the one the host booted: its arguments match
	// the /proc/cmdline oracle in the fixture.
	first := entries[0]
	assert.Equal(t, "Amazon Linux 2018.03 (4.14.355-195.591.amzn1.x86_64)", first.Title)
	assert.Equal(t, "/boot/vmlinuz-4.14.355-195.591.amzn1.x86_64", first.Kernel)
	assert.Equal(t, "/boot/initramfs-4.14.355-195.591.amzn1.x86_64.img", first.Initrd)
	assert.Equal(t, GrubEntryNormal, first.Kind)
	assert.True(t, first.Bootable)
	assert.Equal(t, map[string]string{
		"root":                 "LABEL=/",
		"console":              "ttyS0",
		"selinux":              "0",
		"nvme_core.io_timeout": "4294967295",
		"LANG":                 "en_US.UTF-8",
		"KEYTABLE":             "us",
	}, first.Parameters)
	assert.Equal(t, "/boot/grub/menu.lst", first.Source)

	// The older kernel is a second entry rather than a continuation of the
	// first, and it carries fewer arguments, so a parser that ran the title
	// blocks together would be caught here.
	second := entries[1]
	assert.Equal(t, "/boot/vmlinuz-4.14.330-176.540.amzn1.x86_64", second.Kernel)
	assert.NotContains(t, second.Parameters, "LANG")
	assert.NotContains(t, second.Parameters, "KEYTABLE")
}

func TestParseGrubLegacyEntries(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []GrubEntry
	}{
		{
			name: "chainloader entry boots no kernel",
			content: `title Amazon Linux
kernel /boot/vmlinuz-4.14.355 root=LABEL=/ ro
initrd /boot/initramfs-4.14.355.img

title Windows
rootnoverify (hd0,1)
chainloader +1
`,
			want: []GrubEntry{
				{Title: "Amazon Linux", Kernel: "/boot/vmlinuz-4.14.355", Kind: GrubEntryNormal, Bootable: true},
				{Title: "Windows", Kernel: "", Kind: GrubEntryOther, Bootable: false},
			},
		},
		{
			name: "single marks a recovery entry",
			content: `title Red Hat Enterprise Linux (2.6.32-754.el6.x86_64)
kernel /vmlinuz-2.6.32-754.el6.x86_64 ro root=/dev/mapper/vg-root single
`,
			want: []GrubEntry{
				{Title: "Red Hat Enterprise Linux (2.6.32-754.el6.x86_64)", Kernel: "/vmlinuz-2.6.32-754.el6.x86_64", Kind: GrubEntryRecovery, Bootable: true},
			},
		},
		{
			name: "memory test boots no operating system",
			content: `title Memory test (memtest86+)
kernel /boot/memtest86+-5.01
`,
			want: []GrubEntry{
				{Title: "Memory test (memtest86+)", Kernel: "/boot/memtest86+-5.01", Kind: GrubEntryMemtest, Bootable: false},
			},
		},
		{
			name: "indented and tab separated lines are entry lines",
			content: `title	Debian GNU/Linux
	kernel	/boot/vmlinuz-2.6.32-5-amd64 root=/dev/sda1 ro quiet
	initrd	/boot/initrd.img-2.6.32-5-amd64
`,
			want: []GrubEntry{
				{Title: "Debian GNU/Linux", Kernel: "/boot/vmlinuz-2.6.32-5-amd64", Initrd: "/boot/initrd.img-2.6.32-5-amd64", Kind: GrubEntryNormal, Bootable: true},
			},
		},
		{
			name: "a commented out entry is not an entry",
			content: `# title Old kernel
# kernel /boot/vmlinuz-old root=/dev/sda1
title Current
kernel /boot/vmlinuz-current root=/dev/sda1 ro
`,
			want: []GrubEntry{
				{Title: "Current", Kernel: "/boot/vmlinuz-current", Kind: GrubEntryNormal, Bootable: true},
			},
		},
		{
			name: "menu with no entries",
			content: `default=0
timeout=5
splashimage=(hd0,0)/grub/splash.xpm.gz
`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries, err := ParseGrubLegacyEntries(strings.NewReader(test.content))
			require.NoError(t, err)
			finalizeEntries(entries, "/boot/grub/menu.lst", nil)

			require.Len(t, entries, len(test.want))
			for i, want := range test.want {
				got := entries[i]
				assert.Equal(t, want.Title, got.Title, "title")
				assert.Equal(t, want.Kernel, got.Kernel, "kernel")
				assert.Equal(t, want.Kind, got.Kind, "kind")
				assert.Equal(t, want.Bootable, got.Bootable, "bootable")
				if want.Initrd != "" {
					assert.Equal(t, want.Initrd, got.Initrd, "initrd")
				}
			}
		})
	}
}

// TestGrubCfgCorpusIsNotLegacy is what lets the format check be a single
// positive test. It runs every grub.cfg of all 23 fixture hosts through the
// routing decision, so a loosening of it that started reading a GRUB 2
// configuration with the legacy parser, which silently yields no entries rather
// than an error, fails here against real files rather than against a
// constructed one.
func TestGrubCfgCorpusIsNotLegacy(t *testing.T) {
	seen := 0
	err := filepath.WalkDir(fixtureRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch d.Name() {
		case "grub.cfg", "grub.conf", "menu.lst":
		default:
			return nil
		}

		content, err := os.ReadFile(p)
		if err != nil {
			return err
		}

		legacy := isGrubLegacyCfg(content)
		if strings.HasPrefix(p, filepath.Join(fixtureRoot, "al1")+string(filepath.Separator)) {
			assert.True(t, legacy, "%s is the GRUB legacy menu of the al1 host", p)
		} else {
			assert.False(t, legacy, "%s is a GRUB 2 configuration", p)
		}
		seen++
		return nil
	})
	require.NoError(t, err)
	require.Greater(t, seen, 40, "the corpus should hold a grub.cfg for every host")
}

func TestParseGrubLegacyPasswordProtected(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"amazon linux 1 as shipped", al1MenuLst, false},
		{
			name:    "md5 credential",
			content: "default=0\npassword --md5 $1$4Ktpx$aYSvUvC8JTHKbLZmPQz4S0\ntitle Linux\nkernel /vmlinuz ro\n",
			want:    true,
		},
		{
			name:    "sha512 credential",
			content: "password --encrypted $6$rounds=656000$abc$def\ntitle Linux\nkernel /vmlinuz ro\n",
			want:    true,
		},
		{
			name:    "cleartext credential",
			content: "password hunter2\ntitle Linux\nkernel /vmlinuz ro\n",
			want:    true,
		},
		{
			name:    "no password directive",
			content: "default=0\ntimeout=5\ntitle Linux\nkernel /vmlinuz ro\n",
			want:    false,
		},
		{
			name:    "directive with a flag and no credential",
			content: "password --md5\ntitle Linux\nkernel /vmlinuz ro\n",
			want:    false,
		},
		{
			name:    "bare directive with neither flag nor credential",
			content: "default=0\npassword\ntitle Linux\nkernel /vmlinuz ro\n",
			want:    false,
		},
		{
			// GRUB reads the directive from the menu-level section. A line
			// after the first title is part of an entry, where it does not
			// protect the menu.
			name:    "password after the first entry",
			content: "default=0\ntitle Linux\nkernel /vmlinuz ro\npassword --md5 $1$4Ktpx$aYSvUvC8JTHKbLZmPQz4S0\n",
			want:    false,
		},
		{
			name:    "commented out directive",
			content: "# password --md5 $1$4Ktpx$aYSvUvC8JTHKbLZmPQz4S0\ntitle Linux\nkernel /vmlinuz ro\n",
			want:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, ParseGrubLegacyPasswordProtected([]byte(test.content)))
		})
	}
}

// TestFindBootConfigPrefersGrub2 states the order the resolver has to keep. A
// host upgraded off GRUB legacy can keep a stale menu.lst beside the grub.cfg
// it actually boots from, and reading the stale one would report entries the
// host no longer offers.
func TestFindBootConfigPrefersGrub2(t *testing.T) {
	grubCfg := "menuentry 'Ubuntu' {\n\tlinux /boot/vmlinuz-6.8.0 root=UUID=abc ro\n}\n"

	t.Run("grub.cfg wins over a legacy menu", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/boot/grub/grub.cfg", []byte(grubCfg), 0o644))
		require.NoError(t, afero.WriteFile(fs, "/boot/grub/menu.lst", []byte(al1MenuLst), 0o644))
		assert.Equal(t, "/boot/grub/grub.cfg", findBootConfig(fs))
	})

	t.Run("legacy menu when there is no grub.cfg", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/boot/grub/menu.lst", []byte(al1MenuLst), 0o644))
		assert.Equal(t, "/boot/grub/menu.lst", findBootConfig(fs))
	})

	t.Run("nothing at all", func(t *testing.T) {
		assert.Empty(t, findBootConfig(afero.NewMemMapFs()))
	})
}

// TestFixtureAl1IsALegacyHost pins what the al1 fixture is there to represent,
// so a later change that stopped recognising the layout would fail here rather
// than quietly reporting no entries.
func TestFixtureAl1IsALegacyHost(t *testing.T) {
	fs := fixtureFS("al1")

	cfgPath := findBootConfig(fs)
	require.Equal(t, "/boot/grub/menu.lst", cfgPath, "the real file, not either symlink to it")

	content, err := afero.ReadFile(fs, cfgPath)
	require.NoError(t, err)
	assert.True(t, isGrubLegacyCfg(content))
	assert.False(t, ParseGrubLegacyPasswordProtected(content), "the host shipped without a menu password")

	entries := loadFixtureEntries(t, "al1")
	require.Len(t, entries, 2)
	for _, e := range entries {
		assert.Equal(t, GrubEntryNormal, e.Kind)
		assert.True(t, e.Bootable)
		assert.Equal(t, "LABEL=/", e.Parameters["root"])
		assert.Equal(t, "/boot/grub/menu.lst", e.Source)
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestParseGrubDefaults(t *testing.T) {
	input := `# If you change this file, run 'update-grub' afterwards to update
# /boot/grub/grub.cfg.
GRUB_DEFAULT=0
GRUB_TIMEOUT_STYLE=hidden
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR="$(lsb_release -i -s 2> /dev/null) || echo Debian"
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX="audit=1 apparmor=1 security=apparmor"
GRUB_DISABLE_RECOVERY="true"

# Uncomment to enable BadRAM filtering
#GRUB_BADRAM="0x01234567,0xfefefefe,0x89abcdef,0xefefefef"
`
	params, err := ParseGrubDefaults(strings.NewReader(input))
	require.NoError(t, err)

	assert.Equal(t, "0", params["GRUB_DEFAULT"])
	assert.Equal(t, "hidden", params["GRUB_TIMEOUT_STYLE"])
	assert.Equal(t, "5", params["GRUB_TIMEOUT"])
	assert.Equal(t, "quiet splash", params["GRUB_CMDLINE_LINUX_DEFAULT"])
	assert.Equal(t, "audit=1 apparmor=1 security=apparmor", params["GRUB_CMDLINE_LINUX"])
	assert.Equal(t, "true", params["GRUB_DISABLE_RECOVERY"])
	// Unquoted shell expression
	assert.Equal(t, "$(lsb_release -i -s 2> /dev/null) || echo Debian", params["GRUB_DISTRIBUTOR"])
	// Commented lines should not appear
	_, ok := params["GRUB_BADRAM"]
	assert.False(t, ok)
}

func TestParseGrubDefaultsSingleQuotes(t *testing.T) {
	input := `GRUB_CMDLINE_LINUX='audit=1'
GRUB_TIMEOUT=10
`
	params, err := ParseGrubDefaults(strings.NewReader(input))
	require.NoError(t, err)

	assert.Equal(t, "audit=1", params["GRUB_CMDLINE_LINUX"])
	assert.Equal(t, "10", params["GRUB_TIMEOUT"])
}

// grub-mkconfig sources the defaults file in a shell, so `export KEY=value`
// assigns KEY. Taken from a hand-written defaults file on Ubuntu 24.04.
func TestParseGrubDefaultsExport(t *testing.T) {
	input := `# test defaults
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX="audit=1 apparmor=1 security=apparmor"
export GRUB_DISABLE_RECOVERY='true'
`
	params, err := ParseGrubDefaults(strings.NewReader(input))
	require.NoError(t, err)

	assert.Equal(t, "true", params["GRUB_DISABLE_RECOVERY"])
	assert.NotContains(t, params, "export GRUB_DISABLE_RECOVERY")
	assert.Len(t, params, 5)
}

// The /etc/default/grub and /etc/default/grub.d files of an Ubuntu 22.04
// cloud image. grub-mkconfig sources the drop-ins after the defaults file,
// so the cloud image's GRUB_CMDLINE_LINUX_DEFAULT is the one that reaches
// the kernel command line.
func ubuntuCloudGrubDefaultsFs(t *testing.T) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	files := map[string]string{
		"/etc/default/grub": `# If you change this file, run 'update-grub' afterwards to update
# /boot/grub/grub.cfg.
# For full documentation of the options in this file, see:
#   info -f grub -n 'Simple configuration'

GRUB_DEFAULT=0
GRUB_TIMEOUT_STYLE=hidden
GRUB_TIMEOUT=0
GRUB_DISTRIBUTOR=` + "`lsb_release -i -s 2> /dev/null || echo Debian`" + `
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""

# Uncomment to disable graphical terminal (grub-pc only)
#GRUB_TERMINAL=console
`,
		"/etc/default/grub.d/40-force-partuuid.cfg": `# Force boot without an initramfs by setting GRUB_FORCE_PARTUUID
# Remove this line to enable boot with an initramfs
GRUB_FORCE_PARTUUID=0d1f34a7-78b7-4ddf-9ea2-d42390d32d7c
`,
		"/etc/default/grub.d/50-cloudimg-settings.cfg": `# Cloud Image specific Grub settings for AWS EC2 images
# CLOUD_IMG: This file was created/modified by the Cloud Image build process

# Set the recordfail timeout
GRUB_RECORDFAIL_TIMEOUT=0

# Do not wait on grub prompt
GRUB_TIMEOUT=0

# Set the default commandline
GRUB_CMDLINE_LINUX_DEFAULT="console=tty1 console=ttyS0 nvme_core.io_timeout=4294967295"

# Set the grub console type
GRUB_TERMINAL=console

GRUB_HIDDEN_TIMEOUT=0.1
`,
		"/etc/default/grub.d/init-select.cfg": `# Work around a bug in the obsolete init-select package which broke
# grub-mkconfig when init-select was removed but not purged.  This file does
# nothing and will be removed in a later release.
`,
	}
	for name, content := range files {
		require.NoError(t, afero.WriteFile(fs, name, []byte(content), 0o644))
	}
	return fs
}

func TestLoadGrubDefaultsDropIns(t *testing.T) {
	fs := ubuntuCloudGrubDefaultsFs(t)

	params, err := loadGrubDefaults(fs, "/etc/default/grub", true)
	require.NoError(t, err)

	assert.Equal(t, "console=tty1 console=ttyS0 nvme_core.io_timeout=4294967295", params["GRUB_CMDLINE_LINUX_DEFAULT"])
	assert.Equal(t, "console", params["GRUB_TERMINAL"])
	assert.Equal(t, "0", params["GRUB_RECORDFAIL_TIMEOUT"])
	assert.Equal(t, "0.1", params["GRUB_HIDDEN_TIMEOUT"])
	assert.Equal(t, "0d1f34a7-78b7-4ddf-9ea2-d42390d32d7c", params["GRUB_FORCE_PARTUUID"])
	// keys only the defaults file sets are kept
	assert.Equal(t, "hidden", params["GRUB_TIMEOUT_STYLE"])
	assert.Equal(t, "", params["GRUB_CMDLINE_LINUX"])
}

// Drop-ins are sourced in name order, so a later file wins, and only *.cfg
// files are sourced.
func TestLoadGrubDefaultsDropInOrder(t *testing.T) {
	fs := ubuntuCloudGrubDefaultsFs(t)
	require.NoError(t, afero.WriteFile(fs, "/etc/default/grub.d/99-local.cfg", []byte("GRUB_TIMEOUT=3\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/etc/default/grub.d/10-early.cfg", []byte("GRUB_TERMINAL=serial\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/etc/default/grub.d/99-local.cfg.dpkg-old", []byte("GRUB_TIMEOUT=30\n"), 0o644))

	params, err := loadGrubDefaults(fs, "/etc/default/grub", true)
	require.NoError(t, err)

	assert.Equal(t, "3", params["GRUB_TIMEOUT"])
	assert.Equal(t, "console", params["GRUB_TERMINAL"])
}

func TestLoadGrubDefaultsWithoutDropInDir(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/default/grub", []byte("GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\"\n"), 0o644))

	params, err := loadGrubDefaults(fs, "/etc/default/grub", true)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"GRUB_CMDLINE_LINUX_DEFAULT": "quiet splash"}, params)

	_, err = loadGrubDefaults(fs, "/etc/default/missing", true)
	assert.Error(t, err)
}

// SUSE's grub2-mkconfig sources /etc/default/grub alone, so a drop-in that
// would add audit=1 never reaches grub.cfg there. The defaults line is the one
// openSUSE Leap 16.0 ships on EC2.
func TestLoadGrubDefaultsIgnoresDropInsWhereMkconfigDoes(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/default/grub", []byte(
		"GRUB_CMDLINE_LINUX_DEFAULT=\"console=ttyS0 net.ifnames=0 iommu.passthrough=1 8250.nr_uarts=4 dis_ucode_ldr multipath=off nvme_core.admin_timeout=4294967295 nvme_core.io_timeout=4294967295 security=selinux selinux=1\"\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/etc/default/grub.d/50-audit.cfg", []byte(
		"GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE_LINUX_DEFAULT audit=1\"\n"), 0o644))

	params, err := loadGrubDefaults(fs, "/etc/default/grub", false)
	require.NoError(t, err)
	assert.Equal(t, "console=ttyS0 net.ifnames=0 iommu.passthrough=1 8250.nr_uarts=4 dis_ucode_ldr multipath=off nvme_core.admin_timeout=4294967295 nvme_core.io_timeout=4294967295 security=selinux selinux=1", params["GRUB_CMDLINE_LINUX_DEFAULT"])
}

func TestGrubMkconfigReadsDropIns(t *testing.T) {
	tests := []struct {
		platform *inventory.Platform
		want     bool
	}{
		{&inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}, true},
		{&inventory.Platform{Name: "debian", Family: []string{"debian", "linux", "unix", "os"}}, true},
		{&inventory.Platform{Name: "sles", Family: []string{"suse", "linux", "unix", "os"}}, false},
		{&inventory.Platform{Name: "opensuse-leap", Family: []string{"suse", "linux", "unix", "os"}}, false},
		{&inventory.Platform{Name: "rhel", Family: []string{"redhat", "linux", "unix", "os"}}, false},
		{&inventory.Platform{Name: "fedora", Family: []string{"redhat", "linux", "unix", "os"}}, false},
		{&inventory.Platform{Name: "amazonlinux", Family: []string{"linux", "unix", "os"}}, false},
		{nil, false},
	}
	for _, tt := range tests {
		name := "nil"
		if tt.platform != nil {
			name = tt.platform.Name
		}
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, grubMkconfigReadsDropIns(tt.platform))
		})
	}
}

func TestParseGrubCfgEntries(t *testing.T) {
	input := `#!/bin/sh
exec tail -n +3 $0
# This file provides an easy way to add custom menu entries.
set default=0
set timeout=5

menuentry 'Ubuntu' --class ubuntu {
	load_video
	set gfxpayload=keep
	insmod gzio
	linux /vmlinuz-5.4.0-42-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro quiet splash
	initrd /initrd.img-5.4.0-42-generic
}

menuentry 'Ubuntu, with Linux 5.4.0-40-generic' --class ubuntu {
	linux /vmlinuz-5.4.0-40-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro quiet splash
	initrd /initrd.img-5.4.0-40-generic
}

submenu 'Advanced options for Ubuntu' --class ubuntu {
	menuentry 'Ubuntu, with Linux 5.4.0-42-generic (recovery mode)' {
		linux /vmlinuz-5.4.0-42-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro recovery
		initrd /initrd.img-5.4.0-42-generic
	}
}
`
	entries, err := ParseGrubCfgEntries(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, entries, 4)

	assert.Equal(t, "Ubuntu", entries[0].Title)
	assert.Equal(t, "/vmlinuz-5.4.0-42-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro quiet splash", entries[0].Cmdline)
	assert.Equal(t, "/initrd.img-5.4.0-42-generic", entries[0].Initrd)
	assert.False(t, entries[0].IsSubmenu)

	assert.Equal(t, "Ubuntu, with Linux 5.4.0-40-generic", entries[1].Title)
	assert.False(t, entries[1].IsSubmenu)

	assert.Equal(t, "Advanced options for Ubuntu", entries[2].Title)
	assert.True(t, entries[2].IsSubmenu)

	// Nested entry inside submenu
	assert.Equal(t, "Ubuntu, with Linux 5.4.0-42-generic (recovery mode)", entries[3].Title)
	assert.Contains(t, entries[3].Cmdline, "recovery")
	assert.False(t, entries[3].IsSubmenu)
}

func TestParseGrubCfgEntriesLinux16(t *testing.T) {
	input := `menuentry 'CentOS Linux (3.10.0-1160.el7.x86_64)' {
	linux16 /vmlinuz-3.10.0-1160.el7.x86_64 root=/dev/mapper/centos-root ro crashkernel=auto
	initrd16 /initramfs-3.10.0-1160.el7.x86_64.img
}
`
	entries, err := ParseGrubCfgEntries(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.Equal(t, "CentOS Linux (3.10.0-1160.el7.x86_64)", entries[0].Title)
	assert.Contains(t, entries[0].Cmdline, "vmlinuz-3.10.0")
	assert.Contains(t, entries[0].Initrd, "initramfs-3.10.0")
}

func TestParseGrubCfgEntriesLinuxefi(t *testing.T) {
	input := `menuentry 'Fedora (6.2.0-20.fc38.x86_64)' {
	linuxefi /vmlinuz-6.2.0-20.fc38.x86_64 root=UUID=abc-123 ro rhgb quiet
	initrdefi /initramfs-6.2.0-20.fc38.x86_64.img
}
`
	entries, err := ParseGrubCfgEntries(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.Equal(t, "Fedora (6.2.0-20.fc38.x86_64)", entries[0].Title)
	assert.Contains(t, entries[0].Cmdline, "vmlinuz-6.2.0")
	assert.Contains(t, entries[0].Initrd, "initramfs-6.2.0")
}

func TestParseGrubCfgEntriesBraceOnNextLine(t *testing.T) {
	input := `menuentry 'Test Entry'
{
	linux /vmlinuz root=/dev/sda1 ro
	initrd /initrd.img
}
`
	entries, err := ParseGrubCfgEntries(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.Equal(t, "Test Entry", entries[0].Title)
	assert.Contains(t, entries[0].Cmdline, "vmlinuz")
	assert.Contains(t, entries[0].Initrd, "initrd.img")
}

func TestParseGrubCfgEntriesBlankLineBeforeBrace(t *testing.T) {
	// A blank line between `menuentry` and the opening brace must not cause the
	// entry to be flushed before its linux/initrd lines are read.
	input := `menuentry 'Test Entry'

{
	linux /vmlinuz root=/dev/sda1 ro
	initrd /initrd.img
}
`
	entries, err := ParseGrubCfgEntries(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.Equal(t, "Test Entry", entries[0].Title)
	assert.Contains(t, entries[0].Cmdline, "vmlinuz")
	assert.Contains(t, entries[0].Initrd, "initrd.img")
}

func TestParseGrubCfgEntriesDuplicateTitles(t *testing.T) {
	input := `menuentry 'Ubuntu' {
	linux /vmlinuz-5.4 root=/dev/sda1 ro
	initrd /initrd.img-5.4
}
menuentry 'Ubuntu' {
	linux /vmlinuz-5.3 root=/dev/sda1 ro
	initrd /initrd.img-5.3
}
`
	entries, err := ParseGrubCfgEntries(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, entries, 2)

	assert.Equal(t, "Ubuntu", entries[0].Title)
	assert.Contains(t, entries[0].Cmdline, "vmlinuz-5.4")
	assert.Equal(t, "Ubuntu", entries[1].Title)
	assert.Contains(t, entries[1].Cmdline, "vmlinuz-5.3")
}

func TestParseGrubCfgEntriesCommentWithBraces(t *testing.T) {
	input := `menuentry 'Ubuntu' {
	# echo "Use {grub} menu"
	linux /vmlinuz root=/dev/sda1 ro
	initrd /initrd.img
}
`
	entries, err := ParseGrubCfgEntries(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.Equal(t, "Ubuntu", entries[0].Title)
	assert.Contains(t, entries[0].Cmdline, "vmlinuz")
}

func TestParseGrubPasswordProtected(t *testing.T) {
	t.Run("protected with pbkdf2", func(t *testing.T) {
		input := `set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.ABC123
`
		assert.True(t, ParseGrubPasswordProtected([]byte(input)))
	})

	t.Run("protected with plaintext password", func(t *testing.T) {
		input := `set superusers="root"
password root secret
`
		assert.True(t, ParseGrubPasswordProtected([]byte(input)))
	})

	t.Run("no superusers", func(t *testing.T) {
		input := `password_pbkdf2 root grub.pbkdf2.sha512.10000.ABC123
`
		assert.False(t, ParseGrubPasswordProtected([]byte(input)))
	})

	t.Run("no password", func(t *testing.T) {
		input := `set superusers="root"
`
		assert.False(t, ParseGrubPasswordProtected([]byte(input)))
	})

	t.Run("empty config", func(t *testing.T) {
		assert.False(t, ParseGrubPasswordProtected([]byte("")))
	})
}

func TestParseGrubPasswordProtectedCommentedOut(t *testing.T) {
	t.Run("commented superusers and password", func(t *testing.T) {
		input := `# set superusers="root"
# password_pbkdf2 root grub.pbkdf2.sha512.10000.ABC123
`
		assert.False(t, ParseGrubPasswordProtected([]byte(input)))
	})

	t.Run("commented superusers only", func(t *testing.T) {
		input := `# set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.ABC123
`
		assert.False(t, ParseGrubPasswordProtected([]byte(input)))
	})

	t.Run("commented password only", func(t *testing.T) {
		input := `set superusers="root"
# password_pbkdf2 root grub.pbkdf2.sha512.10000.ABC123
`
		assert.False(t, ParseGrubPasswordProtected([]byte(input)))
	})
}

func TestParseGrubCfgEntriesShellVariableExpansion(t *testing.T) {
	input := `menuentry 'Ubuntu' {
	set root='hd0,msdos1'
	linux /vmlinuz root=${rootdev} ro quiet
	echo "Loading ${kernel_name}"
	initrd /initrd.img
}
menuentry 'Recovery' {
	linux /vmlinuz root=/dev/sda1 ro single
	initrd /initrd-recovery.img
}
`
	entries, err := ParseGrubCfgEntries(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, entries, 2)

	assert.Equal(t, "Ubuntu", entries[0].Title)
	assert.Contains(t, entries[0].Cmdline, "${rootdev}")
	assert.Equal(t, "/initrd.img", entries[0].Initrd)

	assert.Equal(t, "Recovery", entries[1].Title)
	assert.Contains(t, entries[1].Cmdline, "single")
}

func TestStripQuotes(t *testing.T) {
	assert.Equal(t, "hello", stripQuotes(`"hello"`))
	assert.Equal(t, "hello", stripQuotes(`'hello'`))
	assert.Equal(t, "hello", stripQuotes("hello"))
	assert.Equal(t, "", stripQuotes(`""`))
	assert.Equal(t, "", stripQuotes(`''`))
	assert.Equal(t, "a", stripQuotes("a"))
}

// stockRhelUsersBlock is the block /etc/grub.d/01_users writes into grub.cfg on
// every RHEL-family host, whether or not a GRUB password was ever set. It is
// dead code unless ${prefix}/user.cfg defines GRUB2_PASSWORD.
const stockRhelUsersBlock = `### BEGIN /etc/grub.d/01_users ###
if [ -f ${prefix}/user.cfg ]; then
  source ${prefix}/user.cfg
  if [ -n "${GRUB2_PASSWORD}" ]; then
    set superusers="root"
    export superusers
    password_pbkdf2 root ${GRUB2_PASSWORD}
  fi
fi
### END /etc/grub.d/01_users ###
`

func TestParseGrubPasswordProtectedTemplates(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "stock RHEL 01_users block is a template, not a password",
			content: stockRhelUsersBlock,
			want:    false,
		},
		{
			name: "stock RHEL block inside a full grub.cfg",
			content: `set pager=1
` + stockRhelUsersBlock + `### BEGIN /etc/grub.d/10_linux ###
menuentry 'Red Hat Enterprise Linux (5.14.0) 9.4' {
	linux /vmlinuz-5.14.0 root=/dev/mapper/rhel-root ro
	initrd /initramfs-5.14.0.img
}
### END /etc/grub.d/10_linux ###
`,
			want: false,
		},
		{
			name: "configured pbkdf2 password",
			content: `set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.ABC123.DEF456
`,
			want: true,
		},
		{
			name: "configured plaintext password",
			content: `set superusers="root"
password root hunter2
`,
			want: true,
		},
		{
			name: "superusers without a password directive",
			content: `set superusers="root"
export superusers
`,
			want: false,
		},
		{
			name: "password directive without superusers",
			content: `password_pbkdf2 root grub.pbkdf2.sha512.10000.ABC123.DEF456
`,
			want: false,
		},
		{
			name:    "empty content",
			content: "",
			want:    false,
		},
		{
			name: "braceless shell variable credential",
			content: `set superusers="root"
password_pbkdf2 root $GRUB2_PASSWORD
`,
			want: false,
		},
		{
			name: "templated superuser list",
			content: `set superusers="${GRUB2_SUPERUSER}"
password_pbkdf2 root grub.pbkdf2.sha512.10000.ABC123.DEF456
`,
			want: false,
		},
		{
			name: "empty superusers assignment",
			content: `set superusers=""
password_pbkdf2 root grub.pbkdf2.sha512.10000.ABC123.DEF456
`,
			want: false,
		},
		{
			name: "password directive with no credential argument",
			content: `set superusers="root"
password_pbkdf2 root
`,
			want: false,
		},
		{
			name: "indented directives inside a conditional",
			content: `if [ -n "${x}" ]; then
    set superusers="admin"
    password_pbkdf2 admin grub.pbkdf2.sha512.10000.ABC123.DEF456
fi
`,
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, ParseGrubPasswordProtected([]byte(test.content)))
		})
	}
}

func TestParseGrubPasswordConfig(t *testing.T) {
	t.Run("stock RHEL block records the variable it depends on", func(t *testing.T) {
		cfg := ParseGrubPasswordConfig([]byte(stockRhelUsersBlock))
		assert.True(t, cfg.SuperusersLiteral)
		assert.False(t, cfg.PasswordLiteral)
		assert.Equal(t, []string{"GRUB2_PASSWORD"}, cfg.PasswordVars)
		assert.True(t, cfg.ReferencesVars())
		assert.False(t, cfg.Protected())
	})

	t.Run("configured host references no variables", func(t *testing.T) {
		cfg := ParseGrubPasswordConfig([]byte(`set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.ABC123.DEF456
`))
		assert.True(t, cfg.Protected())
		assert.False(t, cfg.ReferencesVars())
	})
}

func TestGrubPasswordConfigProtectedWith(t *testing.T) {
	cfg := ParseGrubPasswordConfig([]byte(stockRhelUsersBlock))

	t.Run("user.cfg with a password", func(t *testing.T) {
		vars, err := ParseGrubDefaults(strings.NewReader("GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.ABC123.DEF456\n"))
		require.NoError(t, err)
		assert.True(t, cfg.ProtectedWith(vars))
	})

	t.Run("user.cfg with an empty password", func(t *testing.T) {
		vars, err := ParseGrubDefaults(strings.NewReader("GRUB2_PASSWORD=\n"))
		require.NoError(t, err)
		assert.False(t, cfg.ProtectedWith(vars))
	})

	t.Run("user.cfg without the variable", func(t *testing.T) {
		vars, err := ParseGrubDefaults(strings.NewReader("GRUB2_SOMETHING_ELSE=1\n"))
		require.NoError(t, err)
		assert.False(t, cfg.ProtectedWith(vars))
	})

	t.Run("absent user.cfg", func(t *testing.T) {
		assert.False(t, cfg.ProtectedWith(map[string]string{}))
	})

	t.Run("templated superusers resolved from user.cfg", func(t *testing.T) {
		templated := ParseGrubPasswordConfig([]byte(`set superusers="${GRUB2_SUPERUSER}"
password_pbkdf2 root ${GRUB2_PASSWORD}
`))
		assert.False(t, templated.ProtectedWith(map[string]string{
			"GRUB2_PASSWORD": "grub.pbkdf2.sha512.10000.ABC123.DEF456",
		}))
		assert.True(t, templated.ProtectedWith(map[string]string{
			"GRUB2_SUPERUSER": "root",
			"GRUB2_PASSWORD":  "grub.pbkdf2.sha512.10000.ABC123.DEF456",
		}))
	})
}

func TestReadGrubUserCfg(t *testing.T) {
	t.Run("reads user.cfg beside grub.cfg", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/boot/grub2/grub.cfg", []byte(stockRhelUsersBlock), 0o644))
		require.NoError(t, afero.WriteFile(fs, "/boot/grub2/user.cfg",
			[]byte("GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.ABC123.DEF456\n"), 0o600))

		vars := readGrubUserCfg(fs, "/boot/grub2/grub.cfg")
		require.NotNil(t, vars)
		assert.Equal(t, "grub.pbkdf2.sha512.10000.ABC123.DEF456", vars["GRUB2_PASSWORD"])
	})

	t.Run("reads user.cfg from an EFI directory", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/boot/efi/EFI/redhat/user.cfg",
			[]byte("GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.ABC123.DEF456\n"), 0o600))

		vars := readGrubUserCfg(fs, "/boot/efi/EFI/redhat/grub.cfg")
		require.NotNil(t, vars)
		assert.NotEmpty(t, vars["GRUB2_PASSWORD"])
	})

	t.Run("missing user.cfg is not an error", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/boot/grub2/grub.cfg", []byte(stockRhelUsersBlock), 0o644))

		assert.Nil(t, readGrubUserCfg(fs, "/boot/grub2/grub.cfg"))
	})

	t.Run("empty grub.cfg path", func(t *testing.T) {
		assert.Nil(t, readGrubUserCfg(afero.NewMemMapFs(), ""))
	})
}

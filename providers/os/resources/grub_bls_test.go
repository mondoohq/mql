// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGrubEnv(t *testing.T) {
	// A GRUB environment block is exactly 1024 bytes, padded to the end with
	// '#' after the last value.
	env := "# GRUB Environment Block\n" +
		"saved_entry=ffff-5.14.0\n" +
		"kernelopts=root=UUID=1234 ro audit=1 crashkernel=auto\n" +
		strings.Repeat("#", 200)

	vars, err := ParseGrubEnv(strings.NewReader(env))
	require.NoError(t, err)

	assert.Equal(t, "root=UUID=1234 ro audit=1 crashkernel=auto", vars["kernelopts"])
	assert.Equal(t, "ffff-5.14.0", vars["saved_entry"])
	assert.NotContains(t, vars, "#")
	assert.Len(t, vars, 2)
}

func TestParseBLSEntry(t *testing.T) {
	t.Run("options referencing kernelopts", func(t *testing.T) {
		entry, err := ParseBLSEntry(strings.NewReader(
			"title Red Hat Enterprise Linux (4.18.0) 8.10 (Ootpa)\n" +
				"version 4.18.0-553.el8_10.x86_64\n" +
				"linux /boot/vmlinuz-4.18.0\n" +
				"initrd /boot/initramfs-4.18.0.img $tuned_initrd\n" +
				"options $kernelopts $tuned_params\n" +
				"grub_class rhel\n"))
		require.NoError(t, err)

		assert.Equal(t, "Red Hat Enterprise Linux (4.18.0) 8.10 (Ootpa)", entry.Title)
		assert.Equal(t, "4.18.0-553.el8_10.x86_64", entry.Version)
		assert.Equal(t, "/boot/vmlinuz-4.18.0", entry.Kernel)
		assert.Equal(t, "$kernelopts $tuned_params", entry.Cmdline)
		assert.Equal(t, []string{"rhel"}, entry.Classes)
	})

	t.Run("several options lines make one command line", func(t *testing.T) {
		entry, err := ParseBLSEntry(strings.NewReader(
			"title Linux\nlinux /vmlinuz\noptions root=UUID=1234 ro\noptions audit=1\n"))
		require.NoError(t, err)
		assert.Equal(t, "root=UUID=1234 ro audit=1", entry.Cmdline)
	})

	t.Run("tab separated keys", func(t *testing.T) {
		entry, err := ParseBLSEntry(strings.NewReader("title\tLinux\noptions\taudit=1\n"))
		require.NoError(t, err)
		assert.Equal(t, "Linux", entry.Title)
		assert.Equal(t, "audit=1", entry.Cmdline)
	})
}

func TestParseCmdline(t *testing.T) {
	t.Run("splits parameters from flags", func(t *testing.T) {
		params, flags := ParseCmdline("root=UUID=1234 ro quiet audit=1 console=ttyS0,115200n8")
		assert.Equal(t, map[string]string{
			"root":    "UUID=1234",
			"audit":   "1",
			"console": "ttyS0,115200n8",
		}, params)
		assert.Equal(t, []string{"ro", "quiet"}, flags)
	})

	t.Run("last occurrence wins, as the kernel reads it", func(t *testing.T) {
		params, _ := ParseCmdline("audit=1 audit=0")
		assert.Equal(t, "0", params["audit"])

		params, _ = ParseCmdline("audit=0 audit=1")
		assert.Equal(t, "1", params["audit"])
	})

	t.Run("a value is not matched by a similar name", func(t *testing.T) {
		params, _ := ParseCmdline("noaudit=1 audit=10 intel_iommu=off")
		assert.Equal(t, "10", params["audit"])
		assert.Equal(t, "1", params["noaudit"])
		assert.NotContains(t, params, "iommu")
	})

	t.Run("an unresolved variable is not a flag", func(t *testing.T) {
		params, flags := ParseCmdline("root=UUID=1234 $tuned_params ro")
		assert.Equal(t, []string{"ro"}, flags)
		assert.Len(t, params, 1)
	})
}

func TestExpandGrubVars(t *testing.T) {
	vars := map[string]string{"kernelopts": "root=UUID=1234 ro audit=1"}

	assert.Equal(t, "root=UUID=1234 ro audit=1",
		expandGrubVars("$kernelopts", vars))
	assert.Equal(t, "root=UUID=1234 ro audit=1 quiet",
		expandGrubVars("${kernelopts} quiet", vars))

	// grubby leaves a variable it cannot resolve as written, and so does this.
	assert.Equal(t, "root=UUID=1234 ro audit=1 $tuned_params",
		expandGrubVars("$kernelopts $tuned_params", vars))
	assert.Equal(t, "$kernelopts", expandGrubVars("$kernelopts", map[string]string{}))
}

func TestIsGrubCfgStub(t *testing.T) {
	// What a distribution installs on the EFI system partition beside the real
	// configuration under /boot.
	stub := []byte("\nsearch --no-floppy --set prefix --file /grub2/grub.cfg\n" +
		"set prefix=($prefix)/grub2\nconfigfile $prefix/grub.cfg\n")
	assert.True(t, isGrubCfgStub(stub))

	assert.False(t, isGrubCfgStub([]byte("menuentry 'Linux' {\n  linux /vmlinuz ro\n}\n")))
	assert.False(t, isGrubCfgStub([]byte("insmod blscfg\nblscfg\n")))

	// A configuration that chains elsewhere but also declares its own entries
	// is not a stub.
	assert.False(t, isGrubCfgStub([]byte("configfile $prefix/other.cfg\nmenuentry 'Linux' {\n  linux /vmlinuz\n}\n")))
}

func TestClassifyEntry(t *testing.T) {
	// The markers each distribution actually writes, taken from the collected
	// fixtures under testdata/grub.
	tests := []struct {
		name  string
		entry GrubEntry
		want  string
	}{
		{
			name:  "debian recovery flag",
			entry: GrubEntry{Title: "Debian, with Linux 7.0 (recovery mode)", Kernel: "/boot/vmlinuz", Flags: []string{"ro", "single"}},
			want:  GrubEntryRecovery,
		},
		{
			name:  "ubuntu recovery flag",
			entry: GrubEntry{Title: "Ubuntu, with Linux 7.0", Kernel: "/vmlinuz", Flags: []string{"ro", "recovery", "nomodeset"}},
			want:  GrubEntryRecovery,
		},
		{
			name:  "red hat rescue entry named in its version",
			entry: GrubEntry{Title: "Red Hat Enterprise Linux (0-rescue-ffff) 8.10", Version: "0-rescue-ffff", Kernel: "/boot/vmlinuz-0-rescue-ffff"},
			want:  GrubEntryRecovery,
		},
		{
			name:  "proxmox memory test by class",
			entry: GrubEntry{Title: "Memory test (memtest86+x64.efi)", Kernel: "/boot/memtest86+x64.efi", Classes: []string{"memtest"}},
			want:  GrubEntryMemtest,
		},
		{
			name:  "memory test by image name alone",
			entry: GrubEntry{Title: "Memory test", Kernel: "/boot/memtest86+x64.bin"},
			want:  GrubEntryMemtest,
		},
		{
			name:  "firmware settings entry boots no kernel",
			entry: GrubEntry{Title: "UEFI Firmware Settings"},
			want:  GrubEntryOther,
		},
		{
			name:  "submenu",
			entry: GrubEntry{Title: "Advanced options", IsSubmenu: true},
			want:  GrubEntrySubmenu,
		},
		{
			name:  "normal entry",
			entry: GrubEntry{Title: "Ubuntu", Kernel: "/vmlinuz", Flags: []string{"ro", "quiet"}},
			want:  GrubEntryNormal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, classifyEntry(&tt.entry))
		})
	}
}

func TestLoadGrubEntriesNoBootloader(t *testing.T) {
	// A host with nothing to read must yield no entries at all, so that the
	// resource reports null rather than an empty list that every assertion
	// made over the entries would satisfy.
	entries, err := LoadGrubEntries(afero.NewMemMapFs(), "", nil)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestLoadGrubEntriesExpandsKernelopts(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/boot/grub2/grub.cfg",
		[]byte("insmod blscfg\nblscfg\n"), 0o600))
	require.NoError(t, afero.WriteFile(fs, "/boot/grub2/grubenv",
		[]byte("# GRUB Environment Block\nkernelopts=root=UUID=1234 ro audit=1\n"+strings.Repeat("#", 100)), 0o600))
	require.NoError(t, afero.WriteFile(fs, "/boot/loader/entries/ffff-4.18.0.conf",
		[]byte("title Linux\nlinux /boot/vmlinuz-4.18.0\noptions $kernelopts\n"), 0o600))

	content, err := afero.ReadFile(fs, "/boot/grub2/grub.cfg")
	require.NoError(t, err)

	entries, err := LoadGrubEntries(fs, "/boot/grub2/grub.cfg", content)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.Equal(t, "1", entries[0].Parameters["audit"])
	assert.Equal(t, "UUID=1234", entries[0].Parameters["root"])
	assert.Equal(t, "/boot/loader/entries/ffff-4.18.0.conf", entries[0].Source)
	assert.Equal(t, GrubEntryNormal, entries[0].Kind)
}

func TestLoadGrubEntriesPrefersEntriesOverStaleGrubCfg(t *testing.T) {
	// A grub.cfg that calls blscfg does not boot its own menu entries, so a
	// leftover linux line in it must not be reported as a boot entry.
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/boot/grub2/grub.cfg",
		[]byte("menuentry 'Stale' {\n  linux /vmlinuz-old root=UUID=old\n}\nblscfg\n"), 0o600))
	require.NoError(t, afero.WriteFile(fs, "/boot/loader/entries/ffff-6.1.conf",
		[]byte("title Current\nlinux /boot/vmlinuz-6.1\noptions root=UUID=new ro audit=1\n"), 0o600))

	content, err := afero.ReadFile(fs, "/boot/grub2/grub.cfg")
	require.NoError(t, err)

	entries, err := LoadGrubEntries(fs, "/boot/grub2/grub.cfg", content)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "Current", entries[0].Title)
	assert.Equal(t, "UUID=new", entries[0].Parameters["root"])
}

func TestFindGrubCfgSkipsStub(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/boot/efi/EFI/redhat/grub.cfg",
		[]byte("search --no-floppy --set prefix --file /grub2/grub.cfg\nconfigfile $prefix/grub.cfg\n"), 0o600))
	require.NoError(t, afero.WriteFile(fs, "/boot/grub2/grub.cfg",
		[]byte("menuentry 'Linux' {\n  linux /vmlinuz ro\n}\n"), 0o600))

	assert.Equal(t, "/boot/grub2/grub.cfg", findGrubCfg(fs, grubCfgPaths))

	// With only the stub readable it is still better than reporting nothing.
	stubOnly := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(stubOnly, "/boot/efi/EFI/redhat/grub.cfg",
		[]byte("configfile $prefix/grub.cfg\n"), 0o600))
	assert.Equal(t, "/boot/efi/EFI/redhat/grub.cfg", findGrubCfg(stubOnly, grubCfgPaths))
}

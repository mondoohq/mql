// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// rhel9BLSEntry is an entry file from a RHEL 9.6 EC2 instance.
const rhel9BLSEntry = `title Red Hat Enterprise Linux (5.14.0-687.54.1.el9_8.x86_64) 9.6 (Plow)
version 5.14.0-687.54.1.el9_8.x86_64
linux /vmlinuz-5.14.0-687.54.1.el9_8.x86_64
initrd /initramfs-5.14.0-687.54.1.el9_8.x86_64.img $tuned_initrd
options root=UUID=d133b612-f0c6-40be-befe-76bef16f0864 console=tty0 console=ttyS0,115200n8 net.ifnames=0 nvme_core.io_timeout=4294967295 crashkernel=1G-4G:192M,4G-64G:256M,64G-:512M $tuned_params
grub_users $grub_users
grub_arg --unrestricted
grub_class rhel
`

func TestBLSEntryKeepsEveryConsole(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeEntryFile(t, fs, "/boot/loader/entries/rhel.conf", rhel9BLSEntry)

	entries, err := readBLSEntries(fs, "/boot/loader/entries", nil)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	e := entries[0]

	assert.Equal(t, []string{"tty0", "ttyS0,115200n8"}, e.ParameterValues["console"])
	assert.Equal(t, []string{"0"}, e.ParameterValues["net.ifnames"])
	// the last-wins view is unchanged
	assert.Equal(t, "ttyS0,115200n8", e.Parameters["console"])
	// an unresolved variable is not a parameter
	for k := range e.ParameterValues {
		assert.False(t, strings.HasPrefix(k, "$"), k)
	}
}

func TestParseCmdlineValues(t *testing.T) {
	values := ParseCmdlineValues("console=tty0 ro console=ttyS0,115200n8 $tuned_params audit=1 audit=0")
	assert.Equal(t, map[string][]string{
		"console": {"tty0", "ttyS0,115200n8"},
		"audit":   {"1", "0"},
	}, values)
	assert.Empty(t, ParseCmdlineValues(""))
}

func TestBLSInitrdExpandsLikeGrub(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeEntryFile(t, fs, "/boot/loader/entries/rhel.conf", rhel9BLSEntry)

	// No TuneD overlay: $tuned_initrd is unset and GRUB loads only the image.
	entries, err := readBLSEntries(fs, "/boot/loader/entries", nil)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "/initramfs-5.14.0-687.54.1.el9_8.x86_64.img", entries[0].Initrd)

	// A TuneD profile with initrd_add_img sets it in the environment block.
	entries, err = readBLSEntries(fs, "/boot/loader/entries", map[string]string{"tuned_initrd": "/tuned-initrd.img"})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "/initramfs-5.14.0-687.54.1.el9_8.x86_64.img /tuned-initrd.img", entries[0].Initrd)

	assert.Equal(t, "/boot/initrd.img-6.8.0-1", expandInitrd("/boot/initrd.img-6.8.0-1", nil))
}

// Every Red Hat family fixture appends $tuned_initrd to its initrd line.
func TestFixtureInitrdHasNoVariables(t *testing.T) {
	for _, name := range []string{"rhel8", "rhel9", "rhel10", "centos-stream9", "centos-stream10", "rocky8", "arm-rhel9"} {
		t.Run(name, func(t *testing.T) {
			entries := loadFixtureEntries(t, name)
			require.NotEmpty(t, entries)
			for _, e := range entries {
				if !e.Bootable {
					continue
				}
				assert.NotEmpty(t, e.Initrd, e.Title)
				assert.NotContains(t, e.Initrd, "$", e.Title)
				assert.True(t, strings.HasSuffix(e.Initrd, ".img"), e.Initrd)
			}
		})
	}
}

// bootDirDeniedFs refuses every path at or below the given directories, the way a
// non-root user meets /boot/grub2 and /boot/loader/entries (0700) on the Red
// Hat family: the directory itself stats, but neither it nor anything inside
// it can be opened or examined.
type bootDirDeniedFs struct {
	afero.Fs
	dirs []string
}

func (f *bootDirDeniedFs) denied(name string) bool {
	for _, d := range f.dirs {
		if name == d || strings.HasPrefix(name, d+"/") {
			return true
		}
	}
	return false
}

func (f *bootDirDeniedFs) Open(name string) (afero.File, error) {
	if f.denied(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: os.ErrPermission}
	}
	return f.Fs.Open(name)
}

func (f *bootDirDeniedFs) Stat(name string) (os.FileInfo, error) {
	for _, d := range f.dirs {
		if strings.HasPrefix(name, d+"/") {
			return nil, &fs.PathError{Op: "stat", Path: name, Err: os.ErrPermission}
		}
	}
	return f.Fs.Stat(name)
}

// rhel9NonRootFs is a RHEL 9 host as a non-root scan sees it.
func rhel9NonRootFs(t *testing.T) afero.Fs {
	t.Helper()
	mem := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(mem, "/etc/default/grub", []byte("GRUB_TIMEOUT=1\n"), 0o644))
	require.NoError(t, afero.WriteFile(mem, "/boot/grub2/grub.cfg", []byte("blscfg\n"), 0o600))
	writeEntryFile(t, mem, "/boot/loader/entries/rhel.conf", rhel9BLSEntry)
	return &bootDirDeniedFs{Fs: mem, dirs: []string{"/boot/grub2", "/boot/loader/entries"}}
}

func TestNonRootGrubIsRefusedNotAbsent(t *testing.T) {
	fs := rhel9NonRootFs(t)

	// What init sees: a boot menu it may not read.
	assert.Equal(t, "/boot/grub2/grub.cfg", findBootConfig(fs))
	g := &mqlGrubConfig{}
	require.NoError(t, g.loadGrubCfg(fs, "/boot/grub2/grub.cfg"))
	assert.False(t, g.cachedGrubFound)
	assert.ErrorIs(t, g.cachedGrubRefused, llx.ErrForbidden)
	assert.ErrorIs(t, g.cachedEntriesRefused, llx.ErrForbidden)

	err := grubConfigRefused(fs)
	assert.ErrorIs(t, err, llx.ErrForbidden)

	entries, err := LoadGrubEntries(fs, "", nil)
	assert.Empty(t, entries)
	assert.ErrorIs(t, err, llx.ErrForbidden)

	// A host without GRUB is not refused.
	assert.NoError(t, grubConfigRefused(afero.NewMemMapFs()))
	entries, err = LoadGrubEntries(afero.NewMemMapFs(), "", nil)
	assert.NoError(t, err)
	assert.Empty(t, entries)
}

func TestReadBLSEntriesRefusedEntryFile(t *testing.T) {
	mem := afero.NewMemMapFs()
	writeEntryFile(t, mem, "/boot/loader/entries/a.conf", rhel9BLSEntry)
	writeEntryFile(t, mem, "/boot/loader/entries/b.conf", rhel9BLSEntry)
	fs := &unlistableFs{Fs: mem, denied: map[string]bool{"/boot/loader/entries/b.conf": true}}

	entries, err := readBLSEntries(fs, "/boot/loader/entries", nil)
	assert.Len(t, entries, 1)
	assert.ErrorIs(t, err, llx.ErrForbidden)
}

func TestGrubConfigAccessorsReportRefusal(t *testing.T) {
	refused := llx.Forbidden(&fs.PathError{Op: "open", Path: "/boot/grub2/grub.cfg", Err: os.ErrPermission})
	newConfig := func() *mqlGrubConfig {
		g := &mqlGrubConfig{}
		g.fetched = true
		g.cachedGrubRefused = refused
		return g
	}

	t.Run("with structured errors the refusal is an error", func(t *testing.T) {
		withStructuredErrors(t, true)
		g := newConfig()
		_, err := g.entries()
		assert.ErrorIs(t, err, llx.ErrForbidden)
		_, err = g.passwordProtected()
		assert.ErrorIs(t, err, llx.ErrForbidden)
	})

	t.Run("without structured errors it stays null as in v13", func(t *testing.T) {
		withStructuredErrors(t, false)
		g := newConfig()
		res, err := g.entries()
		require.NoError(t, err)
		assert.Nil(t, res)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, g.Entries.State)
		_, err = g.passwordProtected()
		require.NoError(t, err)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, g.PasswordProtected.State)
	})

	t.Run("a host without GRUB stays null", func(t *testing.T) {
		withStructuredErrors(t, true)
		g := &mqlGrubConfig{}
		g.fetched = true
		res, err := g.entries()
		require.NoError(t, err)
		assert.Nil(t, res)
		_, err = g.passwordProtected()
		require.NoError(t, err)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, g.PasswordProtected.State)
	})
}

// suseNonRootFs is a SUSE host as a non-root scan sees it: /boot/grub2/grub.cfg
// is 0600, while the stub on the EFI system partition (vfat, fmask 0022) is
// readable by everyone.
func suseNonRootFs(name string) afero.Fs {
	return &bootDirDeniedFs{Fs: fixtureFS(name), dirs: []string{"/boot/grub2/grub.cfg"}}
}

var suseFixtures = []string{"sles15sp7", "opensuse-leap16"}

// SUSE's stub on the EFI system partition reads the real configuration with
// source rather than configfile.
func TestSuseEspGrubCfgIsAStub(t *testing.T) {
	for _, name := range suseFixtures {
		t.Run(name, func(t *testing.T) {
			content, err := afero.ReadFile(fixtureFS(name), "/boot/efi/EFI/BOOT/grub.cfg")
			require.NoError(t, err)
			assert.True(t, isGrubCfgStub(content))

			real, err := afero.ReadFile(fixtureFS(name), "/boot/grub2/grub.cfg")
			require.NoError(t, err)
			assert.False(t, isGrubCfgStub(real))
		})
	}
}

func TestSuseNonRootGrubCfgIsRefusedNotTheStub(t *testing.T) {
	for _, name := range suseFixtures {
		t.Run(name, func(t *testing.T) {
			fs := suseNonRootFs(name)
			// The configuration that exists but refuses to be read, not the
			// stub beside it.
			assert.Equal(t, "/boot/grub2/grub.cfg", findBootConfig(fs))
			// Root reads the same file.
			assert.Equal(t, "/boot/grub2/grub.cfg", findBootConfig(fixtureFS(name)))

			g := &mqlGrubConfig{}
			require.NoError(t, g.loadGrubCfg(fs, "/boot/grub2/grub.cfg"))
			assert.False(t, g.cachedGrubFound)
			assert.ErrorIs(t, g.cachedGrubRefused, llx.ErrForbidden)

			withStructuredErrors(t, true)
			_, err := g.passwordProtected()
			assert.ErrorIs(t, err, llx.ErrForbidden)
			_, err = g.entries()
			assert.ErrorIs(t, err, llx.ErrForbidden)
		})
	}

	// A path the query names that refuses to be read is an error either way.
	g := &mqlGrubConfig{}
	fs := &bootDirDeniedFs{Fs: fixtureFS("sles15sp7"), dirs: []string{"/srv/grub.cfg"}}
	assert.ErrorIs(t, g.loadGrubCfg(fs, "/srv/grub.cfg"), llx.ErrForbidden)
}

// sdbootutilEntry is the entry sdbootutil writes on openSUSE Leap 16, with the
// command line the host booted.
const sdbootutilEntry = `title openSUSE Leap 16.0
version 1@6.12.0-160000.35-default
sort-key opensuse-leap
options root=LABEL=ROOT console=ttyS0 net.ifnames=0 security=selinux selinux=1 audit=1
linux /opensuse-leap/6.12.0-160000.35-default/linux-0123456789abcdef
initrd /opensuse-leap/6.12.0-160000.35-default/initrd-0123456789abcdef
`

func TestBLSEntriesOnTheEsp(t *testing.T) {
	for _, esp := range []string{"/boot/efi", "/efi"} {
		t.Run(esp, func(t *testing.T) {
			fs := afero.NewMemMapFs()
			writeEntryFile(t, fs, esp+"/loader/entries/opensuse-leap-6.12.0-160000.35-default-1.conf", sdbootutilEntry)

			// No grub.cfg: grub2-bls carries its configuration inside its binary.
			entries, err := LoadGrubEntries(fs, "", nil)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Equal(t, "1", entries[0].Parameters["audit"])
			assert.True(t, entries[0].Bootable)

			// A grub.cfg that hands over to blscfg.
			entries, err = LoadGrubEntries(fs, esp+"/EFI/opensuse/grub.cfg", []byte("blscfg\n"))
			require.NoError(t, err)
			require.Len(t, entries, 1)
		})
	}
}

func TestBLSEntriesFromTheGrubCfgFilesystemFirst(t *testing.T) {
	fs := afero.NewMemMapFs()
	writeEntryFile(t, fs, "/boot/loader/entries/rhel.conf", rhel9BLSEntry)
	writeEntryFile(t, fs, "/boot/efi/loader/entries/opensuse.conf", sdbootutilEntry)

	entries, err := LoadGrubEntries(fs, "/boot/efi/EFI/opensuse/grub.cfg", []byte("blscfg\n"))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "openSUSE Leap 16.0", entries[0].Title)

	entries, err = LoadGrubEntries(fs, "/boot/grub2/grub.cfg", []byte("blscfg\n"))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "/boot/loader/entries/rhel.conf", entries[0].Source)
}

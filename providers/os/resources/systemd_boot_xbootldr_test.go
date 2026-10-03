// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// /proc/self/mountinfo lines for /boot and the ESP on Fedora 44 cloud: /boot
// is a btrfs subvolume of the root partition.
const fedora44Mountinfo = `61 43 0:35 /boot /boot rw,relatime shared:166 - btrfs /dev/nvme0n1p3 rw,seclabel,compress=zstd:1,ssd,space_cache=v2,subvolid=257,subvol=/boot
106 61 259:2 / /boot/efi rw,relatime shared:181 - vfat /dev/nvme0n1p2 rw,fmask=0077,dmask=0077,codepage=437,iocharset=ascii,shortname=winnt,errors=remount-ro
`

// fedora44BootFs is a Fedora 44 host with systemd-boot installed next to
// GRUB (`bootctl install --no-variables`): GRUB's Boot Loader Specification
// entries are in /boot/loader/entries, the ESP is /boot/efi.
func fedora44BootFs(t *testing.T, bootPartType string) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	for p, content := range map[string]string{
		"/boot/efi/EFI/systemd/systemd-bootx64.efi":            "#### LoaderInfo: systemd-boot 259.9-1.fc44 ####",
		"/boot/loader/entries/0821-7.2.8-200.fc44.x86_64.conf": "title Fedora Linux\nlinux /vmlinuz-7.2.8-200.fc44.x86_64\noptions root=UUID=b92ff89a\n",
		"/proc/self/mountinfo":                                 fedora44Mountinfo,
		"/sys/class/block/nvme0n1p2/dev":                       "259:2\n",
		"/sys/class/block/nvme0n1p3/dev":                       "259:3\n",
		"/run/udev/data/b259:2":                                "S:disk/by-partuuid/1ce7c703\nE:ID_FS_TYPE=vfat\nE:ID_PART_ENTRY_TYPE=c12a7328-f81f-11d2-ba4b-00a0c93ec93b\n",
		"/run/udev/data/b259:3":                                "E:ID_FS_TYPE=btrfs\nE:ID_PART_ENTRY_TYPE=" + bootPartType + "\n",
	} {
		require.NoError(t, afero.WriteFile(fs, p, []byte(content), 0o644))
	}
	return fs
}

func TestMountinfoSource(t *testing.T) {
	source, ok := mountinfoSource(fedora44Mountinfo, "/boot")
	assert.True(t, ok)
	assert.Equal(t, "/dev/nvme0n1p3", source)
	source, ok = mountinfoSource(fedora44Mountinfo, "/boot/efi")
	assert.True(t, ok)
	assert.Equal(t, "/dev/nvme0n1p2", source)
	_, ok = mountinfoSource(fedora44Mountinfo, "/efi")
	assert.False(t, ok)
}

// bootctl on that host: "$BOOT=/boot/efi", "No boot loader entries found".
// Before, /boot was taken as XBOOTLDR because it holds loader/entries, and
// GRUB's entries were reported as systemd-boot's.
func TestFindBootPathNeedsAnXbootldrPartition(t *testing.T) {
	// the root partition type of x86-64, as on the Fedora host
	fs := fedora44BootFs(t, "4f68bce3-e8cd-4db1-96e7-fbcaf984b709")
	assert.Equal(t, "/boot/efi", findBootPath(fs, "/boot/efi"))
	parts := readBootPartitions(fs)
	assert.Equal(t, "/boot/efi", parts.Boot)
	assert.Empty(t, readBootEntries(fs, parts.Boot))

	// the same layout on a real extended boot loader partition
	fs = fedora44BootFs(t, "BC13C2FF-59E6-4262-A352-B275FD6F7172")
	assert.Equal(t, "/boot", findBootPath(fs, "/boot/efi"))

	// /boot not mounted at all: a directory on the root filesystem
	fs = fedora44BootFs(t, xbootldrPartitionType)
	require.NoError(t, afero.WriteFile(fs, "/proc/self/mountinfo",
		[]byte(strings.SplitN(fedora44Mountinfo, "\n", 2)[1]), 0o644))
	assert.Equal(t, "/boot/efi", findBootPath(fs, "/boot/efi"))
}

// espRefusingFs answers a stat below prefix with a permission error, like the
// 0700 ESP mount does for a non-root scan.
type espRefusingFs struct {
	afero.Fs
	prefix string
}

func (f espRefusingFs) Stat(name string) (os.FileInfo, error) {
	if strings.HasPrefix(name, f.prefix) {
		return nil, &os.PathError{Op: "stat", Path: name, Err: os.ErrPermission}
	}
	return f.Fs.Stat(name)
}

// Ubuntu 26.04, non-root: /boot/efi is mounted 0700, so `ls /boot/efi/EFI`
// says "Permission denied". The ESP was reported as absent and systemd-boot
// as not installed, while root saw it installed.
func TestFindEspReportsARefusal(t *testing.T) {
	base := newBootFs(t, "/boot/efi/EFI/systemd/systemd-bootx64.efi")
	fs := espRefusingFs{Fs: base, prefix: "/boot/efi/"}

	esp, err := findEspChecked(fs)
	assert.Equal(t, "", esp)
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrPermission)

	// root sees it
	esp, err = findEspChecked(base)
	require.NoError(t, err)
	assert.Equal(t, "/boot/efi", esp)

	// a host without any ESP is not a refusal
	esp, err = findEspChecked(afero.NewMemMapFs())
	require.NoError(t, err)
	assert.Equal(t, "", esp)
}

func TestSystemdBootRefusedEspIsForbiddenWithStructuredErrors(t *testing.T) {
	newBoot := func() *mqlSystemdBoot {
		s := &mqlSystemdBoot{}
		s.once.Do(func() {})
		s.espRefused = errors.New("cannot look for the EFI system partition at /boot/efi/EFI/systemd: permission denied")
		return s
	}

	t.Run("v13 behavior keeps the empty values", func(t *testing.T) {
		require.False(t, plugin.StructuredErrors())
		installed, err := newBoot().installed()
		require.NoError(t, err)
		assert.False(t, installed)
	})

	t.Run("structured errors", func(t *testing.T) {
		enableStructuredErrorsForTest(t)
		s := newBoot()
		_, err := s.installed()
		assert.ErrorIs(t, err, llx.ErrForbidden)
		_, err = s.espPath()
		assert.ErrorIs(t, err, llx.ErrForbidden)
		_, err = s.bootPath()
		assert.ErrorIs(t, err, llx.ErrForbidden)
		_, err = s.version()
		assert.ErrorIs(t, err, llx.ErrForbidden)
	})
}

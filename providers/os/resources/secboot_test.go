// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secbootFixtureRoot = "testdata/secboot/host/files"

func secbootImagePath(name string) string {
	return filepath.Join(secbootFixtureRoot, "boot/efi/EFI/Linux", name)
}

// TestParseSecbootConfigAppliesDefaults is the decode test the resource stands
// on. secboot merges config.json over its own defaults, so a key the file omits
// is not unset: reporting the zero value would say this host compresses its
// initramfs with nothing and keeps no signing certificates.
func TestParseSecbootConfigAppliesDefaults(t *testing.T) {
	cfg, err := ParseSecbootConfig(strings.NewReader(`{"kernel-params": "root=LABEL=root rw audit=1"}`))
	require.NoError(t, err)

	assert.Equal(t, "root=LABEL=root rw audit=1", cfg.KernelParams)

	// Everything else falls back to the value the tool itself would use.
	assert.Equal(t, "/dev/disk/by-label/efi", cfg.EfiPartition)
	assert.Equal(t, "/boot/efi", cfg.EfiMountpoint)
	assert.Equal(t, "/boot/efi/EFI/Linux", cfg.EfiSubdir)
	assert.Equal(t, "/dev/disk/by-label/root", cfg.LuksPartition)
	assert.Equal(t, "lz4", cfg.InitramfsCompression)
	assert.Equal(t, "/etc/secboot", cfg.CertificateStorage)
	assert.Equal(t, "/etc/machine-id", cfg.MachineIdPath)
	assert.Equal(t, "/usr/lib/systemd/boot/efi/linuxx64.efi.stub", cfg.EfiStub)
	assert.Equal(t, "/usr/lib/fwupd/efi/fwupdx64.efi", cfg.FwupdBinary)
	assert.Equal(t, "auto", cfg.TpmDevice)
	assert.Equal(t, "7", cfg.TpmPcrs)
	assert.Empty(t, cfg.DkmsFiles)
	assert.Empty(t, cfg.DracutParams)
	assert.Empty(t, cfg.KernelPriority)
}

// TestParseSecbootConfigReadsEveryKey checks each struct tag against the name
// the tool actually uses. The keys are hyphenated and the fields are not, so a
// mistyped tag cannot be rescued by Go's case-insensitive field matching: the
// value would silently stay at its default, which is a plausible-looking wrong
// answer rather than an error.
func TestParseSecbootConfigReadsEveryKey(t *testing.T) {
	cfg, err := ParseSecbootConfig(strings.NewReader(`{
	  "efi-partition": "/dev/nvme0n1p1",
	  "efi-mountpoint": "/efi",
	  "efi-subdir": "/efi/EFI/Linux",
	  "luks-partition": "/dev/nvme0n1p2",
	  "kernel-params": "root=LABEL=root rw",
	  "initramfs-compression": "zstd",
	  "dkms-files": ["/usr/lib/modules/{version}/updates/dkms/*.ko"],
	  "certificate-storage": "/var/lib/secboot",
	  "dracut-params": ["--no-hostonly"],
	  "kernel-priority": ["linux-hardened", "linux"],
	  "machine-id": "/var/lib/dbus/machine-id",
	  "efi-stub": "/usr/lib/systemd/boot/efi/linuxaa64.efi.stub",
	  "fwupd-binary": "/usr/lib/fwupd/efi/fwupdaa64.efi",
	  "tpm-device": "/dev/tpmrm0",
	  "tpm-pcrs": "0+2+7"
	}`))
	require.NoError(t, err)

	assert.Equal(t, "/dev/nvme0n1p1", cfg.EfiPartition)
	assert.Equal(t, "/efi", cfg.EfiMountpoint)
	assert.Equal(t, "/efi/EFI/Linux", cfg.EfiSubdir)
	assert.Equal(t, "/dev/nvme0n1p2", cfg.LuksPartition)
	assert.Equal(t, "root=LABEL=root rw", cfg.KernelParams)
	assert.Equal(t, "zstd", cfg.InitramfsCompression)
	assert.Equal(t, []string{"/usr/lib/modules/{version}/updates/dkms/*.ko"}, cfg.DkmsFiles)
	assert.Equal(t, "/var/lib/secboot", cfg.CertificateStorage)
	assert.Equal(t, []string{"--no-hostonly"}, cfg.DracutParams)
	assert.Equal(t, []string{"linux-hardened", "linux"}, cfg.KernelPriority)
	assert.Equal(t, "/var/lib/dbus/machine-id", cfg.MachineIdPath)
	assert.Equal(t, "/usr/lib/systemd/boot/efi/linuxaa64.efi.stub", cfg.EfiStub)
	assert.Equal(t, "/usr/lib/fwupd/efi/fwupdaa64.efi", cfg.FwupdBinary)
	assert.Equal(t, "/dev/tpmrm0", cfg.TpmDevice)
	assert.Equal(t, "0+2+7", cfg.TpmPcrs)
}

func TestParseSecbootConfigEdgeCases(t *testing.T) {
	t.Run("an empty file is the defaults", func(t *testing.T) {
		cfg, err := ParseSecbootConfig(strings.NewReader("   \n"))
		require.NoError(t, err)
		assert.Equal(t, "lz4", cfg.InitramfsCompression)
	})

	t.Run("malformed json is an error", func(t *testing.T) {
		_, err := ParseSecbootConfig(strings.NewReader(`{"kernel-params": }`))
		assert.Error(t, err)
	})

	t.Run("a decode cannot write into the shared defaults", func(t *testing.T) {
		first, err := ParseSecbootConfig(strings.NewReader(`{"dkms-files": ["/a.ko"]}`))
		require.NoError(t, err)
		require.Equal(t, []string{"/a.ko"}, first.DkmsFiles)

		second, err := ParseSecbootConfig(strings.NewReader(`{}`))
		require.NoError(t, err)
		assert.Empty(t, second.DkmsFiles, "the second host inherited the first host's modules")
	})
}

// TestReadUnifiedKernelImage runs against images built by systemd's own ukify,
// not against hand-made files, so the section layout and padding are the ones a
// real build produces. See testdata/secboot/README.md for how they were made.
func TestReadUnifiedKernelImage(t *testing.T) {
	const luks = "rd.luks.name=8d0b7f2c-1111-2222-3333-444455556666=vault"

	tests := []struct {
		file    string
		cmdline string
		signed  bool
	}{
		{"linux-9f8e7d6c.efi", luks + " root=LABEL=root rw quiet audit=1", false},
		{"signed-9f8e7d6c.efi", luks + " root=LABEL=root rw quiet audit=1", true},
		{"stale-9f8e7d6c.efi", luks + " root=LABEL=root rw quiet", false},
	}

	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			f, err := os.Open(secbootImagePath(test.file))
			require.NoError(t, err)
			defer f.Close()

			img, err := ReadUnifiedKernelImage(f)
			require.NoError(t, err)

			assert.Equal(t, test.cmdline, img.Cmdline)
			assert.Equal(t, "6.19.14-108.fc42.aarch64", img.Kernel)
			assert.Equal(t, test.signed, img.Signed)

			// The command line is split the same way a boot entry's is, so a
			// check asserts on a parameter rather than matching text.
			assert.Equal(t, "LABEL=root", img.Parameters["root"])
			assert.Contains(t, img.Flags, "rw")
			assert.Contains(t, img.Flags, "quiet")
		})
	}

	t.Run("the signed and unsigned images differ only in the signature", func(t *testing.T) {
		// Both were built from the same inputs, so anything else that differs
		// would mean the signature changed what the image says it boots.
		plain, err := os.Open(secbootImagePath("linux-9f8e7d6c.efi"))
		require.NoError(t, err)
		defer plain.Close()
		signed, err := os.Open(secbootImagePath("signed-9f8e7d6c.efi"))
		require.NoError(t, err)
		defer signed.Close()

		a, err := ReadUnifiedKernelImage(plain)
		require.NoError(t, err)
		b, err := ReadUnifiedKernelImage(signed)
		require.NoError(t, err)

		assert.Equal(t, a.Cmdline, b.Cmdline)
		assert.Equal(t, a.Kernel, b.Kernel)
		assert.False(t, a.Signed)
		assert.True(t, b.Signed)
	})
}

// TestReadUnifiedKernelImageOnAPlainEfiBinary covers the file that shares the
// directory without being an image. secboot copies the firmware updater in
// beside the images, and a boot loader lives on the same partition; both are
// valid PE executables with no command line to report.
func TestReadUnifiedKernelImageOnAPlainEfiBinary(t *testing.T) {
	f, err := os.Open(secbootImagePath("fwupdaa64.efi"))
	require.NoError(t, err)
	defer f.Close()

	img, err := ReadUnifiedKernelImage(f)
	require.NoError(t, err, "a plain EFI binary parses as PE, it is simply not an image")
	assert.Empty(t, img.Cmdline, "a boot loader carries no kernel command line")
	assert.Empty(t, img.Kernel)
	assert.Empty(t, img.Parameters)
}

func TestReadUnifiedKernelImageOnSomethingElse(t *testing.T) {
	_, err := ReadUnifiedKernelImage(strings.NewReader("this is not an executable"))
	assert.Error(t, err)
}

// TestSecbootFixtureConfig reads the fixture's own config.json, so the decode
// is exercised against a file on disk rather than only against string literals.
func TestSecbootFixtureConfig(t *testing.T) {
	f, err := os.Open(filepath.Join(secbootFixtureRoot, "etc/secboot/config.json"))
	require.NoError(t, err)
	defer f.Close()

	cfg, err := ParseSecbootConfig(f)
	require.NoError(t, err)

	assert.Equal(t, "/boot/efi/EFI/Linux", cfg.EfiSubdir)
	assert.Equal(t, "root=LABEL=root rw quiet audit=1", cfg.KernelParams)
	assert.Equal(t, "zstd", cfg.InitramfsCompression)
	assert.Equal(t, "0+2+7", cfg.TpmPcrs)
	// Not in the file, so it has to come from the defaults.
	assert.Equal(t, "/etc/machine-id", cfg.MachineIdPath)
	assert.Equal(t, "auto", cfg.TpmDevice)
}

// noReadAtFs stands in for the connections that cannot read a file at an
// offset. A container image layer answers ReadAt with "not implemented yet"
// (connection/tar/file.go), and so do the command-backed filesystems used over
// SSH and WinRM when no file transfer is available.
type noReadAtFs struct{ afero.Fs }

type noReadAtFile struct{ afero.File }

func (f noReadAtFile) ReadAt(_ []byte, _ int64) (int, error) {
	return 0, errors.New("not implemented")
}

func (fs noReadAtFs) Open(name string) (afero.File, error) {
	f, err := fs.Fs.Open(name)
	if err != nil {
		return nil, err
	}
	return noReadAtFile{f}, nil
}

// TestSecbootImageReaderWithoutReadAt is the container-image and SSH-cat case.
// Reading sections out of an executable needs a reader that can seek, so
// without a fallback every image on those connections fails to parse and the
// host reports no images at all rather than the ones it has.
func TestSecbootImageReaderWithoutReadAt(t *testing.T) {
	const image = "/boot/efi/EFI/Linux/linux-9f8e7d6c.efi"
	base := afero.NewBasePathFs(afero.NewOsFs(), secbootFixtureRoot)

	read := func(t *testing.T, fs afero.Fs) SecbootImage {
		t.Helper()
		r, closer, err := secbootImageReader(fs, image)
		require.NoError(t, err)
		defer closer()
		img, err := ReadUnifiedKernelImage(r)
		require.NoError(t, err)
		return img
	}

	seekable := read(t, base)
	buffered := read(t, noReadAtFs{base})

	// The connection decides how the bytes are fetched, never what they say.
	assert.Equal(t, seekable.Cmdline, buffered.Cmdline)
	assert.Equal(t, seekable.Kernel, buffered.Kernel)
	assert.Equal(t, seekable.Signed, buffered.Signed)
	assert.Equal(t, "1", buffered.Parameters["audit"])
	assert.NotEmpty(t, buffered.Cmdline, "the image was not read at all")
}

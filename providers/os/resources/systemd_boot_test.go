// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path"
	"strings"
	"testing"

	"github.com/spf13/afero"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEfiVarString(t *testing.T) {
	t.Run("decodes a UTF-16 variable", func(t *testing.T) {
		// A literal variable as efivarfs exposes it: the 4-byte attribute
		// header, then "sd" as UTF-16LE. Written out so the encoding this
		// rests on is stated by the test rather than by a helper.
		data := []byte{0x07, 0x00, 0x00, 0x00, 's', 0x00, 'd', 0x00}

		got, err := parseEfiVarString(data)
		require.NoError(t, err)
		assert.Equal(t, "sd", got)
	})

	t.Run("drops a trailing NUL", func(t *testing.T) {
		data := []byte{0x07, 0x00, 0x00, 0x00, 's', 0x00, 'd', 0x00, 0x00, 0x00}

		got, err := parseEfiVarString(data)
		require.NoError(t, err)
		assert.Equal(t, "sd", got)
	})

	t.Run("a variable with no data is empty", func(t *testing.T) {
		got, err := parseEfiVarString([]byte{0x07, 0x00, 0x00, 0x00})
		require.NoError(t, err)
		assert.Equal(t, "", got)
	})

	t.Run("too short to hold a header", func(t *testing.T) {
		_, err := parseEfiVarString([]byte{0x07, 0x00})
		require.Error(t, err)
	})

	t.Run("an odd number of data bytes is not UTF-16", func(t *testing.T) {
		_, err := parseEfiVarString([]byte{0x07, 0x00, 0x00, 0x00, 's'})
		require.Error(t, err)
	})
}

func TestParseLoaderInfo(t *testing.T) {
	t.Run("systemd-boot names itself and its version", func(t *testing.T) {
		name, version := parseLoaderInfo("systemd-boot 257.2-1")
		assert.Equal(t, "systemd-boot", name)
		assert.Equal(t, "257.2-1", version)
	})

	t.Run("a loader that states no version", func(t *testing.T) {
		name, version := parseLoaderInfo("systemd-boot")
		assert.Equal(t, "systemd-boot", name)
		assert.Equal(t, "", version)
	})

	t.Run("another boot loader is named, not mistaken for systemd-boot", func(t *testing.T) {
		// Anything that implements the loader protocol may set this variable.
		// The name is what separates them, so it is reported as written.
		name, version := parseLoaderInfo("GRUB 2.12")
		assert.Equal(t, "GRUB", name)
		assert.Equal(t, "2.12", version)
	})

	t.Run("an unset variable names nothing", func(t *testing.T) {
		name, version := parseLoaderInfo("")
		assert.Equal(t, "", name)
		assert.Equal(t, "", version)
	})
}

func TestParseLoaderInfoMagic(t *testing.T) {
	t.Run("reads the version out of the boot loader binary", func(t *testing.T) {
		// The magic exactly as a Fedora 42 systemd-bootaa64.efi carries it:
		// plain ASCII between NUL padding, which is what lets the version be
		// read from an image, where no EFI variable exists.
		binary := []byte("b\x00\x00\x00\x00\x00\x00\x00" +
			"#### LoaderInfo: systemd-boot 257.13-1.fc42 ####" +
			"\x00\x00\x00\x00root_dir")

		assert.Equal(t, "systemd-boot 257.13-1.fc42", parseLoaderInfoMagic(binary))
	})

	t.Run("the version composes with the EFI variable parser", func(t *testing.T) {
		// Both sources state the same thing in the same form, so one parser
		// reads them both.
		name, version := parseLoaderInfo(parseLoaderInfoMagic(
			[]byte("\x00#### LoaderInfo: systemd-boot 257.13-1.fc42 ####\x00")))
		assert.Equal(t, "systemd-boot", name)
		assert.Equal(t, "257.13-1.fc42", version)
	})

	t.Run("an EFI binary that is not systemd-boot", func(t *testing.T) {
		assert.Equal(t, "", parseLoaderInfoMagic([]byte("MZ\x00\x00grubx64 is not systemd-boot")))
	})

	t.Run("a truncated magic states no version", func(t *testing.T) {
		// Opening marker with no closing one. Returning the rest of the file
		// as a version would be worse than reporting none.
		assert.Equal(t, "", parseLoaderInfoMagic([]byte("#### LoaderInfo: systemd-boot 257.13")))
	})
}

// newBootFs builds a filesystem holding exactly the given paths. A path ending
// in "/" is a directory; anything else is an empty file.
func newBootFs(t *testing.T, paths ...string) afero.Fs {
	t.Helper()
	fs := afero.NewMemMapFs()
	for _, p := range paths {
		if strings.HasSuffix(p, "/") {
			require.NoError(t, fs.MkdirAll(strings.TrimSuffix(p, "/"), 0o755))
			continue
		}
		require.NoError(t, fs.MkdirAll(path.Dir(p), 0o755))
		require.NoError(t, afero.WriteFile(fs, p, []byte{}, 0o644))
	}
	return fs
}

func TestFindEsp(t *testing.T) {
	t.Run("mounted at /boot, which is what Arch does", func(t *testing.T) {
		fs := newBootFs(t,
			"/boot/EFI/systemd/systemd-bootx64.efi",
			"/boot/EFI/BOOT/BOOTX64.EFI",
			"/boot/loader/entries/arch.conf",
		)
		assert.Equal(t, "/boot", findEsp(fs))
	})

	t.Run("at /boot/efi beside an XBOOTLDR partition at /boot", func(t *testing.T) {
		// The Fedora layout. /boot carries an EFI directory of its own, for
		// unified kernel images, so the presence of one cannot be what picks
		// the ESP out: only the ESP holds the boot loader binaries.
		fs := newBootFs(t,
			"/boot/EFI/Linux/6.19.0.efi",
			"/boot/loader/entries/fedora.conf",
			"/boot/efi/EFI/systemd/systemd-bootx64.efi",
			"/boot/efi/EFI/BOOT/BOOTX64.EFI",
		)
		assert.Equal(t, "/boot/efi", findEsp(fs))
	})

	t.Run("at /efi, which is what systemd recommends", func(t *testing.T) {
		fs := newBootFs(t,
			"/efi/EFI/systemd/systemd-bootx64.efi",
			"/boot/loader/entries/nixos.conf",
		)
		assert.Equal(t, "/efi", findEsp(fs))
	})

	t.Run("a host with no boot loader still has an ESP", func(t *testing.T) {
		// Nothing is installed under EFI/ yet the partition is plainly there.
		// It is still the ESP, and reporting it is how a scan explains itself.
		fs := newBootFs(t, "/boot/efi/EFI/")
		assert.Equal(t, "/boot/efi", findEsp(fs))
	})

	t.Run("no EFI system partition is visible", func(t *testing.T) {
		fs := newBootFs(t, "/boot/grub2/grub.cfg", "/boot/vmlinuz-6.19.0")
		assert.Equal(t, "", findEsp(fs))
	})
}

func TestFindBootPath(t *testing.T) {
	t.Run("the XBOOTLDR partition holds the entries", func(t *testing.T) {
		fs := newBootFs(t,
			"/boot/loader/entries/fedora.conf",
			"/boot/efi/EFI/systemd/systemd-bootx64.efi",
		)
		assert.Equal(t, "/boot", findBootPath(fs, "/boot/efi"))
	})

	t.Run("without an XBOOTLDR partition it is the ESP", func(t *testing.T) {
		fs := newBootFs(t,
			"/boot/EFI/systemd/systemd-bootx64.efi",
			"/boot/loader/entries/arch.conf",
		)
		assert.Equal(t, "/boot", findBootPath(fs, "/boot"))
	})

	t.Run("unified kernel images alone make a boot partition", func(t *testing.T) {
		// A host booting only unified kernel images has no loader/entries
		// directory at all, and $BOOT is still where the images live.
		fs := newBootFs(t,
			"/boot/EFI/Linux/6.19.0.efi",
			"/boot/efi/EFI/systemd/systemd-bootx64.efi",
		)
		assert.Equal(t, "/boot", findBootPath(fs, "/boot/efi"))
	})

	t.Run("nothing to go on falls back to the ESP", func(t *testing.T) {
		fs := newBootFs(t, "/boot/efi/EFI/")
		assert.Equal(t, "/boot/efi", findBootPath(fs, "/boot/efi"))
	})
}

func TestSystemdBootInstalled(t *testing.T) {
	t.Run("the x64 binary", func(t *testing.T) {
		fs := newBootFs(t, "/boot/EFI/systemd/systemd-bootx64.efi")
		assert.True(t, systemdBootInstalled(fs, "/boot"))
	})

	t.Run("the aarch64 binary", func(t *testing.T) {
		// The binary carries the architecture in its name, so matching the
		// x64 one by hand would report every arm64 host as not installed.
		fs := newBootFs(t, "/boot/EFI/systemd/systemd-bootaa64.efi")
		assert.True(t, systemdBootInstalled(fs, "/boot"))
	})

	t.Run("GRUB on the same partition is not systemd-boot", func(t *testing.T) {
		fs := newBootFs(t,
			"/boot/efi/EFI/fedora/shimx64.efi",
			"/boot/efi/EFI/fedora/grubx64.efi",
			"/boot/efi/EFI/BOOT/BOOTX64.EFI",
		)
		assert.False(t, systemdBootInstalled(fs, "/boot/efi"))
	})

	t.Run("no ESP was found", func(t *testing.T) {
		assert.False(t, systemdBootInstalled(newBootFs(t), ""))
	})
}

func TestReadSystemdBootVersion(t *testing.T) {
	// A stand-in for the binary: the magic as it really appears, with padding
	// on both sides, since the version is found by searching the file.
	binary := []byte("MZ\x00\x00\x00\x00\x00\x00" +
		"#### LoaderInfo: systemd-boot 257.13-1.fc42 ####" +
		"\x00\x00\x00\x00")

	t.Run("reads the version from the installed binary", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, fs.MkdirAll("/boot/EFI/systemd", 0o755))
		require.NoError(t, afero.WriteFile(fs, "/boot/EFI/systemd/systemd-bootx64.efi", binary, 0o644))

		assert.Equal(t, "257.13-1.fc42", readSystemdBootVersion(fs, "/boot"))
	})

	t.Run("a binary carrying no version", func(t *testing.T) {
		// An EFI binary under the systemd directory that is not the loader
		// states no version, and inventing one would be worse than none.
		fs := afero.NewMemMapFs()
		require.NoError(t, fs.MkdirAll("/boot/EFI/systemd", 0o755))
		require.NoError(t, afero.WriteFile(fs, "/boot/EFI/systemd/systemd-bootx64.efi", []byte("MZ not a loader"), 0o644))

		assert.Equal(t, "", readSystemdBootVersion(fs, "/boot"))
	})

	t.Run("systemd-boot is not installed", func(t *testing.T) {
		assert.Equal(t, "", readSystemdBootVersion(newBootFs(t, "/boot/efi/EFI/"), "/boot/efi"))
	})
}

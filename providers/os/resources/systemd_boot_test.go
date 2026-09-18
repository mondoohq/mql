// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"path"
	"strings"
	"testing"
	"unicode/utf16"

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

// writeEfiVar writes a variable the way efivarfs presents one: the attribute
// header, then UTF-16LE.
func writeEfiVar(t *testing.T, fs afero.Fs, name, value string) {
	t.Helper()
	require.NoError(t, fs.MkdirAll(efiVarsDir, 0o755))
	data := append([]byte{0x07, 0x00, 0x00, 0x00}, utf16LE(value)...)
	require.NoError(t, afero.WriteFile(fs, path.Join(efiVarsDir, name+"-"+efiLoaderVariable), data, 0o644))
}

func utf16LE(s string) []byte {
	out := []byte{}
	for _, r := range utf16.Encode([]rune(s)) {
		out = append(out, byte(r), byte(r>>8))
	}
	return append(out, 0x00, 0x00)
}

func TestReadLoaderVariables(t *testing.T) {
	t.Run("reads the loader and the entry it selected", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		writeEfiVar(t, fs, "LoaderInfo", "systemd-boot 257.13-1.fc42")
		writeEfiVar(t, fs, "LoaderEntrySelected", "fedora-6.19.0.conf")

		vars, err := readLoaderVariables(nil, fs)
		require.NoError(t, err)
		assert.True(t, vars.Readable)
		assert.Equal(t, "systemd-boot", vars.Name)
		assert.Equal(t, "257.13-1.fc42", vars.Version)
		assert.Equal(t, "fedora-6.19.0.conf", vars.Selected)
	})

	t.Run("no efivars directory means nothing observed the boot", func(t *testing.T) {
		// An image or a mounted filesystem. Not an error: there is simply no
		// boot to describe.
		vars, err := readLoaderVariables(nil, afero.NewMemMapFs())
		require.NoError(t, err)
		assert.False(t, vars.Readable)
	})

	t.Run("a malformed variable is an error, not an empty answer", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, fs.MkdirAll(efiVarsDir, 0o755))
		require.NoError(t, afero.WriteFile(fs,
			path.Join(efiVarsDir, "LoaderInfo-"+efiLoaderVariable),
			[]byte{0x07, 0x00, 0x00, 0x00, 's'}, 0o644))

		_, err := readLoaderVariables(nil, fs)
		require.Error(t, err)
	})
}

func TestBootPartitionsAreReadIndependentlyOfTheVariables(t *testing.T) {
	// The partition is readable and the variable is not. Reading the EFI system
	// partition must not depend on the variables at all, so that a failure to
	// read one cannot take the other down.
	fs := newBootFs(t, "/boot/EFI/systemd/systemd-bootx64.efi")
	require.NoError(t, afero.WriteFile(fs, "/boot/EFI/systemd/systemd-bootx64.efi",
		[]byte("#### LoaderInfo: systemd-boot 257.13-1.fc42 ####"), 0o644))
	require.NoError(t, fs.MkdirAll(efiVarsDir, 0o755))
	require.NoError(t, afero.WriteFile(fs,
		path.Join(efiVarsDir, "LoaderInfo-"+efiLoaderVariable),
		[]byte{0x07, 0x00, 0x00, 0x00, 's'}, 0o644))

	parts := readBootPartitions(fs)
	assert.True(t, parts.Installed)
	assert.Equal(t, "257.13-1.fc42", parts.Version)
	assert.Equal(t, "/boot", parts.Esp)

	_, err := readLoaderVariables(nil, fs)
	require.Error(t, err)
}

func TestSystemdBootAccessorsSeparateTheTwoFailures(t *testing.T) {
	// A failure to read the boot loader variables must not be reported by the
	// fields that came off the filesystem and were never in doubt.
	s := &mqlSystemdBoot{}
	s.once.Do(func() {}) // the one fetch already happened
	s.cachedEsp = "/boot"
	s.cachedBootPath = "/boot"
	s.cachedInstalled = true
	s.cachedVersion = "257.13-1.fc42"
	s.efiVarErr = errors.New("cannot read LoaderInfo: permission denied")

	installed, err := s.installed()
	require.NoError(t, err)
	assert.True(t, installed)

	version, err := s.version()
	require.NoError(t, err)
	assert.Equal(t, "257.13-1.fc42", version)

	esp, err := s.espPath()
	require.NoError(t, err)
	assert.Equal(t, "/boot", esp)

	// The failure is reported by the fields that depend on it, and as an
	// error rather than as null: the variable was unreadable, not absent.
	_, err = s.active()
	require.Error(t, err)
	_, err = s.selectedEntry()
	require.Error(t, err)
}

// realUnifiedKernelImage is a unified kernel image built by systemd's own
// ukify, committed as a secboot fixture. Reused here so the reader runs against
// real section layout and padding rather than a hand-built PE file.
const realUnifiedKernelImage = "testdata/secboot/host/files/boot/efi/EFI/Linux/linux-9f8e7d6c.efi"

func copyInto(t *testing.T, fs afero.Fs, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	require.NoError(t, err)
	require.NoError(t, fs.MkdirAll(path.Dir(dst), 0o755))
	require.NoError(t, afero.WriteFile(fs, dst, data, 0o644))
}

func writeEntryFile(t *testing.T, fs afero.Fs, p, body string) {
	t.Helper()
	require.NoError(t, fs.MkdirAll(path.Dir(p), 0o755))
	require.NoError(t, afero.WriteFile(fs, p, []byte(body), 0o644))
}

func TestReadBootEntries(t *testing.T) {
	t.Run("an entry file under loader/entries", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		writeEntryFile(t, fs, "/boot/loader/entries/fedora.conf",
			"title Fedora Linux 42\n"+
				"version 6.19.0-63.fc42.aarch64\n"+
				"linux /vmlinuz-6.19.0\n"+
				"initrd /initramfs-6.19.0.img\n"+
				"options root=UUID=x ro audit=1 quiet\n")

		entries := readBootEntries(fs, "/boot")
		require.Len(t, entries, 1)
		assert.Equal(t, "Fedora Linux 42", entries[0].Title)
		assert.Equal(t, "/vmlinuz-6.19.0", entries[0].Kernel)
		assert.Equal(t, "1", entries[0].Parameters["audit"])
		assert.Contains(t, entries[0].Flags, "ro")
		assert.True(t, entries[0].Bootable)
		assert.False(t, entries[0].UnifiedKernelImage)
		assert.Equal(t, "/boot/loader/entries/fedora.conf", entries[0].Source)
	})

	t.Run("a unified kernel image under EFI/Linux", func(t *testing.T) {
		// The case that has no entry file at all, and that a check reading
		// only loader/entries reports as a host with nothing to boot.
		fs := afero.NewMemMapFs()
		copyInto(t, fs, realUnifiedKernelImage, "/boot/EFI/Linux/linux-6.19.0.efi")

		entries := readBootEntries(fs, "/boot")
		require.Len(t, entries, 1)
		assert.True(t, entries[0].UnifiedKernelImage)
		assert.True(t, entries[0].Bootable)
		assert.Equal(t, "1", entries[0].Parameters["audit"])
		assert.Equal(t, "/boot/EFI/Linux/linux-6.19.0.efi", entries[0].Source)
		assert.NotEmpty(t, entries[0].Kernel)
	})

	t.Run("both sources on one host", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		writeEntryFile(t, fs, "/boot/loader/entries/fedora.conf",
			"title Fedora Linux 42\nlinux /vmlinuz-6.19.0\noptions root=UUID=x audit=1\n")
		copyInto(t, fs, realUnifiedKernelImage, "/boot/EFI/Linux/linux-6.19.0.efi")

		entries := readBootEntries(fs, "/boot")
		require.Len(t, entries, 2)
	})

	t.Run("an entry that boots no kernel is not bootable", func(t *testing.T) {
		// bootctl writes an entry for the firmware setup, and a dual-boot host
		// carries one that chainloads Windows. Neither boots a kernel, so
		// neither carries parameters to audit, and requiring audit=1 of them
		// would fail a host that is correctly configured.
		fs := afero.NewMemMapFs()
		writeEntryFile(t, fs, "/boot/loader/entries/firmware.conf",
			"title Reboot Into Firmware Interface\n")
		writeEntryFile(t, fs, "/boot/loader/entries/windows.conf",
			"title Windows\nefi /EFI/Microsoft/Boot/bootmgfw.efi\n")
		writeEntryFile(t, fs, "/boot/loader/entries/fedora.conf",
			"title Fedora Linux 42\nlinux /vmlinuz-6.19.0\noptions root=UUID=x audit=1\n")

		entries := readBootEntries(fs, "/boot")
		require.Len(t, entries, 3)

		bootable := []BootEntry{}
		for _, e := range entries {
			if e.Bootable {
				bootable = append(bootable, e)
			}
		}
		require.Len(t, bootable, 1)
		assert.Equal(t, "Fedora Linux 42", bootable[0].Title)
	})

	t.Run("the boot loader itself is not an entry", func(t *testing.T) {
		// systemd-boot's own binary and a firmware updater are valid PE
		// executables with no command line. They boot no kernel of ours.
		fs := afero.NewMemMapFs()
		copyInto(t, fs, "testdata/secboot/host/files/boot/efi/EFI/Linux/fwupdaa64.efi",
			"/boot/EFI/Linux/fwupdaa64.efi")

		assert.Empty(t, readBootEntries(fs, "/boot"))
	})

	t.Run("nothing readable yields no entries", func(t *testing.T) {
		assert.Empty(t, readBootEntries(afero.NewMemMapFs(), "/boot"))
		assert.Empty(t, readBootEntries(afero.NewMemMapFs(), ""))
	})
}

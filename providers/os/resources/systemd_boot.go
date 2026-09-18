// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
)

// Length of the attribute header every EFI variable file begins with.
const efiVarHeaderLen = 4

// parseEfiVarString reads an EFI variable that holds text. The data after the
// attribute header is UTF-16LE, which is what the UEFI specification says a
// string variable is, and it is conventionally NUL-terminated.
func parseEfiVarString(data []byte) (string, error) {
	if len(data) < efiVarHeaderLen {
		return "", fmt.Errorf("EFI variable is %d bytes, expected at least %d", len(data), efiVarHeaderLen)
	}

	data = data[efiVarHeaderLen:]
	if len(data)%2 != 0 {
		return "", fmt.Errorf("EFI variable holds %d bytes of text, which is not whole UTF-16 characters", len(data))
	}

	chars := make([]uint16, 0, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		chars = append(chars, binary.LittleEndian.Uint16(data[i:]))
	}

	return strings.TrimRight(string(utf16.Decode(chars)), "\x00"), nil
}

// parseLoaderInfo splits the LoaderInfo variable into the name the boot loader
// reports for itself and the version beside it. The variable is set by the
// loader as it runs, so the name is what distinguishes systemd-boot from any
// other loader that implements the same protocol.
func parseLoaderInfo(info string) (string, string) {
	name, version, _ := strings.Cut(strings.TrimSpace(info), " ")
	return name, strings.TrimSpace(version)
}

// Markers systemd-boot writes around its own version inside the EFI binary.
// The version can therefore be read from the file, without the EFI variable
// the loader only sets on a host it has booted.
const (
	loaderInfoMagicPrefix = "#### LoaderInfo: "
	loaderInfoMagicSuffix = " ####"
)

// parseLoaderInfoMagic returns what a boot loader binary states about itself,
// in the same form as the LoaderInfo EFI variable, or an empty string when the
// binary carries no such marker.
func parseLoaderInfoMagic(binary []byte) string {
	start := bytes.Index(binary, []byte(loaderInfoMagicPrefix))
	if start < 0 {
		return ""
	}
	rest := binary[start+len(loaderInfoMagicPrefix):]

	end := bytes.Index(rest, []byte(loaderInfoMagicSuffix))
	if end < 0 {
		// Without the closing marker there is no telling where the version
		// ends, and the rest of the file is not a version.
		return ""
	}
	return string(rest[:end])
}

// Paths the EFI system partition and the extended boot loader partition are
// conventionally mounted at, in the order the Boot Loader Specification
// searches them.
var bootMountpoints = []string{"/efi", "/boot", "/boot/efi"}

// Directories that only the EFI system partition holds, because they hold boot
// loaders. An extended boot loader partition carries an EFI directory too, for
// unified kernel images, so an EFI directory alone does not name the ESP.
var espLoaderDirs = []string{"EFI/systemd", "EFI/BOOT"}

// findEsp returns the mountpoint of the EFI system partition, or an empty
// string when none is visible, which is the case on a legacy-BIOS host and on
// a scan that cannot see the partition.
func findEsp(fs afero.Fs) string {
	for _, mount := range bootMountpoints {
		for _, dir := range espLoaderDirs {
			if bootDirExists(fs, path.Join(mount, dir)) {
				return mount
			}
		}
	}

	// No boot loader is installed. The partition is still the ESP, and naming
	// it explains what was searched.
	for _, mount := range bootMountpoints {
		if bootDirExists(fs, path.Join(mount, "EFI")) {
			return mount
		}
	}
	return ""
}

// findBootPath returns what $BOOT resolves to: the extended boot loader
// partition when the host has one, and the EFI system partition otherwise. It
// is the directory boot entries are read from.
func findBootPath(fs afero.Fs, esp string) string {
	for _, mount := range bootMountpoints {
		if mount == esp {
			continue
		}
		if bootDirExists(fs, path.Join(mount, "loader/entries")) ||
			bootDirExists(fs, path.Join(mount, "EFI/Linux")) {
			return mount
		}
	}
	return esp
}

// systemdBootInstalled reports whether the systemd-boot binary is present on
// the EFI system partition. The name carries the architecture it was built
// for, so every one of them counts.
func systemdBootInstalled(fs afero.Fs, esp string) bool {
	if esp == "" {
		return false
	}
	matches, err := afero.Glob(fs, path.Join(esp, "EFI/systemd/systemd-boot*.efi"))
	return err == nil && len(matches) > 0
}

// bootDirExists reports whether a path is a directory, which is how the boot
// partitions are told apart by what they carry.
func bootDirExists(fs afero.Fs, p string) bool {
	info, err := fs.Stat(p)
	return err == nil && info.IsDir()
}

// readSystemdBootVersion returns the version the installed boot loader states
// for itself, read from the binary rather than from an EFI variable so that it
// resolves on an image or a mounted filesystem. Empty when systemd-boot is not
// installed, or when the binary carries no such marker.
func readSystemdBootVersion(fs afero.Fs, esp string) string {
	if esp == "" {
		return ""
	}

	matches, err := afero.Glob(fs, path.Join(esp, "EFI/systemd/systemd-boot*.efi"))
	if err != nil {
		return ""
	}
	sort.Strings(matches)

	for _, match := range matches {
		data, err := afero.ReadFile(fs, match)
		if err != nil {
			continue
		}
		if _, version := parseLoaderInfo(parseLoaderInfoMagic(data)); version != "" {
			return version
		}
	}
	return ""
}

// EFI variable GUID systemd-boot writes its own state under, from the systemd
// boot loader interface.
const efiLoaderVariable = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

// Name systemd-boot reports for itself, both in the EFI variable it sets and
// in the marker inside its binary.
const systemdBootLoaderName = "systemd-boot"

type mqlSystemdBootInternal struct {
	once              sync.Once
	cachedEsp         string
	cachedBootPath    string
	cachedInstalled   bool
	cachedVersion     string
	cachedActive      bool
	cachedSelected    string
	cachedEfiVarsRead bool
	fetchErr          error
}

func (s *mqlSystemdBoot) id() (string, error) {
	return "systemd.boot", nil
}

// fetch reads the EFI system partition and the boot loader variables once, so
// every field shares a single pass.
func (s *mqlSystemdBoot) fetch() error {
	s.once.Do(func() {
		conn, ok := s.MqlRuntime.Connection.(shared.Connection)
		if !ok {
			s.fetchErr = errors.New("wrong connection type")
			return
		}
		fs := conn.FileSystem()
		if fs == nil {
			s.fetchErr = errors.New("filesystem not available")
			return
		}

		s.cachedEsp = findEsp(fs)
		s.cachedBootPath = findBootPath(fs, s.cachedEsp)
		s.cachedInstalled = systemdBootInstalled(fs, s.cachedEsp)
		s.cachedVersion = readSystemdBootVersion(fs, s.cachedEsp)

		if _, err := fs.Stat(efiVarsDir); err != nil {
			// No EFI variables: a legacy BIOS host, or a scan of an image or a
			// mounted filesystem, where nothing booted at all. What the loader
			// would report about a boot cannot be answered either way.
			return
		}
		s.cachedEfiVarsRead = true

		info, err := readEfiVarString(conn, fs, "LoaderInfo-"+efiLoaderVariable)
		if err != nil {
			s.fetchErr = err
			return
		}
		name, version := parseLoaderInfo(info)
		s.cachedActive = name == systemdBootLoaderName
		if s.cachedActive && version != "" {
			// The loader that ran states its own version, which is what booted
			// this host even where a different binary now sits on the
			// partition.
			s.cachedVersion = version
		}

		s.cachedSelected, s.fetchErr = readEfiVarString(conn, fs, "LoaderEntrySelected-"+efiLoaderVariable)
	})
	return s.fetchErr
}

func (s *mqlSystemdBoot) active() (bool, error) {
	if err := s.fetch(); err != nil {
		return false, err
	}
	if !s.cachedEfiVarsRead {
		// Nothing observed this host boot. Reporting false would say
		// systemd-boot is not what boots it, which is a claim this scan cannot
		// make.
		s.Active.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return s.cachedActive, nil
}

func (s *mqlSystemdBoot) installed() (bool, error) {
	if err := s.fetch(); err != nil {
		return false, err
	}
	return s.cachedInstalled, nil
}

func (s *mqlSystemdBoot) version() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedVersion, nil
}

func (s *mqlSystemdBoot) espPath() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedEsp, nil
}

func (s *mqlSystemdBoot) bootPath() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedBootPath, nil
}

func (s *mqlSystemdBoot) selectedEntry() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	if !s.cachedEfiVarsRead {
		s.SelectedEntry.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return s.cachedSelected, nil
}

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

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
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

// bootPartitions is what the EFI system partition states about the boot loader
// installed on it, all of it read from files.
type bootPartitions struct {
	Esp       string
	Boot      string
	Version   string
	Installed bool
}

// readBootPartitions reads what the partitions state. Every field degrades to an
// empty value, so there is nothing here that fails: a partition that cannot be
// read is a host with no boot loader installed on it, which is an answer rather
// than an error.
func readBootPartitions(fs afero.Fs) bootPartitions {
	esp := findEsp(fs)
	return bootPartitions{
		Esp:       esp,
		Boot:      findBootPath(fs, esp),
		Installed: systemdBootInstalled(fs, esp),
		Version:   readSystemdBootVersion(fs, esp),
	}
}

// Directories under $BOOT that systemd-boot takes entries from: the Boot
// Loader Specification entry files, and the unified kernel images, which
// declare themselves by being there and carry their command line inside.
const (
	bootEntriesDir   = "loader/entries"
	unifiedKernelDir = "EFI/Linux"
)

// readBootEntries returns every entry systemd-boot offers on the next boot,
// from both sources it takes them from. A source that cannot be read yields
// nothing rather than an error: a host keeps its entries in one of these
// places, not both, so an absent directory is the normal case.
func readBootEntries(fs afero.Fs, bootPath string) []BootEntry {
	if bootPath == "" {
		return nil
	}

	// The variables a GRUB entry may reference do not exist here: systemd-boot
	// expands nothing, so an entry states its own command line.
	entries, _ := readBLSEntries(fs, path.Join(bootPath, bootEntriesDir), nil)

	return append(entries, readUnifiedKernelEntries(fs, path.Join(bootPath, unifiedKernelDir))...)
}

// readUnifiedKernelEntries reads the unified kernel images in dir. Only the
// headers and two small sections of each image are read; the kernel inside it
// is the bulk of the file and is never touched.
func readUnifiedKernelEntries(fs afero.Fs, dir string) []BootEntry {
	matches, err := afero.Glob(fs, path.Join(dir, "*.efi"))
	if err != nil {
		return nil
	}
	sort.Strings(matches)

	entries := []BootEntry{}
	for _, p := range matches {
		r, closer, err := secbootImageReader(fs, p)
		if err != nil {
			log.Debug().Str("path", p).Err(err).Msg("cannot open unified kernel image")
			continue
		}
		img, err := ReadUnifiedKernelImage(r)
		closer()
		if err != nil {
			// A file with an .efi suffix that is not a unified kernel image is
			// not an error: it is simply not one of the entries.
			log.Debug().Str("path", p).Err(err).Msg("not a readable unified kernel image")
			continue
		}
		if img.Cmdline == "" {
			// An EFI binary carrying no command line boots no kernel of ours,
			// such as the boot loader itself or a firmware updater beside it.
			continue
		}

		entry := BootEntry{
			Title:              path.Base(p),
			Kernel:             img.Kernel,
			Cmdline:            img.Cmdline,
			Parameters:         img.Parameters,
			Flags:              img.Flags,
			Source:             p,
			UnifiedKernelImage: true,
			Signed:             img.Signed,
		}
		entry.Kind = classifyEntry(&entry)
		entry.Bootable = entryBootable(entry.Kind)
		entries = append(entries, entry)
	}
	return entries
}

// loaderVariables is what the boot loader recorded about the boot it performed,
// read from the EFI variables it sets as it hands control to the kernel.
type loaderVariables struct {
	Name     string
	Version  string
	Selected string

	// Readable records whether the variables could be read at all, which is
	// what separates "another loader booted this host" from "nothing observed
	// the boot".
	Readable bool
}

// readLoaderVariables reads the boot loader interface variables. A host with no
// EFI variables at all is not a failure: an image and a legacy BIOS host both
// have none, and neither booted through a loader that could have written them.
// A variable that exists and cannot be read is an error, because that leaves
// the question open rather than answering it.
func readLoaderVariables(conn shared.Connection, fs afero.Fs) (loaderVariables, error) {
	vars := loaderVariables{}

	if _, err := fs.Stat(efiVarsDir); err != nil {
		return vars, nil
	}
	vars.Readable = true

	info, err := readEfiVarString(conn, fs, "LoaderInfo-"+efiLoaderVariable)
	if err != nil {
		return vars, err
	}
	vars.Name, vars.Version = parseLoaderInfo(info)

	vars.Selected, err = readEfiVarString(conn, fs, "LoaderEntrySelected-"+efiLoaderVariable)
	if err != nil {
		return vars, err
	}
	return vars, nil
}

type mqlSystemdBootInternal struct {
	once              sync.Once
	cachedEsp         string
	cachedBootPath    string
	cachedInstalled   bool
	cachedVersion     string
	cachedActive      bool
	cachedSelected    string
	cachedEfiVarsRead bool
	cachedEntries     []BootEntry
	cachedEntriesOK   bool

	// The two sources fail independently, so their failures are kept apart.
	// fetchErr is a failure to reach the host, which leaves nothing to report.
	// efiVarErr is a failure to read the boot loader variables, which leaves
	// only the fields that depend on them unanswered: the partitions were
	// already read by then, and reporting an error for those would discard a
	// measurement that succeeded.
	fetchErr  error
	efiVarErr error
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

		parts := readBootPartitions(fs)
		s.cachedEsp = parts.Esp
		s.cachedBootPath = parts.Boot
		s.cachedInstalled = parts.Installed
		s.cachedVersion = parts.Version

		s.cachedEntries = readBootEntries(fs, parts.Boot)
		s.cachedEntriesOK = len(s.cachedEntries) > 0

		vars, err := readLoaderVariables(conn, fs)
		if err != nil {
			s.efiVarErr = err
			return
		}
		s.cachedEfiVarsRead = vars.Readable
		s.cachedActive = vars.Name == systemdBootLoaderName
		s.cachedSelected = vars.Selected
		if s.cachedActive && vars.Version != "" {
			// The loader that ran states its own version, which is what booted
			// this host even where a different binary now sits on the
			// partition.
			s.cachedVersion = vars.Version
		}
	})
	return s.fetchErr
}

func (s *mqlSystemdBoot) active() (bool, error) {
	if err := s.fetch(); err != nil {
		return false, err
	}
	if s.efiVarErr != nil {
		return false, s.efiVarErr
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
	if s.efiVarErr != nil {
		return "", s.efiVarErr
	}
	if !s.cachedEfiVarsRead {
		s.SelectedEntry.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return s.cachedSelected, nil
}

func (s *mqlSystemdBoot) entries() ([]any, error) {
	if err := s.fetch(); err != nil {
		return nil, err
	}

	if !s.cachedEntriesOK {
		// A host whose boot entries cannot be read has none to report. An
		// empty list would read as "systemd-boot offers nothing to boot", and
		// would satisfy every assertion made over the entries.
		s.Entries.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	resources := make([]any, 0, len(s.cachedEntries))
	for _, entry := range s.cachedEntries {
		resource, err := CreateResource(s.MqlRuntime, "systemd.boot.entry", map[string]*llx.RawData{
			"__id":               llx.StringData("systemd.boot.entry:" + entry.Source),
			"title":              llx.StringData(entry.Title),
			"kind":               llx.StringData(entry.Kind),
			"bootable":           llx.BoolData(entry.Bootable),
			"kernel":             llx.StringData(entry.Kernel),
			"cmdline":            llx.StringData(entry.Cmdline),
			"parameters":         llx.MapData(convert.MapToInterfaceMap(entry.Parameters), types.String),
			"flags":              llx.ArrayData(convert.SliceAnyToInterface(entry.Flags), types.String),
			"unifiedKernelImage": llx.BoolData(entry.UnifiedKernelImage),
			"signed":             llx.BoolData(entry.Signed),
			"source":             llx.StringData(entry.Source),
			"initrd":             llx.StringData(entry.Initrd),
		})
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

func (e *mqlSystemdBootEntry) id() (string, error) {
	return e.MqlID(), nil
}

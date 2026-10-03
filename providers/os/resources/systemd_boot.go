// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
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
	esp, _ := findEspChecked(fs)
	return esp
}

// findEspChecked is findEsp, and when no ESP is found it also returns the
// first permission error met on the way. The ESP is mounted 0700 on Debian,
// Ubuntu and Fedora, so a non-root scan cannot look inside it, and an empty
// path would read as a legacy BIOS host without systemd-boot.
func findEspChecked(fs afero.Fs) (string, error) {
	var refused error
	isDir := func(p string) bool {
		info, err := fs.Stat(p)
		if err != nil {
			if refused == nil && errors.Is(err, os.ErrPermission) {
				refused = fmt.Errorf("cannot look for the EFI system partition at %s: %w", p, err)
			}
			return false
		}
		return info.IsDir()
	}

	for _, mount := range bootMountpoints {
		for _, dir := range espLoaderDirs {
			if isDir(path.Join(mount, dir)) {
				return mount, nil
			}
		}
	}

	// No boot loader is installed. The partition is still the ESP, and naming
	// it explains what was searched. An EFI directory alone is not enough: a
	// legacy BIOS host of the Red Hat family carries an empty
	// /boot/efi/EFI/redhat on its root filesystem, put there by a package
	// rather than by a partition. The directory names the ESP only when it
	// holds an EFI binary, or when the host booted through UEFI firmware.
	uefi := bootDirExists(fs, efiFirmwareDir)
	for _, mount := range bootMountpoints {
		efi := path.Join(mount, "EFI")
		if isDir(efi) && (uefi || holdsEfiBinary(fs, efi)) {
			return mount, nil
		}
	}
	return "", refused
}

// efiFirmwareDir exists on a running Linux host that UEFI firmware booted.
const efiFirmwareDir = "/sys/firmware/efi"

// holdsEfiBinary reports whether a vendor directory under the EFI directory
// holds an EFI executable, such as EFI/debian/grubx64.efi. The suffix is
// matched without regard to case, since the fallback loader is BOOTX64.EFI.
func holdsEfiBinary(fs afero.Fs, efiDir string) bool {
	vendors, err := afero.ReadDir(fs, efiDir)
	if err != nil {
		return false
	}
	for _, vendor := range vendors {
		if !vendor.IsDir() {
			continue
		}
		files, err := afero.ReadDir(fs, path.Join(efiDir, vendor.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if !f.IsDir() && strings.HasSuffix(strings.ToLower(f.Name()), ".efi") {
				return true
			}
		}
	}
	return false
}

// findBootPath returns what $BOOT resolves to: the extended boot loader
// partition when the host has one, and the EFI system partition otherwise. It
// is the directory boot entries are read from.
//
// Only a partition of the XBOOTLDR type is $BOOT. The Red Hat family keeps
// GRUB's Boot Loader Specification entries in /boot/loader/entries on a plain
// /boot, and with systemd-boot installed beside GRUB, taking that /boot as
// $BOOT reported GRUB's entries as systemd-boot's, where bootctl finds none.
func findBootPath(fs afero.Fs, esp string) string {
	isXbootldr := xbootldrChecker(fs)
	for _, mount := range bootMountpoints {
		if mount == esp {
			continue
		}
		if !bootDirExists(fs, path.Join(mount, "loader/entries")) &&
			!bootDirExists(fs, path.Join(mount, "EFI/Linux")) {
			continue
		}
		if isXbootldr(mount) {
			return mount
		}
	}
	return esp
}

// xbootldrPartitionType is the GPT partition type of an extended boot loader
// partition, from the Discoverable Partitions Specification.
const xbootldrPartitionType = "bc13c2ff-59e6-4262-a352-b275fd6f7172"

// xbootldrChecker returns a test for whether the filesystem mounted at a path
// is an XBOOTLDR partition. It reads the device from the mount table and the
// partition type udev recorded for it. Without a mount table (an image or a
// mounted filesystem) there is no device to ask about, and a directory that
// holds boot entries is taken as $BOOT, the way it was before.
//
// The mount table is read once, on the first call, which comes after the
// directory checks: those can trigger an automounted /boot.
func xbootldrChecker(fs afero.Fs) func(mount string) bool {
	read := false
	mountinfo, noMountinfo := "", false
	return func(mount string) bool {
		if !read {
			read = true
			data, err := afero.ReadFile(fs, "/proc/self/mountinfo")
			mountinfo, noMountinfo = string(data), err != nil
		}
		if noMountinfo {
			return true
		}
		source, ok := mountinfoSource(mountinfo, mount)
		if !ok {
			// not a mount point: a directory on the root filesystem
			return false
		}
		return partitionType(fs, source) == xbootldrPartitionType
	}
}

// mountinfoSource returns the mount source of the last filesystem mounted at
// mountpoint in /proc/self/mountinfo, which is the one in effect.
func mountinfoSource(mountinfo string, mountpoint string) (string, bool) {
	source, found := "", false
	for _, line := range strings.Split(mountinfo, "\n") {
		// 61 43 0:35 /boot /boot rw,relatime shared:166 - btrfs /dev/nvme0n1p3 rw,...
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		fields := strings.Fields(pre)
		if len(fields) < 5 || fields[4] != mountpoint {
			continue
		}
		rest := strings.Fields(post)
		if len(rest) < 2 {
			continue
		}
		source, found = rest[1], true
	}
	return source, found
}

// partitionType returns the GPT partition type udev recorded for a block
// device, lowercased, or "" when it is not known.
func partitionType(fs afero.Fs, device string) string {
	if !strings.HasPrefix(device, "/dev/") {
		return ""
	}
	dev, err := afero.ReadFile(fs, path.Join("/sys/class/block", path.Base(device), "dev"))
	if err != nil {
		return ""
	}
	data, err := afero.ReadFile(fs, "/run/udev/data/b"+strings.TrimSpace(string(dev)))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "E:ID_PART_ENTRY_TYPE="); ok {
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	return ""
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
	// Refused is set when no ESP was found because the scan may not look
	// where it would be.
	Refused error
}

// readBootPartitions reads what the partitions state. Every field degrades to an
// empty value, so there is nothing here that fails: a partition that cannot be
// read is a host with no boot loader installed on it, which is an answer rather
// than an error.
func readBootPartitions(fs afero.Fs) bootPartitions {
	esp, refused := findEspChecked(fs)
	return bootPartitions{
		Refused:   refused,
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
			ParameterValues:    ParseCmdlineValues(img.Cmdline),
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
	// espRefused is a refusal to look for the ESP. With structured errors
	// the partition fields report it; before, they read as no ESP at all.
	espRefused error
}

// espRefusal is the error the partition fields report when the scan was
// refused a look at the ESP, or nil when it was not or when structured errors
// are off (v13 read the fields as empty).
func (s *mqlSystemdBoot) espRefusal() error {
	if s.espRefused == nil || !plugin.StructuredErrors() {
		return nil
	}
	return llx.Forbidden(s.espRefused)
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
		s.espRefused = parts.Refused
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
	if err := s.espRefusal(); err != nil {
		return false, err
	}
	return s.cachedInstalled, nil
}

func (s *mqlSystemdBoot) version() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	if err := s.espRefusal(); err != nil {
		return "", err
	}
	return s.cachedVersion, nil
}

func (s *mqlSystemdBoot) espPath() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	if err := s.espRefusal(); err != nil {
		return "", err
	}
	return s.cachedEsp, nil
}

func (s *mqlSystemdBoot) bootPath() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	if err := s.espRefusal(); err != nil {
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

	if !s.cachedInstalled && !s.cachedActive {
		if err := s.espRefusal(); err != nil {
			return nil, err
		}
		if s.efiVarErr != nil {
			// systemd-boot is not installed, and whether it booted this host
			// is unknown, so whose entries these are is unknown too.
			return nil, s.efiVarErr
		}
		// The entry files belong to another boot loader. GRUB on the Red Hat
		// family reads the same Boot Loader Specification directory, and its
		// entries carry variables such as $kernelopts that only GRUB expands,
		// so reporting them here would audit a boot loader the host does not
		// have.
		s.Entries.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
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
			"parameterValues":    llx.MapData(parameterValuesData(entry.ParameterValues), types.Array(types.String)),
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

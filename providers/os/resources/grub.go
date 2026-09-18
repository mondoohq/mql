// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// Known paths for /etc/default/grub
var grubDefaultsPaths = []string{
	"/etc/default/grub",
}

// Known paths for grub.cfg across different distros and boot modes
var grubCfgPaths = []string{
	"/boot/grub2/grub.cfg",               // RHEL/CentOS/Fedora (BIOS)
	"/boot/grub/grub.cfg",                // Debian/Ubuntu (BIOS)
	"/boot/efi/EFI/centos/grub.cfg",      // CentOS (EFI)
	"/boot/efi/EFI/redhat/grub.cfg",      // RHEL (EFI)
	"/boot/efi/EFI/fedora/grub.cfg",      // Fedora (EFI)
	"/boot/efi/EFI/debian/grub.cfg",      // Debian (EFI)
	"/boot/efi/EFI/ubuntu/grub.cfg",      // Ubuntu (EFI)
	"/boot/efi/EFI/sles/grub.cfg",        // SUSE (EFI)
	"/boot/efi/EFI/opensuse/grub.cfg",    // openSUSE (EFI)
	"/boot/efi/EFI/amazon/grub.cfg",      // Amazon Linux (EFI)
	"/boot/efi/EFI/rocky/grub.cfg",       // Rocky Linux (EFI)
	"/boot/efi/EFI/almalinux/grub.cfg",   // AlmaLinux (EFI)
	"/boot/efi/EFI/arch/grub/grub.cfg",   // Arch Linux (EFI)
	"/boot/efi/EFI/BOOT/grub.cfg",        // Generic EFI fallback
	"/boot/efi/EFI/oracle/grub.cfg",      // Oracle Linux (EFI)
	"/boot/efi/EFI/scientific/grub.cfg",  // Scientific Linux (EFI)
	"/boot/efi/EFI/virtuozzo/grub.cfg",   // Virtuozzo (EFI)
	"/boot/efi/EFI/photon/grub.cfg",      // VMware Photon OS (EFI)
	"/boot/efi/EFI/mariner/grub.cfg",     // Azure Linux / Mariner (EFI)
	"/boot/efi/EFI/CBL-Mariner/grub.cfg", // CBL-Mariner (EFI)
	"/boot/efi/EFI/azurelinux/grub.cfg",  // Azure Linux (EFI)
	"/boot/efi/EFI/Microsoft/grub.cfg",   // WSL/Hyper-V (EFI)
}

// Known paths for a GRUB legacy menu. GRUB 0.97 keeps the whole menu in one
// file, and the distributions that shipped it disagree on its name: Debian and
// Ubuntu wrote menu.lst, the Red Hat family through RHEL 6 and Amazon Linux 1
// wrote grub.conf. On the Red Hat family only one of them is a real file and
// the others are symlinks to it, so every name it answers to is listed, since a
// filesystem or image scan need not resolve a link.
var grubLegacyCfgPaths = []string{
	"/boot/grub/menu.lst",
	"/boot/grub/grub.conf",
	"/boot/grub2/grub.conf",
	"/etc/grub.conf",
}

// Boot Loader Specification entries. Red Hat Enterprise Linux 8 and later,
// CentOS Stream, Rocky Linux, AlmaLinux and Amazon Linux 2023 keep their kernel
// command lines here and leave grub.cfg with no kernel lines at all.
const blsEntriesDir = "/boot/loader/entries"

// The GRUB environment block, which holds the value of $kernelopts on the
// releases whose entries reference it. On some distributions the path under
// /boot/grub2 is a symlink to a copy on the EFI system partition.
var grubEnvPaths = []string{
	"/boot/grub2/grubenv",
	"/boot/grub/grubenv",
}

type mqlGrubConfigInternal struct {
	lock              sync.Mutex
	fetched           bool
	cachedGrubFound   bool
	cachedEntriesOK   bool
	cachedEntries     []BootEntry
	cachedPwProtected bool
}

func initGrubConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return nil, nil, errors.New("wrong connection type")
	}
	fs := conn.FileSystem()
	if fs == nil {
		return nil, nil, errors.New("filesystem not available")
	}

	// Resolve defaultsPath
	if x, ok := args["defaultsPath"]; ok {
		path, ok := x.Value.(string)
		if !ok || path == "" {
			args["defaultsPath"] = llx.StringData(findExistingPath(fs, grubDefaultsPaths))
		}
	} else {
		args["defaultsPath"] = llx.StringData(findExistingPath(fs, grubDefaultsPaths))
	}

	// Resolve grubPath
	if x, ok := args["grubPath"]; ok {
		path, ok := x.Value.(string)
		if !ok || path == "" {
			args["grubPath"] = llx.StringData(findBootConfig(fs))
		}
	} else {
		args["grubPath"] = llx.StringData(findBootConfig(fs))
	}

	return args, nil, nil
}

// findExistingPath returns the first path from candidates that exists on the filesystem,
// or an empty string if none exist.
func findExistingPath(fs afero.Fs, candidates []string) string {
	for _, path := range candidates {
		f, err := fs.Open(path)
		if err == nil {
			f.Close()
			return path
		}
	}
	return ""
}

// findBootConfig returns the boot loader configuration to read. A GRUB 2
// grub.cfg wins wherever one exists, since a host that has been upgraded can
// keep a stale legacy menu beside the configuration it actually boots from.
func findBootConfig(fs afero.Fs) string {
	if p := findGrubCfg(fs, grubCfgPaths); p != "" {
		return p
	}
	return findExistingPath(fs, grubLegacyCfgPaths)
}

// findGrubCfg returns the first candidate holding a real configuration. A
// distribution that boots via EFI commonly installs a grub.cfg on the EFI
// system partition that only chains to the configuration under /boot, and that
// stub declares no entries, so it is used only when nothing else is readable.
func findGrubCfg(fs afero.Fs, candidates []string) string {
	fallback := ""
	for _, path := range candidates {
		content, err := afero.ReadFile(fs, path)
		if err != nil {
			continue
		}
		if fallback == "" {
			fallback = path
		}
		if !isGrubCfgStub(content) {
			return path
		}
	}
	return fallback
}

func (g *mqlGrubConfig) id() (string, error) {
	return "grub.config:" + g.DefaultsPath.Data + "+" + g.GrubPath.Data, nil
}

func (g *mqlGrubConfig) params() (map[string]any, error) {
	defaultsPath := g.GetDefaultsPath().Data
	if defaultsPath == "" {
		return map[string]any{}, nil
	}

	conn, ok := g.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("wrong connection type")
	}
	fs := conn.FileSystem()
	if fs == nil {
		return nil, errors.New("filesystem not available")
	}

	f, err := fs.Open(defaultsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	params, err := ParseGrubDefaults(f)
	if err != nil {
		return nil, err
	}

	result := make(map[string]any, len(params))
	for k, v := range params {
		result[k] = v
	}
	return result, nil
}

// fetchGrubCfg reads grub.cfg once and parses both entries and password
// protection status so that multiple field accessors share a single read.
func (g *mqlGrubConfig) fetchGrubCfg() error {
	if g.fetched {
		return nil
	}
	g.lock.Lock()
	defer g.lock.Unlock()
	if g.fetched {
		return nil
	}

	conn, ok := g.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return errors.New("wrong connection type")
	}
	fs := conn.FileSystem()
	if fs == nil {
		return errors.New("filesystem not available")
	}

	cfgPath := g.GetGrubPath().Data
	if cfgPath == "" {
		// Without a grub.cfg the entry files can still be read directly. The
		// Boot Loader Specification is not GRUB's alone, so entries here say
		// nothing about which bootloader reads them, and systemd-boot keeps
		// its entries in the same directory. cachedGrubFound therefore stays
		// false and passwordProtected stays null: reporting false would say
		// GRUB is installed and unprotected on a host that may not run GRUB
		// at all.
		entries, _ := LoadGrubEntries(fs, "", nil)
		g.cachedEntries = entries
		g.cachedEntriesOK = len(entries) > 0
		g.fetched = true
		return nil
	}

	f, err := fs.Open(cfgPath)
	if err != nil {
		return err
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	entries, err := LoadGrubEntries(fs, cfgPath, content)
	if err != nil {
		return err
	}
	g.cachedEntriesOK = len(entries) > 0

	if isGrubLegacyCfg(content) {
		// A legacy menu states password protection with a directive of its
		// own, which the GRUB 2 parser does not recognise and would read as
		// no password on a host that has one.
		g.cachedEntries = entries
		g.cachedPwProtected = ParseGrubLegacyPasswordProtected(content)
		g.cachedGrubFound = true
		g.fetched = true
		return nil
	}

	pwCfg := ParseGrubPasswordConfig(content)
	protected := pwCfg.Protected()
	// RHEL-family grub.cfg files carry a templated 01_users block whose
	// credential is read from ${prefix}/user.cfg at boot. When grub.cfg only
	// references those variables, the credential itself lives in user.cfg.
	if !protected && pwCfg.ReferencesVars() {
		if vars := readGrubUserCfg(fs, cfgPath); vars != nil {
			protected = pwCfg.ProtectedWith(vars)
		}
	}

	g.cachedEntries = entries
	g.cachedPwProtected = protected
	g.cachedGrubFound = true
	g.fetched = true
	return nil
}

func (g *mqlGrubConfig) entries() ([]any, error) {
	if err := g.fetchGrubCfg(); err != nil {
		return nil, err
	}

	if !g.cachedEntriesOK {
		// A host that does not boot with GRUB has no entries to report. An
		// empty list would read as "GRUB is installed and offers nothing to
		// boot", and would satisfy every assertion made over the entries.
		g.Entries.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	resources := make([]any, 0, len(g.cachedEntries))
	for _, entry := range g.cachedEntries {
		entryID := "grub.config.entry:" + entry.Source + ":" + entry.Title + ":" + entry.Cmdline
		resource, err := CreateResource(g.MqlRuntime, "grub.config.entry", map[string]*llx.RawData{
			"__id":       llx.StringData(entryID),
			"title":      llx.StringData(entry.Title),
			"kind":       llx.StringData(entry.Kind),
			"bootable":   llx.BoolData(entry.Bootable),
			"kernel":     llx.StringData(entry.Kernel),
			"cmdline":    llx.StringData(entry.Cmdline),
			"parameters": llx.MapData(convert.MapToInterfaceMap(entry.Parameters), types.String),
			"flags":      llx.ArrayData(convert.SliceAnyToInterface(entry.Flags), types.String),
			"source":     llx.StringData(entry.Source),
			"initrd":     llx.StringData(entry.Initrd),
			"isSubmenu":  llx.BoolData(entry.IsSubmenu),
		})
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

func (g *mqlGrubConfig) passwordProtected() (bool, error) {
	if err := g.fetchGrubCfg(); err != nil {
		return false, err
	}
	if !g.cachedGrubFound {
		// No grub.cfg exists in any known location, so the host either boots
		// with a different bootloader or keeps its configuration somewhere we
		// cannot see. Reporting false there would read as "GRUB is installed
		// and has no password", which is a finding we have not made.
		g.PasswordProtected.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return g.cachedPwProtected, nil
}

func (e *mqlGrubConfigEntry) id() (string, error) {
	return e.MqlID(), nil
}

// ParseGrubDefaults parses /etc/default/grub which is a shell-style key=value file.
func ParseGrubDefaults(r io.Reader) (map[string]string, error) {
	params := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip comments and empty lines
		if line == "" || line[0] == '#' {
			continue
		}
		// Parse KEY=VALUE (shell-style, with optional quoting)
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		// Strip surrounding quotes
		value = stripQuotes(value)
		params[key] = value
	}
	return params, scanner.Err()
}

// stripQuotes removes surrounding single or double quotes from a string.
func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

var (
	reMenuEntry = regexp.MustCompile(`^\s*menuentry\s+['"]([^'"]+)['"]`)
	reSubmenu   = regexp.MustCompile(`^\s*submenu\s+['"]([^'"]+)['"]`)
	reLinux     = regexp.MustCompile(`^\s*(?:linux|linux16|linuxefi)\s+(.+)`)
	reInitrd    = regexp.MustCompile(`^\s*(?:initrd|initrd16|initrdefi)\s+(.+)`)
	reClass     = regexp.MustCompile(`--class\s+(\S+)`)

	// reBlscfg matches the command that hands the menu over to the Boot Loader
	// Specification entry files.
	reBlscfg = regexp.MustCompile(`(?m)^\s*blscfg\s*$`)

	// A GRUB legacy menu introduces each entry with a title line and names the
	// kernel with `kernel`, where GRUB 2 writes `menuentry` and `linux`.
	reLegacyTitle    = regexp.MustCompile(`^\s*title\s+(.*)$`)
	reLegacyKernel   = regexp.MustCompile(`^\s*kernel\s+(.+)$`)
	reLegacyInitrd   = regexp.MustCompile(`^\s*initrd\s+(.+)$`)
	reAnyLegacyTitle = regexp.MustCompile(`(?m)^\s*title\s+\S`)

	// A stub grub.cfg chains to the real configuration instead of declaring
	// any entries of its own.
	reConfigfile   = regexp.MustCompile(`(?m)^\s*configfile\s`)
	reAnyMenuEntry = regexp.MustCompile(`(?m)^\s*(?:menuentry|submenu)\s+['"]`)
	reAnyLinux     = regexp.MustCompile(`(?m)^\s*(?:linux|linux16|linuxefi)\s`)
)

// isGrubLegacyCfg reports whether content is a GRUB legacy menu rather than a
// GRUB 2 configuration. The decision is made from the file itself rather than
// from the path it was found at, because the Red Hat family shipped the legacy
// menu under a name that GRUB 2 also uses on other distributions.
//
// Declaring an entry with `title` is what separates the two formats: GRUB 2
// writes `menuentry`, and none of the 43 grub.cfg files in testdata/grub, which
// cover 22 hosts across every layout the provider meets, contains a line
// beginning with `title`. TestGrubCfgCorpusIsNotLegacy holds that.
func isGrubLegacyCfg(content []byte) bool {
	return reAnyLegacyTitle.Match(content)
}

// ParseGrubLegacyEntries parses a GRUB legacy menu. An entry opens with a
// title line and runs to the next one, so there is no nesting to track and no
// submenus to separate. `kernel` carries the image and its arguments on one
// line, exactly as a GRUB 2 `linux` line does, which is why the split into
// kernel and arguments is left to finalizeEntries. An entry that boots another
// loader with `chainloader`, which is how a legacy menu offers Windows, names
// no kernel and is classified as booting no operating system.
func ParseGrubLegacyEntries(r io.Reader) ([]BootEntry, error) {
	var entries []BootEntry
	var current *BootEntry

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}

		if m := reLegacyTitle.FindStringSubmatch(line); m != nil {
			if current != nil {
				entries = append(entries, *current)
			}
			current = &BootEntry{Title: strings.TrimSpace(m[1])}
			continue
		}
		if current == nil {
			// Menu-level settings such as default, timeout and password
			// precede the first entry and belong to no entry.
			continue
		}

		if m := reLegacyKernel.FindStringSubmatch(line); m != nil {
			current.Cmdline = strings.TrimSpace(m[1])
			continue
		}
		if m := reLegacyInitrd.FindStringSubmatch(line); m != nil {
			current.Initrd = strings.TrimSpace(m[1])
		}
	}
	if current != nil {
		entries = append(entries, *current)
	}

	return entries, scanner.Err()
}

// isGrubCfgStub reports whether a grub.cfg only points at another
// configuration file. Booting from the EFI system partition commonly installs
// one of these beside the real configuration under /boot.
func isGrubCfgStub(content []byte) bool {
	if !reConfigfile.Match(content) {
		return false
	}
	return !reAnyMenuEntry.Match(content) && !reAnyLinux.Match(content) && !reBlscfg.Match(content)
}

// ParseGrubEnv parses a GRUB environment block. The file is a fixed 1024 bytes
// padded to the end with '#', which the comment rule discards along with the
// header line.
func ParseGrubEnv(r io.Reader) (map[string]string, error) {
	vars := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		vars[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return vars, scanner.Err()
}

// readGrubEnv returns the GRUB environment variables, or an empty map when no
// environment block is readable.
func readGrubEnv(fs afero.Fs) map[string]string {
	for _, path := range grubEnvPaths {
		f, err := fs.Open(path)
		if err != nil {
			continue
		}
		vars, err := ParseGrubEnv(f)
		f.Close()
		if err == nil && len(vars) > 0 {
			return vars
		}
	}
	return map[string]string{}
}

// LoadGrubEntries returns the entries the bootloader offers on the next boot,
// reading whichever source it takes them from. content is the grub.cfg at
// cfgPath, which may be empty when the host has none.
func LoadGrubEntries(fs afero.Fs, cfgPath string, content []byte) ([]BootEntry, error) {
	vars := readGrubEnv(fs)

	// A grub.cfg that calls blscfg hands the menu over to the entry files, so
	// whatever menu entries it declares itself do not boot.
	if cfgPath == "" || reBlscfg.Match(content) {
		return readBLSEntries(fs, blsEntriesDir, vars)
	}

	var entries []BootEntry
	var err error
	if isGrubLegacyCfg(content) {
		entries, err = ParseGrubLegacyEntries(bytes.NewReader(content))
	} else {
		entries, err = ParseGrubCfgEntries(bytes.NewReader(content))
	}
	if err != nil {
		return nil, err
	}
	finalizeEntries(entries, cfgPath, vars)
	return entries, nil
}

// menuEntryClasses returns the --class values declared on a menuentry line.
func menuEntryClasses(line string) []string {
	matches := reClass.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return nil
	}
	classes := make([]string, 0, len(matches))
	for _, m := range matches {
		classes = append(classes, m[1])
	}
	return classes
}

// ParseGrubCfgEntries parses grub.cfg for menuentry and submenu blocks.
func ParseGrubCfgEntries(r io.Reader) ([]BootEntry, error) {
	var entries []BootEntry
	var current *BootEntry
	depth := 0
	// opened tracks whether the current entry's opening brace has been seen.
	// GRUB allows the `{` on a line after `menuentry`, so until it appears we
	// must not treat depth <= 0 as the entry having closed.
	opened := false

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		if m := reMenuEntry.FindStringSubmatch(line); m != nil {
			// Flush any in-progress entry that was never closed
			if current != nil {
				entries = append(entries, *current)
			}
			current = &BootEntry{Title: m[1], Classes: menuEntryClasses(line)}
			depth = 0
			opened = false
			if strings.Contains(line, "{") {
				depth = 1
				opened = true
			}
			continue
		}

		if m := reSubmenu.FindStringSubmatch(line); m != nil {
			// Flush any in-progress entry that was never closed
			if current != nil {
				entries = append(entries, *current)
				current = nil
			}
			entries = append(entries, BootEntry{Title: m[1], IsSubmenu: true})
			depth = 0
			if strings.Contains(line, "{") {
				depth = 1
			}
			continue
		}

		// Skip comment lines for brace counting to avoid false matches
		// from braces inside comments (e.g., "# echo {something}")
		trimmed := strings.TrimSpace(line)
		isComment := len(trimmed) > 0 && trimmed[0] == '#'

		if current != nil {
			if !isComment {
				if strings.Contains(line, "{") {
					opened = true
				}
				depth += strings.Count(line, "{") - strings.Count(line, "}")
				// Only consider the entry closed once its opening brace has
				// been seen; otherwise a blank or non-brace line before the
				// `{` would prematurely flush an empty entry.
				if opened && depth <= 0 {
					entries = append(entries, *current)
					current = nil
					depth = 0
					opened = false
					continue
				}
			}

			if m := reLinux.FindStringSubmatch(line); m != nil {
				current.Cmdline = strings.TrimSpace(m[1])
			}
			if m := reInitrd.FindStringSubmatch(line); m != nil {
				current.Initrd = strings.TrimSpace(m[1])
			}
		} else if !isComment {
			// Track braces outside of menu entries (e.g., submenu closing braces)
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth < 0 {
				depth = 0
			}
		}
	}

	// If we ended mid-entry (no closing brace), still include it
	if current != nil {
		entries = append(entries, *current)
	}

	return entries, scanner.Err()
}

var (
	reSuperusers = regexp.MustCompile(`^set\s+superusers\s*=\s*(.*)$`)
	rePassword   = regexp.MustCompile(`^password(?:_pbkdf2)?\s+(.*)$`)
	// reShellVar matches an unexpanded shell variable reference, such as
	// ${GRUB2_PASSWORD} or $GRUB2_PASSWORD.
)

// GrubPasswordConfig captures what a grub.cfg states about password protection.
// The distinction that matters is whether the superuser list and the credential
// are literal values or unexpanded shell variables: every RHEL-family grub.cfg
// carries a templated `password_pbkdf2 root ${GRUB2_PASSWORD}` block emitted by
// /etc/grub.d/01_users, and on a host without a GRUB password that variable is
// never defined.
type GrubPasswordConfig struct {
	// SuperusersLiteral is true when a `set superusers=` directive assigns a
	// literal, non-empty user list.
	SuperusersLiteral bool
	// SuperusersVars holds the variable names a `set superusers=` directive
	// reads its value from.
	SuperusersVars []string
	// PasswordLiteral is true when a `password` or `password_pbkdf2` directive
	// carries a literal, non-empty credential.
	PasswordLiteral bool
	// PasswordVars holds the variable names a password directive reads its
	// credential from.
	PasswordVars []string
}

// ParseGrubPasswordConfig scans grub.cfg for superuser and password directives.
func ParseGrubPasswordConfig(content []byte) GrubPasswordConfig {
	var cfg GrubPasswordConfig

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		if m := reSuperusers.FindStringSubmatch(line); m != nil {
			value := stripQuotes(strings.TrimSpace(m[1]))
			if vars := shellVarNames(value); len(vars) > 0 {
				cfg.SuperusersVars = append(cfg.SuperusersVars, vars...)
			} else if value != "" {
				cfg.SuperusersLiteral = true
			}
			continue
		}

		if m := rePassword.FindStringSubmatch(line); m != nil {
			// `password <user> <cleartext>` and
			// `password_pbkdf2 <user> <hash>` both carry the credential as the
			// second argument. Anything shorter states no credential at all.
			fields := strings.Fields(m[1])
			if len(fields) < 2 {
				continue
			}
			credential := stripQuotes(fields[1])
			if vars := shellVarNames(credential); len(vars) > 0 {
				cfg.PasswordVars = append(cfg.PasswordVars, vars...)
			} else if credential != "" {
				cfg.PasswordLiteral = true
			}
		}
	}

	return cfg
}

// Protected reports whether grub.cfg on its own proves a password is set, which
// requires a literal superuser list and a literal credential.
func (c GrubPasswordConfig) Protected() bool {
	return c.SuperusersLiteral && c.PasswordLiteral
}

// ReferencesVars reports whether any directive takes its value from a shell
// variable that grub.cfg does not define, in which case the credential has to be
// resolved from user.cfg before the config can be judged.
func (c GrubPasswordConfig) ReferencesVars() bool {
	return len(c.SuperusersVars) > 0 || len(c.PasswordVars) > 0
}

// ProtectedWith reports whether the config is password protected once the
// variables it references are resolved from the given assignments, typically the
// contents of ${prefix}/user.cfg.
func (c GrubPasswordConfig) ProtectedWith(vars map[string]string) bool {
	superusers := c.SuperusersLiteral || anyVarSet(c.SuperusersVars, vars)
	password := c.PasswordLiteral || anyVarSet(c.PasswordVars, vars)
	return superusers && password
}

// anyVarSet reports whether any of the named variables has a non-empty value.
func anyVarSet(names []string, vars map[string]string) bool {
	for _, name := range names {
		if strings.TrimSpace(vars[name]) != "" {
			return true
		}
	}
	return false
}

// shellVarNames returns the names of every unexpanded shell variable in value.
func shellVarNames(value string) []string {
	matches := reShellVar.FindAllStringSubmatch(value, -1)
	if matches == nil {
		return nil
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		if m[1] != "" {
			names = append(names, m[1])
		} else if m[2] != "" {
			names = append(names, m[2])
		}
	}
	return names
}

// ParseGrubPasswordProtected checks grub.cfg content for password protection.
// GRUB password protection requires both a `set superusers=` directive and a
// `password` or `password_pbkdf2` directive, and both have to carry literal
// values. A credential that is still an unexpanded shell variable, as in the
// `password_pbkdf2 root ${GRUB2_PASSWORD}` block that /etc/grub.d/01_users emits
// on every RHEL-family host, is a template rather than a password.
func ParseGrubPasswordProtected(content []byte) bool {
	return ParseGrubPasswordConfig(content).Protected()
}

// ParseGrubLegacyPasswordProtected reports whether a GRUB legacy menu requires
// a password before its boot parameters can be changed. GRUB 0.97 has no
// superusers list and no separate password file: a single menu-level
// `password` directive gates the interactive command line and the editing of
// any entry, and is what a `lock` line on an individual entry defers to.
//
//	password --md5 $1$salt$hash
//	password --encrypted $6$salt$hash
//	password cleartext
//
// The directive is only meaningful before the first entry, which is where GRUB
// reads it, so a `password` line inside an entry body is not counted. The
// credential is taken literally: unlike a GRUB 2 configuration, a legacy menu
// is written by hand rather than generated, so there is no templated variable
// to resolve, and an MD5 crypt hash begins with the `$` that a variable would.
func ParseGrubLegacyPasswordProtected(content []byte) bool {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if reLegacyTitle.MatchString(line) {
			// Past the menu-level section.
			return false
		}

		fields := strings.Fields(line)
		if fields[0] != "password" {
			continue
		}
		// Skip the option flags that say how the credential is encoded. A
		// directive carrying nothing but flags, or nothing at all, names no
		// credential and protects nothing, so it falls through to the next
		// line rather than counting.
		for _, field := range fields[1:] {
			if strings.HasPrefix(field, "--") {
				continue
			}
			return true
		}
	}
	return false
}

// readGrubUserCfg reads user.cfg next to grub.cfg. That is the ${prefix}/user.cfg
// the 01_users block sources, and where grub2-setpassword stores GRUB2_PASSWORD
// on RHEL-family systems. A missing or unreadable file is the normal case and
// returns a nil map rather than an error.
func readGrubUserCfg(fs afero.Fs, grubCfgPath string) map[string]string {
	if grubCfgPath == "" {
		return nil
	}

	f, err := fs.Open(path.Join(path.Dir(grubCfgPath), "user.cfg"))
	if err != nil {
		return nil
	}
	defer f.Close()

	vars, err := ParseGrubDefaults(f)
	if err != nil {
		return nil
	}
	return vars
}

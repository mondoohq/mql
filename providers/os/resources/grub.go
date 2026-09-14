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
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
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

type mqlGrubConfigInternal struct {
	lock              sync.Mutex
	fetched           bool
	cachedGrubFound   bool
	cachedEntries     []GrubEntry
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
			args["grubPath"] = llx.StringData(findExistingPath(fs, grubCfgPaths))
		}
	} else {
		args["grubPath"] = llx.StringData(findExistingPath(fs, grubCfgPaths))
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

	cfgPath := g.GetGrubPath().Data
	if cfgPath == "" {
		g.fetched = true
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

	f, err := fs.Open(cfgPath)
	if err != nil {
		return err
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	entries, err := ParseGrubCfgEntries(strings.NewReader(string(content)))
	if err != nil {
		return err
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

	resources := make([]any, 0, len(g.cachedEntries))
	for _, entry := range g.cachedEntries {
		entryID := "grub.config.entry:" + entry.Title + ":" + entry.Cmdline
		resource, err := CreateResource(g.MqlRuntime, "grub.config.entry", map[string]*llx.RawData{
			"__id":      llx.StringData(entryID),
			"title":     llx.StringData(entry.Title),
			"cmdline":   llx.StringData(entry.Cmdline),
			"initrd":    llx.StringData(entry.Initrd),
			"isSubmenu": llx.BoolData(entry.IsSubmenu),
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

// GrubEntry represents a parsed GRUB menu entry.
type GrubEntry struct {
	Title     string
	Cmdline   string
	Initrd    string
	IsSubmenu bool
}

var (
	reMenuEntry = regexp.MustCompile(`^\s*menuentry\s+['"]([^'"]+)['"]`)
	reSubmenu   = regexp.MustCompile(`^\s*submenu\s+['"]([^'"]+)['"]`)
	reLinux     = regexp.MustCompile(`^\s*(?:linux|linux16|linuxefi)\s+(.+)`)
	reInitrd    = regexp.MustCompile(`^\s*(?:initrd|initrd16|initrdefi)\s+(.+)`)
)

// ParseGrubCfgEntries parses grub.cfg for menuentry and submenu blocks.
func ParseGrubCfgEntries(r io.Reader) ([]GrubEntry, error) {
	var entries []GrubEntry
	var current *GrubEntry
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
			current = &GrubEntry{Title: m[1]}
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
			entries = append(entries, GrubEntry{Title: m[1], IsSubmenu: true})
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
	reShellVar = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
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

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/json"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// PHP, Apache httpd, MariaDB/MySQL and OpenSSL are often on a Windows host
// without an Add/Remove Programs entry of their own: bundled in XAMPP,
// WampServer or Laragon, or unzipped from php.net. The bundle's entry
// ("XAMPP 7.3.2-0") says nothing about the versions of its parts, so
// vulnerability matching never sees PHP 7.3.2 or Apache 2.4.38.
//
// This file finds the component executables on disk and reports each as its
// own windows/app package, with the version from the executable's PE version
// resource (never from a readme or properties file: XAMPP's readme lists
// OpenSSL 1.0.2j next to a binary that is 1.1.1a).
//
// Where it looks, never recursively:
//  1. fixed sub-layouts inside the install directory of every other app
//     package (XAMPP, WampServer, Laragon),
//  2. the machine PATH and every profile's PATH,
//  3. the directories of service executables,
//  4. C:\php, C:\tools\php* and the scoop php app of each profile.

// bundledComponentLayouts are the directories, relative to the install
// directory of a bundle, that can hold a component. A "*" segment matches one
// directory level, case-insensitively.
var bundledComponentLayouts = [][]string{
	// XAMPP
	{"php"},
	{"apache", "bin"},
	{"mysql", "bin"},
	// WampServer
	{"bin", "php", "php*"},
	{"bin", "apache", "apache*", "bin"},
	{"bin", "mariadb", "mariadb*", "bin"},
	{"bin", "mysql", "mysql*", "bin"},
	// Laragon
	{"bin", "php", "*"},
	{"bin", "apache", "*", "bin"},
	{"bin", "mysql", "*", "bin"},
}

const (
	bundledGlobLimit    = 64
	bundledPackageLimit = 512
)

// componentHints are the directories the machine itself points at.
type componentHints struct {
	// MachinePath is the machine PATH, as stored (a ";" separated list).
	MachinePath string
	// Services are the ImagePath values of the registered services.
	Services []string
	// Profiles are the user profiles with the raw (unexpanded) user PATH,
	// which is empty when the user's hive is not available.
	Profiles []componentProfile
}

type componentProfile struct {
	Dir  string
	Path string
}

var winPercentVar = regexp.MustCompile(`%([^%]+)%`)

// expandComponentEnv expands the %VAR% references a PATH or ImagePath holds.
// Machine-wide variables resolve to their default values, %USERPROFILE% to
// the profile the value belongs to. Anything else stays and is rejected later
// by normalizeWindowsDir.
func expandComponentEnv(s, profile string) string {
	return winPercentVar.ReplaceAllStringFunc(s, func(m string) string {
		switch strings.ToLower(m[1 : len(m)-1]) {
		case "systemdrive":
			return "C:"
		case "systemroot", "windir":
			return `C:\Windows`
		case "programfiles", "programw6432":
			return `C:\Program Files`
		case "programfiles(x86)":
			return `C:\Program Files (x86)`
		case "programdata", "allusersprofile":
			return `C:\ProgramData`
		case "userprofile":
			if profile != "" {
				return profile
			}
		}
		return m
	})
}

// cleanComponentDir returns p as a usable absolute directory with its case
// kept, or "" when it is not one, still holds a %VAR%, or is a broad root
// (see normalizeWindowsDir) that many products live under.
func cleanComponentDir(p string) string {
	p = strings.TrimSpace(strings.Trim(strings.TrimSpace(p), `"`))
	if p == "" || normalizeWindowsDir(p, nil) == "" {
		return ""
	}
	p = strings.ReplaceAll(p, "/", `\`)
	unc := strings.HasPrefix(p, `\\`)
	body := strings.TrimLeft(p, `\`)
	for strings.Contains(body, `\\`) {
		body = strings.ReplaceAll(body, `\\`, `\`)
	}
	body = strings.TrimRight(body, `\ `)
	if unc {
		return `\\` + body
	}
	return body
}

// candidateDirs returns the directories the hints and the fixed folders name,
// each to be checked directly.
func (h componentHints) candidateDirs() []string {
	var out []string
	add := func(p string) {
		if d := cleanComponentDir(p); d != "" {
			out = append(out, d)
		}
	}
	for _, e := range strings.Split(expandComponentEnv(h.MachinePath, ""), ";") {
		add(e)
	}
	for _, s := range h.Services {
		if exe := executableFromCommand(expandComponentEnv(s, "")); exe != "" {
			add(parentDir(exe))
		}
	}
	for _, p := range h.Profiles {
		for _, e := range strings.Split(expandComponentEnv(p.Path, p.Dir), ";") {
			add(e)
		}
	}
	return out
}

// componentFinder reads a filesystem for component executables.
type componentFinder struct {
	fs       afero.Fs
	toFsPath func(string) (string, bool)
	listed   map[string]map[string]string // lower-cased dir -> lower-cased file -> real name
	subdirs  map[string][]string
}

// list returns the files of a directory by lower-cased name, nil when it
// can't be read. Windows names are case-insensitive, an image mounted on a
// POSIX scanner is not.
func (c *componentFinder) list(dir string) map[string]string {
	key := strings.ToLower(dir)
	if m, ok := c.listed[key]; ok {
		return m
	}
	files, dirs := c.readEntries(dir)
	c.listed[key] = files
	c.subdirs[key] = dirs
	return files
}

func (c *componentFinder) readEntries(dir string) (files map[string]string, dirs []string) {
	fp, ok := c.toFsPath(dir)
	if !ok {
		return nil, nil
	}
	infos, err := afero.ReadDir(c.fs, fp)
	if err != nil {
		return nil, nil
	}
	files = map[string]string{}
	for _, fi := range infos {
		if fi.IsDir() {
			dirs = append(dirs, fi.Name())
		} else {
			files[strings.ToLower(fi.Name())] = fi.Name()
		}
	}
	sort.Strings(dirs)
	return files, dirs
}

// childDirs returns the subdirectories of dir whose name matches the glob
// pattern, case-insensitively, up to bundledGlobLimit.
func (c *componentFinder) childDirs(dir, pattern string) []string {
	c.list(dir)
	var out []string
	for _, d := range c.subdirs[strings.ToLower(dir)] {
		if ok, _ := path.Match(strings.ToLower(pattern), strings.ToLower(d)); ok {
			out = append(out, dir+`\`+d)
			if len(out) >= bundledGlobLimit {
				break
			}
		}
	}
	return out
}

// expand resolves a layout below base into the directories it names.
func (c *componentFinder) expand(base string, segments []string) []string {
	dirs := []string{base}
	for _, seg := range segments {
		var next []string
		for _, d := range dirs {
			if strings.ContainsAny(seg, "*?[") {
				next = append(next, c.childDirs(d, seg)...)
			} else {
				next = append(next, d+`\`+seg)
			}
		}
		dirs = next
	}
	return dirs
}

func (c *componentFinder) info(dir, name string) (peInfo, bool) {
	fp, ok := c.toFsPath(dir + `\` + name)
	if !ok {
		return peInfo{}, false
	}
	return fsPEVersion(c.fs, fp, peVersionInfo)
}

// component is one find, before it becomes a package.
type component struct {
	name, vendor, version, arch, dir string
}

var (
	phpCoreDLL     = regexp.MustCompile(`^php\d*(?:ts)?\.dll$`)
	opensslLibName = regexp.MustCompile(`^(?:libssl[^\\/]*|ssleay32)\.dll$`)
)

func versionToken(info peInfo) string {
	v := info.ProductVersion
	if v == "" {
		v = formatWindowsVersion(info.File)
	}
	if f := strings.Fields(v); len(f) > 0 {
		return f[0]
	}
	return ""
}

func majorVersion(v string) int {
	digits := v
	if i := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		digits = v[:i]
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return -1
	}
	return n
}

// minorVersion returns the second number of a dotted version, -1 if it has none.
func minorVersion(v string) int {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return -1
	}
	return majorVersion(parts[1])
}

// mysqlFlavor decides between MariaDB and MySQL for a server executable.
// MariaDB started at 10.0 after 5.5 while MySQL went from 5.7 to 8.0, so the
// major version tells them apart when the resource carries no name. Returns
// "" for a version that fits neither (5.5 with no name).
func mysqlFlavor(productName, version string, hasMariadbd bool) string {
	name := strings.ToLower(productName)
	switch {
	case strings.Contains(name, "mariadb"):
		return "MariaDB"
	case strings.Contains(name, "mysql"):
		return "MySQL Server"
	case hasMariadbd:
		return "MariaDB"
	}
	switch major := majorVersion(version); {
	case major >= 10:
		return "MariaDB"
	case major == 8 || major == 9:
		return "MySQL Server"
	case major == 5 && minorVersion(version) >= 6:
		// MariaDB's 5.x series ended at 5.5; MySQL's 5.6 and 5.7 follow.
		return "MySQL Server"
	}
	return ""
}

// componentsIn returns the components whose executables are in dir.
func (c *componentFinder) componentsIn(dir string) []component {
	files := c.list(dir)
	if len(files) == 0 {
		return nil
	}
	var out []component

	// PHP: php.exe and its core DLL, so a stray php.exe stub is not one.
	if exe, ok := files["php.exe"]; ok {
		hasCore := false
		for lower := range files {
			if phpCoreDLL.MatchString(lower) {
				hasCore = true
				break
			}
		}
		if info, ok := c.info(dir, exe); ok && hasCore && strings.EqualFold(info.ProductName, "PHP") {
			if v := versionToken(info); v != "" {
				out = append(out, component{"PHP", "The PHP Group", v, info.Machine, dir})
			}
		}
	}

	if exe, ok := files["httpd.exe"]; ok {
		if info, ok := c.info(dir, exe); ok && strings.EqualFold(info.ProductName, "Apache HTTP Server") {
			if v := versionToken(info); v != "" {
				out = append(out, component{"Apache HTTP Server", "Apache Software Foundation", v, info.Machine, dir})
			}
		}
	}

	_, hasMariadbd := files["mariadbd.exe"]
	exe, ok := files["mariadbd.exe"]
	if !ok {
		exe, ok = files["mysqld.exe"]
	}
	if ok {
		if info, ok := c.info(dir, exe); ok {
			if v := versionToken(info); v != "" {
				switch mysqlFlavor(info.ProductName, v, hasMariadbd) {
				case "MariaDB":
					out = append(out, component{"MariaDB", "MariaDB", v, info.Machine, dir})
				case "MySQL Server":
					out = append(out, component{"MySQL Server", "Oracle Corporation", v, info.Machine, dir})
				}
			}
		}
	}

	// OpenSSL: once per directory, from the first matching library.
	var libs []string
	for lower := range files {
		if opensslLibName.MatchString(lower) {
			libs = append(libs, lower)
		}
	}
	sort.Strings(libs)
	for _, lower := range libs {
		info, ok := c.info(dir, files[lower])
		if !ok || !strings.Contains(strings.ToLower(info.ProductName), "openssl") {
			continue
		}
		if v := versionToken(info); v != "" {
			out = append(out, component{"OpenSSL", "The OpenSSL Project", v, info.Machine, dir})
			break
		}
	}
	return out
}

// containsDir reports whether outer is dir or one of its parents.
func containsDir(outer, dir string) bool {
	o, d := strings.ToLower(outer), strings.ToLower(dir)
	return o == d || strings.HasPrefix(d, o+`\`)
}

// bundleDir is the install directory of an app package.
type bundleDir struct {
	name, dir string
}

// appInstallDirs returns the usable install directories of the windows/app
// packages. A package without files, or whose directory is a broad root such
// as Program Files, has none.
func appInstallDirs(pkgs []Package) []bundleDir {
	var out []bundleDir
	for i := range pkgs {
		p := &pkgs[i]
		if p.Format != "windows/app" || len(p.Files) == 0 {
			continue
		}
		if d := cleanComponentDir(p.Files[0].Path); d != "" {
			out = append(out, bundleDir{p.Name, d})
		}
		if len(out) >= bundledPackageLimit {
			break
		}
	}
	return out
}

// findBundledComponents returns a package for each PHP, Apache, MariaDB/MySQL
// and OpenSSL install found next to or inside the given packages, on the
// PATH, behind a service, or in a fixed folder. A candidate is skipped when
// an existing package already covers it: one whose install directory equals
// or contains the component's and whose name holds the component's name.
func findBundledComponents(fs afero.Fs, toFsPath func(string) (string, bool), pkgs []Package, hints componentHints, platform *inventory.Platform) []Package {
	if fs == nil {
		return nil
	}
	c := &componentFinder{fs: fs, toFsPath: toFsPath, listed: map[string]map[string]string{}, subdirs: map[string][]string{}}
	bundles := appInstallDirs(pkgs)

	var candidates []string
	seen := map[string]bool{}
	add := func(d string) {
		if k := strings.ToLower(d); d != "" && !seen[k] {
			seen[k] = true
			candidates = append(candidates, d)
		}
	}
	for _, b := range bundles {
		for _, layout := range bundledComponentLayouts {
			for _, d := range c.expand(b.dir, layout) {
				add(d)
			}
		}
	}
	for _, d := range hints.candidateDirs() {
		add(d)
	}
	add(`C:\php`)
	for _, d := range c.childDirs(`C:\tools`, "php*") {
		add(d)
	}
	for _, p := range hints.Profiles {
		apps := strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(p.Dir), "/", `\`), `\`) + `\scoop\apps\php`
		if normalizeWindowsDir(apps, nil) == "" {
			continue
		}
		versions := c.childDirs(apps, "*")
		for _, d := range versions {
			// "current" is a junction to a versioned directory.
			if len(versions) > 1 && strings.EqualFold(path.Base(strings.ReplaceAll(d, `\`, "/")), "current") {
				continue
			}
			add(d)
		}
	}

	var found []Package
	for _, dir := range candidates {
		for _, comp := range c.componentsIn(dir) {
			if coveredByPackage(pkgs, comp) {
				log.Debug().Str("component", comp.name).Str("dir", comp.dir).Msg("component already covered by a package")
				continue
			}
			if addComponentLocation(found, comp) {
				continue
			}
			pkg := createPackage(comp.name, comp.version, "windows/app", comp.arch, comp.vendor, comp.dir, platform)
			pkg.InstallScope = installScopeMachine
			pkg.Origin = originOf(bundles, comp.dir)
			found = append(found, *pkg)
			log.Debug().Str("component", comp.name).Str("version", comp.version).Str("dir", comp.dir).Msg("found bundled component")
		}
	}
	return found
}

// coveredByPackage reports whether a package of the component's name already
// lives in the component's directory or a parent of it.
func coveredByPackage(pkgs []Package, comp component) bool {
	needle := strings.ToLower(comp.name)
	for i := range pkgs {
		p := &pkgs[i]
		if p.Format != "windows/app" || len(p.Files) == 0 || !strings.Contains(strings.ToLower(p.Name), needle) {
			continue
		}
		if d := cleanComponentDir(p.Files[0].Path); d != "" && containsDir(d, comp.dir) {
			return true
		}
	}
	return false
}

// addComponentLocation adds comp's directory to the file list of an already
// found package of the same name, version and architecture. Packages with that
// identity are one row in the package list, so a second copy is evidence of
// the first.
func addComponentLocation(found []Package, comp component) bool {
	for i := range found {
		p := &found[i]
		if p.Name == comp.name && p.Version == comp.version && p.Arch == comp.arch {
			p.Files = append(p.Files, FileRecord{Path: comp.dir})
			return true
		}
	}
	return false
}

// originOf returns the name of the package whose install directory holds dir,
// the innermost one when several do.
func originOf(bundles []bundleDir, dir string) string {
	best := -1
	origin := ""
	for _, b := range bundles {
		if containsDir(b.dir, dir) && len(b.dir) > best {
			best, origin = len(b.dir), b.name
		}
	}
	return origin
}

// bundledComponents adds the components the machine's files show. Nothing in
// here fails the package list: a source that can't be read is skipped.
func (w *WinPkgManager) bundledComponents(pkgs []Package) []Package {
	toFs := nativeWindowsPath
	var hints componentHints
	switch {
	case w.conn.Type() == shared.Type_FileSystem || w.conn.Type() == shared.Type_Device:
		toFs = mountedSystemDrivePath
		hints = w.offlineComponentHints()
	case w.conn.Capabilities().Has(shared.Capability_RunCommand):
		hints = w.remoteComponentHints()
	default:
		log.Debug().Msg("cannot read PATH and services of the target, probing install directories and fixed folders only")
	}
	return findBundledComponents(w.conn.FileSystem(), toFs, pkgs, hints, w.platform)
}

// componentHintsScript prints the machine PATH, the service ImagePaths and
// the profiles with the raw PATH of every loaded user hive as JSON. The raw
// user value lets the caller resolve %USERPROFILE% against the right profile.
const componentHintsScript = `
$ErrorActionPreference = 'SilentlyContinue'
$skip = @{ 'S-1-5-18' = $true; 'S-1-5-19' = $true; 'S-1-5-20' = $true }
$machinePath = ''
try { $machinePath = [string](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').Path } catch {}
$services = @()
try { $services = @(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\*' -Name ImagePath | ForEach-Object { [string]$_.ImagePath }) } catch {}
$profiles = @()
try {
    foreach ($k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList') {
        $sid = $k.PSChildName
        if ($skip.ContainsKey($sid)) { continue }
        $dir = [string]$k.GetValue('ProfileImagePath')
        if (-not $dir) { continue }
        $p = ''
        if (Test-Path -LiteralPath "Registry::HKEY_USERS\$sid\Environment") {
            try { $p = [string](Get-Item -LiteralPath "Registry::HKEY_USERS\$sid\Environment").GetValue('Path', '', 'DoNotExpandEnvironmentNames') } catch {}
        }
        $profiles += [pscustomobject]@{ Dir = $dir; Path = $p }
    }
} catch {}
[pscustomobject]@{ MachinePath = $machinePath; Services = $services; Profiles = $profiles } | ConvertTo-Json -Compress -Depth 4
`

// psList reads a JSON value that Windows PowerShell 5.1 writes as an array,
// a single element, null or {}.
type psList[T any] []T

func (l *psList[T]) UnmarshalJSON(data []byte) error {
	*l = nil
	s := strings.TrimSpace(string(data))
	switch {
	case s == "" || s == "null" || s == "{}":
		return nil
	case strings.HasPrefix(s, "["):
		return json.Unmarshal(data, (*[]T)(l))
	}
	var one T
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*l = psList[T]{one}
	return nil
}

// parseComponentHints reads componentHintsScript's output.
func parseComponentHints(r io.Reader) (componentHints, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return componentHints{}, err
	}
	var raw struct {
		MachinePath psOptionalString
		Services    psList[string]
		Profiles    psList[struct {
			Dir  string
			Path psOptionalString
		}]
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return componentHints{}, err
	}
	h := componentHints{Services: raw.Services}
	if raw.MachinePath.v != nil {
		h.MachinePath = *raw.MachinePath.v
	}
	for _, p := range raw.Profiles {
		cp := componentProfile{Dir: p.Dir}
		if p.Path.v != nil {
			cp.Path = *p.Path.v
		}
		h.Profiles = append(h.Profiles, cp)
	}
	return h, nil
}

// remoteComponentHints reads the hints with one PowerShell run over the
// active connection; local scans on Windows take the same route.
func (w *WinPkgManager) remoteComponentHints() componentHints {
	cmd, err := w.conn.RunCommand(powershell.Encode(componentHintsScript))
	if err != nil || cmd.ExitStatus != 0 {
		log.Debug().Err(err).Msg("could not read PATH and services of the target")
		return componentHints{}
	}
	h, err := parseComponentHints(cmd.Stdout)
	if err != nil {
		log.Debug().Err(err).Msg("could not parse PATH and services of the target")
		return componentHints{}
	}
	return h
}

// componentRegistry is the subset of *registry.RegistryHandler the offline
// hints need.
type componentRegistry interface {
	GetNativeRegistryKeyItems(registryId, path string) ([]registry.RegistryKeyItem, error)
	GetNativeRegistryKeyChildren(registryId, path string) ([]registry.RegistryKeyChild, error)
	LoadUserHive(sid, filepath string) error
	GetUserHiveKeyItems(sid, path string) ([]registry.RegistryKeyItem, error)
}

func itemString(items []registry.RegistryKeyItem, key string) string {
	for _, i := range items {
		if strings.EqualFold(i.Key, key) {
			return i.Value.String
		}
	}
	return ""
}

// offlineComponentHints reads the same hints from the SYSTEM and SOFTWARE
// hives of a mounted volume, which must be loaded into reg already, and from
// each profile's NTUSER.DAT. userHivePath maps a profile directory to the
// path of its NTUSER.DAT on the connection. Each part that can't be read is
// left out.
func offlineComponentHints(reg componentRegistry, userHivePath func(profileDir string) (string, bool)) componentHints {
	var h componentHints

	// The control set the machine booted from.
	controlSet := "ControlSet001"
	if items, err := reg.GetNativeRegistryKeyItems(registry.System, "Select"); err == nil {
		for _, i := range items {
			if strings.EqualFold(i.Key, "Current") && i.Value.Number > 0 {
				controlSet = "ControlSet" + leftPad3(i.Value.Number)
			}
		}
	}
	if items, err := reg.GetNativeRegistryKeyItems(registry.System, controlSet+`\Control\Session Manager\Environment`); err == nil {
		h.MachinePath = itemString(items, "Path")
	} else {
		log.Debug().Err(err).Msg("could not read the machine PATH from the SYSTEM hive")
	}
	if children, err := reg.GetNativeRegistryKeyChildren(registry.System, controlSet+`\Services`); err == nil {
		for _, ch := range children {
			items, err := reg.GetNativeRegistryKeyItems(registry.System, controlSet+`\Services\`+ch.Name)
			if err != nil {
				continue
			}
			if img := itemString(items, "ImagePath"); img != "" {
				h.Services = append(h.Services, img)
			}
		}
	} else {
		log.Debug().Err(err).Msg("could not read the services from the SYSTEM hive")
	}

	children, err := reg.GetNativeRegistryKeyChildren(registry.Software, `Microsoft\Windows NT\CurrentVersion\ProfileList`)
	if err != nil {
		log.Debug().Err(err).Msg("could not read the profile list from the SOFTWARE hive")
		return h
	}
	for _, ch := range children {
		if isWellKnownSystemSID(ch.Name) || !isValidSID(ch.Name) {
			continue
		}
		items, err := reg.GetNativeRegistryKeyItems(registry.Software, `Microsoft\Windows NT\CurrentVersion\ProfileList\`+ch.Name)
		if err != nil {
			continue
		}
		dir := itemString(items, "ProfileImagePath")
		if dir == "" {
			continue
		}
		dir = expandComponentEnv(dir, "")
		p := componentProfile{Dir: dir}
		if hive, ok := userHivePath(dir); ok {
			if err := reg.LoadUserHive(ch.Name, hive); err != nil {
				log.Debug().Err(err).Str("sid", ch.Name).Msg("could not load the user hive")
			} else if uitems, err := reg.GetUserHiveKeyItems(ch.Name, "Environment"); err == nil {
				p.Path = itemString(uitems, "Path")
			}
		}
		h.Profiles = append(h.Profiles, p)
	}
	return h
}

func leftPad3(n int64) string {
	s := strconv.FormatInt(n, 10)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

// offlineComponentHints loads the hives of the mounted volume and reads the
// hints from them.
func (w *WinPkgManager) offlineComponentHints() componentHints {
	rh := registry.NewRegistryHandler()
	defer func() {
		if err := rh.UnloadSubkeys(); err != nil {
			log.Debug().Err(err).Msg("could not unload registry subkeys")
		}
	}()
	for id, p := range map[string]string{registry.System: registry.SystemRegPath, registry.Software: registry.SoftwareRegPath} {
		fi, err := w.conn.FileInfo(p)
		if err != nil {
			log.Debug().Err(err).Str("hive", id).Msg("could not find registry hive file")
			return componentHints{}
		}
		if err := rh.LoadSubkey(id, fi.Path); err != nil {
			log.Debug().Err(err).Str("hive", id).Msg("could not load registry hive file")
			return componentHints{}
		}
	}
	return offlineComponentHints(rh, func(dir string) (string, bool) {
		fp, ok := mountedSystemDrivePath(dir + `\NTUSER.DAT`)
		if !ok {
			return "", false
		}
		fi, err := w.conn.FileInfo(fp)
		if err != nil {
			return "", false
		}
		return fi.Path, true
	})
}

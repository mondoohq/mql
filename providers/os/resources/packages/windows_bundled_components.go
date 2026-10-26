// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"runtime"
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
// (see normalizeWindowsDir) that many products live under. A UNC path
// (\\server\share) gives "" too: listing one waits on SMB timeouts when the
// server is unreachable, and an install there is not realistic. Every
// directory the search touches goes through here.
func cleanComponentDir(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(strings.Trim(strings.TrimSpace(p), `"`)), "/", `\`)
	if p == "" || strings.HasPrefix(p, `\\`) || normalizeWindowsDir(p, nil) == "" {
		return ""
	}
	body := p
	for strings.Contains(body, `\\`) {
		body = strings.ReplaceAll(body, `\\`, `\`)
	}
	return strings.TrimRight(body, `\ `)
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

// componentSource is where the finder reads directories and version
// resources from. A scan that can read files itself (local Windows, an
// offline image) uses the filesystem; a remote scan can't, because every
// directory listing would be a command on the target and the remote file
// handles don't support the random reads a PE parser needs, so it gets
// everything it may ask for from one PowerShell run (see
// remoteComponentSource).
type componentSource interface {
	// list returns the file and directory names in dir, ok false when dir
	// can't be read.
	list(dir string) (files, dirs []string, ok bool)
	// info returns the version resource and machine of dir\name.
	info(dir, name string) (peInfo, bool)
}

// fsComponentSource reads through a filesystem. toFsPath maps a Windows path
// to the path on fs, or reports that it can't be reached.
type fsComponentSource struct {
	fs       afero.Fs
	toFsPath func(string) (string, bool)
}

func (s fsComponentSource) list(dir string) (files, dirs []string, ok bool) {
	fp, ok := s.toFsPath(dir)
	if !ok {
		return nil, nil, false
	}
	infos, err := afero.ReadDir(s.fs, fp)
	if err != nil {
		return nil, nil, false
	}
	for _, fi := range infos {
		if fi.IsDir() {
			dirs = append(dirs, fi.Name())
		} else {
			files = append(files, fi.Name())
		}
	}
	return files, dirs, true
}

func (s fsComponentSource) info(dir, name string) (peInfo, bool) {
	fp, ok := s.toFsPath(dir + `\` + name)
	if !ok {
		return peInfo{}, false
	}
	return fsPEVersion(s.fs, fp, peVersionInfo)
}

// componentFinder finds component executables through a componentSource.
type componentFinder struct {
	src     componentSource
	listed  map[string]map[string]string // lower-cased dir -> lower-cased file -> real name
	subdirs map[string][]string
}

// list returns the files of a directory by lower-cased name, nil when it
// can't be read. Windows names are case-insensitive, an image mounted on a
// POSIX scanner is not.
func (c *componentFinder) list(dir string) map[string]string {
	key := strings.ToLower(dir)
	if m, ok := c.listed[key]; ok {
		return m
	}
	names, dirs, _ := c.src.list(dir)
	var files map[string]string
	if names != nil {
		files = make(map[string]string, len(names))
		for _, n := range names {
			files[strings.ToLower(n)] = n
		}
	}
	sort.Strings(dirs)
	c.listed[key] = files
	c.subdirs[key] = dirs
	return files
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
	return c.src.info(dir, name)
}

// component is one find, before it becomes a package. machine is the
// architecture family of its PE image ("x64", "x86", "arm64"), see
// componentArch for the package architecture.
type component struct {
	name, vendor, version, machine, dir string
	// file is the library an OpenSSL find is reported at, empty for the others
	file string
}

// location is the path the package carries as its file. OpenSSL is reported at
// its library, not its directory: it shares the directory with Apache or PHP,
// and the running-binaries owner lookup takes the longest matching install
// directory, so with equal directories OpenSSL would own httpd.exe.
func (c component) location() string {
	if c.file != "" {
		return c.file
	}
	return c.dir
}

// componentArch maps the architecture family of a PE image onto the
// architecture a Windows app package carries: the platform's own spelling for
// the host's family, "x86" for a 32-bit image, the family string otherwise. An
// unknown machine gives "", which leaves createPackage with the platform's.
func componentArch(machine string, platform *inventory.Platform) string {
	if machine == "" {
		return ""
	}
	if platform != nil && machine == windowsArchFamily(platform.Arch) {
		return platform.Arch
	}
	return machine
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
//
// 5.5 with no name is ambiguous on purpose: both MariaDB and MySQL shipped a
// 5.5, so it must not be "fixed" to MySQL.
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

// IsMariaDBServer reports whether a mysqld executable with this PE
// ProductName and version is MariaDB, by the rules that name the Windows
// bundled components (ProductName first, then the version). ok is false when
// they can't tell, such as 5.5 with no name.
func IsMariaDBServer(productName, version string) (mariadb, ok bool) {
	switch mysqlFlavor(productName, version, false) {
	case "MariaDB":
		return true, true
	case "MySQL Server":
		return false, true
	}
	return false, false
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
				out = append(out, component{"PHP", "The PHP Group", v, info.Machine, dir, ""})
			}
		}
	}

	if exe, ok := files["httpd.exe"]; ok {
		if info, ok := c.info(dir, exe); ok && strings.EqualFold(info.ProductName, "Apache HTTP Server") {
			if v := versionToken(info); v != "" {
				out = append(out, component{"Apache HTTP Server", "Apache Software Foundation", v, info.Machine, dir, ""})
			}
		}
	}

	exe, hasMariadbd := files["mariadbd.exe"]
	ok := hasMariadbd
	if !ok {
		exe, ok = files["mysqld.exe"]
	}
	if ok {
		if info, ok := c.info(dir, exe); ok {
			if v := versionToken(info); v != "" {
				switch mysqlFlavor(info.ProductName, v, hasMariadbd) {
				case "MariaDB":
					out = append(out, component{"MariaDB", "MariaDB", v, info.Machine, dir, ""})
				case "MySQL Server":
					out = append(out, component{"MySQL Server", "Oracle Corporation", v, info.Machine, dir, ""})
				}
			}
		}
	}

	// OpenSSL: once per directory, from the first matching library, and only
	// beside a component above. Many unrelated products ship their own
	// libssl next to a service executable or into a PATH directory; those
	// vendor copies are not what this reports.
	if len(out) == 0 {
		return nil
	}
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
			out = append(out, component{"OpenSSL", "The OpenSSL Project", v, info.Machine, dir, dir + `\` + files[lower]})
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
func findBundledComponents(src componentSource, pkgs []Package, hints componentHints, platform *inventory.Platform) []Package {
	if src == nil {
		return nil
	}
	c := &componentFinder{src: src, listed: map[string]map[string]string{}, subdirs: map[string][]string{}}
	bundles := appInstallDirs(pkgs)

	var candidates []string
	seen := map[string]bool{}
	for _, spec := range componentProbeSpecs(bundles, hints) {
		dirs := c.expand(spec.base, spec.segments)
		if spec.skipCurrent && len(dirs) > 1 {
			// "current" is a junction to a versioned directory.
			kept := dirs[:0:0]
			for _, d := range dirs {
				if !strings.EqualFold(path.Base(strings.ReplaceAll(d, `\`, "/")), "current") {
					kept = append(kept, d)
				}
			}
			dirs = kept
		}
		for _, d := range dirs {
			if k := strings.ToLower(d); !seen[k] {
				seen[k] = true
				candidates = append(candidates, d)
			}
		}
	}

	var found []Package
	for _, dir := range candidates {
		for _, comp := range c.componentsIn(dir) {
			if coveredByPackage(pkgs, comp) {
				log.Debug().Str("component", comp.name).Str("dir", comp.dir).Msg("component already covered by a package")
				continue
			}
			if addComponentLocation(found, comp, platform) {
				continue
			}
			pkg := createPackage(comp.name, comp.version, "windows/app", componentArch(comp.machine, platform), comp.vendor, comp.location(), platform)
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
func addComponentLocation(found []Package, comp component, platform *inventory.Platform) bool {
	for i := range found {
		p := &found[i]
		if p.Name == comp.name && p.Version == comp.version && p.Arch == componentArch(comp.machine, platform) {
			p.Files = append(p.Files, FileRecord{Path: comp.location()})
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

// probeSpec names the directories to check: base, then one directory level
// per segment, where a segment with a wildcard matches any number of
// directories. A spec without segments is the directory itself.
type probeSpec struct {
	base     string
	segments []string
	// skipCurrent drops a directory named "current" when others matched,
	// scoop's junction to the active version.
	skipCurrent bool
}

// probePlan is where to look. Every install directory of another app takes
// the same layouts, so the plan keeps those directories once and the layouts
// stay a constant; that keeps the remote script small on a host with hundreds
// of apps.
type probePlan struct {
	// bundles are the install directories each bundledComponentLayouts entry
	// is applied to.
	bundles []string
	// direct are the directories the machine points at and the fixed folders.
	direct []probeSpec
}

// componentProbePlan plans the search.
func componentProbePlan(bundles []bundleDir, hints componentHints) probePlan {
	var plan probePlan
	for _, b := range bundles {
		plan.bundles = append(plan.bundles, b.dir)
	}
	for _, d := range hints.candidateDirs() {
		plan.direct = append(plan.direct, probeSpec{base: d})
	}
	plan.direct = append(plan.direct, probeSpec{base: `C:\php`}, probeSpec{base: `C:\tools`, segments: []string{"php*"}})
	for _, p := range hints.Profiles {
		apps := cleanComponentDir(p.Dir + `\scoop\apps\php`)
		if apps == "" {
			continue
		}
		plan.direct = append(plan.direct, probeSpec{base: apps, segments: []string{"*"}, skipCurrent: true})
	}
	return plan
}

// specs lists the plan as probe specs, in the order the packages come out: the
// layouts inside other apps, then the direct directories.
func (p probePlan) specs() []probeSpec {
	var specs []probeSpec
	for _, b := range p.bundles {
		for _, layout := range bundledComponentLayouts {
			specs = append(specs, probeSpec{base: b, segments: layout})
		}
	}
	return append(specs, p.direct...)
}

// componentProbeSpecs lists where to look as probe specs.
func componentProbeSpecs(bundles []bundleDir, hints componentHints) []probeSpec {
	return componentProbePlan(bundles, hints).specs()
}

// remoteSafeString reports whether s can sit in a single-quoted PowerShell
// literal, or in the "|" separated spec list: no quote character PowerShell
// accepts, no control character, no "|" (not valid in a Windows path).
func remoteSafeString(s string) bool {
	return !strings.ContainsAny(s, "'|\u2018\u2019\u201a\u201b") &&
		strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) < 0
}

// componentProbeScript returns a PowerShell script that expands the specs as
// componentFinder.expand does and prints, as JSON, the relevant files of every
// directory it lists plus the version resource and machine of the executables
// the confirmation logic reads. Only names componentFiles matches are
// returned, so a directory with thousands of files stays small. The libraries
// are read only where a component executable is, since OpenSSL is only
// reported beside one. A spec with a character that could break out of the
// literal is left out.
//
// The layouts are written into the script once, from bundledComponentLayouts,
// and each bundle directory once; the script applies every layout to every
// bundle. The direct directories are one spec string each.
func componentProbeScript(plan probePlan) (string, bool) {
	var bundles []string
	for _, b := range plan.bundles {
		if remoteSafeString(b) {
			bundles = append(bundles, "'"+b+"'")
		}
	}
	var direct []string
direct:
	for _, s := range plan.direct {
		parts := append([]string{s.base}, s.segments...)
		for _, p := range parts {
			if !remoteSafeString(p) {
				continue direct
			}
		}
		skip := "0"
		if s.skipCurrent {
			skip = "1"
		}
		direct = append(direct, "'"+skip+"|"+strings.Join(parts, "|")+"'")
	}
	if len(bundles)+len(direct) == 0 {
		return "", false
	}
	layouts := make([]string, 0, len(bundledComponentLayouts))
	for _, l := range bundledComponentLayouts {
		layouts = append(layouts, "'"+strings.Join(l, "|")+"'")
	}
	return `$ErrorActionPreference = 'SilentlyContinue'
$layouts = @(` + strings.Join(layouts, ",") + `)
$bundles = @(` + strings.Join(bundles, ",") + `)
$specs = New-Object System.Collections.Generic.List[string]
foreach ($b in $bundles) { foreach ($l in $layouts) { $specs.Add('0|' + $b + '|' + $l) } }
$specs.AddRange([string[]]@(` + strings.Join(direct, ",") + `))
$wanted = '^(php\d*(ts)?\.dll|php\.exe|httpd\.exe|mysqld\.exe|mariadbd\.exe|libssl[^\\/]*\.dll|ssleay32\.dll)$'
$exes = '^(php|httpd|mysqld|mariadbd)\.exe$'
$libs = '^(libssl[^\\/]*|ssleay32)\.dll$'
$listed = @{}
$out = New-Object System.Collections.Generic.List[object]
function Get-Machine($p) {
    try {
        $s = [IO.File]::OpenRead($p)
        try {
            $b = New-Object byte[] 64
            if ($s.Read($b, 0, 64) -lt 64) { return 0 }
            $off = [BitConverter]::ToInt32($b, 60)
            if ($off -lt 0 -or $off -gt 1048576) { return 0 }
            $s.Position = $off
            $h = New-Object byte[] 6
            if ($s.Read($h, 0, 6) -lt 6) { return 0 }
            if ($h[0] -ne 80 -or $h[1] -ne 69 -or $h[2] -ne 0 -or $h[3] -ne 0) { return 0 }
            return [int][BitConverter]::ToUInt16($h, 4)
        } finally { $s.Dispose() }
    } catch { return 0 }
}
function Add-Dir($d, $withDirs) {
    $key = $d.ToLowerInvariant()
    if ($listed.ContainsKey($key)) {
        if ($withDirs -and -not $listed[$key].DirsDone) {
            $listed[$key].Entry.Dirs = @(Get-ChildItem -LiteralPath $d -Force -Directory | Select-Object -First 256 -ExpandProperty Name)
            $listed[$key].DirsDone = $true
        }
        return
    }
    $entry = [ordered]@{ Path = $d; Files = @(); Dirs = @(); Infos = @() }
    $listed[$key] = @{ Entry = $entry; DirsDone = [bool]$withDirs }
    if (-not (Test-Path -LiteralPath $d -PathType Container)) { $entry.Missing = $true; return }
    $files = @(Get-ChildItem -LiteralPath $d -Force -File | Where-Object { $_.Name -match $wanted })
    $entry.Files = @($files | ForEach-Object { $_.Name })
    if ($withDirs) { $entry.Dirs = @(Get-ChildItem -LiteralPath $d -Force -Directory | Select-Object -First 256 -ExpandProperty Name) }
    $hasExe = @($files | Where-Object { $_.Name -match $exes }).Count -gt 0
    $infos = @()
    foreach ($f in $files) {
        if (-not (($f.Name -match $exes) -or ($hasExe -and $f.Name -match $libs))) { continue }
        $v = $f.VersionInfo
        $infos += [pscustomobject]@{
            Name = $f.Name; ProductName = [string]$v.ProductName; CompanyName = [string]$v.CompanyName
            ProductVersion = [string]$v.ProductVersion
            File = ('{0}.{1}.{2}.{3}' -f $v.FileMajorPart, $v.FileMinorPart, $v.FileBuildPart, $v.FilePrivatePart)
            Machine = Get-Machine $f.FullName
        }
    }
    $entry.Infos = $infos
    $out.Add($entry)
}
foreach ($spec in $specs) {
    $parts = $spec.Split('|')
    $dirs = @($parts[1])
    for ($i = 2; $i -lt $parts.Length; $i++) {
        $seg = $parts[$i]
        $next = @()
        foreach ($d in $dirs) {
            if ($seg -match '[*?\[]') {
                Add-Dir $d $true
                $next += @(Get-ChildItem -LiteralPath $d -Force -Directory | Where-Object { $_.Name -like $seg } | Select-Object -First 64 | ForEach-Object { $_.FullName })
            } else {
                $next += ($d.TrimEnd('\') + '\' + $seg)
            }
        }
        $dirs = $next
    }
    if ($parts[0] -eq '1' -and $dirs.Count -gt 1) { $dirs = @($dirs | Where-Object { (Split-Path $_ -Leaf) -ne 'current' }) }
    foreach ($d in $dirs) { Add-Dir $d $false }
}
ConvertTo-Json -InputObject @($out | ForEach-Object { [pscustomobject]$_ }) -Compress -Depth 5
`, true
}

// psComponentInfo is one executable of componentProbeScript's output. The
// strings may be null or {} (Windows PowerShell 5.1) when the resource has none.
type psComponentInfo struct {
	Name           string
	ProductName    psOptionalString
	CompanyName    psOptionalString
	ProductVersion psOptionalString
	File           string
	Machine        int
}

type psComponentDir struct {
	Path  string
	Files psList[string]
	Dirs  psList[string]
	Infos psList[psComponentInfo]
}

// remoteComponentSource serves what componentProbeScript printed.
type remoteComponentSource struct {
	dirs  map[string]psComponentDir // lower-cased path
	infos map[string]peInfo         // lower-cased path + "\x00" + lower-cased name
}

func peMachineFromNumber(m int) string {
	if m < 0 || m > 0xffff {
		return ""
	}
	return peMachineArch(uint16(m))
}

// errEmptyProbeOutput is what a script that failed inside PowerShell leaves:
// the script runs with errors silenced and exits 0, so a failed conversion
// prints nothing. A host with nothing to find still prints "[]", so empty output
// is a failure and must not read as "nothing found".
var errEmptyProbeOutput = errors.New("the probe script printed nothing")

// parseComponentProbe reads componentProbeScript's output.
func parseComponentProbe(r io.Reader) (*remoteComponentSource, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	src := &remoteComponentSource{dirs: map[string]psComponentDir{}, infos: map[string]peInfo{}}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return nil, errEmptyProbeOutput
	}
	var dirs psList[psComponentDir]
	if err := json.Unmarshal([]byte(s), &dirs); err != nil {
		return nil, err
	}
	for _, d := range dirs {
		key := strings.ToLower(d.Path)
		src.dirs[key] = d
		for _, i := range d.Infos {
			info := peInfo{Machine: peMachineFromNumber(i.Machine)}
			if v, ok := windowsNumericVersion(i.File); ok && compareWindowsNumericVersions(v, nil) != 0 {
				info.File = v
			} else if i.ProductVersion.v == nil || strings.TrimSpace(*i.ProductVersion.v) == "" {
				continue
			}
			if i.ProductVersion.v != nil {
				info.ProductVersion = strings.TrimSpace(*i.ProductVersion.v)
			}
			if i.ProductName.v != nil {
				info.ProductName = strings.TrimSpace(*i.ProductName.v)
			}
			if i.CompanyName.v != nil {
				info.CompanyName = strings.TrimSpace(*i.CompanyName.v)
			}
			src.infos[key+"\x00"+strings.ToLower(i.Name)] = info
		}
	}
	return src, nil
}

func (s *remoteComponentSource) list(dir string) (files, dirs []string, ok bool) {
	d, found := s.dirs[strings.ToLower(dir)]
	if !found || len(d.Files)+len(d.Dirs) == 0 {
		return nil, nil, false
	}
	return d.Files, d.Dirs, true
}

func (s *remoteComponentSource) info(dir, name string) (peInfo, bool) {
	i, ok := s.infos[strings.ToLower(dir)+"\x00"+strings.ToLower(name)]
	return i, ok
}

// runComponentScript runs a PowerShell script on the target. A script that
// fits on a command line travels as an encoded command; a longer one is staged
// as a file and run with -File (powershell.Stage), because a target rejects an
// over-long command before PowerShell starts: 28k encoded over WinRM, which
// allows 8191. componentProbeScript is always that long on a host with a few
// apps, since it carries the paths to probe.
func runComponentScript(conn shared.Connection, name, script string) (*shared.Command, error) {
	if powershell.FitsCommandLine(script) {
		return conn.RunCommand(powershell.Encode(script))
	}
	if !powershell.CanStage(conn) {
		return nil, errors.New("script is too long for a command line and the connection can't stage it")
	}
	staged, err := powershell.Stage(conn, name, script)
	if err != nil {
		return nil, err
	}
	defer staged.Remove()
	return conn.RunCommand(staged.Command)
}

// remoteComponentSource reads everything the finder may ask for with one
// PowerShell run. The specs are those the finder will expand, computed from
// the same packages and hints.
func (w *WinPkgManager) remoteComponentSource(pkgs []Package, hints componentHints) componentSource {
	script, ok := componentProbeScript(componentProbePlan(appInstallDirs(pkgs), hints))
	if !ok {
		return nil
	}
	cmd, err := runComponentScript(w.conn, "components", script)
	if err != nil || cmd.ExitStatus != 0 {
		log.Debug().Err(err).Msg("could not probe component directories on the target")
		return nil
	}
	src, err := parseComponentProbe(cmd.Stdout)
	if errors.Is(err, errEmptyProbeOutput) {
		log.Debug().Err(err).Msg("component probe failed on the target: empty output, which is not the same as nothing found")
		return nil
	}
	if err != nil {
		log.Debug().Err(err).Msg("could not parse component directories of the target")
		return nil
	}
	return src
}

// bundledComponents adds the components the machine's files show. Nothing in
// here fails the package list: a source that can't be read is skipped.
//
// A remote scan (WinRM, SSH) reads through PowerShell, in two runs: the hints,
// then the directories. Local Windows and offline images read files directly.
func (w *WinPkgManager) bundledComponents(pkgs []Package) []Package {
	var hints componentHints
	var src componentSource
	switch {
	case w.conn.Type() == shared.Type_FileSystem || w.conn.Type() == shared.Type_Device:
		hints = w.offlineComponentHints()
		src = fsComponentSource{fs: w.conn.FileSystem(), toFsPath: mountedSystemDrivePath}
	case w.conn.Capabilities().Has(shared.Capability_RunCommand):
		hints = w.remoteComponentHints()
		if w.conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {
			src = fsComponentSource{fs: w.conn.FileSystem(), toFsPath: nativeWindowsPath}
		} else {
			src = w.remoteComponentSource(pkgs, hints)
		}
	default:
		log.Debug().Msg("cannot read the target, skipping bundled components")
	}
	return findBundledComponents(src, pkgs, hints, w.platform)
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
	cmd, err := runComponentScript(w.conn, "componenthints", componentHintsScript)
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

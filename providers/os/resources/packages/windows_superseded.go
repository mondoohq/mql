// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/registry"
)

// Superseded Add/Remove-Programs entries.
//
// Windows keeps one Uninstall registry entry per installer registration, not
// per installed product. When an upgrade is done by a DIFFERENT installer
// technology than the original install, the new installer registers its own
// entry and never removes the old one. Observed on a Windows 11 host after
// upgrading 7-Zip from its EXE installer (23.01) to its MSI (26.03), which
// leaves the EXE's entry under its fixed key "Uninstall\7-Zip" and adds the
// MSI's under its product code:
//
//	DisplayName                DisplayVersion
//	7-Zip 23.01 (x64)          23.01
//	7-Zip 26.03 (x64 edition)  26.03.00.0
//
// Both entries point at C:\Program Files\7-Zip\, which holds only the 26.03
// files. Reporting one package per entry reports a 23.01 install that no
// longer exists, and with it every vulnerability fixed since 23.01.
//
// dropSupersededUninstallEntries removes such stale entries using only what
// the device itself says, never a list of products:
//
//   - Same product. productIdentity: the DisplayName, case-folded, with a
//     trailing architecture qualifier removed ("(x64)", "(x64 edition)",
//     "(64-bit)", ...) and with every word removed that spells the entry's
//     OWN version (a dotted number whose components are a leading run of the
//     DisplayVersion's). "7-Zip 23.01 (x64)" at 23.01 and "7-Zip 26.03 (x64
//     edition)" at 26.03.00.0 are both "7-zip". A number that is not the
//     entry's own version stays part of the name, so "Java 8 Update 381" at
//     8.0.3810.9 keeps its "381". Publisher, architecture and install
//     scope/user must also agree.
//   - Same directory. uninstallEntryDir: InstallLocation; if absent, the
//     directory of the executable in UninstallString; if that yields none
//     (MsiExec.exe /X{GUID} names no directory), the directory of the file
//     in DisplayIcon. Compared case-insensitively, without a trailing
//     backslash, and only when fully resolved (see normalizeWindowsDir).
//   - Orderable versions. Every version in the group must be purely numeric
//     and dotted (windowsNumericVersion). The entries below the highest are
//     dropped; the highest, and any tie with it, are kept.
//
// Everything else keeps the behaviour of reporting one package per entry:
// entries in different directories (real side-by-side installs: several
// JDKs, Python per minor version, an x86 build in Program Files (x86) beside
// an x64 build in Program Files), entries whose directory cannot be
// determined, groups with any version that does not order, and the .NET
// installer family, whose runtimes are designed to coexist under one shared
// dotnet root.
//
// Dropped entries are logged at debug level, naming the entry that
// superseded them and the directory they shared.

// uninstallEvidence is what an Uninstall entry says about where the product
// lives on disk, kept raw until dropSupersededUninstallEntries resolves it.
type uninstallEvidence struct {
	installLocation string
	uninstallString string
	displayIcon     string
}

// uninstallEvidenceFromItems collects the path-bearing values of one
// Uninstall subkey read through the native registry API.
func uninstallEvidenceFromItems(items []registry.RegistryKeyItem) *uninstallEvidence {
	ev := &uninstallEvidence{}
	for _, i := range items {
		switch i.Key {
		case "InstallLocation":
			ev.installLocation = i.Value.String
		case "UninstallString":
			ev.uninstallString = i.Value.String
		case "DisplayIcon":
			ev.displayIcon = i.Value.String
		}
	}
	return ev
}

// machineEnvVars are the environment variables whose value is the same for
// every user on a host. Only these are expanded in an Uninstall entry's
// paths; anything per-user (%LOCALAPPDATA%, %USERPROFILE%) would resolve
// against the identity running the scan rather than the profile the entry
// came from, so a path using one is left unresolved and the entry is not
// considered.
var machineEnvVars = map[string]struct{}{
	"systemdrive":             {},
	"systemroot":              {},
	"windir":                  {},
	"programfiles":            {},
	"programfiles(x86)":       {},
	"programfiles(arm)":       {},
	"programw6432":            {},
	"commonprogramfiles":      {},
	"commonprogramfiles(x86)": {},
	"commonprogramfiles(arm)": {},
	"commonprogramw6432":      {},
	"programdata":             {},
	"allusersprofile":         {},
	"public":                  {},
}

// expandMachineEnvFromProcess expands the machine-wide %VAR% references in s
// from this process's environment. Only correct when the process runs on
// the scanned host (the local native registry path); remote PowerShell
// already returns REG_EXPAND_SZ values expanded, and the offline path has no
// environment of the target to expand from.
func expandMachineEnvFromProcess(s string) string {
	return winEnvPercentPattern.ReplaceAllStringFunc(s, func(m string) string {
		name := m[1 : len(m)-1]
		if _, ok := machineEnvVars[strings.ToLower(name)]; !ok {
			return m
		}
		if v, ok := os.LookupEnv(name); ok && v != "" {
			return v
		}
		return m
	})
}

var (
	winDriveAbsPath = regexp.MustCompile(`^[a-z]:\\`)
	winUNCPath      = regexp.MustCompile(`^\\\\[^\\]+\\[^\\]+`)
	winIconIndex    = regexp.MustCompile(`,\s*-?\d+$`)
)

// sharedWindowsDirs are directories that many products live UNDER. An
// Uninstall entry that names one of them as its directory says nothing about
// which product's files are there, so it never groups entries.
var sharedWindowsDirs = map[string]struct{}{
	`program files`:                    {},
	`program files (x86)`:              {},
	`program files (arm)`:              {},
	`programdata`:                      {},
	`users`:                            {},
	`windows`:                          {},
	`program files\common files`:       {},
	`program files (x86)\common files`: {},
	`programdata\package cache`:        {},
}

// sharedUserSubdirs are the per-user roots that many products live under,
// relative to a user's profile directory.
var sharedUserSubdirs = map[string]struct{}{
	``:                       {},
	`appdata`:                {},
	`appdata\local`:          {},
	`appdata\roaming`:        {},
	`appdata\locallow`:       {},
	`appdata\local\programs`: {},
	`appdata\local\temp`:     {},
}

// normalizeWindowsDir canonicalises a directory path for comparison:
// quotes and surrounding space removed, forward slashes turned into
// backslashes, repeated and trailing backslashes removed, case folded. The
// result is "" (no usable directory) when the path is not absolute, still
// carries an unexpanded %VAR%, is a drive root, lies inside the Windows
// directory, or is one of the shared roots above.
func normalizeWindowsDir(p string, expandEnv func(string) string) string {
	p = strings.TrimSpace(strings.Trim(strings.TrimSpace(p), `"`))
	if p == "" {
		return ""
	}
	if expandEnv != nil {
		p = expandEnv(p)
	}
	if strings.Contains(p, "%") {
		return ""
	}
	p = strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	unc := strings.HasPrefix(p, `\\`)
	body := strings.TrimLeft(p, `\`)
	for strings.Contains(body, `\\`) {
		body = strings.ReplaceAll(body, `\\`, `\`)
	}
	body = strings.TrimRight(body, `\ `)
	if unc {
		p = `\\` + body
		if !winUNCPath.MatchString(p) {
			return ""
		}
		return p
	}
	p = body
	if !winDriveAbsPath.MatchString(p + `\`) {
		return ""
	}
	rest := strings.TrimPrefix(p[2:], `\`)
	if rest == "" {
		return ""
	}
	if rest == "windows" || strings.HasPrefix(rest, `windows\`) {
		return ""
	}
	if _, shared := sharedWindowsDirs[rest]; shared {
		return ""
	}
	if strings.HasPrefix(rest, `users\`) {
		profileRest := strings.TrimPrefix(rest, `users\`)
		sub := ""
		if i := strings.IndexByte(profileRest, '\\'); i >= 0 {
			sub = profileRest[i+1:]
		}
		if _, shared := sharedUserSubdirs[sub]; shared {
			return ""
		}
	}
	return p
}

// executableFromCommand returns the path of the program a command line runs:
// the quoted prefix if the line starts with a quote, otherwise everything up
// to and including the first ".exe". Returns "" when the program is named
// without a directory (MsiExec.exe /X{GUID}, rundll32.exe ...) or no program
// can be found.
func executableFromCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	var exe string
	if cmd[0] == '"' {
		end := strings.IndexByte(cmd[1:], '"')
		if end < 0 {
			return ""
		}
		exe = cmd[1 : end+1]
	} else {
		i := strings.Index(strings.ToLower(cmd), ".exe")
		if i < 0 {
			return ""
		}
		exe = cmd[:i+len(".exe")]
	}
	if !strings.ContainsAny(exe, `\/`) {
		return ""
	}
	return exe
}

// iconFilePath returns the file a DisplayIcon value names, without quotes
// or the ",<index>" resource suffix.
func iconFilePath(icon string) string {
	icon = strings.TrimSpace(icon)
	if strings.HasPrefix(icon, `"`) {
		if end := strings.IndexByte(icon[1:], '"'); end >= 0 {
			icon = icon[1 : end+1]
		}
	}
	icon = strings.TrimSpace(winIconIndex.ReplaceAllString(icon, ""))
	if !strings.ContainsAny(icon, `\/`) {
		return ""
	}
	return icon
}

// parentDir returns the directory part of a Windows file path.
func parentDir(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	i := strings.LastIndexByte(p, '\\')
	if i <= 0 {
		return ""
	}
	return p[:i]
}

// uninstallEntryDir derives the directory an Uninstall entry's product lives
// in, in order of preference: InstallLocation, the directory of the
// UninstallString's executable, the directory of the DisplayIcon's file. A
// source that is present but resolves to nothing usable (see
// normalizeWindowsDir) falls through to the next one. Returns "" when none
// yields a directory.
func uninstallEntryDir(ev *uninstallEvidence, expandEnv func(string) string) string {
	if ev == nil {
		return ""
	}
	if d := normalizeWindowsDir(ev.installLocation, expandEnv); d != "" {
		return d
	}
	if exe := executableFromCommand(ev.uninstallString); exe != "" {
		if d := normalizeWindowsDir(parentDir(exe), expandEnv); d != "" {
			return d
		}
	}
	if icon := iconFilePath(ev.displayIcon); icon != "" {
		if d := normalizeWindowsDir(parentDir(icon), expandEnv); d != "" {
			return d
		}
	}
	return ""
}

// displayNameArchSuffix matches the architecture qualifier installers append
// to a DisplayName: "(x64)", "(x64 edition)", "(64-bit)", "(arm64)".
var displayNameArchSuffix = regexp.MustCompile(`\s*\((?:x64|x86|x86_64|amd64|arm64|arm|ia64|64-bit|32-bit|64 bit|32 bit)(?:\s+edition)?\)$`)

// displayNameVersionWord matches a word that spells a dotted version, with an
// optional leading "v".
var displayNameVersionWord = regexp.MustCompile(`^v?(\d+(?:\.\d+)+)$`)

// productIdentity is the name two Uninstall entries must share to be the
// same product; see the rules at the top of this file. Returns "" when
// nothing is left of the name.
func productIdentity(displayName, version string) string {
	name := strings.ToLower(strings.Join(strings.Fields(displayName), " "))
	for {
		stripped := displayNameArchSuffix.ReplaceAllString(name, "")
		if stripped == name {
			break
		}
		name = stripped
	}
	own, ownOK := windowsNumericVersion(version)
	words := strings.Fields(name)
	kept := words[:0]
	for _, w := range words {
		if ownOK {
			if m := displayNameVersionWord.FindStringSubmatch(w); m != nil {
				if wv, ok := windowsNumericVersion(m[1]); ok && isLeadingRun(wv, own) {
					continue
				}
			}
		}
		kept = append(kept, w)
	}
	return strings.Join(kept, " ")
}

// isLeadingRun reports whether every component of prefix equals the
// component at the same position in v ("26.03" of "26.03.00.0").
func isLeadingRun(prefix, v []uint64) bool {
	if len(prefix) > len(v) {
		return false
	}
	for i := range prefix {
		if prefix[i] != v[i] {
			return false
		}
	}
	return true
}

var windowsNumericVersionShape = regexp.MustCompile(`^\d+(?:\.\d+)*$`)

// windowsNumericVersion parses a purely numeric dotted version ("23.01",
// "26.03.00.0"). Anything else ("1.0-beta", "2024 R2", "") does not order
// and returns false.
func windowsNumericVersion(v string) ([]uint64, bool) {
	v = strings.TrimSpace(v)
	if !windowsNumericVersionShape.MatchString(v) {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]uint64, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// compareWindowsNumericVersions orders two parsed versions, treating
// missing trailing components as zero (23.01 == 23.1.0.0).
func compareWindowsNumericVersions(a, b []uint64) int {
	n := max(len(a), len(b))
	for i := range n {
		var x, y uint64
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

// isDotNetInstallerEntry reports whether a DisplayName belongs to the .NET
// installer family. Its runtimes install side by side under one shared
// dotnet root by design, so a shared directory is no evidence that one
// release replaced another.
func isDotNetInstallerEntry(name string) bool {
	for _, re := range dotNetInstallerReleasePatterns {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

// dropSupersededUninstallEntries removes Add/Remove-Programs entries that an
// entry for the same product at a higher version, installed into the same
// directory, has superseded. See the rules at the top of this file.
// expandEnv, when non-nil, expands %VAR% references in the entries' paths.
// Order of the kept packages is preserved, and the raw path evidence is
// cleared from every package on the way out.
func dropSupersededUninstallEntries(pkgs []Package, expandEnv func(string) string) []Package {
	type member struct {
		idx     int
		version []uint64
		ok      bool
	}
	groups := map[string][]member{}
	dirs := make([]string, len(pkgs))
	for i := range pkgs {
		p := &pkgs[i]
		if p.Format != "windows/app" || p.uninstallEvidence == nil || isDotNetInstallerEntry(p.Name) {
			continue
		}
		dir := uninstallEntryDir(p.uninstallEvidence, expandEnv)
		if dir == "" {
			continue
		}
		id := productIdentity(p.Name, p.Version)
		if id == "" {
			continue
		}
		dirs[i] = dir
		v, ok := windowsNumericVersion(p.Version)
		key := strings.Join([]string{
			id, dir, p.Arch, strings.ToLower(strings.TrimSpace(p.Vendor)), p.InstallScope, p.InstallUser,
		}, "\x00")
		groups[key] = append(groups[key], member{idx: i, version: v, ok: ok})
	}

	drop := map[int]int{} // dropped index -> index of the entry that superseded it
	for _, members := range groups {
		if len(members) < 2 {
			continue
		}
		orderable := true
		for _, m := range members {
			if !m.ok {
				orderable = false
				break
			}
		}
		if !orderable {
			continue
		}
		best := members[0]
		for _, m := range members[1:] {
			if compareWindowsNumericVersions(m.version, best.version) > 0 {
				best = m
			}
		}
		for _, m := range members {
			if compareWindowsNumericVersions(m.version, best.version) < 0 {
				drop[m.idx] = best.idx
			}
		}
	}

	out := make([]Package, 0, len(pkgs))
	for i := range pkgs {
		if by, dropped := drop[i]; dropped {
			log.Debug().
				Str("name", pkgs[i].Name).
				Str("version", pkgs[i].Version).
				Str("superseded_by_name", pkgs[by].Name).
				Str("superseded_by_version", pkgs[by].Version).
				Str("install_dir", dirs[i]).
				Msg("dropping superseded Add/Remove-Programs entry: a newer entry for the same product is registered in the same directory")
			continue
		}
		p := pkgs[i]
		p.uninstallEvidence = nil
		out = append(out, p)
	}
	return out
}

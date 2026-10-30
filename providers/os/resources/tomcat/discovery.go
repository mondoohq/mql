// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tomcat

import (
	"path"
	"regexp"
	"strings"

	"github.com/spf13/afero"
)

// HomeGlobs lists the directories a Tomcat *installation* is commonly found
// in. A candidate is only accepted when it carries an installation marker, so
// an unrelated directory that happens to match cannot win.
var HomeGlobs = []string{
	"/usr/local/tomcat",
	"/usr/share/tomcat",
	"/usr/share/tomcat[0-9]*",
	"/opt/tomcat*",
	"/opt/apache-tomcat*",
	"/usr/local/apache-tomcat*",
	"/usr/share/apache-tomcat*",
}

// BaseGlobs lists the directories a Tomcat *instance* is commonly found in.
// The instance directory is the one that owns conf/, so that is what a
// candidate is tested for.
var BaseGlobs = []string{
	"/var/lib/tomcat[0-9]*",
	"/var/lib/tomcats/*",
	"/srv/tomcat/*",
	"/opt/tomcat*/instances/*",
}

// HomeMarkers are the files that identify a directory as CATALINA_HOME.
//
// catalina.jar is the reliable signal: it is present in every installation
// layout and absent from every separate instance directory. Note that it is
// deliberately not bin/catalina.sh — the Red Hat packages ship no catalina.sh
// at all (their bin/ holds only the jars, and startup goes through
// /usr/libexec/tomcat/server), so keying on the script misses those installs
// entirely. bin/bootstrap.jar and bin/tomcat-juli.jar corroborate.
var HomeMarkers = []string{
	"lib/catalina.jar",
	"bin/bootstrap.jar",
	"bin/tomcat-juli.jar",
}

// BaseMarker identifies a directory as CATALINA_BASE.
const BaseMarker = "conf/server.xml"

// SystemdUnitDirs lists the directories scanned for a unit that starts Tomcat.
var SystemdUnitDirs = []string{
	"/etc/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// EnvConfigGlobs lists the distribution-specific files that declare
// CATALINA_HOME or CATALINA_BASE outside of a systemd unit.
var EnvConfigGlobs = []string{
	"/etc/tomcat/tomcat.conf",
	"/etc/tomcat[0-9]*/tomcat.conf",
	"/etc/tomcat/conf.d/*.conf",
	"/etc/tomcat[0-9]*/conf.d/*.conf",
	"/etc/sysconfig/tomcat*",
	"/etc/default/tomcat*",
}

var (
	reCatalinaHomeProp = regexp.MustCompile(`-Dcatalina\.home=("[^"]+"|'[^']+'|\S+)`)
	reCatalinaBaseProp = regexp.MustCompile(`-Dcatalina\.base=("[^"]+"|'[^']+'|\S+)`)
)

// IsCatalinaCommand reports whether a command line belongs to a Tomcat server.
//
// The system-property forms are matched with their `-D` prefix rather than as
// bare substrings. An unrelated JVM that merely names a catalina property —
// a build, a client, a deployment tool passing a path around — would otherwise
// be mistaken for the server and hand back whatever paths it happened to
// mention.
func IsCatalinaCommand(cmd string) bool {
	return strings.Contains(cmd, "org.apache.catalina.startup.Bootstrap") ||
		strings.Contains(cmd, "-Dcatalina.home=") ||
		strings.Contains(cmd, "-Dcatalina.base=") ||
		reCatalinaScript.MatchString(cmd)
}

// reCatalinaScript matches the startup script as an argument in its own right,
// so that a backup or a note named after it does not count.
var reCatalinaScript = regexp.MustCompile(`(?:^|[\s/])catalina\.sh(?:\s|$)`)

// PathsFromCommand extracts -Dcatalina.home= and -Dcatalina.base= from a
// running Catalina process's command line.
func PathsFromCommand(cmd string) (home string, base string) {
	if m := reCatalinaHomeProp.FindStringSubmatch(cmd); m != nil {
		home = unquote(m[1])
	}
	if m := reCatalinaBaseProp.FindStringSubmatch(cmd); m != nil {
		base = unquote(m[1])
	}
	return home, base
}

// PathsFromEnviron extracts CATALINA_HOME and CATALINA_BASE from the raw,
// NUL-separated contents of a process's environment.
func PathsFromEnviron(environ string) (home string, base string) {
	for entry := range strings.SplitSeq(environ, "\x00") {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		switch key {
		case "CATALINA_HOME":
			home = value
		case "CATALINA_BASE":
			base = value
		}
	}
	return home, base
}

// IsCatalinaUnit reports whether a systemd unit file starts Tomcat.
func IsCatalinaUnit(content string) bool {
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart") && !strings.HasPrefix(line, "Environment") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "catalina") || strings.Contains(lower, "tomcat") {
			return true
		}
	}
	return false
}

// PathsFromUnit extracts CATALINA_HOME and CATALINA_BASE from a systemd unit's
// Environment= assignments and its ExecStart line, and returns the paths of any
// EnvironmentFile= directives so the caller can read them too.
func PathsFromUnit(content string) (home string, base string, envFiles []string) {
	envFiles = []string{}

	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "Environment":
			for _, assignment := range splitUnitEnvironment(value) {
				k, v, ok := strings.Cut(assignment, "=")
				if !ok {
					continue
				}
				switch k {
				case "CATALINA_HOME":
					home = unquote(v)
				case "CATALINA_BASE":
					base = unquote(v)
				}
			}
		case "EnvironmentFile":
			// A leading '-' marks the file as optional; it is not part of the path.
			envFiles = append(envFiles, strings.TrimPrefix(unquote(value), "-"))
		case "ExecStart", "ExecStartPre":
			h, b := PathsFromCommand(line)
			if h != "" && home == "" {
				home = h
			}
			if b != "" && base == "" {
				base = b
			}
		}
	}

	return home, base, envFiles
}

// PathsFromEnvFile extracts CATALINA_HOME and CATALINA_BASE from a shell-style
// environment file — a unit's EnvironmentFile= target, /etc/tomcat/tomcat.conf,
// /etc/sysconfig/tomcat, or an instance's bin/setenv.sh.
func PathsFromEnvFile(content string) (home string, base string) {
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "CATALINA_HOME":
			home = unquote(strings.TrimSpace(value))
		case "CATALINA_BASE":
			base = unquote(strings.TrimSpace(value))
		}
	}
	return home, base
}

// PathsFromSystemd scans the systemd unit directories for a unit that starts
// Tomcat and reads CATALINA_HOME / CATALINA_BASE out of it.
func PathsFromSystemd(fs afero.Fs) (string, string) {
	for _, unit := range catalinaUnits(fs) {
		if unit.Home != "" || unit.Base != "" {
			return unit.Home, unit.Base
		}
	}
	return "", ""
}

// CatalinaUnit is a systemd unit that starts Tomcat, with the paths it
// declares directly or through its EnvironmentFile= targets.
type CatalinaUnit struct {
	Path     string
	Content  string
	Home     string
	Base     string
	EnvFiles []string
}

// catalinaUnits returns every systemd unit that starts Tomcat, in the order
// the unit directories are scanned.
func catalinaUnits(fs afero.Fs) []CatalinaUnit {
	afs := &afero.Afero{Fs: fs}
	res := []CatalinaUnit{}

	for _, dir := range SystemdUnitDirs {
		entries, err := afs.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".service") {
				continue
			}
			// `tomcat@.service` is a template, not an instance: it resolves
			// CATALINA_BASE from a %i that is only bound when a named instance
			// is started. Reading it would yield a literal "%i" path.
			if strings.Contains(name, "@.service") {
				continue
			}

			unitPath := path.Join(dir, name)
			content, err := afs.ReadFile(unitPath)
			if err != nil || !IsCatalinaUnit(string(content)) {
				continue
			}

			home, base, envFiles := PathsFromUnit(string(content))
			for _, envFile := range envFiles {
				if home != "" && base != "" {
					break
				}
				envContent, err := afs.ReadFile(envFile)
				if err != nil {
					continue
				}
				fileHome, fileBase := PathsFromEnvFile(string(envContent))
				if home == "" {
					home = fileHome
				}
				if base == "" {
					base = fileBase
				}
			}

			res = append(res, CatalinaUnit{
				Path:     unitPath,
				Content:  string(content),
				Home:     home,
				Base:     base,
				EnvFiles: envFiles,
			})
		}
	}

	return res
}

// PathsFromEnvConfigs reads the distribution-specific environment files that
// declare CATALINA_HOME or CATALINA_BASE without going through a unit file.
func PathsFromEnvConfigs(fs afero.Fs) (string, string) {
	afs := &afero.Afero{Fs: fs}
	home, base := "", ""

	for _, pattern := range EnvConfigGlobs {
		matches, err := afero.Glob(afs, pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			content, err := afs.ReadFile(match)
			if err != nil {
				continue
			}
			fileHome, fileBase := PathsFromEnvFile(string(content))
			if home == "" {
				home = fileHome
			}
			if base == "" {
				base = fileBase
			}
			if home != "" && base != "" {
				return home, base
			}
		}
	}

	return home, base
}

// IsInstallDir reports whether a directory is a CATALINA_HOME.
func IsInstallDir(fs afero.Fs, dir string) bool {
	for _, marker := range HomeMarkers {
		if fileExists(fs, path.Join(dir, marker)) {
			return true
		}
	}
	return false
}

// IsInstanceDir reports whether a directory is a CATALINA_BASE.
func IsInstanceDir(fs afero.Fs, dir string) bool {
	return fileExists(fs, path.Join(dir, BaseMarker))
}

// ProbeHome searches the well-known layouts for an installation directory.
func ProbeHome(fs afero.Fs) string {
	afs := &afero.Afero{Fs: fs}
	for _, pattern := range HomeGlobs {
		matches, err := afero.Glob(afs, pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			if IsInstallDir(fs, match) {
				return match
			}
		}
	}
	return ""
}

// ProbeBase searches for an instance directory, preferring the installation
// directory itself.
//
// Preferring home matters on the packaged layouts where $CATALINA_HOME/conf is
// a symlink into /etc: that shared directory is the default instance, and a
// named instance elsewhere on the box is an additional one, reachable with
// `tomcat(base: "...")` rather than a guess made here.
func ProbeBase(fs afero.Fs, home string) string {
	if home != "" && IsInstanceDir(fs, home) {
		return home
	}

	afs := &afero.Afero{Fs: fs}
	for _, pattern := range BaseGlobs {
		matches, err := afero.Glob(afs, pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			if IsInstanceDir(fs, match) {
				return match
			}
		}
	}
	return ""
}

// PathsFromSetenv reads an instance's bin/setenv.sh, the standard place a
// multi-instance layout declares which installation it belongs to.
func PathsFromSetenv(fs afero.Fs, dirs ...string) (string, string) {
	afs := &afero.Afero{Fs: fs}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		content, err := afs.ReadFile(path.Join(dir, "bin", "setenv.sh"))
		if err != nil {
			continue
		}
		if home, base := PathsFromEnvFile(string(content)); home != "" || base != "" {
			return home, base
		}
	}
	return "", ""
}

func fileExists(fs afero.Fs, filePath string) bool {
	// Stat follows symlinks, which the packaged layouts depend on: a Red Hat
	// install reaches its jars through lib -> /usr/share/java/tomcat and its
	// configuration through conf -> /etc/tomcat.
	stat, err := fs.Stat(filePath)
	return err == nil && !stat.IsDir()
}

// splitUnitEnvironment splits a systemd Environment= value into its individual
// assignments, honoring the quoting systemd allows around each one.
func splitUnitEnvironment(value string) []string {
	res := []string{}
	var cur strings.Builder
	var quote byte

	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case quote != 0:
			// systemd lets a backslash escape the quote character, and itself,
			// inside a quoted value: Environment="JAVA_OPTS=-Dx=\"y\"". Without
			// this the escaped quote is read as the closing one and the value is
			// silently truncated at that point -- which for a CATALINA_HOME would
			// mean discovering a path that does not exist rather than failing.
			if c == '\\' && i+1 < len(value) {
				i++
				cur.WriteByte(value[i])
				continue
			}
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteByte(c)
		case c == '"' || c == '\'':
			quote = c
		case c == ' ' || c == '\t':
			if cur.Len() > 0 {
				res = append(res, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		res = append(res, cur.String())
	}
	return res
}

func unquote(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

var reReleaseNotesVersion = regexp.MustCompile(`(?i)Apache Tomcat Version\s+([0-9][0-9A-Za-z.\-]*)`)

// VersionFromReleaseNotes reads the version out of the RELEASE-NOTES file an
// installation ships. That is cheap and always on disk, unlike the version
// recorded inside catalina.jar.
func VersionFromReleaseNotes(content string) string {
	if m := reReleaseNotesVersion.FindStringSubmatch(content); m != nil {
		return strings.TrimSpace(m[1])
	}
	return ""
}

var reInstallDirVersion = regexp.MustCompile(`^(?:apache-)?tomcat-([0-9]+(?:\.[0-9]+)+[0-9A-Za-z.\-]*)$`)

// VersionFromInstallDir reads the version out of an unpacked distribution's
// directory name, e.g. /opt/apache-tomcat-11.0.24.
func VersionFromInstallDir(home string) string {
	if home == "" {
		return ""
	}
	if m := reInstallDirVersion.FindStringSubmatch(path.Base(home)); m != nil {
		return m[1]
	}
	return ""
}

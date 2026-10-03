// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/logrotate"
	"go.mondoo.com/mql/types"
)

const (
	defaultLogrotateConf = "/etc/logrotate.conf"
	defaultLogrotateDir  = "/etc/logrotate.d"

	// The FreeBSD port (sysutils/logrotate) installs its configuration under
	// the local prefix; base FreeBSD rotates logs with newsyslog(8) instead.
	localLogrotateConf = "/usr/local/etc/logrotate.conf"
	localLogrotateDir  = "/usr/local/etc/logrotate.d"
)

// logrotateLocations returns the main configuration file and the drop-in
// directories to read. /etc (or its /usr/etc vendor copy) wins; the
// /usr/local/etc tree used by the FreeBSD port is read only when there is no
// configuration under /etc.
func logrotateLocations(fs afero.Fs) (string, []string) {
	conf := resolveVendorConfigPath(fs, defaultLogrotateConf)
	if fs == nil {
		return conf, nil
	}
	// conf is /etc/logrotate.conf or its /usr/etc copy. Only when neither
	// exists does the /usr/local/etc tree take over, drop-ins included.
	if _, err := fs.Stat(conf); err != nil {
		if _, err := fs.Stat(localLogrotateConf); err == nil {
			var dirs []string
			if fi, err := fs.Stat(localLogrotateDir); err == nil && fi.IsDir() {
				dirs = append(dirs, localLogrotateDir)
			}
			return localLogrotateConf, dirs
		}
	}
	return conf, vendorConfigDirs(fs, defaultLogrotateDir)
}

func initLogrotate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return args, nil, nil
}

func (l *mqlLogrotate) id() (string, error) {
	return "logrotate", nil
}

func (le *mqlLogrotateEntry) id() (string, error) {
	file := le.File.Data
	if file == nil {
		return "", errors.New("cannot determine logrotate entry ID (missing file)")
	}

	lineNum := strconv.FormatInt(le.LineNumber.Data, 10)

	return file.Path.Data + ":" + lineNum + ":" + le.Path.Data, nil
}

// files discovers logrotate configuration files from the main config and logrotate.d directory.
func (l *mqlLogrotate) files() ([]any, error) {
	var allFiles []any

	var fs afero.Fs
	if conn, ok := l.MqlRuntime.Connection.(shared.Connection); ok {
		fs = conn.FileSystem()
	}

	// Add main logrotate.conf. Distributions that ship packaged defaults under
	// /usr/etc (openSUSE Leap 16, SLE 16) keep it there unless an administrator
	// overrode it in /etc.
	mainPath, dropInDirs := logrotateLocations(fs)
	mainFile, err := CreateResource(l.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(mainPath),
	})
	if err != nil {
		return nil, err
	}
	f := mainFile.(*mqlFile)
	exists := f.GetExists()
	if exists.Error != nil {
		return nil, exists.Error
	}

	if exists.Data {
		allFiles = append(allFiles, f)
	}

	skip, recursive := l.dropInFilter(fs)

	// Drop-ins merge across both trees, with /etc shadowing a same-named file
	// in /usr/etc.
	for _, dir := range dropInDirs {
		findArgs := map[string]*llx.RawData{
			"from": llx.StringData(dir),
			"type": llx.StringData("file"),
		}
		if !recursive {
			findArgs["depth"] = llx.IntData(1)
		}
		files, err := CreateResource(l.MqlRuntime, "files.find", findArgs)
		if err != nil {
			return nil, err
		}

		ff := files.(*mqlFilesFind)
		list := ff.GetList()
		if list.Error != nil {
			return nil, list.Error
		}

		for i := range list.Data {
			file := list.Data[i].(*mqlFile)
			basename := file.GetBasename()
			if basename.Error != nil {
				continue
			}

			if skip(basename.Data) {
				continue
			}
			if vendorConfigShadowed(fs, file.Path.Data) {
				continue
			}

			allFiles = append(allFiles, file)
		}
	}

	return allFiles, nil
}

const (
	// logrotateAllPath is the wrapper SUSE's logrotate.service runs on SLE 16
	// and openSUSE Leap 16. It hands logrotate every file in
	// {/usr,}/etc/logrotate.d by name, so no taboo list applies to them.
	logrotateAllPath = "/usr/sbin/logrotate-all"
	logrotateBinPath = "/usr/sbin/logrotate"
)

// logrotateServiceUnits are the logrotate.service unit files in the order
// systemd looks them up.
var logrotateServiceUnits = []string{
	"/etc/systemd/system/logrotate.service",
	"/usr/lib/systemd/system/logrotate.service",
	"/lib/systemd/system/logrotate.service",
}

// dropInFilter returns the test that drops a logrotate.d file logrotate does
// not read, and whether files in subdirectories count.
//
//   - When logrotate.service runs logrotate-all, every regular file in the
//     drop-in trees, subdirectories included, is passed to logrotate.
//   - Otherwise logrotate reads the directory through `include` and skips the
//     names matching its built-in taboo list, which depends on its version:
//     3.8.6 (RHEL 7) to 3.16 read x.bak, everything before 3.22 reads x.old,
//     and every version skips x.disabled and x.swp.
//   - When the version cannot be read, SUSE gets the list of SLE 15's 3.18
//     and other platforms the long-standing suffix list.
func (l *mqlLogrotate) dropInFilter(fs afero.Fs) (func(string) bool, bool) {
	if logrotateAllDrivesRotation(fs) {
		return func(string) bool { return false }, true
	}

	conn, ok := l.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return logrotateLegacySkip, false
	}
	asset := conn.Asset()
	suse := asset != nil && asset.Platform != nil && asset.Platform.IsFamily("suse")
	return logrotateDropInSkip(logrotateInstalledVersion(l.MqlRuntime), suse), false
}

// logrotateDropInSkip returns the test for a drop-in name logrotate of this
// version skips. An empty version is unknown.
func logrotateDropInSkip(version string, suse bool) func(string) bool {
	if version == "" && !suse {
		return logrotateLegacySkip
	}
	exts := logrotateTabooExts(version)
	return func(name string) bool { return logrotateTabooMatch(exts, name) }
}

// logrotateInstalledVersion is the version `logrotate --version` prints, or
// "" when it cannot be run. The command resource caches the answer.
func logrotateInstalledVersion(runtime *plugin.Runtime) string {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return ""
	}
	for _, cmdline := range []string{logrotateBinPath + " --version", "logrotate --version"} {
		o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
			"command": llx.StringData(cmdline),
		})
		if err != nil {
			continue
		}
		cmd := o.(*mqlCommand)
		if cmd.GetExitcode().Data != 0 {
			continue
		}
		// logrotate before 3.9 (3.8.6 on RHEL 7) prints its version on stderr
		for _, out := range []string{cmd.GetStdout().Data, cmd.GetStderr().Data} {
			if version := parseLogrotateVersion(out); version != "" {
				return version
			}
		}
	}
	return ""
}

// logrotateRejectsFile reports whether the installed logrotate skips a whole
// configuration file because it does not parse. logrotate reads a "{" or "}"
// followed by a carriage return as an error, so a file with CRLF line endings
// is one; strict releases log "found error in file g04crlf, skipping" and use
// none of its rules.
func logrotateRejectsFile(runtime *plugin.Runtime, content string) bool {
	if !logrotateFileHasCRLF(content) {
		return false
	}
	version := logrotateInstalledVersion(runtime)
	release := ""
	if version == "3.14.0" {
		if stdout, ok, err := runSystemctl(runtime, "rpm -q --qf '%{RELEASE}' logrotate"); err == nil && ok {
			release = strings.TrimSpace(stdout)
		}
	}
	return logrotateStrictParsing(version, release)
}

// logrotateStrictParsing reports whether a logrotate skips a configuration
// file with a syntax error rather than logging it and keeping the rest.
// Upstream does so from 3.18; RHEL 8 backported it into 3.14.0-6 ("enforce
// stricter parsing of config files"), which the rpm release tells apart from
// Debian's and Ubuntu's 3.14.0.
func logrotateStrictParsing(version, rpmRelease string) bool {
	major, minor, ok := logrotateMajorMinor(version)
	if !ok {
		return false
	}
	if major > 3 || (major == 3 && minor >= 18) {
		return true
	}
	if version == "3.14.0" && rpmRelease != "" {
		n, _, _ := strings.Cut(rpmRelease, ".")
		if r, err := strconv.Atoi(n); err == nil && r >= 6 {
			return true
		}
	}
	return false
}

// logrotateFileHasCRLF reports whether a configuration line other than a
// comment ends in a carriage return. logrotate itself only fails on the "{"
// and "}" lines (a keyword line such as "weekly\r" parses, the carriage
// return reading as whitespace), so this stands for "the file has CRLF line
// endings": an editor or a copy from Windows converts every line, the braces
// included.
func logrotateFileHasCRLF(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(line, "\r") {
			return true
		}
	}
	return false
}

// logrotateAllDrivesRotation reports whether logrotate.service runs the
// logrotate-all wrapper instead of logrotate with its main configuration.
func logrotateAllDrivesRotation(fs afero.Fs) bool {
	if fs == nil {
		return false
	}
	if _, err := fs.Stat(logrotateAllPath); err != nil {
		return false
	}
	for _, unit := range logrotateServiceUnits {
		content, err := afero.ReadFile(fs, unit)
		if err != nil {
			continue
		}
		// the first unit file found is the one systemd loads
		for _, line := range strings.Split(string(content), "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && strings.TrimSpace(key) == "ExecStart" && strings.Contains(value, logrotateAllPath) {
				return true
			}
		}
		return false
	}
	return false
}

// logrotateLegacySkip is the suffix list applied outside SUSE.
func logrotateLegacySkip(name string) bool {
	for _, suffix := range []string{".bak", ".old", ".rpmsave", ".rpmorig", ".dpkg-old", ".dpkg-new", ".dpkg-dist", "~"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// parseLogrotateVersion reads the version from the first line of
// `logrotate --version`, which is `logrotate 3.18.1`.
func parseLogrotateVersion(stdout string) string {
	first, _, _ := strings.Cut(strings.TrimSpace(stdout), "\n")
	name, version, ok := strings.Cut(strings.TrimSpace(first), " ")
	if !ok || name != "logrotate" {
		return ""
	}
	return strings.TrimSpace(version)
}

// logrotateTabooExts returns logrotate's built-in taboo extensions
// (defTabooExts in config.c) for a version. An unknown version gets the list
// of 3.17 to 3.21, which covers the logrotate of SLE 15 and openSUSE Leap 15.
func logrotateTabooExts(version string) []string {
	exts := []string{",v", ".cfsaved", ".disabled", ".dpkg-dist", ".dpkg-new", ".dpkg-old",
		".rhn-cfg-tmp-*", ".rpmnew", ".rpmorig", ".rpmsave", ".swp", ".ucf-dist", ".ucf-new", ".ucf-old", "~"}

	major, minor, ok := logrotateMajorMinor(version)
	if !ok {
		major, minor = 3, 18
	}
	atLeast := func(m int) bool { return major > 3 || (major == 3 && minor >= m) }
	if atLeast(13) {
		exts = append(exts, ".dpkg-bak", ".dpkg-del")
	}
	if atLeast(14) {
		exts = append(exts, ".dpkg-tmp")
	}
	if atLeast(17) {
		exts = append(exts, ".bak")
	}
	if atLeast(22) {
		exts = append(exts, ".new", ".old", ".orig")
	}
	return exts
}

func logrotateMajorMinor(version string) (int, int, bool) {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// logrotateTabooMatch reports whether logrotate skips a drop-in name. It
// matches each extension as the pattern `*<ext>` with fnmatch(FNM_PERIOD), so
// a name starting with a dot is never taboo, and `.` and `..` are skipped.
func logrotateTabooMatch(exts []string, name string) bool {
	if name == "." || name == ".." {
		return true
	}
	if strings.HasPrefix(name, ".") {
		return false
	}
	for _, ext := range exts {
		if ok, err := path.Match("*"+ext, name); err == nil && ok {
			return true
		}
	}
	return false
}

// globalConfig parses all config files and returns the global directives.
func (l *mqlLogrotate) globalConfig(files []any) (map[string]any, error) {
	merged := make(map[string]any)

	for i := range files {
		file := files[i].(*mqlFile)
		content := file.GetContent()
		if content.Error != nil {
			continue
		}

		if logrotateRejectsFile(l.MqlRuntime, content.Data) {
			continue
		}
		global, _ := logrotate.ParseContent(file.Path.Data, content.Data)
		for k, v := range global {
			merged[k] = v
		}
	}

	return merged, nil
}

// entries parses all config files and returns logrotate entries.
func (l *mqlLogrotate) entries(files []any) ([]any, error) {
	var allEntries []any
	var errs []error

	for i := range files {
		file := files[i].(*mqlFile)

		content := file.GetContent()
		if content.Error != nil {
			errs = append(errs, fmt.Errorf("failed to read %s: %w", file.Path.Data, content.Error))
			continue
		}

		if logrotateRejectsFile(l.MqlRuntime, content.Data) {
			continue
		}
		entries, err := parseLogrotateContent(l.MqlRuntime, file, content.Data)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse %s: %w", file.Path.Data, err))
			continue
		}

		allEntries = append(allEntries, entries...)
	}

	if len(errs) > 0 {
		return allEntries, errors.Join(errs...)
	}

	return allEntries, nil
}

func parseLogrotateContent(runtime *plugin.Runtime, file *mqlFile, content string) ([]any, error) {
	_, parsed := logrotate.ParseContent(file.Path.Data, content)
	var entries []any

	for _, e := range parsed {
		configMap := make(map[string]any, len(e.Config))
		for k, v := range e.Config {
			configMap[k] = v
		}

		entry, err := CreateResource(runtime, "logrotate.entry", map[string]*llx.RawData{
			"file":       llx.ResourceData(file, "file"),
			"lineNumber": llx.IntData(int64(e.LineNumber)),
			"path":       llx.StringData(e.Path),
			"config":     llx.MapData(configMap, types.String),
		})
		if err != nil {
			return nil, err
		}

		entries = append(entries, entry.(*mqlLogrotateEntry))
	}

	return entries, nil
}

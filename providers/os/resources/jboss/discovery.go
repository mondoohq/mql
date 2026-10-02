// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package jboss

import (
	"path"
	"regexp"
	"strings"

	"github.com/spf13/afero"
)

// HomeGlobs lists the directories a JBoss installation is commonly found in.
//
// A candidate is only accepted when it carries an installation marker, so an
// unrelated directory that happens to match cannot win. The list is broad on
// purpose: JBoss ships as a zip that is unpacked wherever the site wants it,
// and the vendor's own images disagree with each other — the Red Hat
// OpenShift image installs into /opt/eap, the community container images into
// /opt/jboss/wildfly, the Software Collections packages into
// /opt/rh/eap7/root/usr/share/wildfly.
var HomeGlobs = []string{
	"/opt/eap",
	"/opt/jboss/jboss-eap-*",
	"/opt/jboss/wildfly",
	"/opt/jboss/wildfly-*",
	"/opt/jboss/jboss-as-*",
	"/opt/jboss-eap-*",
	"/opt/jboss-as-*",
	"/opt/wildfly",
	"/opt/wildfly-*",
	"/opt/rh/eap*/root/usr/share/wildfly",
	"/opt/rh/eap*/root/usr/share/jbossas",
	"/usr/share/jbossas",
	"/usr/share/wildfly",
	"/usr/share/jboss-as",
	"/usr/share/jboss-eap-*",
	"/usr/local/jboss-eap-*",
	"/usr/local/wildfly*",
	"/srv/jboss-eap-*",
	"/srv/wildfly*",
	"/home/jboss/jboss-eap-*",
}

// HomeMarkers are the files that identify a directory as JBOSS_HOME.
//
// jboss-modules.jar is the reliable signal: every JBoss AS 7, EAP 6+ and
// WildFly installation boots through it and it sits at the top of the
// installation, while no instance or configuration directory carries it. The
// module repository and the startup script corroborate.
var HomeMarkers = []string{
	"jboss-modules.jar",
	"modules/system/layers/base",
	"bin/standalone.sh",
}

// SystemdUnitDirs lists the directories scanned for a unit that starts JBoss.
var SystemdUnitDirs = []string{
	"/etc/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// EnvConfigGlobs lists the files a distribution or a vendor package uses to
// declare JBOSS_HOME outside of a systemd unit.
var EnvConfigGlobs = []string{
	"/etc/default/wildfly",
	"/etc/default/jboss-eap*",
	"/etc/default/jbossas",
	"/etc/sysconfig/wildfly",
	"/etc/sysconfig/jboss-eap*",
	"/etc/sysconfig/jbossas",
	"/etc/wildfly/wildfly.conf",
	"/etc/jboss-eap/jboss-eap.conf",
	"/etc/jbossas/jbossas.conf",
	"/etc/opt/rh/eap*/wildfly.conf",
}

var (
	reHomeProp       = regexp.MustCompile(`-Djboss\.home\.dir=("[^"]+"|'[^']+'|\S+)`)
	reServerConfig   = regexp.MustCompile(`(?:--server-config=|--server-config\s+|-c\s+|-c=)("[^"]+"|'[^']+'|[\w.\-/]+)`)
	reDomainConfig   = regexp.MustCompile(`--domain-config[=\s]("[^"]+"|'[^']+'|[\w.\-/]+)`)
	reHostConfig     = regexp.MustCompile(`--host-config[=\s]("[^"]+"|'[^']+'|[\w.\-/]+)`)
	reStandaloneMain = regexp.MustCompile(`org\.jboss\.as\.standalone`)
	reDomainMain     = regexp.MustCompile(`org\.jboss\.as\.(?:process-controller|host-controller)`)
	reSecurityMgr    = regexp.MustCompile(`-Djava\.security\.manager(?:\s|=|$)`)
	reSecurityPolicy = regexp.MustCompile(`-Djava\.security\.policy=+("[^"]+"|'[^']+'|\S+)`)
	reSecmgrVar      = regexp.MustCompile(`^\s*(?:export\s+)?SECMGR\s*=\s*"?(\w+)"?`)
)

// IsJBossCommand reports whether a command line belongs to a JBoss server.
//
// The system property is matched with its `-D` prefix rather than as a bare
// substring, so an unrelated JVM that merely names a jboss path — a build, a
// client, a deployment tool — is not mistaken for the server.
func IsJBossCommand(cmd string) bool {
	return strings.Contains(cmd, "-Djboss.home.dir=") ||
		reStandaloneMain.MatchString(cmd) ||
		reDomainMain.MatchString(cmd) ||
		strings.Contains(cmd, "org.jboss.modules.Main") ||
		runsStartupScript(cmd, "standalone.sh") ||
		runsStartupScript(cmd, "domain.sh")
}

// runsStartupScript reports whether a command line *runs* one of the startup
// scripts, rather than merely mentioning it.
//
// The script has to be the program itself or the argument of a shell. An
// editor opening the file, a backup naming it, a grep searching it — all of
// them put the same path on a command line, and treating those as a running
// server would hand back a mode nobody selected.
func runsStartupScript(cmd string, script string) bool {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return false
	}

	for i, field := range fields {
		field = strings.Trim(field, `'"`)
		if field != script && !strings.HasSuffix(field, "/"+script) {
			continue
		}
		if i == 0 {
			return true
		}
		switch path.Base(strings.Trim(fields[0], `'"`)) {
		case "sh", "bash", "dash", "ksh", "zsh":
			return true
		}
		return false
	}
	return false
}

// SameHome reports whether two JBOSS_HOME values name the same directory. An
// empty value names none.
func SameHome(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return path.Clean(a) == path.Clean(b)
}

// HomeFromCommand extracts -Djboss.home.dir= from a running server's command
// line.
func HomeFromCommand(cmd string) string {
	if m := reHomeProp.FindStringSubmatch(cmd); m != nil {
		return unquote(m[1])
	}
	return ""
}

// LaunchTypeFromCommand reports whether a command line starts a standalone
// server or a domain host controller, and "" when it says neither.
func LaunchTypeFromCommand(cmd string) string {
	// The domain patterns are tested first: a host controller spawns its
	// managed servers with org.jboss.as.server, and the process controller's
	// own command line is the one that identifies the mode.
	if reDomainMain.MatchString(cmd) || runsStartupScript(cmd, "domain.sh") {
		return "domain"
	}
	if reStandaloneMain.MatchString(cmd) || runsStartupScript(cmd, "standalone.sh") {
		return "standalone"
	}
	return ""
}

// ConfigFromCommand extracts the configuration file selected on the command
// line: --server-config / -c in standalone mode, --domain-config and
// --host-config in domain mode.
func ConfigFromCommand(cmd string) (serverConfig string, domainConfig string, hostConfig string) {
	if m := reServerConfig.FindStringSubmatch(cmd); m != nil {
		serverConfig = unquote(m[1])
	}
	if m := reDomainConfig.FindStringSubmatch(cmd); m != nil {
		domainConfig = unquote(m[1])
	}
	if m := reHostConfig.FindStringSubmatch(cmd); m != nil {
		hostConfig = unquote(m[1])
	}
	return serverConfig, domainConfig, hostConfig
}

// HomeFromEnviron extracts JBOSS_HOME from the raw, NUL-separated contents of
// a process's environment.
func HomeFromEnviron(environ string) string {
	for _, entry := range strings.Split(environ, "\x00") {
		key, value, found := strings.Cut(entry, "=")
		if found && key == "JBOSS_HOME" {
			return value
		}
	}
	return ""
}

// IsJBossUnit reports whether a systemd unit file starts a JBoss server.
func IsJBossUnit(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart") && !strings.HasPrefix(line, "Environment") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "jboss") || strings.Contains(lower, "wildfly") || strings.Contains(lower, "eap") {
			return true
		}
	}
	return false
}

// PathsFromUnit extracts JBOSS_HOME and the launch mode from a systemd unit's
// Environment= assignments and its ExecStart line, and returns the paths of
// any EnvironmentFile= directives so the caller can read them too.
func PathsFromUnit(content string) (home string, launchType string, envFiles []string) {
	envFiles = []string{}

	for _, line := range strings.Split(content, "\n") {
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
				if ok && k == "JBOSS_HOME" {
					home = unquote(v)
				}
			}
		case "EnvironmentFile":
			// A leading '-' marks the file as optional; it is not part of the path.
			envFiles = append(envFiles, strings.TrimPrefix(unquote(value), "-"))
		case "ExecStart", "ExecStartPre":
			// The command is the value, not the whole line: the `ExecStart=`
			// prefix would otherwise be read as the program being run and a
			// script named after it would no longer be recognized.
			if h := HomeFromCommand(value); h != "" && home == "" {
				home = h
			}
			if lt := LaunchTypeFromCommand(value); lt != "" && launchType == "" {
				launchType = lt
			}
		}
	}

	return home, launchType, envFiles
}

// HomeFromEnvFile extracts JBOSS_HOME from a shell-style environment file — a
// unit's EnvironmentFile= target, /etc/default/wildfly, or the vendor's own
// bin/init.d/jboss-as.conf.
func HomeFromEnvFile(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(key) == "JBOSS_HOME" {
			return unquote(strings.TrimSpace(value))
		}
	}
	return ""
}

// PathsFromSystemd scans the systemd unit directories for a unit that starts
// JBoss and reads JBOSS_HOME and the launch mode out of it.
//
// With a non-empty want, only a unit whose JBOSS_HOME is that installation
// counts. A host can carry several installations, and the launch mode of a
// unit that runs one of them says nothing about the others.
func PathsFromSystemd(fs afero.Fs, want string) (string, string) {
	afs := &afero.Afero{Fs: fs}

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
			// A template unit resolves its instance from a %i that is only
			// bound when a named instance is started; reading it would yield a
			// literal "%i" path.
			if strings.Contains(name, "@.service") {
				continue
			}

			content, err := afs.ReadFile(path.Join(dir, name))
			if err != nil || !IsJBossUnit(string(content)) {
				continue
			}

			home, launchType, envFiles := PathsFromUnit(string(content))
			for _, envFile := range envFiles {
				if home != "" {
					break
				}
				envContent, err := afs.ReadFile(envFile)
				if err != nil {
					continue
				}
				home = HomeFromEnvFile(string(envContent))
			}

			if want != "" && !SameHome(home, want) {
				continue
			}
			if home != "" || launchType != "" {
				return home, launchType
			}
		}
	}

	return "", ""
}

// HomeFromEnvConfigs reads the distribution and vendor environment files that
// declare JBOSS_HOME without going through a unit file.
func HomeFromEnvConfigs(fs afero.Fs) string {
	afs := &afero.Afero{Fs: fs}

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
			if home := HomeFromEnvFile(string(content)); home != "" {
				return home
			}
		}
	}

	return ""
}

// IsInstallDir reports whether a directory is a JBOSS_HOME.
func IsInstallDir(fs afero.Fs, dir string) bool {
	for _, marker := range HomeMarkers {
		if pathExists(fs, path.Join(dir, marker)) {
			return true
		}
	}
	return false
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

// LaunchTypeFromDisk decides the operating mode from the trees an installation
// carries, for the case where nothing was running and no unit file said so.
//
// It only answers when the two trees disagree — one present, the other not. An
// installation that has both is not distinguishable this way and the caller
// falls back to standalone, which is what a JBoss installation runs as unless
// it is deliberately started with domain.sh.
func LaunchTypeFromDisk(fs afero.Fs, home string) string {
	if home == "" {
		return ""
	}
	standalone := pathExists(fs, path.Join(home, "standalone", "configuration"))
	domain := pathExists(fs, path.Join(home, "domain", "configuration"))
	switch {
	case standalone && !domain:
		return "standalone"
	case domain && !standalone:
		return "domain"
	default:
		return ""
	}
}

var reVersionLine = regexp.MustCompile(`(?i)^(.*?)\s*-\s*Version\s+(\S+)\s*$`)

// ParseVersionFile reads the product name and version out of the version.txt
// an installation ships, e.g.
//
//	Red Hat JBoss Enterprise Application Platform - Version 6.4.23.GA
//	WildFly Full - Version 26.1.3.Final
func ParseVersionFile(content string) (product string, version string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := reVersionLine.FindStringSubmatch(line); m != nil {
			return strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
		}
	}
	return "", ""
}

var reManifestProduct = regexp.MustCompile(`(?mi)^JBoss-Product-Release-Name:\s*(.+?)\s*$`)
var reManifestVersion = regexp.MustCompile(`(?mi)^JBoss-Product-Release-Version:\s*(.+?)\s*$`)

// ParseProductManifest reads the product name and version out of the
// MANIFEST.MF of a product module. It is the fallback for installations that
// ship no version.txt, which is the case for a plain WildFly zip.
func ParseProductManifest(content string) (product string, version string) {
	if m := reManifestProduct.FindStringSubmatch(content); m != nil {
		product = strings.TrimSpace(m[1])
	}
	if m := reManifestVersion.FindStringSubmatch(content); m != nil {
		version = strings.TrimSpace(m[1])
	}
	return product, version
}

// VersionJarGlob locates the module that carries the server's own version.
//
// A community WildFly ships no version.txt and no product module, but it does
// name the version in the file name of this jar — so the version is readable
// without opening an archive, which is far more expensive than the answer is
// worth.
const VersionJarGlob = "modules/system/layers/base/org/jboss/as/version/main/*-version-*.jar"

var reVersionJar = regexp.MustCompile(`^(wildfly|jboss-as)-version-(.+)\.jar$`)

// ParseVersionJarName reads the product name and version out of the version
// module's file name, e.g. wildfly-version-8.2.1.Final.jar.
func ParseVersionJarName(name string) (product string, version string) {
	m := reVersionJar.FindStringSubmatch(path.Base(name))
	if m == nil {
		return "", ""
	}
	switch m[1] {
	case "wildfly":
		product = "WildFly"
	case "jboss-as":
		product = "JBoss AS"
	}
	return product, m[2]
}

// ProductVersionFromJars picks the product identity out of the version
// module's contents.
//
// WildFly ships two of these jars side by side — it kept the jboss-as name for
// compatibility — and only the wildfly one names the product correctly, so it
// wins when both are present.
func ProductVersionFromJars(names []string) (string, string) {
	fallbackProduct, fallbackVersion := "", ""
	for _, name := range names {
		product, version := ParseVersionJarName(name)
		if version == "" {
			continue
		}
		if product == "WildFly" {
			return product, version
		}
		if fallbackVersion == "" {
			fallbackProduct, fallbackVersion = product, version
		}
	}
	return fallbackProduct, fallbackVersion
}

var reInstallDirVersion = regexp.MustCompile(`^(?:jboss-eap-|jboss-as-|wildfly-)([0-9]+(?:\.[0-9]+)*[0-9A-Za-z.\-]*)$`)

// VersionFromInstallDir reads the version out of an unpacked distribution's
// directory name, e.g. /opt/jboss/jboss-eap-6.3.
func VersionFromInstallDir(home string) string {
	if home == "" {
		return ""
	}
	if m := reInstallDirVersion.FindStringSubmatch(path.Base(home)); m != nil {
		return m[1]
	}
	return ""
}

// StartupConfig is what a bin/standalone.conf or bin/domain.conf declares that
// matters to a configuration review.
type StartupConfig struct {
	// JavaOpts are the JVM options, in declaration order.
	JavaOpts []string
	// SecurityManager reports whether the Java Security Manager is turned on,
	// either through SECMGR=true or through -Djava.security.manager.
	SecurityManager bool
	// SecurityPolicy is the policy file named with -Djava.security.policy.
	SecurityPolicy string
}

// ParseStartupConfig reads a bin/standalone.conf or bin/domain.conf.
//
// The file is a shell script, so this does not try to evaluate it. It collects
// what is written down: every JAVA_OPTS assignment in order, and the two
// settings that turn the Security Manager on. Commented-out lines are skipped,
// which matters because the shipped file carries the interesting options as
// commented examples.
func ParseStartupConfig(content string) StartupConfig {
	res := StartupConfig{JavaOpts: []string{}}

	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if m := reSecmgrVar.FindStringSubmatch(trimmed); m != nil {
			if strings.EqualFold(m[1], "true") {
				res.SecurityManager = true
			}
			continue
		}

		stripped := strings.TrimPrefix(trimmed, "export ")
		key, value, found := strings.Cut(stripped, "=")
		if !found || strings.TrimSpace(key) != "JAVA_OPTS" {
			continue
		}
		for _, opt := range splitShellWords(value) {
			// A JVM option starts with a dash. Everything else in the
			// assignment is shell — the JAVA_OPTS="$JAVA_OPTS …" self-append
			// the shipped file is built from, and the command substitutions
			// the vendor images add around it — and is not an option.
			if !strings.HasPrefix(opt, "-") {
				continue
			}
			res.JavaOpts = append(res.JavaOpts, opt)
			if reSecurityMgr.MatchString(opt) {
				res.SecurityManager = true
			}
			if m := reSecurityPolicy.FindStringSubmatch(opt); m != nil {
				res.SecurityPolicy = unquote(m[1])
			}
		}
	}

	return res
}

func pathExists(fs afero.Fs, p string) bool {
	// Stat follows symlinks, which the packaged layouts depend on: a Software
	// Collections install reaches its configuration through a symlink into
	// /etc.
	_, err := fs.Stat(p)
	return err == nil
}

// splitShellWords splits the right-hand side of a shell assignment into the
// words it holds.
//
// A shell assignment usually wraps the whole option list in one pair of
// quotes — JAVA_OPTS="-Xms64m -Xmx512m" — and those are still two options, so
// an enclosing pair is removed before the value is tokenized. Quotes that
// remain, around a single option carrying a space, keep their grouping.
func splitShellWords(value string) []string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		inner := value[1 : len(value)-1]
		if !strings.ContainsRune(inner, rune(value[0])) {
			value = inner
		}
	}
	return splitUnitEnvironment(value)
}

// splitUnitEnvironment splits a shell or systemd assignment value into its
// individual words, honoring the quoting allowed around each one.
func splitUnitEnvironment(value string) []string {
	res := []string{}
	var cur strings.Builder
	var quote byte
	quoted := false

	flush := func() {
		if cur.Len() > 0 || quoted {
			res = append(res, cur.String())
			cur.Reset()
			quoted = false
		}
	}

	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case quote != 0:
			// A backslash escapes the quote character, and itself, inside a
			// quoted value. Without this the escaped quote is read as the
			// closing one and the value is silently truncated at that point.
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
			quoted = true
		case c == ' ' || c == '\t':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()

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

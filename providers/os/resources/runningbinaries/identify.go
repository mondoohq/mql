// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"bufio"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/resources/packages"
	"golang.org/x/mod/module"
	"howett.net/plist"
)

// Version sources, as binary.versionSource reports them.
const (
	SourceGoBuildInfo     = "goBuildInfo"
	SourcePEVersionInfo   = "peVersionInfo"
	SourceVersionString   = "versionString"
	SourceInstallMetadata = "installMetadata"
	SourceBundleInfo      = "bundleInfo"
)

// Identity is what a binary identifies as. An empty Version means no
// version was found, and VersionSource is empty with it.
type Identity struct {
	Name          string
	Version       string
	VersionSource string
	Vendor        string
}

// knownRuntime is software recognized by its executable's file name, whose
// version is read from a file shipped beside it or from a string inside it.
type knownRuntime struct {
	// name is the software name reported for it
	name string
	// matches the executable's file name, lower case without .exe
	fileName *regexp.Regexp
	// metadata reads the version from a file installed beside the binary
	metadata func(fs afero.Fs, path string) (version, vendor string, ok bool)
	// versionString returns the pattern that finds the version inside the
	// binary, in the first of its groups that matched, nil when there is
	// none for this file name
	versionString func(fileName string) *regexp.Regexp
}

// The version strings below are checked against the released binaries:
// node 22.22.0 (official tarball), php 8.3.6 (Ubuntu php8.3-cli),
// python 3.13.16 (python3.13), and the binaries of the official container
// images of nginx 1.31.8, httpd 2.4.69, PostgreSQL 18.6, MySQL 8.4.13 and
// 26.10.0, MariaDB 10.6.28, 10.11.19 and 13.0.2, Redis 6.2.24, 7.4.11 and
// 8.10.2, HAProxy 2.8.31 and 3.4.7, memcached 1.6.45, Ruby 3.3.12 and 4.0.8
// and Perl 5.44.0, and the packages of Debian 13, Ubuntu 24.04 and Alpine
// 3.22.
var knownRuntimes = []knownRuntime{
	{
		name:     "node",
		fileName: regexp.MustCompile(`^node$`),
		metadata: nodeVersionHeader,
		versionString: func(string) *regexp.Regexp {
			// part of the default user agent, e.g. "node.js/v22.22.0"
			return regexp.MustCompile(`node\.js/v(\d+\.\d+\.\d+)`)
		},
	},
	{
		name: "php",
		// php, php8.3, php-fpm, php-fpm8.3, php-cgi, php-cgi8.3
		fileName: regexp.MustCompile(`^php(-fpm|-cgi)?\d*(\.\d+)?$`),
		versionString: func(string) *regexp.Regexp {
			// the X-Powered-By header every SAPI sends, e.g. "X-Powered-By: PHP/8.3.6"
			return regexp.MustCompile(`X-Powered-By: PHP/(\d+\.\d+\.\d+(?:(?:alpha|beta|RC)\d+)?)`)
		},
	},
	{
		name:     "python",
		fileName: regexp.MustCompile(`^python\d+\.\d+$`),
		versionString: func(fileName string) *regexp.Regexp {
			// PY_VERSION, a NUL-terminated string such as "3.13.16". The bare
			// pattern matches any dotted triple, so it is anchored on the
			// major and minor version the file name carries.
			minor := strings.TrimPrefix(fileName, "python")
			return regexp.MustCompile(`\x00(` + regexp.QuoteMeta(minor) + `\.\d+(?:(?:a|b|rc)\d+)?\+?)\x00`)
		},
	},
	{
		name:     "openjdk",
		fileName: regexp.MustCompile(`^javaw?$`),
		metadata: javaReleaseFile,
	},
	{
		name:     "nginx",
		fileName: regexp.MustCompile(`^nginx$`),
		versionString: fixedPattern(
			// what nginx -v prints
			`nginx version: nginx/(\d+\.\d+\.\d+)`),
	},
	{
		name:     "httpd",
		fileName: regexp.MustCompile(`^(httpd|apache2)$`),
		versionString: fixedPattern(
			// the server banner without the platform, "Apache/2.4.69"; the
			// banners with fewer parts, "Apache/2.4", are left out by the
			// three-part version
			`\x00Apache/(\d+\.\d+\.\d+)\x00`),
	},
	{
		name:     "postgresql",
		fileName: regexp.MustCompile(`^postgres$`),
		versionString: fixedPattern(
			// what postgres --version prints, "postgres (PostgreSQL) 18.6",
			// a two-part version since PostgreSQL 10
			`postgres \(PostgreSQL\) (\d+(?:\.\d+){0,2}(?:(?:alpha|beta|rc)\d+|devel)?)[ \n]`),
	},
	{
		name:     "mysql",
		fileName: regexp.MustCompile(`^mysqld$`),
		versionString: fixedPattern(
			// the server version, stored before the compilation comment
			// ("MySQL Community Server - GPL") since MySQL 8.4. MySQL 8.0
			// keeps it apart from any string to anchor on.
			`\x00(\d+\.\d+\.\d+)\x00+MySQL (?:Community|Enterprise|Cluster) Server`),
	},
	{
		name:     "mariadb",
		fileName: regexp.MustCompile(`^mariadbd$`),
		versionString: fixedPattern(
			// the server version, "13.0.2-MariaDB", before the packager's
			// suffix is appended at run time
			`\x00(\d+\.\d+\.\d+)-MariaDB\x00`),
	},
	{
		name: "redis",
		// Debian installs redis-server as a link to redis-check-rdb, the
		// file the process runs
		fileName: regexp.MustCompile(`^redis-(server|check-rdb)$`),
		versionString: fixedPattern(
			// REDIS_VERSION, stored before the format of the INFO command's
			// server section, or in recent builds before the ASCII art logo
			// redis logs at startup. The raw build id carries the version
			// too, but runs it into the build host's name, which may start
			// with a digit.
			`\x00(\d+\.\d+\.\d+)\x00+(?:# Server\r\nredis_version:| +_\._ )`),
	},
	{
		name:     "haproxy",
		fileName: regexp.MustCompile(`^haproxy$`),
		versionString: fixedPattern(
			// " version 3.4.7-8872a26, released 2026/10/14", from haproxy -vv;
			// the release without the commit or a packager's revision
			`version (\d+\.\d+(?:\.\d+|-dev\d+)?)(?:[-+~][0-9A-Za-z.+~-]*)?, released \d{4}/\d{2}/\d{2}`),
	},
	{
		name:     "memcached",
		fileName: regexp.MustCompile(`^memcached$`),
		versionString: fixedPattern(
			// what memcached -V prints
			`\x00memcached (\d+\.\d+\.\d+)[\n\x00]`),
	},
	{
		name: "ruby",
		// ruby, and ruby3.1 as Debian names it
		fileName: regexp.MustCompile(`^ruby(\d+\.\d+)?$`),
		metadata: rubyPkgConfig,
		versionString: fixedPattern(
			// RUBY_DESCRIPTION, what ruby -v prints, in a ruby built without
			// a shared libruby: "ruby 4.0.8 (2026-10-22 revision 60c3d71bfb)",
			// or "ruby 2.7.8p225 (...)" with a patch level before 3.0
			`ruby (\d+\.\d+\.\d+(?:preview\d+|rc\d+)?)(?:p\d+)? \(\d{4}-\d{2}-\d{2} (?:revision|patchlevel)`),
	},
	{
		name:     "perl",
		fileName: regexp.MustCompile(`^perl(5[\d.]*)?$`),
		versionString: fixedPattern(
			// a perl linked to a shared libperl finds it through its run
			// path, <prefix>/lib/perl5/5.44.0/<arch>/CORE; a static one
			// carries the version as "v5.44.0"
			`/(5\.\d+\.\d+)/[^\x00/]+/CORE\x00|\x00v(5\.\d+\.\d+)\x00`),
	},
}

// fixedPattern is a versionString for software whose pattern does not
// depend on the file name.
func fixedPattern(expr string) func(string) *regexp.Regexp {
	re := regexp.MustCompile(expr)
	return func(string) *regexp.Regexp { return re }
}

// Identify reads what the binary is from the file, without running it. fs
// may be nil when the connection cannot read files; then only what the
// process listing carried is used.
func Identify(fs afero.Fs, b Binary) Identity {
	fileName := executableName(b.Path)

	if fs != nil {
		// A release build stamps its version with linker flags rather than
		// tagging its module, which leaves the build information with only a
		// pseudo-version, such as v0.0.0-20261008172703-eab0c2d0a9e9 for
		// cnspec 14.4.0. The Windows version resource then knows better.
		if id, ok := goIdentity(fs, b); ok && (goReleaseVersion(id.Version) || peVersion(b.VersionInfo) == "") {
			return id
		}
	}

	var runtime *knownRuntime
	for i := range knownRuntimes {
		if knownRuntimes[i].fileName.MatchString(fileName) {
			runtime = &knownRuntimes[i]
			break
		}
	}

	if runtime == nil && b.VersionInfo == nil && fs != nil {
		if id, ok := bundleIdentity(fs, b.Path); ok {
			return id
		}
	}

	id := Identity{Name: fileName}
	if runtime != nil {
		id.Name = runtime.name
	} else if name := peName(b.VersionInfo); name != "" {
		id.Name = name
	}
	if b.VersionInfo != nil {
		id.Vendor = b.VersionInfo.CompanyName
	}

	switch {
	case runtime != nil && runtime.metadata != nil && fs != nil && id.fromMetadata(fs, b.Path, runtime):
	case b.VersionInfo != nil && peVersion(b.VersionInfo) != "":
		id.Version = peVersion(b.VersionInfo)
		id.VersionSource = SourcePEVersionInfo
	case runtime != nil && runtime.versionString != nil && fs != nil:
		if v, ok := scanVersionString(fs, b, runtime.versionString(fileName)); ok {
			id.Version = v
			id.VersionSource = SourceVersionString
		}
	}

	// MariaDB 10.0 and later and XAMPP's MariaDB 10.1 still run as mysqld.
	// The same rules as the Windows package scan decide: the version
	// resource's product name first, then the version (MySQL went from 5.7 to
	// 8.0). A mysqld they can't classify stays mysql. The mariadbd.exe sibling
	// the package scan also uses is not looked at here, since mariadbd is its
	// own known runtime.
	if runtime != nil && runtime.name == "mysql" {
		productName := ""
		if b.VersionInfo != nil {
			productName = b.VersionInfo.ProductName
		}
		if mariadb, ok := packages.IsMariaDBServer(productName, id.Version); ok && mariadb {
			id.Name = "mariadb"
		}
	}

	return id
}

func (id *Identity) fromMetadata(fs afero.Fs, path string, runtime *knownRuntime) bool {
	version, vendor, ok := runtime.metadata(fs, path)
	if !ok {
		return false
	}
	id.Version = version
	id.VersionSource = SourceInstallMetadata
	if vendor != "" {
		id.Vendor = vendor
	}
	return true
}

// executableName is the file name of an executable, lower case and without
// a Windows .exe extension.
func executableName(p string) string {
	name := p[strings.LastIndexAny(p, `/\`)+1:]
	name = strings.ToLower(name)
	return strings.TrimSuffix(name, ".exe")
}

// dirOf returns the directory of p, for either path separator, and the
// separator it uses.
func dirOf(p string) (string, string) {
	i := strings.LastIndexAny(p, `/\`)
	if i < 0 {
		return "", "/"
	}
	return p[:i], p[i : i+1]
}

// goIdentity reads the build information the Go toolchain embeds in every
// binary it links. The main module's path names the software. Only the main
// module is reported: the dependency modules compiled into the binary are
// not running software of their own.
func goIdentity(fs afero.Fs, b Binary) (Identity, bool) {
	f, err := openContent(fs, b)
	if err != nil {
		return Identity{}, false
	}
	defer f.Close()

	info, err := buildinfo.Read(f)
	if err != nil {
		return Identity{}, false
	}
	if info.Main.Path == "" {
		return goToolchainIdentity(info)
	}

	id := Identity{Name: info.Main.Path}
	// "(devel)" is what a build from a source checkout records: no version
	if v := info.Main.Version; v != "" && v != "(devel)" {
		id.Version = v
		id.VersionSource = SourceGoBuildInfo
	}
	return id, true
}

// goReleaseVersion reports whether v is a version a module was tagged with,
// not a pseudo-version for an untagged commit.
func goReleaseVersion(v string) bool {
	return v != "" && !module.IsPseudoVersion(v)
}

// goToolchainIdentity identifies a command of the Go distribution, such as
// go or gofmt. It is built from the standard library alone, records no main
// module, and is versioned with the toolchain that built it.
func goToolchainIdentity(info *buildinfo.BuildInfo) (Identity, bool) {
	if !strings.HasPrefix(info.Path, "cmd/") {
		return Identity{}, false
	}
	id := Identity{Name: "go"}
	if v, ok := strings.CutPrefix(info.GoVersion, "go"); ok && v != "" {
		// a toolchain built from source records "devel go1.x-<hash>"
		if !strings.Contains(v, " ") {
			id.Version = v
			id.VersionSource = SourceGoBuildInfo
		}
	}
	return id, true
}

// bundleIdentity reads the Info.plist of the macOS bundle (an application,
// app extension, XPC service or helper app) whose executable p is: the
// bundle's name and the version it shows users. A bundle without a version
// identifies nothing beyond the file name.
func bundleIdentity(fs afero.Fs, p string) (Identity, bool) {
	bundle, executable, ok := strings.CutLast(p, bundleExecutableDir)
	if !ok || bundle == "" || strings.Contains(executable, "/") {
		return Identity{}, false
	}
	f, err := fs.Open(bundle + "/Contents/Info.plist")
	if err != nil {
		return Identity{}, false
	}
	defer f.Close()
	// an Info.plist is a few kilobytes; the limit keeps a damaged one from
	// being read whole
	data, err := io.ReadAll(io.LimitReader(f, maxInfoPlist))
	if err != nil {
		return Identity{}, false
	}
	var info struct {
		Name        string `plist:"CFBundleName"`
		DisplayName string `plist:"CFBundleDisplayName"`
		Version     string `plist:"CFBundleShortVersionString"`
	}
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return Identity{}, false
	}
	version := strings.TrimSpace(info.Version)
	if version == "" {
		return Identity{}, false
	}
	id := Identity{Name: executableName(p), Version: version, VersionSource: SourceBundleInfo}
	for _, name := range []string{info.Name, info.DisplayName} {
		if name = strings.TrimSpace(name); name != "" {
			id.Name = name
			break
		}
	}
	return id, true
}

// bundleExecutableDir is where a macOS bundle keeps its executable.
const bundleExecutableDir = "/Contents/MacOS/"

const maxInfoPlist = 1 << 20

// openContent opens the running file: the content path when there is one,
// which outlives a file replaced at its path, otherwise the path.
func openContent(fs afero.Fs, b Binary) (afero.File, error) {
	if b.ContentPath != "" {
		if f, err := fs.Open(b.ContentPath); err == nil {
			return f, nil
		}
	}
	return fs.Open(b.Path)
}

// SHA256 returns the lower-case hex SHA-256 digest of the running file.
func SHA256(fs afero.Fs, b Binary) (string, error) {
	f, err := openContent(fs, b)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// maxVersionScan bounds how much of a binary is read looking for a version
// string. The node binary carries its version 50 MB into 123 MB.
const maxVersionScan = 256 << 20

func scanVersionString(fs afero.Fs, b Binary, re *regexp.Regexp) (string, bool) {
	f, err := openContent(fs, b)
	if err != nil {
		return "", false
	}
	defer f.Close()
	v, err := findInReader(f, re, maxVersionScan)
	if err != nil {
		return "", false
	}
	return v, v != ""
}

const (
	scanChunk = 1 << 20
	// scanOverlap is carried from one chunk into the next so a version
	// string that straddles the chunk boundary is still found whole.
	scanOverlap = 256
)

// findInReader returns the first group that matched in re's first match
// within the first limit bytes of r, or "" when there is none.
func findInReader(r io.Reader, re *regexp.Regexp, limit int64) (string, error) {
	buf := make([]byte, 0, scanChunk+scanOverlap)
	chunk := make([]byte, scanChunk)
	var read int64
	for read < limit {
		n, err := io.ReadFull(r, chunk[:min(int64(scanChunk), limit-read)])
		read += int64(n)
		buf = append(buf, chunk[:n]...)
		if m := re.FindSubmatch(buf); len(m) > 1 {
			for _, group := range m[1:] {
				if len(group) > 0 {
					return string(group), nil
				}
			}
		}
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if len(buf) > scanOverlap {
			buf = append(buf[:0], buf[len(buf)-scanOverlap:]...)
		}
	}
	return "", nil
}

// peVersion is the version of a Windows version resource: the product
// version, else the file version. Both are free text. A file version often
// carries a build tag after a space, "10.0.17763.1 (WinBuild.160101.0800)",
// and older resources separate the parts with commas, "1, 0, 0, 1".
func peVersion(vi *PEVersionInfo) string {
	if vi == nil {
		return ""
	}
	v := vi.ProductVersion
	if v == "" {
		v = vi.FileVersion
	}
	v = strings.TrimSpace(v)
	if strings.Contains(v, ",") {
		v = strings.ReplaceAll(v, " ", "")
		v = strings.ReplaceAll(v, ",", ".")
		return v
	}
	v, _, _ = strings.Cut(v, " ")
	return v
}

// nodeVersionHeader reads the version from the node_version.h header the
// node distribution installs beside its binary, <prefix>/bin/node and
// <prefix>/include/node/node_version.h.
func nodeVersionHeader(fs afero.Fs, path string) (string, string, bool) {
	bin, sep := dirOf(path)
	prefix, _ := dirOf(bin)
	f, err := fs.Open(prefix + sep + "include" + sep + "node" + sep + "node_version.h")
	if err != nil {
		return "", "", false
	}
	defer f.Close()
	v, ok := parseNodeVersionHeader(f)
	return v, "", ok
}

var nodeVersionDefine = regexp.MustCompile(`^#define NODE_(MAJOR|MINOR|PATCH)_VERSION (\d+)\s*$`)

func parseNodeVersionHeader(r io.Reader) (string, bool) {
	parts := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if m := nodeVersionDefine.FindStringSubmatch(scanner.Text()); m != nil {
			if _, ok := parts[m[1]]; !ok {
				parts[m[1]] = m[2]
			}
		}
	}
	if parts["MAJOR"] == "" || parts["MINOR"] == "" || parts["PATCH"] == "" {
		return "", false
	}
	return parts["MAJOR"] + "." + parts["MINOR"] + "." + parts["PATCH"], true
}

// javaReleaseFile reads the release file at the root of a Java runtime,
// <home>/bin/java and <home>/release. A Java 8 JDK runs its JRE's binary,
// <home>/jre/bin/java, with the release file one directory further up.
func javaReleaseFile(fs afero.Fs, path string) (string, string, bool) {
	bin, sep := dirOf(path)
	home, _ := dirOf(bin)
	for range 2 {
		if home == "" {
			break
		}
		if f, err := fs.Open(home + sep + "release"); err == nil {
			version, vendor, ok := parseJavaRelease(f)
			f.Close()
			if ok {
				return version, vendor, true
			}
		}
		home, _ = dirOf(home)
	}
	return "", "", false
}

// rubyPkgConfig reads the version from the pkg-config file ruby installs,
// <prefix>/lib/pkgconfig/ruby-4.0.pc, whose MAJOR, MINOR and TEENY are the
// version. A ruby linked to a shared libruby carries no version of its own.
// The file is ruby's when its RUBY_INSTALL_NAME is the binary's name.
func rubyPkgConfig(fs afero.Fs, path string) (string, string, bool) {
	bin, sep := dirOf(path)
	prefix, _ := dirOf(bin)
	if prefix == "" {
		return "", "", false
	}
	dir := prefix + sep + "lib" + sep + "pkgconfig"
	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		return "", "", false
	}
	name := path[strings.LastIndexAny(path, `/\`)+1:]
	for _, e := range entries {
		if !rubyPkgConfigName.MatchString(e.Name()) {
			continue
		}
		f, err := fs.Open(dir + sep + e.Name())
		if err != nil {
			continue
		}
		version, installName := parseRubyPkgConfig(f)
		f.Close()
		if version != "" && installName == name {
			return version, "", true
		}
	}
	return "", "", false
}

var rubyPkgConfigName = regexp.MustCompile(`^ruby(-\d+\.\d+)?\.pc$`)

// parseRubyPkgConfig reads the version, MAJOR.MINOR.TEENY, and
// RUBY_INSTALL_NAME from ruby's pkg-config file, whose values refer to
// other variables as ${name}.
func parseRubyPkgConfig(r io.Reader) (version, installName string) {
	vars := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if key, value, ok := strings.Cut(scanner.Text(), "="); ok {
			vars[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	expand := func(v string) string {
		// a few rounds resolve the nesting ruby writes, and end a cycle
		for range 4 {
			v = pkgConfigVar.ReplaceAllStringFunc(v, func(ref string) string {
				return vars[ref[2:len(ref)-1]]
			})
		}
		return v
	}
	major, minor, teeny := expand(vars["MAJOR"]), expand(vars["MINOR"]), expand(vars["TEENY"])
	installName = expand(vars["RUBY_INSTALL_NAME"])
	if major == "" || minor == "" || teeny == "" {
		return "", installName
	}
	return major + "." + minor + "." + teeny, installName
}

var pkgConfigVar = regexp.MustCompile(`\$\{[A-Za-z0-9_]+\}`)

// parseJavaRelease reads JAVA_VERSION and IMPLEMENTOR from a Java release
// file, KEY="value" lines.
func parseJavaRelease(r io.Reader) (string, string, bool) {
	var version, vendor string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch strings.TrimSpace(key) {
		case "JAVA_VERSION":
			version = value
		case "IMPLEMENTOR":
			vendor = value
		}
	}
	return version, vendor, version != ""
}

// peName is the name a version resource gives its file: the product's name,
// or the file's description for a component of Windows, whose product name
// is the operating system's. It is empty for a component without a
// description, which the file's own name then describes better.
func peName(vi *PEVersionInfo) string {
	if vi == nil {
		return ""
	}
	if windowsProductName(vi.ProductName) {
		return vi.FileDescription
	}
	return vi.ProductName
}

// windowsProductName reports whether name is the product name the
// components of Windows carry, "Microsoft® Windows® Operating System", in
// any of its spellings.
func windowsProductName(name string) bool {
	name = strings.NewReplacer("®", " ", "(R)", " ", "(r)", " ").Replace(name)
	return strings.EqualFold(strings.Join(strings.Fields(name), " "), "Microsoft Windows Operating System")
}

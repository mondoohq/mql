// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/purl"
	plist "howett.net/plist"
)

// macOSJavaVMDir is where the JDK and JRE installers of every vendor (Azul
// Zulu, Eclipse Temurin, Amazon Corretto, Oracle, Microsoft) put their
// bundle, and where /usr/libexec/java_home looks for one.
const macOSJavaVMDir = "/Library/Java/JavaVirtualMachines"

// macOSJavaUserVMDir is the per-user counterpart under a home directory.
// java_home lists it too, and IntelliJ IDEA downloads JDKs into it.
const macOSJavaUserVMDir = "Library/Java/JavaVirtualMachines"

// macOSJavaAppletPlugin is where Oracle's Java 8 JRE installer (java.com)
// installs the runtime. It is a browser plug-in bundle with a full JRE under
// Contents/Home, and it is the only place that JRE exists.
const macOSJavaAppletPlugin = "/Library/Internet Plug-Ins/JavaAppletPlugin.plugin"

// javaInfoPlist holds the keys we read from a Java bundle's Contents/Info.plist.
type javaInfoPlist struct {
	BundleID   string `plist:"CFBundleIdentifier"`
	BundleName string `plist:"CFBundleName"`
	Executable string `plist:"CFBundleExecutable"`
	JavaVM     struct {
		JVMVendor  string `plist:"JVMVendor"`
		JVMVersion string `plist:"JVMVersion"`
	} `plist:"JavaVM"`
}

// javaRelease holds the keys we read from a Java runtime's Contents/Home/release.
type javaRelease struct {
	implementor string
	javaVersion string
	osArch      string
}

// macOSJavaPackages lists the Java runtimes installed as bundles: the JDKs and
// JREs in /Library/Java/JavaVirtualMachines and each user's
// ~/Library/Java/JavaVirtualMachines, and Oracle's Java 8 JRE in the applet
// plug-in. None of them is an application bundle, so neither system_profiler
// nor the application folders see them, and a Mac running only a vendor JDK
// would otherwise report no Java at all.
//
// Symbolic links are skipped. Homebrew's openjdk formula tells users to link
// its bundle into /Library/Java/JavaVirtualMachines, and a link always points
// at a runtime that another package manager owns and reports.
func macOSJavaPackages(conn shared.Connection, platform *inventory.Platform) []Package {
	if conn == nil {
		return nil
	}
	fs := conn.FileSystem()

	dirs := []string{macOSJavaVMDir}
	if users, err := readDirNames(fs, usersRoot); err == nil {
		for _, user := range users {
			if strings.HasPrefix(user, ".") {
				continue
			}
			dirs = append(dirs, path.Join(usersRoot, user, macOSJavaUserVMDir))
		}
	}

	var pkgs []Package
	for _, dir := range dirs {
		entries, err := readDirEntries(fs, dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if skipFolderEntry(entry) || !entry.IsDir() {
				continue
			}
			if pkg, ok := macOSJavaPackage(conn, platform, path.Join(dir, entry.Name())); ok {
				pkgs = append(pkgs, pkg)
			}
		}
	}
	if fi, err := fs.Stat(macOSJavaAppletPlugin); err == nil && fi.IsDir() {
		if pkg, ok := macOSJavaPackage(conn, platform, macOSJavaAppletPlugin); ok {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs
}

// macOSJavaPackage reads one Java bundle. It reports false for a directory
// that holds no Java runtime, or one whose Java version cannot be read.
func macOSJavaPackage(conn shared.Connection, platform *inventory.Platform, bundle string) (Package, bool) {
	fs := conn.FileSystem()
	info, hasInfo := readJavaInfoPlist(conn, path.Join(bundle, "Contents", "Info.plist"))
	release, hasRelease := readJavaRelease(conn, path.Join(bundle, "Contents", "Home", "release"))
	if !hasInfo && !hasRelease {
		return Package{}, false
	}

	// JVMVersion is the Java version in every vendor's plist ("17.0.21",
	// "17.0.21.0.3" for Zulu, "1.8.0_512" for Java 8). The release file states
	// the same value and is the only source in Oracle's applet plug-in, which
	// has no JavaVM dictionary. The bundle versions are not used: Zulu 8 and
	// Temurin 8 set CFBundleShortVersionString to "1.0", and CFBundleVersion is
	// a build number ("1", "9") for most vendors.
	version := strings.TrimSpace(info.JavaVM.JVMVersion)
	if version == "" {
		version = release.javaVersion
	}
	if !looksLikeVersion(version) {
		log.Debug().Str("path", bundle).Str("version", version).
			Msg("skipping Java bundle without a Java version")
		return Package{}, false
	}

	// A JDK ships javac, a JRE does not. Java 8 JDKs carry a whole JRE under
	// Contents/Home/jre, which is part of the JDK and not reported apart.
	jdk := false
	if _, err := fs.Stat(path.Join(bundle, "Contents", "Home", "bin", "javac")); err == nil {
		jdk = true
	}

	vendor := info.JavaVM.JVMVendor
	if vendor == "" {
		vendor = release.implementor
	}
	name := javaPackageName(vendor, info, jdk, bundle)

	arch := javaArch(conn, platform, bundle, info, release)
	scope, user := appInstallScope(bundle)
	app := &MacOSApp{BundleID: info.BundleID}
	qualifiers := map[string]string{}
	addMacOSPurlQualifiers(qualifiers, app, scope)

	return Package{
		Name:    name,
		Version: version,
		Format:  MacosPkgFormat,
		Arch:    arch,
		PUrl: purl.NewPackageURL(
			platform, purl.TypeMacos, name, version,
			purl.WithArch(arch),
			purl.WithQualifiers(qualifiers),
		).String(),
		MacOS:        app,
		InstallScope: scope,
		InstallUser:  user,
		Files:        []FileRecord{{Path: bundle}},
	}, true
}

// javaDistribution names a vendor's Java build, as a JDK and as a JRE.
type javaDistribution struct {
	jdk string
	jre string
}

// javaVendors maps the vendor a Java bundle names (JavaVM.JVMVendor in its
// Info.plist, or IMPLEMENTOR in its release file) to its distribution. The
// values are copied from the vendors' macOS builds.
//
// The vendor is needed because CFBundleName cannot name the package. It carries
// a version for most vendors ("Zulu 17.70.113", "OpenJDK 17.0.21", "Java SE
// 21.0.5"), so every update would become a new package name, and Temurin and
// Microsoft both call their builds "OpenJDK <version>" with the bundle
// identifier net.java.openjdk.jdk. Only the vendor tells them apart.
var javaVendors = map[string]javaDistribution{
	"Azul Systems, Inc.": {jdk: "Azul Zulu JDK", jre: "Azul Zulu JRE"},
	"Eclipse Adoptium":   {jdk: "Eclipse Temurin JDK", jre: "Eclipse Temurin JRE"},
	// Temurin 8 names itself rather than the Adoptium project.
	"Eclipse Temurin": {jdk: "Eclipse Temurin JDK", jre: "Eclipse Temurin JRE"},
	"Amazon.com Inc.": {jdk: "Amazon Corretto JDK", jre: "Amazon Corretto JRE"},
	// Corretto 8 names the vendor "Amazon".
	"Amazon": {jdk: "Amazon Corretto JDK", jre: "Amazon Corretto JRE"},
	// Microsoft ships no JRE.
	"Microsoft": {jdk: "Microsoft Build of OpenJDK", jre: "Microsoft Build of OpenJDK"},
}

// oracleJava is Oracle's own Java. It is recognized by its bundle identifier
// (com.oracle.java.jdk, com.oracle.java.JavaAppletPlugin) rather than by
// vendor: the applet plug-in names no vendor, and other Oracle-built
// distributions such as GraalVM also say "Oracle Corporation".
var oracleJava = javaDistribution{jdk: "Oracle JDK", jre: "Oracle JRE"}

const oracleJavaBundleIDPrefix = "com.oracle.java."

// trailingVersionWords matches the version words at the end of a bundle name,
// " 17.70.113" in "Zulu 17.70.113" or " 6" in "Java SE 6".
var trailingVersionWords = regexp.MustCompile(`(\s+v?\d[\d._]*)+$`)

// javaPackageName names a Java runtime after its distribution, the same name
// for every version so that versions of it compare against each other. A
// vendor we do not know keeps its CFBundleName without the version, or the
// bundle's directory name when that leaves nothing.
func javaPackageName(vendor string, info javaInfoPlist, jdk bool, bundle string) string {
	dist, ok := javaVendors[strings.TrimSpace(vendor)]
	if strings.HasPrefix(info.BundleID, oracleJavaBundleIDPrefix) {
		dist, ok = oracleJava, true
	}
	if ok {
		if jdk {
			return dist.jdk
		}
		return dist.jre
	}
	if name := trailingVersionWords.ReplaceAllString(strings.TrimSpace(info.BundleName), ""); name != "" {
		return name
	}
	return strings.TrimSuffix(path.Base(bundle), path.Ext(bundle))
}

// javaArch reports the architecture a Java runtime was built for. It reads the
// Mach-O header of the bundle's executable (Contents/MacOS/libjli.dylib), as
// for applications, so an x86_64 JDK on Apple Silicon says so. The release
// file's OS_ARCH is next, and the host's architecture last.
func javaArch(conn shared.Connection, platform *inventory.Platform, bundle string, info javaInfoPlist, release javaRelease) string {
	if info.Executable != "" {
		if arch, ok := executableArch(conn, path.Join(bundle, "Contents", "MacOS", info.Executable)); ok && arch != "" {
			return arch
		}
	}
	switch release.osArch {
	case "aarch64", "arm64":
		return "arm64"
	case "x86_64", "amd64":
		return "x86_64"
	}
	if platform != nil {
		return platform.Arch
	}
	return ""
}

// readJavaInfoPlist reads a Java bundle's Contents/Info.plist. The second
// return value reports whether the file was there; a plist that fails to
// parse still counts, so the release file can stand in for it.
func readJavaInfoPlist(conn shared.Connection, infoPath string) (javaInfoPlist, bool) {
	var info javaInfoPlist
	f, err := conn.FileSystem().Open(infoPath)
	if err != nil {
		return info, false
	}
	defer f.Close()
	content, err := io.ReadAll(f)
	if err != nil {
		log.Debug().Err(err).Str("path", infoPath).Msg("could not read Java Info.plist")
		return info, false
	}
	if _, err := plist.Unmarshal(content, &info); err != nil {
		log.Debug().Err(err).Str("path", infoPath).Msg("could not parse Java Info.plist")
		return javaInfoPlist{}, true
	}
	return info, true
}

// readJavaRelease reads the KEY="value" lines of a Java runtime's release file.
func readJavaRelease(conn shared.Connection, releasePath string) (javaRelease, bool) {
	var release javaRelease
	f, err := conn.FileSystem().Open(releasePath)
	if err != nil {
		return release, false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	// MODULES lists every module on one line, longer than the default buffer.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch strings.TrimSpace(key) {
		case "IMPLEMENTOR":
			release.implementor = value
		case "JAVA_VERSION":
			release.javaVersion = value
		case "OS_ARCH":
			release.osArch = value
		}
	}
	return release, true
}

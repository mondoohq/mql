// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// javaHost lays out a macOS file system under a temporary directory. It is a
// real directory rather than an in-memory one so that symbolic links behave
// as they do on a Mac.
type javaHost struct {
	t    *testing.T
	root string
}

func newJavaHost(t *testing.T) *javaHost {
	return &javaHost{t: t, root: t.TempDir()}
}

func (h *javaHost) conn() *memFsConn {
	return &memFsConn{fs: afero.NewBasePathFs(afero.NewOsFs(), h.root)}
}

func (h *javaHost) write(path string, data []byte) {
	h.t.Helper()
	full := filepath.Join(h.root, path)
	require.NoError(h.t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(h.t, os.WriteFile(full, data, 0o644))
}

func (h *javaHost) copy(path, testdata string) {
	h.t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", testdata))
	require.NoError(h.t, err)
	h.write(path, data)
}

// bundle lays out a Java bundle from testdata/macos_java/<fixture>: its
// Info.plist and release file when the fixture has them, libjli.dylib built
// for arch, and javac when it is a JDK.
func (h *javaHost) bundle(path, fixture, arch string, jdk bool) {
	h.t.Helper()
	for _, f := range []string{"Info.plist", "release"} {
		src := filepath.Join("testdata", "macos_java", fixture, f)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(path, "Contents", f)
		if f == "release" {
			dst = filepath.Join(path, "Contents", "Home", f)
		}
		h.copy(dst, filepath.Join("macos_java", fixture, f))
	}
	if arch != "" {
		h.copy(filepath.Join(path, "Contents", "MacOS", "libjli.dylib"), filepath.Join("macho", arch+".bin"))
	}
	h.write(filepath.Join(path, "Contents", "Home", "bin", "java"), nil)
	if jdk {
		h.write(filepath.Join(path, "Contents", "Home", "bin", "javac"), nil)
	}
}

func TestMacOSJavaPackages(t *testing.T) {
	pf := &inventory.Platform{Name: "macos", Version: "26.0", Arch: "arm64"}
	h := newJavaHost(t)
	const vms = "/Library/Java/JavaVirtualMachines"

	// The Info.plist and release files are the vendors' own, taken from their
	// macOS aarch64 builds (Temurin 8 from its x64 build). The bundle
	// directories are the ones the vendors' installers use where known:
	// zulu-17.jdk (Azul's pkg), temurin-17.jdk (Temurin's pkg),
	// amazon-corretto-21.jdk (Corretto's pkg), jdk-21.0.5.jdk (Oracle's
	// archive) and JavaAppletPlugin.plugin (Oracle's Java 8 JRE installer).
	h.bundle(vms+"/zulu-17.jdk", "zulu17", "arm64", true)
	h.bundle(vms+"/temurin-17.jdk", "temurin17", "arm64", true)
	h.bundle(vms+"/amazon-corretto-21.jdk", "corretto21", "arm64", true)
	h.bundle(vms+"/jdk-21.0.5.jdk", "oracle21", "arm64", true)
	h.bundle(vms+"/microsoft-17.jdk", "microsoft17", "arm64", true)
	h.bundle(vms+"/zulu-8.jdk", "zulu8", "arm64", true)
	// An Intel build on Apple Silicon.
	h.bundle(vms+"/temurin-8.jdk", "temurin8", "x86_64", true)
	// Corretto 8 ships no release file, and names its vendor "Amazon".
	h.bundle(vms+"/amazon-corretto-8.jdk", "corretto8", "arm64", true)
	// A JRE has no javac. This one has no libjli.dylib either, so the
	// architecture comes from the release file.
	h.bundle(vms+"/temurin-17.jre", "temurin17-jre", "", false)
	h.bundle("/Library/Internet Plug-Ins/JavaAppletPlugin.plugin", "oracle-jre8-plugin", "arm64", false)
	// A JDK IntelliJ IDEA downloaded for one user, into a directory without the
	// .jdk extension.
	h.bundle("/Users/alice/Library/Java/JavaVirtualMachines/corretto-21.0.13", "corretto21", "arm64", true)

	got := map[string]Package{}
	for _, p := range macOSJavaPackages(h.conn(), pf) {
		got[p.PUrl] = p
	}

	want := map[string]struct{ name, version string }{
		"pkg:macos/macos/Azul%20Zulu%20JDK@17.0.21.0.3?arch=arm64&bundle-id=com.azul.zulu.jdk":                           {"Azul Zulu JDK", "17.0.21.0.3"},
		"pkg:macos/macos/Eclipse%20Temurin%20JDK@17.0.21?arch=arm64&bundle-id=net.java.openjdk.jdk":                      {"Eclipse Temurin JDK", "17.0.21"},
		"pkg:macos/macos/Amazon%20Corretto%20JDK@21.0.13?arch=arm64&bundle-id=com.amazon.corretto.21":                    {"Amazon Corretto JDK", "21.0.13"},
		"pkg:macos/macos/Oracle%20JDK@21.0.5?arch=arm64&bundle-id=com.oracle.java.jdk":                                   {"Oracle JDK", "21.0.5"},
		"pkg:macos/macos/Microsoft%20Build%20of%20OpenJDK@17.0.21.0.2?arch=arm64&bundle-id=net.java.openjdk.jdk":         {"Microsoft Build of OpenJDK", "17.0.21.0.2"},
		"pkg:macos/macos/Azul%20Zulu%20JDK@1.8.0_512?arch=arm64&bundle-id=com.azul.zulu.jdk":                             {"Azul Zulu JDK", "1.8.0_512"},
		"pkg:macos/macos/Eclipse%20Temurin%20JDK@1.8.0_504?arch=x86_64&bundle-id=net.temurin.8.jdk":                      {"Eclipse Temurin JDK", "1.8.0_504"},
		"pkg:macos/macos/Amazon%20Corretto%20JDK@1.8.0_512?arch=arm64&bundle-id=com.amazon.corretto.8":                   {"Amazon Corretto JDK", "1.8.0_512"},
		"pkg:macos/macos/Eclipse%20Temurin%20JRE@17.0.21?arch=arm64&bundle-id=net.java.openjdk.jre":                      {"Eclipse Temurin JRE", "17.0.21"},
		"pkg:macos/macos/Oracle%20JRE@1.8.0_511?arch=arm64&bundle-id=com.oracle.java.JavaAppletPlugin":                   {"Oracle JRE", "1.8.0_511"},
		"pkg:macos/macos/Amazon%20Corretto%20JDK@21.0.13?arch=arm64&bundle-id=com.amazon.corretto.21&install-scope=user": {"Amazon Corretto JDK", "21.0.13"},
	}
	for p := range got {
		assert.Contains(t, want, p, "unexpected package")
	}
	for p, w := range want {
		pkg, ok := got[p]
		if !assert.True(t, ok, "missing %s", p) {
			continue
		}
		assert.Equal(t, w.name, pkg.Name, p)
		assert.Equal(t, w.version, pkg.Version, p)
		assert.Equal(t, MacosPkgFormat, pkg.Format, p)
		assert.Equal(t, pkg.Arch, map[bool]string{true: "x86_64", false: "arm64"}[w.version == "1.8.0_504"], p)
	}

	zulu := got["pkg:macos/macos/Azul%20Zulu%20JDK@17.0.21.0.3?arch=arm64&bundle-id=com.azul.zulu.jdk"]
	assert.Equal(t, []FileRecord{{Path: vms + "/zulu-17.jdk"}}, zulu.Files)
	require.NotNil(t, zulu.MacOS)
	assert.Equal(t, "com.azul.zulu.jdk", zulu.MacOS.BundleID)
	assert.Equal(t, InstallScopeMachine, zulu.InstallScope)

	user := got["pkg:macos/macos/Amazon%20Corretto%20JDK@21.0.13?arch=arm64&bundle-id=com.amazon.corretto.21&install-scope=user"]
	assert.Equal(t, InstallScopeUser, user.InstallScope)
	assert.Equal(t, "alice", user.InstallUser)
}

func TestMacOSJavaPackagesSkipped(t *testing.T) {
	pf := &inventory.Platform{Name: "macos", Arch: "arm64"}

	// Nothing installed: no Java directory at all, or an empty one.
	h := newJavaHost(t)
	assert.Empty(t, macOSJavaPackages(h.conn(), pf))
	require.NoError(t, os.MkdirAll(filepath.Join(h.root, "/Library/Java/JavaVirtualMachines"), 0o755))
	assert.Empty(t, macOSJavaPackages(h.conn(), pf))

	const vms = "/Library/Java/JavaVirtualMachines"
	// A bundle directory left empty, for example by an uninstaller.
	require.NoError(t, os.MkdirAll(filepath.Join(h.root, vms, "empty.jdk"), 0o755))
	// A malformed Info.plist and no release file: no version to report.
	h.write(vms+"/broken.jdk/Contents/Info.plist", []byte("<?xml version=\"1.0\"?><plist><dict><key>CFBundleName"))
	// A bundle that is not a Java runtime: an Info.plist without JavaVM.
	h.write(vms+"/other.jdk/Contents/Info.plist", []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleName</key><string>Other</string><key>CFBundleShortVersionString</key><string>1.0</string></dict></plist>`))
	// Stray files.
	h.write(vms+"/.DS_Store", []byte("x"))
	h.write(vms+"/notes.txt", []byte("x"))
	// Homebrew's openjdk formula, linked in as its caveat says. Homebrew owns
	// and reports it.
	h.bundle("/opt/homebrew/opt/openjdk/libexec/openjdk.jdk", "temurin17", "arm64", true)
	require.NoError(t, os.Symlink(
		filepath.Join(h.root, "/opt/homebrew/opt/openjdk/libexec/openjdk.jdk"),
		filepath.Join(h.root, vms, "openjdk.jdk")))

	assert.Empty(t, macOSJavaPackages(h.conn(), pf))
}

func TestMacOSJavaPackagesMalformedPlistWithRelease(t *testing.T) {
	pf := &inventory.Platform{Name: "macos", Arch: "arm64"}
	h := newJavaHost(t)
	const bundle = "/Library/Java/JavaVirtualMachines/zulu-17.jdk"
	h.bundle(bundle, "zulu17", "", true)
	// The release file still identifies the runtime.
	h.write(bundle+"/Contents/Info.plist", []byte("not a plist"))

	pkgs := macOSJavaPackages(h.conn(), pf)
	require.Len(t, pkgs, 1)
	assert.Equal(t, "Azul Zulu JDK", pkgs[0].Name)
	assert.Equal(t, "17.0.21.0.3", pkgs[0].Version)
	assert.Equal(t, "pkg:macos/macos/Azul%20Zulu%20JDK@17.0.21.0.3?arch=arm64", pkgs[0].PUrl)
}

func TestJavaPackageName(t *testing.T) {
	// Synthetic: a vendor not in the table keeps its bundle name without the
	// version, or the directory name when the bundle has no name.
	assert.Equal(t, "Liberica JDK", javaPackageName("BellSoft", javaInfoPlist{BundleName: "Liberica JDK 21.0.13"}, true, "/x/liberica-jdk-21.jdk"))
	assert.Equal(t, "Java SE", javaPackageName("Apple Inc.", javaInfoPlist{BundleName: "Java SE 6"}, true, "/x/1.6.0.jdk"))
	assert.Equal(t, "sapmachine-21", javaPackageName("SAP SE", javaInfoPlist{}, true, "/x/sapmachine-21.jdk"))
	// Oracle is recognized by bundle identifier, whatever the vendor says.
	assert.Equal(t, "Oracle JDK", javaPackageName("", javaInfoPlist{BundleID: "com.oracle.java.jdk"}, true, "/x/jdk.jdk"))
}

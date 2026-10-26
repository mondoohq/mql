// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func memFS(t *testing.T, files map[string]string) afero.Fs {
	fs := afero.NewMemMapFs()
	for name, content := range files {
		require.NoError(t, afero.WriteFile(fs, name, []byte(content), 0o755))
	}
	return fs
}

func TestIdentifyGoBinary(t *testing.T) {
	// the test binary is itself a Go binary built from this module
	exe, err := os.Executable()
	require.NoError(t, err)

	id := Identify(afero.NewOsFs(), Binary{Path: exe})
	assert.Equal(t, "go.mondoo.com/mql", id.Name)
}

func TestIdentifyGoBinaryThroughContentPath(t *testing.T) {
	// the file at the path was replaced; the running one is still readable
	exe, err := os.Executable()
	require.NoError(t, err)

	id := Identify(afero.NewOsFs(), Binary{Path: "/nonexistent/app", ContentPath: exe})
	assert.Equal(t, "go.mondoo.com/mql", id.Name)
}

func TestIdentifyGoBinaryWithVersionResource(t *testing.T) {
	// a Go binary without a tagged module version, as cnspec's release
	// builds are on Windows, takes the version its version resource names
	exe, err := os.Executable()
	require.NoError(t, err)

	id := Identify(afero.NewOsFs(), Binary{Path: exe, VersionInfo: &PEVersionInfo{
		ProductName:    "cnspec",
		ProductVersion: "14.4.0",
		CompanyName:    "Mondoo, Inc.",
	}})
	assert.Equal(t, Identity{Name: "cnspec", Version: "14.4.0", VersionSource: SourcePEVersionInfo, Vendor: "Mondoo, Inc."}, id)
}

func TestGoReleaseVersion(t *testing.T) {
	assert.True(t, goReleaseVersion("v0.21.1"))
	assert.True(t, goReleaseVersion("v2.3.0+incompatible"))
	assert.False(t, goReleaseVersion(""))
	assert.False(t, goReleaseVersion("v0.0.0-20261008172703-eab0c2d0a9e9"))
	assert.False(t, goReleaseVersion("v0.0.1-0.20260925143234-619ab1b35122+dirty"))
}

func TestIdentifyPhpVersionString(t *testing.T) {
	fs := memFS(t, map[string]string{
		"/usr/local/sbin/php-fpm8.3": "\x7fELF\x00\x00PHP/%s\x00X-Powered-By: PHP/8.3.6\x00\x00",
	})
	id := Identify(fs, Binary{Path: "/usr/local/sbin/php-fpm8.3"})
	assert.Equal(t, Identity{
		Name:          "php",
		Version:       "8.3.6",
		VersionSource: SourceVersionString,
	}, id)
}

func TestIdentifyPythonVersionAnchoredOnFileName(t *testing.T) {
	fs := memFS(t, map[string]string{
		// other dotted triples come first: only the one matching the file
		// name's major and minor version is the interpreter's
		"/opt/python/bin/python3.12": "\x001.2.13\x00\x003.11.9\x00LC_ALL\x003.12.4\x00strict\x00",
	})
	id := Identify(fs, Binary{Path: "/opt/python/bin/python3.12"})
	assert.Equal(t, "python", id.Name)
	assert.Equal(t, "3.12.4", id.Version)
	assert.Equal(t, SourceVersionString, id.VersionSource)
}

func TestIdentifyNodeFromVersionHeader(t *testing.T) {
	fs := memFS(t, map[string]string{
		"/opt/node22/bin/node": "\x7fELF",
		"/opt/node22/include/node/node_version.h": `#ifndef SRC_NODE_VERSION_H_
#define NODE_MAJOR_VERSION 22
#define NODE_MINOR_VERSION 22
#define NODE_PATCH_VERSION 0
#define NODE_VERSION_IS_RELEASE 1
`,
	})
	id := Identify(fs, Binary{Path: "/opt/node22/bin/node"})
	assert.Equal(t, Identity{
		Name:          "node",
		Version:       "22.22.0",
		VersionSource: SourceInstallMetadata,
	}, id)
}

func TestIdentifyNodeFromVersionString(t *testing.T) {
	// no header installed beside the binary
	fs := memFS(t, map[string]string{
		"/usr/local/bin/node": "\x00node.js/v20.11.1\x00",
	})
	id := Identify(fs, Binary{Path: "/usr/local/bin/node"})
	assert.Equal(t, "20.11.1", id.Version)
	assert.Equal(t, SourceVersionString, id.VersionSource)
}

func TestIdentifyJavaRelease(t *testing.T) {
	fs := memFS(t, map[string]string{
		"/opt/jdk-17/bin/java": "\x7fELF",
		"/opt/jdk-17/release":  "IMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_RUNTIME_VERSION=\"17.0.10+7\"\nJAVA_VERSION=\"17.0.10\"\n",
		// Java 8: the JDK runs its JRE's binary, the release file is a level up
		"/opt/jdk8/jre/bin/java": "\x7fELF",
		"/opt/jdk8/release":      "JAVA_VERSION=\"1.8.0_402\"\n",
	})

	id := Identify(fs, Binary{Path: "/opt/jdk-17/bin/java"})
	assert.Equal(t, "openjdk", id.Name)
	assert.Equal(t, "17.0.10", id.Version)
	assert.Equal(t, SourceInstallMetadata, id.VersionSource)
	assert.Equal(t, "Eclipse Adoptium", id.Vendor)

	id = Identify(fs, Binary{Path: "/opt/jdk8/jre/bin/java"})
	assert.Equal(t, "1.8.0_402", id.Version)
}

func TestIdentifyServerVersionStrings(t *testing.T) {
	// the strings around each version as the released binaries store them,
	// each after a decoy a looser pattern would take: a library version, or
	// the same software's version in a different string
	for _, tc := range []struct {
		path    string
		content string
		name    string
		version string
	}{{
		path:    "/usr/sbin/nginx",
		content: "\x00OpenSSL 3.5.4 30 Sep 2025\x00nginx/%s\x00nginx version: nginx/1.31.8\n\x00Usage: nginx",
		name:    "nginx",
		version: "1.31.8",
	}, {
		path:    "/usr/local/apache2/bin/httpd",
		content: "\x00Apache/2.4\x00\x00Apache/2\x00 Server at \x00Apache/2.4.69 (Unix)\x00\x00Apache/2.4.69\x00mailto:",
		name:    "httpd",
		version: "2.4.69",
	}, {
		path:    "/usr/sbin/apache2",
		content: "\x00Apache/2.4.58\x00Apache/2.4.58 (Ubuntu)\x00",
		name:    "httpd",
		version: "2.4.58",
	}, {
		path:    "/usr/lib/postgresql/18/bin/postgres",
		content: "\x00PostgreSQL 9.1.\x00-V\x00postgres (PostgreSQL) 18.6 (Debian 18.6-1.pgdg13+2)\n\x00--describe",
		name:    "postgresql",
		version: "18.6",
	}, {
		path:    "/usr/local/pgsql/bin/postgres",
		content: "\x00postgres (PostgreSQL) 19beta1\n\x00",
		name:    "postgresql",
		version: "19beta1",
	}, {
		path:    "/usr/sbin/mysqld",
		content: "/BUILD/mysql-8.4.13/mysys/my_file.cc\x00\x008.4.13\x00\x00MySQL Community Server - GPL\x00\x00aarch64\x00Linux\x00%s  Ver %s for %s on %s (%s)\n",
		name:    "mysql",
		version: "8.4.13",
	}, {
		path:    "/usr/sbin/mariadbd",
		content: "\x00for example 10.1.1-MariaDB-mariadb1precise-log\x00-log\x00-ubu2604\x00\x0013.0.2-MariaDB\x00\x00mariadb.org binary distribution\x00",
		name:    "mariadb",
		version: "13.0.2",
	}, {
		path:    "/usr/local/bin/redis-server",
		content: "\x00cjson\x00_NAME\x00\x002.1.0\x00\x00NORMAL\x00\x003.2.0\x00\x0000000000\x00\x008.10.2\x00\x00                _._                \n",
		name:    "redis",
		version: "8.10.2",
	}, {
		// Debian's reproducible build, which records no build host
		path:    "/usr/bin/redis-check-rdb",
		content: "\x00NORMAL\x00\x003.2.0\x00\x00server\x00\x008.0.2\x00\x00\x00# Server\r\nredis_version:%s\r\nredis_git_sha1",
		name:    "redis",
		version: "8.0.2",
	}, {
		path:    "/usr/local/sbin/haproxy",
		content: "text/plain; version=0.0.4\x00\x00 version 3.4.7-8872a26, released 2026/10/14\x00\x002026/10/14\x00",
		name:    "haproxy",
		version: "3.4.7",
	}, {
		path:    "/usr/sbin/haproxy",
		content: "\x00 version 2.8.30-0ubuntu0.24.04.1, released 2026/10/06\x00",
		name:    "haproxy",
		version: "2.8.30",
	}, {
		path:    "/usr/local/bin/memcached",
		content: "\x00libevent 2.1.12-stable\x00must be greater than 0\n\x00\x00memcached 1.6.45\x00\x00-p, --port=<num>",
		name:    "memcached",
		version: "1.6.45",
	}, {
		// built without a shared libruby
		path:    "/opt/rubies/2.7.8/bin/ruby",
		content: "\x00Copyright (C) 1993-2023 Yukihiro Matsumoto\x00ruby 2.7.8p225 (2023-03-30 revision 1f4d455848) [x86_64-linux]\x00",
		name:    "ruby",
		version: "2.7.8",
	}, {
		// linked to a shared libperl, found through its run path
		path:    "/usr/local/bin/perl",
		content: "GLIBC_2.17\x00/usr/local/lib/perl5/5.44.0/aarch64-linux-gnu/CORE\x00\x00",
		name:    "perl",
		version: "5.44.0",
	}, {
		// a static perl
		path:    "/opt/perl/bin/perl5.40.1",
		content: "PERL_INTERNAL_RAND_SEED\x00v5.40.1\x00panic: sysconf: %s\x00",
		name:    "perl",
		version: "5.40.1",
	}} {
		fs := memFS(t, map[string]string{tc.path: tc.content})
		id := Identify(fs, Binary{Path: tc.path})
		assert.Equal(t, Identity{Name: tc.name, Version: tc.version, VersionSource: SourceVersionString}, id, tc.path)
	}
}

func TestIdentifyServerWithoutVersionString(t *testing.T) {
	// MySQL 8.0 keeps its version apart from any string to anchor on, and
	// redis's build id runs the version into the build host's name: neither
	// is taken for a version, which could be wrong
	for path, content := range map[string]string{
		"/usr/sbin/mysqld":            "\x00admin-tls-ciphersuites\x00\x008.0.46\x00\x00'CHANGE REPLICATION SOURCE TO\x00",
		"/usr/local/bin/redis-server": "\x00\x007.2.43f2a9c1e-1792543350000000000\x00",
	} {
		fs := memFS(t, map[string]string{path: content})
		id := Identify(fs, Binary{Path: path})
		assert.Equal(t, "", id.Version, path)
	}
}

func TestIdentifyRubyFromPkgConfig(t *testing.T) {
	// the official image's ruby, linked to a shared libruby
	fs := memFS(t, map[string]string{
		"/usr/local/bin/ruby": "\x7fELF\x00libruby.so.4.0\x00",
		"/usr/local/lib/pkgconfig/ruby-4.0.pc": `MAJOR=4
MINOR=0
TEENY=8
ruby_version=4.0.0
RUBY_PROGRAM_VERSION=${MAJOR}.${MINOR}.${TEENY}
RUBY_BASE_NAME=ruby
RUBY_INSTALL_NAME=${RUBY_BASE_NAME}
`,
		// a second ruby installed into the same prefix under another name
		"/usr/local/bin/ruby33":                "\x7fELF",
		"/usr/local/lib/pkgconfig/ruby-3.3.pc": "MAJOR=3\nMINOR=3\nTEENY=12\nRUBY_INSTALL_NAME=ruby33\n",
	})
	assert.Equal(t, Identity{Name: "ruby", Version: "4.0.8", VersionSource: SourceInstallMetadata}, Identify(fs, Binary{Path: "/usr/local/bin/ruby"}))

	// without a pkg-config file of its own name, and no version inside it
	fs = memFS(t, map[string]string{
		"/usr/local/bin/ruby":                  "\x7fELF",
		"/usr/local/lib/pkgconfig/ruby-3.3.pc": "MAJOR=3\nMINOR=3\nTEENY=12\nRUBY_INSTALL_NAME=ruby33\n",
	})
	assert.Equal(t, Identity{Name: "ruby"}, Identify(fs, Binary{Path: "/usr/local/bin/ruby"}))
}

func TestIdentifyUnknownBinary(t *testing.T) {
	fs := memFS(t, map[string]string{"/opt/tool/bin/thing": "\x7fELF\x001.2.3\x00"})
	id := Identify(fs, Binary{Path: "/opt/tool/bin/thing"})
	assert.Equal(t, Identity{Name: "thing"}, id)
}

func TestIdentifyWindowsVersionResource(t *testing.T) {
	id := Identify(nil, Binary{
		Path: `C:\Program Files\Contoso\Agent\agent.exe`,
		VersionInfo: &PEVersionInfo{
			ProductName:    "Contoso Agent",
			ProductVersion: "4, 2, 0, 17",
			CompanyName:    "Contoso",
		},
	})
	assert.Equal(t, Identity{
		Name:          "Contoso Agent",
		Version:       "4.2.0.17",
		VersionSource: SourcePEVersionInfo,
		Vendor:        "Contoso",
	}, id)
}

func TestIdentifyWindowsComponent(t *testing.T) {
	// a component of Windows is named by what the file is, not by the
	// operating system it is part of
	id := Identify(nil, Binary{
		Path: `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3009-0\MsMpEng.exe`,
		VersionInfo: &PEVersionInfo{
			ProductName:     "Microsoft® Windows® Operating System",
			ProductVersion:  "4.18.25090.3009",
			CompanyName:     "Microsoft Corporation",
			FileDescription: "Antimalware Service Executable",
		},
	})
	assert.Equal(t, Identity{
		Name:          "Antimalware Service Executable",
		Version:       "4.18.25090.3009",
		VersionSource: SourcePEVersionInfo,
		Vendor:        "Microsoft Corporation",
	}, id)
}

func TestPEName(t *testing.T) {
	assert.Equal(t, "", peName(nil))
	assert.Equal(t, "Contoso Agent", peName(&PEVersionInfo{ProductName: "Contoso Agent", FileDescription: "Contoso Agent Service"}))
	for _, product := range []string{
		"Microsoft® Windows® Operating System",
		"Microsoft (R) Windows (R) Operating System",
		"Microsoft(R) Windows(R) Operating System",
		"Microsoft Windows Operating System",
	} {
		assert.Equal(t, "Windows Terminal Host", peName(&PEVersionInfo{ProductName: product, FileDescription: "Windows Terminal Host"}), product)
	}
	// without a description, the file's own name is left to describe it
	assert.Equal(t, "", peName(&PEVersionInfo{ProductName: "Microsoft® Windows® Operating System"}))
	id := Identify(nil, Binary{
		Path:        `C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience_526.21100.40.0_arm64__cw5n1h2txyewy\WidgetBoard.exe`,
		VersionInfo: &PEVersionInfo{ProductName: "Microsoft® Windows® Operating System", ProductVersion: "526.21100.10.0", CompanyName: "Microsoft Corporation"},
	})
	assert.Equal(t, "widgetboard", id.Name)
	assert.Equal(t, "526.21100.10.0", id.Version)
}

func TestIdentifyWindowsKnownRuntime(t *testing.T) {
	// a recognized runtime keeps its own name and NVD identifiers
	id := Identify(nil, Binary{
		Path: `C:\Program Files\nodejs\node.exe`,
		VersionInfo: &PEVersionInfo{
			ProductName:    "Node.js",
			ProductVersion: "22.11.0",
			CompanyName:    "Node.js",
		},
	})
	assert.Equal(t, "node", id.Name)
	assert.Equal(t, "22.11.0", id.Version)
	assert.Equal(t, SourcePEVersionInfo, id.VersionSource)
}

func TestPEVersion(t *testing.T) {
	assert.Equal(t, "10.0.20348.1", peVersion(&PEVersionInfo{FileVersion: "10.0.20348.1 (WinBuild.160101.0800)"}))
	assert.Equal(t, "1.0.0.1", peVersion(&PEVersionInfo{ProductVersion: "1, 0, 0, 1"}))
	assert.Equal(t, "8.3.6", peVersion(&PEVersionInfo{ProductVersion: " 8.3.6 ", FileVersion: "8.3.6.0"}))
	assert.Equal(t, "", peVersion(&PEVersionInfo{ProductName: "x"}))
}

func TestFindInReaderAcrossChunks(t *testing.T) {
	re := regexp.MustCompile(`node\.js/v(\d+\.\d+\.\d+)`)
	marker := "node.js/v22.22.0"

	// the marker straddles the first chunk boundary
	data := bytes.Repeat([]byte{0}, scanChunk-5)
	data = append(data, marker...)
	data = append(data, bytes.Repeat([]byte{0}, 100)...)
	v, err := findInReader(bytes.NewReader(data), re, int64(len(data)))
	require.NoError(t, err)
	assert.Equal(t, "22.22.0", v)

	// past the limit it is not read
	data = append(bytes.Repeat([]byte{0}, 2*scanChunk), marker...)
	v, err = findInReader(bytes.NewReader(data), re, scanChunk)
	require.NoError(t, err)
	assert.Equal(t, "", v)
}

func TestParseNodeVersionHeaderIncomplete(t *testing.T) {
	_, ok := parseNodeVersionHeader(strings.NewReader("#define NODE_MAJOR_VERSION 22\n"))
	assert.False(t, ok)
}

func TestSHA256(t *testing.T) {
	fs := memFS(t, map[string]string{
		"/opt/app/server": "running build",
		"/proc/42/exe":    "running build",
	})

	// printf 'running build' | sha256sum
	const want = "2c571a925326f79d66147ad5768fbaadc9a580fda6de38003fa916bb568c954d"
	got, err := SHA256(fs, Binary{Path: "/opt/app/server"})
	require.NoError(t, err)
	assert.Equal(t, want, got)

	// the running file is hashed, not whatever an upgrade left at the path
	require.NoError(t, afero.WriteFile(fs, "/opt/app/server", []byte("upgraded build"), 0o755))
	running, err := SHA256(fs, Binary{Path: "/opt/app/server", ContentPath: "/proc/42/exe"})
	require.NoError(t, err)
	assert.Equal(t, want, running)
	onDisk, err := SHA256(fs, Binary{Path: "/opt/app/server"})
	require.NoError(t, err)
	assert.NotEqual(t, want, onDisk)

	_, err = SHA256(fs, Binary{Path: "/opt/missing"})
	assert.Error(t, err)
}

const slackInfoPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>Slack</string>
	<key>CFBundleName</key>
	<string>Slack</string>
	<key>CFBundleShortVersionString</key>
	<string>4.41.105</string>
	<key>CFBundleVersion</key>
	<string>441105</string>
</dict>
</plist>`

func TestIdentifyMacOSBundle(t *testing.T) {
	fs := memFS(t, map[string]string{
		"/Applications/Slack.app/Contents/MacOS/Slack": "not a go binary",
		"/Applications/Slack.app/Contents/Info.plist":  slackInfoPlist,
	})
	id := Identify(fs, Binary{Path: "/Applications/Slack.app/Contents/MacOS/Slack"})
	assert.Equal(t, Identity{Name: "Slack", Version: "4.41.105", VersionSource: SourceBundleInfo}, id)
}

func TestIdentifyMacOSBundleWithoutVersion(t *testing.T) {
	fs := memFS(t, map[string]string{
		"/Applications/Tool.app/Contents/MacOS/Tool": "not a go binary",
		"/Applications/Tool.app/Contents/Info.plist": `<plist version="1.0"><dict><key>CFBundleName</key><string>Tool</string></dict></plist>`,
		// a file below MacOS is not the bundle's executable
		"/Applications/Other.app/Contents/MacOS/lib/helper": "not a go binary",
		"/Applications/Other.app/Contents/Info.plist":       slackInfoPlist,
	})
	assert.Equal(t, Identity{Name: "tool"}, Identify(fs, Binary{Path: "/Applications/Tool.app/Contents/MacOS/Tool"}))
	assert.Equal(t, Identity{Name: "helper"}, Identify(fs, Binary{Path: "/Applications/Other.app/Contents/MacOS/lib/helper"}))
}

func TestIdentifyNodeInBundleIsNode(t *testing.T) {
	// a runtime shipped inside an application is identified as the runtime
	fs := memFS(t, map[string]string{
		"/Applications/App.app/Contents/MacOS/node": "node.js/v22.11.0",
		"/Applications/App.app/Contents/Info.plist": slackInfoPlist,
	})
	id := Identify(fs, Binary{Path: "/Applications/App.app/Contents/MacOS/node"})
	assert.Equal(t, "node", id.Name)
	assert.Equal(t, "22.11.0", id.Version)
}

func TestIdentifyMysqldMariaDB(t *testing.T) {
	// Measured: Azure Windows Server 2022, XAMPP 7.3.2, 2026-10-26. The
	// resource of C:\xampp\mysql\bin\mysqld.exe has no product or company name
	// and the version 10.1.38.0, which is MariaDB 10.1.38.
	id := Identify(nil, Binary{
		Path:        `C:\xampp\mysql\bin\mysqld.exe`,
		VersionInfo: &PEVersionInfo{FileVersion: "10.1.38.0", ProductVersion: "10.1.38.0"},
	})
	assert.Equal(t, Identity{Name: "mariadb", Version: "10.1.38.0", VersionSource: SourcePEVersionInfo}, id)

	// Synthetic: MySQL versions below 10 stay mysql; no host showed these.
	for _, v := range []string{"5.7.44.0", "8.4.13.0", "9.1.0.0"} {
		id := Identify(nil, Binary{Path: `C:\mysql\bin\mysqld.exe`, VersionInfo: &PEVersionInfo{ProductVersion: v}})
		assert.Equal(t, "mysql", id.Name, v)
	}
	// Synthetic: the product name decides before the version does, as it does
	// in the Windows package scan.
	id = Identify(nil, Binary{Path: `C:\mysql\bin\mysqld.exe`, VersionInfo: &PEVersionInfo{ProductName: "MySQL Server", ProductVersion: "10.1.38.0"}})
	assert.Equal(t, "mysql", id.Name)
	id = Identify(nil, Binary{Path: `C:\maria\bin\mysqld.exe`, VersionInfo: &PEVersionInfo{ProductName: "MariaDB Server", ProductVersion: "5.5.68"}})
	assert.Equal(t, "mariadb", id.Name)
	// Synthetic: 5.5 with no name is ambiguous, so it stays mysql.
	id = Identify(nil, Binary{Path: `C:\mysql\bin\mysqld.exe`, VersionInfo: &PEVersionInfo{ProductVersion: "5.5.62.0"}})
	assert.Equal(t, "mysql", id.Name)
	// Synthetic: no version found, so no evidence for either.
	assert.Equal(t, "mysql", Identify(nil, Binary{Path: "/usr/sbin/mysqld"}).Name)
}

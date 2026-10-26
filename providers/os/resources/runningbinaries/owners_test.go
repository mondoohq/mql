// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
)

func TestPathAliases(t *testing.T) {
	assert.Equal(t, []string{"/usr/bin/bash", "/bin/bash", "/sbin/bash", "/usr/sbin/bash"}, pathAliases("/usr/bin/bash"))
	assert.Equal(t, []string{"/sbin/sshd", "/usr/sbin/sshd", "/bin/sshd", "/usr/bin/sshd"}, pathAliases("/sbin/sshd"))
	assert.Equal(t, []string{"/usr/lib/systemd/systemd", "/lib/systemd/systemd"}, pathAliases("/usr/lib/systemd/systemd"))
	// /usr merged only the top-level bin, sbin and lib directories
	assert.Equal(t, []string{"/opt/node/bin/node"}, pathAliases("/opt/node/bin/node"))
	assert.Equal(t, []string{"/usr/local/bin/php"}, pathAliases("/usr/local/bin/php"))
}

func TestParseListMatches(t *testing.T) {
	out := strings.Join([]string{
		"/var/lib/dpkg/info/bash.list:/bin/bash",
		"/var/lib/dpkg/info/libc6:amd64.list:/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib/opkg/info/dropbear.list:/usr/sbin/dropbear",
	}, "\n")

	assert.Equal(t, Owners{
		"/bin/bash": {"bash"},
		// the architecture qualifier of a multi-arch list is not part of the name
		"/usr/lib/x86_64-linux-gnu/libc.so.6": {"libc6"},
		"/usr/sbin/dropbear":                  {"dropbear"},
	}, parseListMatches(strings.NewReader(out)))
}

func TestResolveAliases(t *testing.T) {
	recorded := Owners{
		// recorded under the pre-merge path
		"/bin/bash": {"bash"},
		// /usr/sbin merged into /usr/bin: an old package still lists the
		// sbin path of the file the new package installs into bin
		"/usr/sbin/iptables": {"iptables-legacy"},
		"/usr/bin/iptables":  {"iptables-nft"},
	}
	assert.Equal(t, Owners{
		// reported under the path the process runs
		"/usr/bin/bash": {"bash"},
		// the package that lists that very path comes first
		"/usr/bin/iptables": {"iptables-nft", "iptables-legacy"},
	}, resolveAliases([]string{"/usr/bin/bash", "/usr/bin/iptables", "/opt/app/bin/app"}, recorded))
}

func TestListFileOwners(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner queries run in a unix shell")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dropbear.list"), []byte("/usr/sbin/dropbear\n/etc/dropbear\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "busybox.list"), []byte("/bin/busybox\n/bin/sh\n"), 0o644))

	conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})
	// the first of the directories that exists, as opkg's are configured
	owners, err := listFileOwners(conn, "opkg", []string{missing, dir}, []string{"/usr/sbin/dropbear", "/bin/sh", "/usr/bin/app"})
	require.NoError(t, err)
	assert.Equal(t, Owners{
		"/usr/sbin/dropbear": {"dropbear"},
		"/bin/sh":            {"busybox"},
	}, owners)

	_, err = listFileOwners(conn, "opkg", []string{missing}, []string{"/bin/sh"})
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_FOUND, llx.KindOf(err))
}

func TestParseApkInstalledOwners(t *testing.T) {
	db := `C:Q1abc=
P:busybox
V:1.36.1-r15
F:bin
R:busybox
F:etc
R:securetty

P:nginx
V:1.24.0-r15
F:usr/sbin
R:nginx

P:php83
F:usr/bin
R:php83
`
	files := lookupPaths([]string{"/bin/busybox", "/usr/sbin/nginx", "/usr/local/bin/php83"})
	assert.Equal(t, Owners{
		"/bin/busybox":    {"busybox"},
		"/usr/sbin/nginx": {"nginx"},
	}, parseApkInstalledOwners(strings.NewReader(db), files))
}

func TestGentooOwners(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner queries run in a unix shell")
	}
	db := t.TempDir()
	writeContents := func(pkg, contents string) {
		dir := filepath.Join(db, pkg)
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "CONTENTS"), []byte(contents), 0o644))
	}
	writeContents("net-misc/curl-8.4.0", "dir /usr/bin\nobj /usr/bin/curl 0c4b1b0f3f2e1d0c 1700000000\n")
	writeContents("app-shells/bash-5.2_p21-r1", "obj /bin/bash 1a2b3c 1700000000\nsym /bin/sh -> bash 1700000000\n")
	writeContents("dev-lang/python-3.12.1", "obj /usr/lib/python-exec/my app 9f8e7d 1700000000\n")

	conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})
	owners, err := gentooOwners(conn, db, lookupPaths([]string{"/usr/bin/curl", "/usr/bin/bash", "/usr/lib/python-exec/my app", "/opt/app"}))
	require.NoError(t, err)
	assert.Equal(t, Owners{
		"/usr/bin/curl": {"net-misc/curl"},
		"/bin/bash":     {"app-shells/bash"},
		// a path with a space, ahead of the digest and the time
		"/usr/lib/python-exec/my app": {"dev-lang/python"},
	}, owners)

	_, err = gentooOwners(conn, filepath.Join(db, "missing"), []string{"/bin/bash"})
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_FOUND, llx.KindOf(err))
}

func TestXbpsOwners(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner queries run in a unix shell")
	}
	db := t.TempDir()
	acl, err := os.ReadFile("../packages/testdata/xbps_acl_files.plist")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(db, ".acl-files.plist"), acl, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(db, ".r&d-tools-files.plist"), []byte(`<plist version="1.0">
<dict>
	<key>files</key>
	<array>
		<dict>
			<key>file</key>
			<string>/opt/r&amp;d/bin/tool</string>
		</dict>
	</array>
</dict>
</plist>
`), 0o644))

	conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})
	owners, err := xbpsOwners(conn, db, []string{"/usr/lib/libacl.so.1.1.2301", "/usr/lib/libacl.so.1", "/opt/r&d/bin/tool", "/usr/bin/app"})
	require.NoError(t, err)
	assert.Equal(t, Owners{
		"/usr/lib/libacl.so.1.1.2301": {"acl"},
		// a link the package installs is a file of it too
		"/usr/lib/libacl.so.1": {"acl"},
		"/opt/r&d/bin/tool":    {"r&d-tools"},
	}, owners)
}

func TestPathOwners(t *testing.T) {
	assert.Equal(t, Owners{
		"/snap/lxd/29351/bin/lxd": {"lxd"},
	}, pathOwners([]string{"/snap/lxd/29351/bin/lxd", "/snap/bin/lxc", "/usr/bin/snap"}, snapPackage))

	assert.Equal(t, Owners{
		"/home/linuxbrew/.linuxbrew/Cellar/node/22.11.0/bin/node": {"node"},
	}, pathOwners([]string{"/home/linuxbrew/.linuxbrew/Cellar/node/22.11.0/bin/node", "/home/linuxbrew/.linuxbrew/bin/node"}, HomebrewPackage))

	assert.Equal(t, Owners{
		"/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/active/files/lib/firefox/firefox": {"org.mozilla.firefox"},
	}, pathOwners([]string{"/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/active/files/lib/firefox/firefox"}, flatpakPackage))
}

func TestLinuxOwnersUnsupportedFormat(t *testing.T) {
	// a package manager that keeps no file database cannot vouch that a
	// binary is unowned
	_, err := LinuxOwners(nil, []string{"cos"}, []string{"/usr/bin/a"})
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(err))
}

// stubTool puts an executable shell script named name first on PATH.
func stubTool(t *testing.T, name, script string) {
	if runtime.GOOS == "windows" {
		t.Skip("owner queries run in a unix shell")
	}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestRpmOwners(t *testing.T) {
	// rpm prints the file list of the package owning each path it is given,
	// as the package recorded the files, and a line of its own on stdout
	// for a path no package owns
	stubTool(t, "rpm", `[ "$1 $2 $3" = "-qf --qf [%{FILENAMES}\t%{=NAME}\n]" ] || exit 2
shift 3
for f; do
  case "$f" in
    /usr/sbin/httpd) printf '/etc/httpd\thttpd\n/usr/sbin/httpd\thttpd\n/usr/sbin/httpd-backup\thttpd\n' ;;
    /usr/bin/curl|/bin/curl) printf '/usr/bin/curl\tcurl\n/usr/share/man/man1/curl.1.gz\tcurl\n' ;;
    *) echo "file $f is not owned by any package" ;;
  esac
done
`)
	conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})
	owners, err := LinuxOwners(conn, []string{"rpm"}, []string{"/usr/sbin/httpd", "/usr/bin/curl", "/opt/app/bin/app"})
	require.NoError(t, err)
	assert.Equal(t, Owners{
		"/usr/sbin/httpd": {"httpd"},
		"/usr/bin/curl":   {"curl"},
	}, owners)
}

func TestParseRpmOwners(t *testing.T) {
	out := "/usr/bin/curl\tcurl\n/usr/bin/curl\tcurl-minimal\nfile /opt/app is not owned by any package\n/usr/bin/x\t\n"
	assert.Equal(t, Owners{
		"/usr/bin/curl": {"curl", "curl-minimal"},
	}, parseRpmOwners(strings.NewReader(out)))
}

func TestPacmanOwners(t *testing.T) {
	// pacman prints one line per owned path, and an error on stderr for a
	// path no package owns
	stubTool(t, "pacman", `[ "$1" = "-Qo" ] || exit 2
shift
for f; do
  case "$f" in
    /usr/bin/bash) echo "$f is owned by bash 5.2.037-1" ;;
    "/opt/my app/bin/is owned by") echo "$f is owned by weird-app 1.0-1" ;;
    *) echo "error: No package owns $f" >&2 ;;
  esac
done
exit 1
`)
	conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})
	owners, err := pacmanOwners(conn, []string{"/usr/bin/bash", "/opt/my app/bin/is owned by", "/opt/app"})
	require.NoError(t, err)
	assert.Equal(t, Owners{
		"/usr/bin/bash":               {"bash"},
		"/opt/my app/bin/is owned by": {"weird-app"},
	}, owners)
}

func TestBulkOwnersMissingTool(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner queries run in a unix shell")
	}
	conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})
	_, err := bulkOwners(conn, "mql-test-no-such-tool", requireTool("mql-test-no-such-tool"), []string{"/usr/bin/a"}, parseRpmOwners)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_FOUND, llx.KindOf(err))
}

func TestWindowsOwner(t *testing.T) {
	dirs := []InstallDir{
		{Package: "Mondoo", Dir: `C:\Program Files\Mondoo\`},
		{Package: "Mondoo Providers", Dir: `C:\Program Files\Mondoo\providers`},
		{Package: "Sloppy Installer", Dir: `C:\Program Files`},
		{Package: "Root Installer", Dir: `C:\`},
		{Package: "Tool", Dir: `D:\tool`},
	}

	name, ok := WindowsOwner(`C:\Program Files\Mondoo\cnspec.exe`, dirs)
	assert.True(t, ok)
	assert.Equal(t, "Mondoo", name)

	// the most specific install directory wins
	name, ok = WindowsOwner(`c:\program files\mondoo\providers\os\os.exe`, dirs)
	assert.True(t, ok)
	assert.Equal(t, "Mondoo Providers", name)

	// a shared directory or a drive root does not make a package the owner
	_, ok = WindowsOwner(`C:\Program Files\Other\other.exe`, dirs)
	assert.False(t, ok)

	// a directory name that only starts the same is another directory
	_, ok = WindowsOwner(`D:\toolbox\x.exe`, dirs)
	assert.False(t, ok)
}

func TestWindowsOwnerComponentSharingADirectory(t *testing.T) {
	// Measured: Azure Windows Server 2022, XAMPP 7.3.2, 2026-10-26. XAMPP's
	// apache\bin holds httpd.exe and the OpenSSL libraries. Reported at the
	// directory, OpenSSL tied with Apache on the longest install directory and
	// owned httpd.exe. Reported at its library file it owns only that file.
	dirs := []InstallDir{
		{Package: "Apache HTTP Server", Dir: `C:\xampp\apache\bin`},
		{Package: "OpenSSL", Dir: `C:\xampp\apache\bin\libssl-1_1-x64.dll`},
		{Package: "XAMPP", Dir: `C:\xampp`},
	}
	name, ok := WindowsOwner(`C:\xampp\apache\bin\httpd.exe`, dirs)
	assert.True(t, ok)
	assert.Equal(t, "Apache HTTP Server", name)

	// The library itself is OpenSSL's.
	name, ok = WindowsOwner(`C:\xampp\apache\bin\libssl-1_1-x64.dll`, dirs)
	assert.True(t, ok)
	assert.Equal(t, "OpenSSL", name)
}

func TestWindowsOwnerSharedDirs(t *testing.T) {
	// install locations some installers record that hold other products too
	for _, dir := range []string{
		`C:\Windows\System32`,
		`C:\Program Files\Common Files`,
		`C:\Program Files (x86)\Common Files\`,
		`C:\Users\dev`,
		`C:\Users\dev\AppData`,
		`C:\Users\dev\AppData\Local`,
		`C:\Users\dev\AppData\Roaming`,
		`C:\Users\dev\AppData\Local\Programs`,
	} {
		dirs := []InstallDir{{Package: "Sloppy", Dir: dir}}
		_, ok := WindowsOwner(dir+`\Other\other.exe`, dirs)
		assert.False(t, ok, dir)
	}

	// a product's own directory below them still owns its files
	for _, dir := range []string{
		`C:\Program Files\Common Files\Oracle\Java`,
		`C:\Users\dev\AppData\Local\Programs\Microsoft VS Code`,
		`C:\Users\dev\AppData\Local\Discord`,
		`C:\Users\dev\tools`,
	} {
		dirs := []InstallDir{{Package: "Product", Dir: dir}}
		name, ok := WindowsOwner(dir+`\app.exe`, dirs)
		assert.True(t, ok, dir)
		assert.Equal(t, "Product", name)
	}
}

func TestDarwinOwner(t *testing.T) {
	dirs := []InstallDir{
		{Package: "Slack", Dir: "/Applications/Slack.app"},
		{Package: "Sloppy", Dir: "/Applications/"},
		{Package: "Tool", Dir: "/opt/tool"},
	}

	name, ok := DarwinOwner("/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper", dirs)
	assert.True(t, ok)
	assert.Equal(t, "Slack", name)

	// macOS compares names case-insensitively
	name, ok = DarwinOwner("/applications/slack.app/Contents/MacOS/Slack", dirs)
	assert.True(t, ok)
	assert.Equal(t, "Slack", name)

	// a shared directory does not make a package the owner
	_, ok = DarwinOwner("/Applications/Other.app/Contents/MacOS/Other", dirs)
	assert.False(t, ok)

	// a directory name that only starts the same is another directory
	_, ok = DarwinOwner("/opt/toolbox/bin/x", dirs)
	assert.False(t, ok)
}

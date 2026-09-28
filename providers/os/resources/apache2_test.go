// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The three literals below are copied verbatim out of real httpd binaries, so
// these tests fail if a vendor ever stops embedding them in this shape.
const (
	sourceBuildLayout = ` -D HTTPD_ROOT="/usr/local/apache2"` + "\x00" +
		` -D SERVER_CONFIG_FILE="conf/httpd.conf"` + "\x00"
	redhatLayout = ` -D HTTPD_ROOT="/etc/httpd"` + "\x00" +
		` -D SERVER_CONFIG_FILE="conf/httpd.conf"` + "\x00"
	debianLayout = ` -D HTTPD_ROOT="/etc/apache2"` + "\x00" +
		` -D SERVER_CONFIG_FILE="apache2.conf"` + "\x00"
)

func writeApacheBinary(t *testing.T, path string, data []byte) *afero.Afero {
	t.Helper()
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, path, data, 0o755))
	return &afero.Afero{Fs: fs}
}

func TestApacheLayoutFromBinary(t *testing.T) {
	t.Run("source build under a custom prefix", func(t *testing.T) {
		afs := writeApacheBinary(t, "/usr/local/apache2/bin/httpd", []byte("\x7fELF\x00"+sourceBuildLayout))
		layout := apacheLayoutFromBinary(afs, "/usr/local/apache2/bin/httpd")
		assert.Equal(t, "/usr/local/apache2", layout.root)
		assert.Equal(t, "conf/httpd.conf", layout.conf)
		assert.Equal(t, "/usr/local/apache2/conf/httpd.conf", layout.confPath())
	})

	t.Run("redhat package", func(t *testing.T) {
		afs := writeApacheBinary(t, "/usr/sbin/httpd", []byte(redhatLayout))
		assert.Equal(t, "/etc/httpd/conf/httpd.conf", apacheLayoutFromBinary(afs, "/usr/sbin/httpd").confPath())
	})

	t.Run("debian package", func(t *testing.T) {
		afs := writeApacheBinary(t, "/usr/sbin/apache2", []byte(debianLayout))
		assert.Equal(t, "/etc/apache2/apache2.conf", apacheLayoutFromBinary(afs, "/usr/sbin/apache2").confPath())
	})

	t.Run("binary does not exist", func(t *testing.T) {
		afs := &afero.Afero{Fs: afero.NewMemMapFs()}
		assert.Equal(t, "", apacheLayoutFromBinary(afs, "/usr/sbin/httpd").confPath())
	})

	t.Run("a binary without the literals yields nothing", func(t *testing.T) {
		afs := writeApacheBinary(t, "/usr/sbin/httpd", []byte("\x7fELF just some bytes"))
		layout := apacheLayoutFromBinary(afs, "/usr/sbin/httpd")
		assert.Equal(t, "", layout.root)
		assert.Equal(t, "", layout.confPath())
	})

	// The scanner reads in 64 KiB chunks. A literal landing across that seam is
	// the case a naive implementation truncates, so place one there deliberately.
	t.Run("literal spanning a chunk boundary", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteString(strings.Repeat("\x00", 64*1024-20))
		buf.WriteString(sourceBuildLayout)
		afs := writeApacheBinary(t, "/usr/sbin/httpd", buf.Bytes())
		assert.Equal(t, "/usr/local/apache2/conf/httpd.conf", apacheLayoutFromBinary(afs, "/usr/sbin/httpd").confPath())
	})
}

func TestApacheLayoutConfPath(t *testing.T) {
	t.Run("an absolute SERVER_CONFIG_FILE ignores the root", func(t *testing.T) {
		layout := apacheLayout{root: "/etc/httpd", conf: "/etc/custom/httpd.conf"}
		assert.Equal(t, "/etc/custom/httpd.conf", layout.confPath())
	})

	t.Run("a relative config with no root names nothing", func(t *testing.T) {
		assert.Equal(t, "", apacheLayout{conf: "conf/httpd.conf"}.confPath())
	})

	t.Run("a root with no config names nothing", func(t *testing.T) {
		assert.Equal(t, "", apacheLayout{root: "/usr/local/apache2"}.confPath())
	})

	t.Run("the zero layout names nothing", func(t *testing.T) {
		assert.Equal(t, "", apacheLayout{}.confPath())
	})
}

// The upstream httpd container image installs to /usr/local/apache2, which no
// packaged path covers. Guard that it is reachable, and that the packaged paths
// this replaces are all still listed.
func TestApacheBinariesCoverKnownInstallations(t *testing.T) {
	for _, want := range []string{
		"/usr/sbin/apache2",            // debian, ubuntu
		"/usr/sbin/httpd",              // rhel, fedora, suse
		"/usr/local/apache2/bin/httpd", // source build default prefix
	} {
		assert.Contains(t, apacheBinaries, want)
	}
}

func TestApacheVersionFromBinary(t *testing.T) {
	scan := func(data []byte) string {
		afs := writeApacheBinary(t, "/usr/local/sbin/httpd", data)
		return scanBinaryForTag(afs, "/usr/local/sbin/httpd", apacheVersionTag, isFullApacheVersion)
	}

	// String order in the apache24-2.4.68 httpd from FreeBSD 14.5 packages
	// (`strings /usr/local/sbin/httpd | grep Apache/[0-9]`): the ServerTokens
	// Major form comes first, then the full version, then the Minor form.
	t.Run("the reduced ServerTokens forms are skipped", func(t *testing.T) {
		data := []byte("LimitXMLRequestBody requires a non-negative integer.\x00Apache/2\x00file_walk_rxpool\x00" +
			"Apache/2.4.68 (FreeBSD)\x00Apache/2.4.68\x00" +
			"Container for directives based on existence of command line defines\x00Apache/2.4\x00")
		assert.Equal(t, "2.4.68", scan(data))
	})

	t.Run("the minor form before the full version is skipped", func(t *testing.T) {
		assert.Equal(t, "2.4.62", scan([]byte("\x00Apache/2.4\x00Apache/2.4.62 (Ubuntu)\x00")))
	})

	t.Run("a binary with only reduced forms yields nothing", func(t *testing.T) {
		assert.Equal(t, "", scan([]byte("\x00Apache/2\x00Apache/2.4\x00Apache/2.4.\x00")))
	})

	// A rejected match must not stop the scan from reading the chunks that
	// follow it.
	t.Run("the full version in a later chunk", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteString("\x00Apache/2\x00")
		buf.WriteString(strings.Repeat("\x00", 64*1024))
		buf.WriteString("Apache/2.4.68 (FreeBSD)\x00")
		assert.Equal(t, "2.4.68", scan(buf.Bytes()))
	})

	// A rejected match inside the overlap retained between chunks is seen
	// twice; it must be rejected both times.
	t.Run("a reduced form in the retained overlap", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteString(strings.Repeat("\x00", 64*1024-4))
		buf.WriteString("Apache/2\x00")
		buf.WriteString(strings.Repeat("\x00", 100))
		buf.WriteString("Apache/2.4.68\x00")
		assert.Equal(t, "2.4.68", scan(buf.Bytes()))
	})
}

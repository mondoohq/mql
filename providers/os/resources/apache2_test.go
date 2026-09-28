// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
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

func newApache2Conf(t *testing.T, platform *inventory.Platform, files map[string]string) *mqlApache2Conf {
	t.Helper()
	mockFiles := map[string]*mock.MockFileData{}
	for path, content := range files {
		mockFiles[path] = &mock.MockFileData{Path: path, Content: content}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: platform}, mock.WithData(&mock.TomlData{Files: mockFiles}))
	require.NoError(t, err)
	rt := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	res, err := NewResource(rt, "apache2.conf", nil)
	require.NoError(t, err)
	return res.(*mqlApache2Conf)
}

func TestApache2ConfEnvvars(t *testing.T) {
	t.Run("debian family reads /etc/apache2/envvars", func(t *testing.T) {
		// envvars-debian is /etc/apache2/envvars as shipped by the apache2
		// package on Ubuntu 24.04; Debian 10 ships a byte-identical file.
		envvars, err := os.ReadFile("testdata/apache2/envvars-debian")
		require.NoError(t, err)
		conf := newApache2Conf(t,
			&inventory.Platform{Name: "ubuntu", Version: "24.04", Family: []string{"debian", "linux", "unix", "os"}},
			map[string]string{
				"/etc/apache2/apache2.conf": "ServerRoot \"/etc/apache2\"\n",
				"/etc/apache2/envvars":      string(envvars),
			})

		ev := conf.GetEnvvars()
		require.NoError(t, ev.Error)
		require.NotNil(t, ev.Data)
		assert.Equal(t, "apache2.conf.envvars//etc/apache2/envvars", ev.Data.MqlID())

		file := ev.Data.GetFile()
		require.NoError(t, file.Error)
		require.NotNil(t, file.Data)
		assert.Equal(t, "/etc/apache2/envvars", file.Data.Path.Data)

		params := ev.Data.GetParams()
		require.NoError(t, params.Error)
		assert.Equal(t, "www-data", params.Data["APACHE_RUN_USER"])
		assert.Equal(t, "www-data", params.Data["APACHE_RUN_GROUP"])
		assert.Equal(t, "/var/run/apache2/apache2.pid", params.Data["APACHE_PID_FILE"])
		assert.Equal(t, "/var/log/apache2", params.Data["APACHE_LOG_DIR"])
		assert.Equal(t, "C", params.Data["LANG"])
	})

	t.Run("debian family without the envvars file is null", func(t *testing.T) {
		conf := newApache2Conf(t,
			&inventory.Platform{Name: "debian", Version: "12", Family: []string{"debian", "linux", "unix", "os"}},
			map[string]string{"/etc/apache2/apache2.conf": "ServerRoot \"/etc/apache2\"\n"})
		ev := conf.GetEnvvars()
		require.NoError(t, ev.Error)
		assert.Nil(t, ev.Data)
	})

	t.Run("redhat family has no envvars file", func(t *testing.T) {
		conf := newApache2Conf(t,
			&inventory.Platform{Name: "rhel", Version: "9.6", Family: []string{"redhat", "linux", "unix", "os"}},
			map[string]string{"/etc/httpd/conf/httpd.conf": "ServerRoot \"/etc/httpd\"\n"})
		ev := conf.GetEnvvars()
		require.NoError(t, ev.Error)
		assert.Nil(t, ev.Data)
	})
}

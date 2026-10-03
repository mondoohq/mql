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
	"go.mondoo.com/mql/providers/os/resources/systemd"
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

// Apache 2.4 compiled-in defaults apply when a directive is absent: Debian's
// security.conf is the only place that sets these, and `a2disconf security`
// leaves them unset (the server then sends the full version banner and answers
// TRACE).
func TestApache2ConfDisclosureDefaults(t *testing.T) {
	conf := &mqlApache2Conf{}

	t.Run("unset uses the compiled-in defaults", func(t *testing.T) {
		// params of a Debian apache2.conf with conf-enabled/security.conf disabled
		params := map[string]any{
			"DefaultRuntimeDir": "${APACHE_RUN_DIR}",
			"PidFile":           "${APACHE_PID_FILE}",
			"Timeout":           "300",
			"KeepAlive":         "On",
			"IncludeOptional":   "conf-enabled/*.conf",
		}
		tokens, err := conf.serverTokens(params)
		require.NoError(t, err)
		assert.Equal(t, "Full", tokens)
		sig, err := conf.serverSignature(params)
		require.NoError(t, err)
		assert.Equal(t, "Off", sig)
		trace, err := conf.traceEnable(params)
		require.NoError(t, err)
		assert.Equal(t, "On", trace)
	})

	t.Run("set values are reported as written", func(t *testing.T) {
		// Debian's security.conf, any key casing
		params := map[string]any{
			"ServerTokens":    "OS",
			"serversignature": "On",
			"TRACEENABLE":     "Off",
		}
		tokens, err := conf.serverTokens(params)
		require.NoError(t, err)
		assert.Equal(t, "OS", tokens)
		sig, err := conf.serverSignature(params)
		require.NoError(t, err)
		assert.Equal(t, "On", sig)
		trace, err := conf.traceEnable(params)
		require.NoError(t, err)
		assert.Equal(t, "Off", trace)
	})
}

func TestApacheUnitEnvironment(t *testing.T) {
	write := func(fs afero.Fs, path, content string) {
		require.NoError(t, afero.WriteFile(fs, path, []byte(content), 0o644))
	}
	rhel7Unit := "[Service]\nType=notify\nEnvironmentFile=/etc/sysconfig/httpd\n" +
		"ExecStart=/usr/sbin/httpd $OPTIONS -DFOREGROUND\n"

	t.Run("RHEL 7 reads /etc/sysconfig/httpd", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(fs, "/usr/lib/systemd/system/httpd.service", rhel7Unit)
		write(fs, "/etc/sysconfig/httpd", "#OPTIONS=\nLANG=C\nSWEEPTOK=Full\nOPTIONS=-DSSL\n")
		env, defines, err := apacheUnitEnvironment(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		assert.Equal(t, "Full", env["SWEEPTOK"])
		assert.Equal(t, []string{"SSL", "FOREGROUND"}, defines)
	})

	t.Run("drop-ins apply by name, /etc hides /usr/lib", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(fs, "/usr/lib/systemd/system/httpd.service",
			"[Service]\nEnvironment=LANG=C\nExecStart=/usr/sbin/httpd $OPTIONS -DFOREGROUND\n")
		write(fs, "/usr/lib/systemd/system/httpd.service.d/override.conf", "[Service]\nEnvironment=OPTIONS=-DPACKAGED\n")
		write(fs, "/etc/systemd/system/httpd.service.d/override.conf", "[Service]\nEnvironment=OPTIONS=-DLOCAL\n")
		write(fs, "/etc/systemd/system/httpd.service.d/zz.conf", "[Service]\nEnvironment=TOKENS=Prod\n")
		env, defines, err := apacheUnitEnvironment(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		assert.Equal(t, "Prod", env["TOKENS"])
		assert.Equal(t, []string{"LOCAL", "FOREGROUND"}, defines)
	})

	t.Run("no unit", func(t *testing.T) {
		env, defines, err := apacheUnitEnvironment(&afero.Afero{Fs: afero.NewMemMapFs()}, systemd.AllDropInDirs)
		require.NoError(t, err)
		assert.Nil(t, env)
		assert.Nil(t, defines)
	})

	// systemd 246 and later (and RHEL 8's 239) apply /etc/systemd/system/service.d
	// to every service; RHEL 7's 219 does not.
	t.Run("type-level drop-ins apply where systemd reads them", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(fs, "/usr/lib/systemd/system/httpd.service",
			"[Service]\nEnvironment=LANG=C\nExecStart=/usr/sbin/httpd $OPTIONS -DFOREGROUND\n")
		write(fs, "/etc/systemd/system/service.d/zz.conf", "[Service]\nEnvironment=SWEEPTOK2=Full\n")
		env, _, err := apacheUnitEnvironment(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		assert.Equal(t, "Full", env["SWEEPTOK2"])

		env, _, err = apacheUnitEnvironment(&afero.Afero{Fs: fs}, systemd.DropInDirsForVersion(219, true))
		require.NoError(t, err)
		assert.NotContains(t, env, "SWEEPTOK2")
	})

	// SUSE ships apache2.service with Alias=httpd.service apache.service.
	// systemctl enable links both aliases to it, and systemd then applies the
	// drop-ins of every name: `systemctl show apache2 -p DropInPaths` lists
	// apache2.service.d, httpd.service.d and apache.service.d files. A
	// disabled apache2 has no aliases and only apache2.service.d applies.
	suseUnit := "[Unit]\nDescription=The Apache Webserver\n[Service]\nType=notify\nPrivateTmp=true\n" +
		"ExecStart=/usr/sbin/start_apache2 -DSYSTEMD -DFOREGROUND -k start\n" +
		"[Install]\nWantedBy=multi-user.target\nAlias=httpd.service apache.service\n"
	t.Run("SUSE's apache2.service drop-ins, unit disabled", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(fs, "/usr/lib/systemd/system/apache2.service", suseUnit)
		write(fs, "/etc/systemd/system/apache2.service.d/zz-sweep.conf", "[Service]\nEnvironment=SWEEPTOK=On\n")
		write(fs, "/etc/systemd/system/httpd.service.d/zz-h.conf", "[Service]\nEnvironment=NOTALIAS=On\n")
		env, defines, err := apacheUnitEnvironment(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		assert.Equal(t, "On", env["SWEEPTOK"])
		assert.NotContains(t, env, "NOTALIAS")
		assert.Equal(t, []string{"SYSTEMD", "FOREGROUND"}, defines)
	})

	t.Run("SUSE's apache2.service enabled applies the drop-ins of every alias", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(fs, "/usr/lib/systemd/system/apache2.service", suseUnit)
		// the alias symlinks systemctl enable creates read as the same unit
		write(fs, "/etc/systemd/system/httpd.service", suseUnit)
		write(fs, "/etc/systemd/system/apache.service", suseUnit)
		write(fs, "/etc/systemd/system/apache2.service.d/zz-b.conf", "[Service]\nEnvironment=A1=x TOK=apache2\n")
		write(fs, "/etc/systemd/system/httpd.service.d/zz-a.conf", "[Service]\nEnvironment=H1=x TOK=httpd\n")
		write(fs, "/etc/systemd/system/apache.service.d/zz-p.conf", "[Service]\nEnvironment=P1=x\n")
		write(fs, "/etc/systemd/system/service.d/zz-t.conf", "[Service]\nEnvironment=T1=x\n")
		env, _, err := apacheUnitEnvironment(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		for _, k := range []string{"A1", "H1", "P1", "T1"} {
			assert.Equal(t, "x", env[k], k)
		}
		// drop-ins of all names apply together in file-name order: zz-a.conf,
		// then zz-b.conf
		assert.Equal(t, "apache2", env["TOK"])
	})

	t.Run("a separate apache2.service does not lend httpd.service its drop-ins", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(fs, "/usr/lib/systemd/system/httpd.service",
			"[Service]\nEnvironment=LANG=C\nExecStart=/usr/sbin/httpd $OPTIONS -DFOREGROUND\n")
		write(fs, "/usr/lib/systemd/system/apache2.service", suseUnit)
		write(fs, "/etc/systemd/system/apache2.service.d/zz.conf", "[Service]\nEnvironment=OTHER=x\n")
		env, _, err := apacheUnitEnvironment(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		assert.Equal(t, "C", env["LANG"])
		assert.NotContains(t, env, "OTHER")
	})

	t.Run("a missing EnvironmentFile contributes nothing", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(fs, "/usr/lib/systemd/system/httpd.service", rhel7Unit)
		env, defines, err := apacheUnitEnvironment(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		assert.Empty(t, env)
		assert.Equal(t, []string{"FOREGROUND"}, defines)
	})
}

func TestApacheLaunch(t *testing.T) {
	write := func(fs afero.Fs, path, content string) {
		require.NoError(t, afero.WriteFile(fs, path, []byte(content), 0o644))
	}
	suseCmdline := "/usr/sbin/httpd-prefork\x00-DSYSCONFIG\x00-C\x00PidFile /run/httpd.pid\x00" +
		"-C\x00Include /etc/apache2/sysconfig.d//loadmodule.conf\x00-C\x00Include /etc/apache2/sysconfig.d//global.conf\x00" +
		"-f\x00/etc/apache2/httpd.conf\x00-c\x00Include /etc/apache2/sysconfig.d//include.conf\x00" +
		"-DSYSTEMD\x00-DFOREGROUND\x00-k\x00start\x00"
	suseUnit := "[Service]\nType=notify\nExecStart=/usr/sbin/start_apache2 -DSYSTEMD -DFOREGROUND -k start\n"
	suseHost := func() afero.Fs {
		fs := afero.NewMemMapFs()
		write(fs, "/usr/sbin/start_apache2", "#!/bin/sh\n")
		write(fs, "/usr/sbin/httpd-prefork", "")
		write(fs, "/usr/lib/systemd/system/apache2.service", suseUnit)
		write(fs, "/usr/lib64/apache2-prefork/mod_info.so", "")
		write(fs, "/etc/sysconfig/apache2", "APACHE_MODULES=\"info\"\nAPACHE_SERVERTOKENS=\"OS\"\nAPACHE_SERVER_FLAGS=\"\"\n")
		return fs
	}

	t.Run("the running master's command line", func(t *testing.T) {
		fs := suseHost()
		write(fs, "/run/httpd.pid", "20045\n")
		write(fs, "/proc/20045/cmdline", suseCmdline)
		l, err := apacheLaunch(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		require.NotNil(t, l)
		assert.Equal(t, []string{"SYSCONFIG", "SYSTEMD", "FOREGROUND"}, l.Defines)
		assert.Equal(t, "Include /etc/apache2/sysconfig.d//global.conf", l.PreDirectives[2])
	})

	t.Run("SUSE without a running httpd builds it from sysconfig", func(t *testing.T) {
		fs := suseHost()
		// a stale pid file pointing at another process is ignored
		write(fs, "/run/httpd.pid", "20045\n")
		write(fs, "/proc/20045/cmdline", "/usr/bin/bash\x00")
		l, err := apacheLaunch(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		require.NotNil(t, l)
		assert.Equal(t, []string{"SYSCONFIG", "SYSTEMD", "FOREGROUND"}, l.Defines)
		assert.Equal(t, []string{
			"PidFile /run/httpd.pid",
			"LoadModule info_module /usr/lib64/apache2-prefork/mod_info.so",
			"ServerTokens OS",
		}, l.PreDirectives)
	})

	t.Run("SUSE applies the httpd.service alias drop-ins to the unit's arguments", func(t *testing.T) {
		fs := suseHost()
		write(fs, "/etc/systemd/system/httpd.service", suseUnit)
		write(fs, "/etc/systemd/system/httpd.service.d/zz.conf",
			"[Service]\nExecStart=\nExecStart=/usr/sbin/start_apache2 -DSYSTEMD -DFOREGROUND -DSWEEP -k start\n")
		l, err := apacheLaunch(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		require.NotNil(t, l)
		assert.Contains(t, l.Defines, "SWEEP")
	})

	// /run/httpd is 0710 root:apache on Red Hat, so a non-root scan cannot
	// read the running master's pid file; a stopped httpd has none. The unit
	// then says how httpd starts.
	rhelUnit := "[Service]\nType=notify\nEnvironment=LANG=C\nExecStart=/usr/sbin/httpd $OPTIONS -DFOREGROUND\n"
	t.Run("the unit's -f, -d and -C when the master cannot be read", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(fs, "/usr/lib/systemd/system/httpd.service", rhelUnit)
		write(fs, "/etc/systemd/system/httpd.service.d/zz-sweep.conf",
			"[Service]\nEnvironment=OPTIONS=\"-f /etc/httpd/conf/httpd-alt.conf -d /srv/httpd\"\n")
		write(fs, "/etc/systemd/system/httpd.service.d/zz-tokens.conf",
			"[Service]\nExecStart=\nExecStart=/usr/sbin/httpd $OPTIONS -C \"ServerTokens OS\" -DFOREGROUND\n")
		l, err := apacheLaunch(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		require.NotNil(t, l)
		assert.Equal(t, "/etc/httpd/conf/httpd-alt.conf", l.ConfigFile)
		assert.Equal(t, "/srv/httpd", l.ServerRoot)
		assert.Equal(t, []string{"ServerTokens OS"}, l.PreDirectives)
	})

	t.Run("a type-level drop-in's OPTIONS", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(fs, "/usr/lib/systemd/system/httpd.service", rhelUnit)
		write(fs, "/etc/systemd/system/service.d/zz.conf",
			"[Service]\nEnvironment=OPTIONS=\"-f /etc/httpd/conf/httpd-alt.conf\"\n")
		l, err := apacheLaunch(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		require.NotNil(t, l)
		assert.Equal(t, "/etc/httpd/conf/httpd-alt.conf", l.ConfigFile)

		l, err = apacheLaunch(&afero.Afero{Fs: fs}, systemd.DropInDirsForVersion(219, true))
		require.NoError(t, err)
		assert.Nil(t, l)
	})

	t.Run("the running master wins over the unit", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(fs, "/usr/lib/systemd/system/httpd.service", rhelUnit)
		write(fs, "/etc/systemd/system/httpd.service.d/zz-sweep.conf",
			"[Service]\nEnvironment=OPTIONS=\"-f /etc/httpd/conf/httpd-alt.conf\"\n")
		write(fs, "/run/httpd/httpd.pid", "4242\n")
		write(fs, "/proc/4242/cmdline", "/usr/sbin/httpd\x00-DFOREGROUND\x00")
		l, err := apacheLaunch(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		require.NotNil(t, l)
		assert.Equal(t, "", l.ConfigFile)
	})

	t.Run("Debian's apachectl unit adds nothing", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(fs, "/usr/lib/systemd/system/apache2.service",
			"[Service]\nType=forking\nEnvironment=APACHE_STARTED_BY_SYSTEMD=true\nExecStart=/usr/sbin/apachectl start\n")
		l, err := apacheLaunch(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		assert.Nil(t, l)
	})

	t.Run("other layouts have nothing to add when httpd is not running", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		write(fs, "/usr/lib/systemd/system/httpd.service", "[Service]\nExecStart=/usr/sbin/httpd $OPTIONS -DFOREGROUND\n")
		l, err := apacheLaunch(&afero.Afero{Fs: fs}, systemd.AllDropInDirs)
		require.NoError(t, err)
		assert.Nil(t, l)
	})
}

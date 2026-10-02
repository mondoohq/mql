// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apache2

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// suseRunningArgv is /proc/<pid>/cmdline of the httpd master on SLES 15 SP7
// with APACHE_SERVER_FLAGS="SSL", as start_apache2 starts it under systemd.
var suseRunningArgv = []string{
	"/usr/sbin/httpd-prefork", "-DSYSCONFIG", "-DSSL",
	"-C", "PidFile /run/httpd.pid",
	"-C", "Include /etc/apache2/sysconfig.d//loadmodule.conf",
	"-C", "Include /etc/apache2/sysconfig.d//global.conf",
	"-f", "/etc/apache2/httpd.conf",
	"-c", "Include /etc/apache2/sysconfig.d//include.conf",
	"-DSYSTEMD", "-DFOREGROUND", "-k", "start",
}

func TestParseLaunchArgs(t *testing.T) {
	t.Run("SUSE start_apache2", func(t *testing.T) {
		l := ParseLaunchArgs(suseRunningArgv[1:])
		assert.Equal(t, Launch{
			ConfigFile: "/etc/apache2/httpd.conf",
			Defines:    []string{"SYSCONFIG", "SSL", "SYSTEMD", "FOREGROUND"},
			PreDirectives: []string{
				"PidFile /run/httpd.pid",
				"Include /etc/apache2/sysconfig.d//loadmodule.conf",
				"Include /etc/apache2/sysconfig.d//global.conf",
			},
			PostDirectives: []string{"Include /etc/apache2/sysconfig.d//include.conf"},
		}, l)
	})

	t.Run("RHEL and Debian masters", func(t *testing.T) {
		assert.Equal(t, Launch{Defines: []string{"FOREGROUND"}}, ParseLaunchArgs([]string{"-DFOREGROUND"}))
		assert.Equal(t, Launch{}, ParseLaunchArgs([]string{"-k", "start"}))
	})

	t.Run("separate, attached and grouped arguments", func(t *testing.T) {
		l := ParseLaunchArgs([]string{"-d", "/srv/httpd", "-fconf/alt.conf", "-XD", "DEBUG", "-e", "debug", "-C", "-D", "-cTraceEnable on"})
		assert.Equal(t, "/srv/httpd", l.ServerRoot)
		assert.Equal(t, "conf/alt.conf", l.ConfigFile)
		// -X is a flag, so D takes the next argument; -e's argument is not a define
		assert.Equal(t, []string{"DEBUG"}, l.Defines)
		// "-D" here is the argument of -C, not an option
		assert.Equal(t, []string{"-D"}, l.PreDirectives)
		assert.Equal(t, []string{"TraceEnable on"}, l.PostDirectives)
	})
}

// suseSysconfig is /etc/sysconfig/apache2 on the SLES 15 SP7 sweep host,
// after `a2enmod headers proxy proxy_http`.
var suseSysconfig = map[string]string{
	"APACHE_CONF_INCLUDE_FILES": "/etc/apache2/sweep-include.conf",
	"APACHE_CONF_INCLUDE_DIRS":  "",
	"APACHE_MODULES":            "actions alias auth_basic authn_core authn_file authz_host authz_groupfile authz_core authz_user autoindex cgi dir env expires include log_config mime negotiation setenvif ssl socache_shmcb userdir reqtimeout headers proxy proxy_http",
	"APACHE_SERVER_FLAGS":       "SSL",
	"APACHE_HTTPD_CONF":         "",
	"APACHE_MPM":                "",
	"APACHE_SERVERADMIN":        "",
	"APACHE_SERVERNAME":         "",
	"APACHE_START_TIMEOUT":      "2",
	"APACHE_SERVERSIGNATURE":    "off",
	"APACHE_LOGLEVEL":           "warn",
	"APACHE_ACCESS_LOG":         "/var/log/apache2/access_log combined",
	"APACHE_USE_CANONICAL_NAME": "off",
	"APACHE_SERVERTOKENS":       "ProductOnly",
	"APACHE_TRACEENABLE":        "off",
	"APACHE_EXTENDED_STATUS":    "off",
}

// suseInstalled says which files exist: every module under
// /usr/lib64/apache2-prefork and /usr/lib64/apache2, and the include file.
func suseInstalled(p string) bool {
	if p == "/etc/apache2/sweep-include.conf" {
		return true
	}
	for _, dir := range []string{"/usr/lib64/apache2-prefork/", "/usr/lib64/apache2/"} {
		if name, ok := strings.CutPrefix(p, dir); ok {
			return strings.HasPrefix(name, "mod_") && !strings.HasPrefix(name, "mod_mod_")
		}
	}
	return false
}

func TestSUSESysconfigLaunch(t *testing.T) {
	t.Run("matches what start_apache2 generated on SLES 15 SP7", func(t *testing.T) {
		l := SUSESysconfig{
			Vars:     suseSysconfig,
			MPM:      "prefork",
			UnitArgs: []string{"-DSYSTEMD", "-DFOREGROUND", "-k", "start"},
			Exists:   suseInstalled,
		}.Launch()

		assert.Equal(t, "/etc/apache2/httpd.conf", l.ConfigFile)
		assert.Equal(t, []string{"SYSCONFIG", "SSL", "SYSTEMD", "FOREGROUND"}, l.Defines)

		// sysconfig.d/loadmodule.conf and global.conf from the host, in order
		var want []string
		want = append(want, "PidFile /run/httpd.pid")
		for _, m := range strings.Fields(suseSysconfig["APACHE_MODULES"]) {
			want = append(want, "LoadModule "+m+"_module /usr/lib64/apache2-prefork/mod_"+m+".so")
		}
		want = append(want,
			"CustomLog /var/log/apache2/access_log combined",
			"ServerSignature off",
			"LogLevel warn",
			"UseCanonicalName off",
			"ServerTokens ProductOnly",
			"TraceEnable off",
		)
		assert.Equal(t, want, l.PreDirectives)
		// sysconfig.d/include.conf
		assert.Equal(t, []string{"Include /etc/apache2/sweep-include.conf"}, l.PostDirectives)
	})

	t.Run("module names follow get_module_list", func(t *testing.T) {
		vars := map[string]string{"APACHE_MODULES": "mod_cgi cgid php8 auth_mysql missing"}
		exists := func(p string) bool {
			return strings.HasSuffix(p, "/apache2-event/mod_cgid.so") ||
				strings.HasSuffix(p, "/apache2/mod_php8.so") ||
				strings.HasSuffix(p, "/apache2/mod_auth_mysql.so")
		}
		l := SUSESysconfig{Vars: vars, MPM: "event", Exists: exists}.Launch()
		assert.Equal(t, []string{
			"PidFile /run/httpd.pid",
			"LoadModule cgid_module /usr/lib64/apache2-event/mod_cgid.so",
			"LoadModule cgid_module /usr/lib64/apache2-event/mod_cgid.so",
			"LoadModule php_module /usr/lib64/apache2/mod_php8.so",
			"LoadModule mysql_auth_module /usr/lib64/apache2/mod_auth_mysql.so",
		}, l.PreDirectives)
	})

	t.Run("flags, extended status, include dirs and the access log split", func(t *testing.T) {
		vars := map[string]string{
			"APACHE_SERVER_FLAGS":      "-D -DSTATUS INFO",
			"APACHE_EXTENDED_STATUS":   "on",
			"APACHE_HTTPD_CONF":        "/etc/apache2/alt.conf",
			"APACHE_ACCESS_LOG":        "/var/log/a combined,/var/log/b common",
			"APACHE_CONF_INCLUDE_DIRS": "vhosts.d/*.conf /nonexistent/dir/*.conf",
		}
		exists := func(p string) bool { return p == "/etc/apache2/vhosts.d" }
		l := SUSESysconfig{Vars: vars, Exists: exists}.Launch()
		assert.Equal(t, []string{"SYSCONFIG", "STATUS", "INFO", "EXTENDED_STATUS"}, l.Defines)
		assert.Equal(t, "/etc/apache2/alt.conf", l.ConfigFile)
		assert.Equal(t, []string{"PidFile /run/httpd.pid", "CustomLog /var/log/a combined", "CustomLog /var/log/b common"}, l.PreDirectives)
		assert.Equal(t, []string{"Include /etc/apache2/vhosts.d/*.conf"}, l.PostDirectives)
	})
}

// suseTree is the part of SLES 15 SP7's httpd.conf that the sysconfig layer
// replaces, with the static loadmodule.conf and global.conf httpd skips
// under -DSYSCONFIG.
func suseTree() map[string]string {
	return map[string]string{
		"/etc/apache2/httpd.conf": `<IfDefine !SYSCONFIG>
  Include /etc/apache2/loadmodule.conf
</IfDefine>
Include /etc/apache2/listen.conf
<IfDefine !SYSCONFIG>
  Include /etc/apache2/global.conf
</IfDefine>
`,
		"/etc/apache2/loadmodule.conf": `<IfModule prefork.c>
    LoadModule userdir_module /usr/lib64/apache2-prefork/mod_userdir.so
    LoadModule ssl_module /usr/lib64/apache2-prefork/mod_ssl.so
</IfModule>
`,
		"/etc/apache2/global.conf": "ServerTokens ProductOnly\nTraceEnable off\n",
		"/etc/apache2/listen.conf": `Listen 80
<IfDefine SSL>
	<IfDefine !NOSSL>
	<IfModule mod_ssl.c>
		Listen 443
	</IfModule>
	</IfDefine>
</IfDefine>
`,
		"/etc/apache2/sysconfig.d/loadmodule.conf": "LoadModule info_module /usr/lib64/apache2-prefork/mod_info.so\nLoadModule ssl_module /usr/lib64/apache2-prefork/mod_ssl.so\n",
		"/etc/apache2/sysconfig.d/global.conf":     "ServerTokens Full\nTraceEnable on\n",
		"/etc/apache2/sysconfig.d/include.conf":    "Include /etc/apache2/sweep-include.conf\n",
		"/etc/apache2/sweep-include.conf":          "MaxKeepAliveRequests 77\n",
	}
}

func parseSUSE(t *testing.T, opts ParseOptions) *Config {
	t.Helper()
	files := suseTree()
	cfg, err := ParseWithGlobOptions("/etc/apache2/httpd.conf",
		func(p string) (string, error) { return files[p], nil },
		// expandGlob in apache2.go cleans "sysconfig.d//global.conf"
		func(p string) ([]string, error) { return []string{filepath.Clean(p)}, nil },
		nil, opts)
	require.NoError(t, err)
	return cfg
}

// With APACHE_SERVERTOKENS=Full, APACHE_TRACEENABLE=on, `a2enmod info` and
// `a2dismod userdir`, SLES 15 SP7 answers with a full Server banner, TRACE
// 200 and /server-info, and serves no ~user pages: httpd reads the
// sysconfig.d files it is passed with -C/-c and skips the static ones under
// <IfDefine !SYSCONFIG>.
func TestParseSUSESysconfigLayer(t *testing.T) {
	l := ParseLaunchArgs(suseRunningArgv[1:])
	cfg := parseSUSE(t, ParseOptions{
		StaticModules:  []string{"core.c", "mod_so.c", "http_core.c", "prefork.c"},
		Defines:        l.Defines,
		PreDirectives:  l.PreDirectives,
		PostDirectives: l.PostDirectives,
	})

	var mods []string
	for _, m := range cfg.Modules {
		mods = append(mods, m.Name)
	}
	assert.Equal(t, []string{"info_module", "ssl_module"}, mods)
	assert.Equal(t, "Full", cfg.Params["ServerTokens"])
	assert.Equal(t, "on", cfg.Params["TraceEnable"])
	assert.Equal(t, "77", cfg.Params["MaxKeepAliveRequests"])
	assert.Equal(t, "/run/httpd.pid", cfg.Params["PidFile"])
	assert.Equal(t, "80,443", cfg.Params["Listen"])

	t.Run("without SYSCONFIG httpd reads the static files", func(t *testing.T) {
		cfg := parseSUSE(t, ParseOptions{StaticModules: []string{"core.c", "mod_so.c", "http_core.c", "prefork.c"}})
		assert.Equal(t, "ProductOnly", cfg.Params["ServerTokens"])
		assert.Equal(t, "80", cfg.Params["Listen"])
	})

	t.Run("-c directives come after the configuration file", func(t *testing.T) {
		cfg := parseSUSE(t, ParseOptions{
			Defines:        []string{"SYSCONFIG"},
			PreDirectives:  []string{"TraceEnable on"},
			PostDirectives: []string{"TraceEnable extended"},
		})
		assert.Equal(t, "extended", cfg.Params["TraceEnable"])
	})
}

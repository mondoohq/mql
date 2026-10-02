// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apache2

import (
	"path"
	"regexp"
	"strings"
)

// Launch is what httpd's command line adds to its configuration file.
type Launch struct {
	// ConfigFile is the -f argument, "" when httpd reads its compiled-in
	// default.
	ConfigFile string
	// ServerRoot is the -d argument.
	ServerRoot string
	// Defines are the -D parameters.
	Defines []string
	// PreDirectives are -C directives, processed before the configuration
	// file; PostDirectives are -c directives, processed after it.
	PreDirectives  []string
	PostDirectives []string
}

// httpdOptsWithArg are the httpd options that take an argument, from
// AP_SERVER_BASEARGS ("C:c:D:d:E:e:f:vVlLtTSMhX") in server/main.c plus the
// Unix MPMs' "k:" and the shared-core "R:".
const httpdOptsWithArg = "CcDdEefkR"

// ParseLaunchArgs reads an httpd command line (without argv[0]) the way
// httpd's apr_getopt does, so an attached argument (`-DSSL`) and grouped
// flags (`-tDX`) read like separate ones.
func ParseLaunchArgs(args []string) Launch {
	var l Launch
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" || len(a) < 2 || a[0] != '-' {
			break
		}
		for j := 1; j < len(a); j++ {
			opt := a[j]
			if !strings.ContainsRune(httpdOptsWithArg, rune(opt)) {
				continue
			}
			var val string
			if j+1 < len(a) {
				val = a[j+1:]
			} else if i+1 < len(args) {
				i++
				val = args[i]
			}
			switch opt {
			case 'C':
				l.PreDirectives = append(l.PreDirectives, val)
			case 'c':
				l.PostDirectives = append(l.PostDirectives, val)
			case 'D':
				l.Defines = append(l.Defines, val)
			case 'd':
				l.ServerRoot = val
			case 'f':
				l.ConfigFile = val
			}
			break
		}
	}
	return l
}

// SUSESysconfig is what SUSE's start_apache2 needs to build httpd's command
// line from /etc/sysconfig/apache2.
type SUSESysconfig struct {
	// Vars are the variables of /etc/sysconfig/apache2.
	Vars map[string]string
	// MPM is the multi-processing module of the httpd binary start_apache2
	// runs: APACHE_MPM, or the target of the /usr/sbin/httpd alternative.
	MPM string
	// UnitArgs are the arguments the systemd unit passes to start_apache2
	// (`-DSYSTEMD -DFOREGROUND -k start`).
	UnitArgs []string
	// Exists reports whether a file or directory exists.
	Exists func(string) bool
}

var phpModuleID = regexp.MustCompile(`^php[89]_module$`)

// Launch returns the command line start_apache2 (SLES 15 and 16, openSUSE
// Leap 15 and 16) runs httpd with, with the files it generates into
// /etc/apache2/sysconfig.d/ inlined as the directives they hold:
//
//	httpd-<mpm> -DSYSCONFIG <flags> -C "PidFile /run/httpd.pid"
//	  -C "Include sysconfig.d/loadmodule.conf" -C "Include sysconfig.d/global.conf"
//	  -f /etc/apache2/httpd.conf -c "Include sysconfig.d/include.conf" <unit args>
//
// start_apache2 regenerates those files from the sysconfig variables on
// every start, so this is the configuration the next start loads.
func (s SUSESysconfig) Launch() Launch {
	exists := s.Exists
	if exists == nil {
		exists = func(string) bool { return false }
	}
	v := s.Vars

	l := Launch{Defines: []string{"SYSCONFIG"}}
	for _, f := range strings.Fields(v["APACHE_SERVER_FLAGS"]) {
		switch {
		case f == "-D":
		case strings.HasPrefix(f, "-D"):
			l.Defines = append(l.Defines, f[2:])
		default:
			l.Defines = append(l.Defines, f)
		}
	}
	switch v["APACHE_EXTENDED_STATUS"] {
	case "lua":
		l.Defines = append(l.Defines, "LUA_STATUS")
	case "on":
		l.Defines = append(l.Defines, "EXTENDED_STATUS")
	}

	l.ConfigFile = v["APACHE_HTTPD_CONF"]
	if l.ConfigFile == "" {
		l.ConfigFile = "/etc/apache2/httpd.conf"
	}

	l.PreDirectives = append(l.PreDirectives, "PidFile /run/httpd.pid")
	l.PreDirectives = append(l.PreDirectives, s.loadModules()...)

	// global.conf, in the order start_apache2 writes it
	if log := v["APACHE_ACCESS_LOG"]; log != "" {
		// `sed 's:,:\nCustomLog :'` splits at the first comma only
		first, rest, found := strings.Cut(log, ",")
		l.PreDirectives = append(l.PreDirectives, "CustomLog "+first)
		if found {
			l.PreDirectives = append(l.PreDirectives, "CustomLog "+rest)
		}
	}
	for _, d := range []struct{ name, variable string }{
		{"ServerAdmin", "APACHE_SERVERADMIN"},
		{"ServerName", "APACHE_SERVERNAME"},
		{"ServerSignature", "APACHE_SERVERSIGNATURE"},
		{"LogLevel", "APACHE_LOGLEVEL"},
		{"UseCanonicalName", "APACHE_USE_CANONICAL_NAME"},
		{"ServerTokens", "APACHE_SERVERTOKENS"},
		{"TraceEnable", "APACHE_TRACEENABLE"},
	} {
		if val := v[d.variable]; val != "" {
			l.PreDirectives = append(l.PreDirectives, d.name+" "+val)
		}
	}

	// include.conf
	for _, f := range strings.Fields(v["APACHE_CONF_INCLUDE_FILES"]) {
		if !strings.HasPrefix(f, "/") {
			f = "/etc/apache2/" + f
		}
		if exists(f) {
			l.PostDirectives = append(l.PostDirectives, "Include "+f)
		}
	}
	for _, d := range strings.Fields(v["APACHE_CONF_INCLUDE_DIRS"]) {
		if !strings.HasPrefix(d, "/") {
			d = "/etc/apache2/" + d
		}
		parent := d
		if i := strings.LastIndexByte(d, '/'); i >= 0 {
			parent = d[:i]
		}
		if exists(d) || exists(parent) {
			l.PostDirectives = append(l.PostDirectives, "Include "+d)
		}
	}

	unit := ParseLaunchArgs(s.UnitArgs)
	l.Defines = append(l.Defines, unit.Defines...)
	l.PreDirectives = append(l.PreDirectives, unit.PreDirectives...)
	l.PostDirectives = append(l.PostDirectives, unit.PostDirectives...)
	return l
}

// loadModules returns the LoadModule lines get_module_list in
// /usr/share/apache2/script-helpers builds from APACHE_MODULES. A module
// whose shared object is not installed is left out, as start_apache2 does.
func (s SUSESysconfig) loadModules() []string {
	var res []string
	for _, module := range strings.Fields(s.Vars["APACHE_MODULES"]) {
		switch module {
		case "mod_cgid", "cgid":
			if s.MPM == "prefork" {
				module = strings.TrimSuffix(module, "d")
			}
		case "mod_cgi", "cgi":
			if s.MPM == "event" || s.MPM == "worker" {
				module += "d"
			}
		}

		id := strings.TrimPrefix(module, "mod_") + "_module"
		switch {
		case id == "auth_mysql_module":
			id = "mysql_auth_module"
		case phpModuleID.MatchString(id):
			id = "php_module"
		}

		modulePath := ""
	search:
		for _, libdir := range []string{"/usr/lib64", "/usr/lib"} {
			for _, p := range []string{
				path.Join(libdir, "apache2-"+s.MPM, "mod_"+module+".so"),
				path.Join(libdir, "apache2-"+s.MPM, module+".so"),
				path.Join(libdir, "apache2", "mod_"+module+".so"),
				path.Join(libdir, "apache2", module+".so"),
			} {
				if s.Exists != nil && s.Exists(p) {
					modulePath = p
					break search
				}
			}
		}
		if modulePath != "" {
			res = append(res, "LoadModule "+id+" "+modulePath)
		}
	}
	return res
}

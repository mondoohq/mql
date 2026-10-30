// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package nginx

import (
	"path"
	"regexp"
	"strings"
)

// LaunchArgs is what an nginx command line says about the configuration it
// loads. The last -c, -p and -g win, as in nginx's own option parser.
type LaunchArgs struct {
	// Binary is argv[0].
	Binary string
	// Conf is the -c configuration file.
	Conf string
	// Prefix is the -p prefix path.
	Prefix string
	// Globals holds the -g directives, which nginx reads as part of the main
	// context.
	Globals string
}

// masterTitle starts the process title nginx gives its master process.
const masterTitle = "nginx: master process "

// nginxOptsWithArg are the nginx options that take an argument (src/core/nginx.c,
// ngx_get_options): -s signal, -p prefix, -e error log, -c file, -g directives.
const nginxOptsWithArg = "specg"

// ParseProcCmdline reads the content of /proc/<pid>/cmdline of an nginx
// process. The master process rewrites its argv into the title
// "nginx: master process <argv joined by spaces>", which is read back by
// splitting on spaces; the -g value, which contains spaces, runs up to the
// next option. A process that kept its NUL-separated argv is read as is.
// ok is false when the content is not an nginx master or an nginx binary's
// command line, as with a stale pid file that names another process.
func ParseProcCmdline(data []byte) (LaunchArgs, bool) {
	s := strings.TrimRight(string(data), "\x00")
	if s == "" {
		return LaunchArgs{}, false
	}

	if rest, ok := strings.CutPrefix(s, masterTitle); ok && !strings.Contains(rest, "\x00") {
		argv := strings.Fields(rest)
		if len(argv) == 0 {
			return LaunchArgs{}, false
		}
		return parseArgs(argv, true), true
	}
	if strings.HasPrefix(s, "nginx: ") {
		// a worker, cache manager or cache loader title carries no arguments
		return LaunchArgs{}, false
	}

	argv := strings.Split(s, "\x00")
	if !strings.Contains(path.Base(argv[0]), "nginx") {
		return LaunchArgs{}, false
	}
	return parseArgs(argv, false), true
}

// parseArgs reads argv the way ngx_get_options does: options may be grouped
// (-tq) and an option's argument may be attached (-c/etc/x.conf) or follow
// as the next argument. In a process title the -g value was split on its
// spaces, so with title set it extends over the following words up to the
// next one that starts with '-'.
func parseArgs(argv []string, title bool) LaunchArgs {
	la := LaunchArgs{Binary: argv[0]}
	args := argv[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			continue
		}
		for j := 1; j < len(a); j++ {
			opt := a[j]
			if !strings.ContainsRune(nginxOptsWithArg, rune(opt)) {
				continue
			}
			val := a[j+1:]
			if val == "" && i+1 < len(args) {
				i++
				val = args[i]
			}
			if opt == 'g' && title {
				for i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					i++
					val += " " + args[i]
				}
			}
			switch opt {
			case 'c':
				la.Conf = val
			case 'p':
				la.Prefix = val
			case 'g':
				la.Globals = val
			}
			break
		}
	}
	return la
}

// BuildInfo holds the paths nginx was built with, from `nginx -V`.
type BuildInfo struct {
	// Prefix is --prefix, or /usr/local/nginx/ when the build does not set it.
	Prefix string
	// ConfPath is --conf-path, or conf/nginx.conf.
	ConfPath string
	// PidPath is --pid-path, or logs/nginx.pid.
	PidPath string
}

var (
	reConfigureArgs = regexp.MustCompile(`(?m)^configure arguments:(.*)$`)
	reConfigureOpt  = regexp.MustCompile(`--(prefix|conf-path|pid-path)=(\S+)`)
)

// ParseBuildInfo reads the paths from `nginx -V` output. ok is false when the
// output has no "configure arguments:" line, so it did not come from nginx.
// The defaults for options the build leaves out are those of nginx's
// auto/options.
func ParseBuildInfo(output string) (BuildInfo, bool) {
	m := reConfigureArgs.FindStringSubmatch(output)
	if m == nil {
		return BuildInfo{}, false
	}
	b := BuildInfo{
		Prefix:   "/usr/local/nginx/",
		ConfPath: "conf/nginx.conf",
		PidPath:  "logs/nginx.pid",
	}
	for _, o := range reConfigureOpt.FindAllStringSubmatch(m[1], -1) {
		v := strings.Trim(o[2], `'"`)
		switch o[1] {
		case "prefix":
			b.Prefix = v
		case "conf-path":
			b.ConfPath = v
		case "pid-path":
			b.PidPath = v
		}
	}
	return b, true
}

// ConfFile returns the configuration file an nginx started with la loads:
// its -c, otherwise the build's conf path. A relative path is relative to
// the -p prefix, otherwise to the build's prefix.
func ConfFile(la LaunchArgs, b BuildInfo) string {
	conf := la.Conf
	if conf == "" {
		conf = b.ConfPath
	}
	return FullPath(conf, la, b)
}

// FullPath resolves a path from the command line or the build against the
// prefix the way ngx_conf_full_name does.
func FullPath(p string, la LaunchArgs, b BuildInfo) string {
	if p == "" || path.IsAbs(p) {
		return p
	}
	prefix := la.Prefix
	if prefix == "" {
		prefix = b.Prefix
	}
	if !path.IsAbs(prefix) {
		// nginx resolves a relative prefix against its working directory,
		// which is / under systemd and init scripts.
		prefix = "/" + prefix
	}
	return path.Join(prefix, p)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"regexp"
	"strings"
)

// The FreeBSD loader reads its configuration from the loader.conf files
// before the kernel starts. `module_blacklist` there names the modules whose
// `<name>_load="YES"` it skips.

const (
	// FreeBSDLoaderDefaultsConf is read first and sets the default
	// module_blacklist.
	FreeBSDLoaderDefaultsConf = "/boot/defaults/loader.conf"
	// FreeBSDLoaderConf is the administrator's loader configuration.
	FreeBSDLoaderConf = "/boot/loader.conf"
	// FreeBSDLoaderConfDir holds *.conf files read after FreeBSDLoaderConf
	// (loader_conf_dirs).
	FreeBSDLoaderConfDir = "/boot/loader.conf.d"
	// FreeBSDLoaderConfLocal is read last (local_loader_conf_files).
	FreeBSDLoaderConfLocal = "/boot/loader.conf.local"
)

// FreeBSDLoaderConfFiles returns the loader configuration files in the order
// the loader reads them, given the *.conf files of FreeBSDLoaderConfDir in
// their order: the defaults, /boot/loader.conf, the directory's files, and
// /boot/loader.conf.local.
func FreeBSDLoaderConfFiles(confDirFiles []string) []string {
	files := []string{FreeBSDLoaderDefaultsConf, FreeBSDLoaderConf}
	files = append(files, confDirFiles...)
	return append(files, FreeBSDLoaderConfLocal)
}

var (
	// `name="value"` or `name=value`, with an optional trailing comment
	freebsdLoaderAssignment = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*=\s*(?:"([^"]*)"|([^\s#]*))`)
	// ${name} in a value
	freebsdLoaderVariable = regexp.MustCompile(`\$\{([A-Za-z0-9_.-]+)\}`)
	// a module name in module_blacklist; the loader splits the list on
	// anything that is not a letter, digit, '-' or '_'
	freebsdBlacklistToken = regexp.MustCompile(`[-A-Za-z0-9_]+`)
)

// ParseFreeBSDLoaderConf applies the assignments of one loader.conf file to
// env, in order, the way the loader does: a later assignment replaces an
// earlier one, and ${name} in a value expands to name's value at that point
// (`module_blacklist="${module_blacklist} nvidia"` appends).
func ParseFreeBSDLoaderConf(content string, env map[string]string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := freebsdLoaderAssignment.FindStringSubmatchIndex(line)
		if m == nil {
			continue
		}
		name := line[m[2]:m[3]]
		var value string
		if m[4] >= 0 {
			// quoted
			value = line[m[4]:m[5]]
		} else if m[6] >= 0 {
			value = line[m[6]:m[7]]
		}
		env[name] = freebsdLoaderVariable.ReplaceAllStringFunc(value, func(ref string) string {
			return env[ref[2:len(ref)-1]]
		})
	}
}

// ParseFreeBSDModuleBlacklist returns the module names of a module_blacklist
// value.
func ParseFreeBSDModuleBlacklist(value string) map[string]bool {
	res := map[string]bool{}
	for _, name := range freebsdBlacklistToken.FindAllString(value, -1) {
		res[name] = true
	}
	return res
}

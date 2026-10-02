// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mongodb

import (
	"path"
	"strings"
)

// ConfigFromArgs returns the configuration file a mongod command line loads,
// from `-f <file>`, `-f<file>`, `--config <file>` or `--config=<file>`. argv
// excludes the program name. It is empty when the command line names no
// file, in which case mongod reads none.
//
// A relative path is resolved against the root directory, which is where
// systemd starts a service that sets no WorkingDirectory=.
func ConfigFromArgs(argv []string) string {
	// A repeated -f/--config keeps the last one, as a later option on a
	// command line overrides an earlier one.
	var conf string
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "-f" || arg == "--config":
			if i+1 < len(argv) {
				conf = argv[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--config="):
			conf = strings.TrimPrefix(arg, "--config=")
		case strings.HasPrefix(arg, "-f") && !strings.HasPrefix(arg, "--"):
			conf = strings.TrimPrefix(arg, "-f")
		}
	}
	if conf == "" {
		return ""
	}
	if !path.IsAbs(conf) {
		conf = path.Join("/", conf)
	}
	return conf
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package bind9

import "strings"

// namedOptsWithArg are the named(8) options that take an argument, from the
// getopt string in bin/named/include/named/main.h (NS_MAIN_ARGS in BIND 9.10
// and 9.11, NAMED_MAIN_ARGS from 9.16). Options that later releases dropped
// (-i, -P) are kept so an old command line still parses. -C took an argument
// only up to 9.11 and is read the way current releases read it, as a flag.
const namedOptsWithArg = "AcdDEiLMmnNpPStTUuxX"

// ConfigFromArgs returns the configuration file a named command line
// (without argv[0]) loads with -c, or "" when it passes none and named reads
// its compiled-in default. It parses the arguments the way named's getopt
// does, so `-c/etc/x.conf`, `-fc /etc/x.conf` and an option argument that
// happens to be "-c" (as in `-u -c`) are read correctly. The last -c wins.
func ConfigFromArgs(args []string) string {
	conf := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if len(a) < 2 || a[0] != '-' {
			// named takes no operands; getopt stops at the first one.
			break
		}
		for j := 1; j < len(a); j++ {
			opt := a[j]
			if !strings.ContainsRune(namedOptsWithArg, rune(opt)) {
				continue
			}
			var val string
			if j+1 < len(a) {
				val = a[j+1:]
			} else if i+1 < len(args) {
				i++
				val = args[i]
			}
			if opt == 'c' {
				conf = val
			}
			break
		}
	}
	return conf
}

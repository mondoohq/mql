// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package squid

import "strings"

// argOptions are the single-letter squid options that take an argument, from
// squid's getopt string "CDFNRSYXa:d:f:hk:m::n:sl:u:vz?". -m takes an
// optional one, which getopt only reads when it is attached (-mmalloc).
const argOptions = "adfknlu"

// ConfigFromArgs returns the configuration file a squid command line names
// with -f, "" when it names none. argv excludes the program name. Short
// options may be grouped (-NYCf /etc/squid/alt.conf) and their argument
// attached (-f/etc/squid/alt.conf), as getopt allows; the last -f wins. Long
// options (--foreground, --kid squid-1) take no part.
func ConfigFromArgs(argv []string) string {
	conf := ""
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			break
		}
		if len(arg) < 2 || arg[0] != '-' || arg[1] == '-' {
			continue
		}
		for j := 1; j < len(arg); j++ {
			opt := arg[j]
			if !strings.ContainsRune(argOptions, rune(opt)) {
				// -m's optional argument is the rest of this word
				if opt == 'm' {
					break
				}
				continue
			}
			value := arg[j+1:]
			if value == "" {
				if i+1 >= len(argv) {
					return conf
				}
				i++
				value = argv[i]
			}
			if opt == 'f' {
				conf = value
			}
			break
		}
	}
	return conf
}

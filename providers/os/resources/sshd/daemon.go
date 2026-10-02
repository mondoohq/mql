// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sshd

import (
	"path"
	"strings"
)

// DaemonCommandLine holds what a running sshd was started with that changes
// its effective configuration.
type DaemonCommandLine struct {
	// ConfigFile is the -f argument, empty when sshd reads its default file
	ConfigFile string
	// Options are the -o arguments in order, each a "Keyword=value" or
	// "Keyword value" config line
	Options []string
}

// sshdFlagsWithArgument are the sshd(8) flags that take an argument
// (getopt "C:E:b:c:f:g:h:k:o:p:u:"). -b and -k are protocol 1 options that
// OpenSSH 7.4 removed; they stay so a daemon from an older release that was
// started with them is still parsed correctly.
const sshdFlagsWithArgument = "CEbcfghkopu"

// algorithmListKeywords are the keywords whose value is a comma-separated
// algorithm list. Such a value never holds whitespace, so it survives the
// listener rewriting its argv into one space-joined process title.
var algorithmListKeywords = map[string]struct{}{
	"ciphers":                     {},
	"macs":                        {},
	"kexalgorithms":               {},
	"gssapikexalgorithms":         {},
	"hostkeyalgorithms":           {},
	"pubkeyacceptedkeytypes":      {},
	"pubkeyacceptedalgorithms":    {},
	"hostbasedacceptedkeytypes":   {},
	"hostbasedacceptedalgorithms": {},
	"casignaturealgorithms":       {},
}

// ParseDaemonCommandLine reads /proc/<pid>/cmdline of a running sshd and
// returns the -f and -o arguments it was started with. ok is false when the
// command line is not sshd's.
//
// RHEL 8 starts sshd as `sshd -D $OPTIONS $CRYPTO_POLICY`, where
// CRYPTO_POLICY holds the system crypto policy as -oCiphers=..., -oMACs=...
// options. Options given on the command line override sshd_config, so a bare
// `sshd -T` does not show what the daemon accepts.
//
// From OpenSSH 8.2 on, the listener replaces its argv with a single process
// title, "sshd: /usr/sbin/sshd -D -o ... [listener] 0 of 10-100 startups",
// and the boundaries between arguments are lost. From such a title only
// algorithm-list options are taken, since their values cannot hold spaces.
func ParseDaemonCommandLine(cmdline []byte) (DaemonCommandLine, bool) {
	args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	exact := true
	if len(args) == 1 {
		title, isTitle := strings.CutPrefix(args[0], "sshd: ")
		if isTitle {
			if i := strings.Index(title, " [listener]"); i >= 0 {
				title = title[:i]
			}
		}
		if isTitle || strings.ContainsAny(args[0], " \t") {
			args = strings.Fields(title)
			exact = false
		}
	}
	if len(args) == 0 || path.Base(args[0]) != "sshd" {
		return DaemonCommandLine{}, false
	}

	var res DaemonCommandLine
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if len(arg) < 2 || arg[0] != '-' {
			continue
		}
		if arg == "--" {
			break
		}
		// walk a flag cluster like -De or -oCiphers=...
		for j := 1; j < len(arg); j++ {
			flag := arg[j]
			if !strings.ContainsRune(sshdFlagsWithArgument, rune(flag)) {
				continue
			}
			value := arg[j+1:]
			if value == "" {
				if i+1 >= len(args) {
					break
				}
				i++
				value = args[i]
			}
			switch flag {
			case 'f':
				res.ConfigFile = value
			case 'o':
				if exact || isAlgorithmListOption(value) {
					res.Options = append(res.Options, value)
				}
			}
			break
		}
	}
	return res, true
}

func isAlgorithmListOption(opt string) bool {
	keyword, value, ok := strings.Cut(opt, "=")
	if !ok || value == "" {
		return false
	}
	_, known := algorithmListKeywords[strings.ToLower(strings.TrimSpace(keyword))]
	return known
}

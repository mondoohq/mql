// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"io"
	"strings"
	"unicode"

	"github.com/cockroachdb/errors"
)

type LinuxKernelArguments struct {
	Path      string
	Device    string
	Arguments map[string]string
}

// ParseLinuxKernelArguments parses /proc/cmdline. Parameters are separated
// by whitespace, and double quotes keep whitespace inside one (the kernel's
// next_arg); a parameter is split at its first '=' only, so values like
// `root=UUID=...` and `rootflags=subvol=root` keep their own '='.
// BOOT_IMAGE (set by the boot loader) becomes Path and root becomes Device,
// wherever they appear; both are left out of Arguments. When a parameter
// repeats, the last one wins.
func ParseLinuxKernelArguments(r io.Reader) (LinuxKernelArguments, error) {
	res := LinuxKernelArguments{
		Arguments: map[string]string{},
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return res, err
	}

	for _, param := range splitKernelCmdline(string(data)) {
		key, value, _ := strings.Cut(param, "=")
		switch key {
		case "BOOT_IMAGE":
			res.Path = value
		case "root":
			res.Device = value
		default:
			res.Arguments[key] = value
		}
	}

	return res, nil
}

// splitKernelCmdline splits a kernel command line into parameters the way
// the kernel does: whitespace separates them except inside double quotes,
// and the quotes themselves are dropped.
func splitKernelCmdline(cmdline string) []string {
	var params []string
	var cur strings.Builder
	inQuote := false
	started := false
	for _, r := range cmdline {
		switch {
		case r == '"':
			inQuote = !inQuote
			started = true
		case unicode.IsSpace(r) && !inQuote:
			if started {
				params = append(params, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if started {
		params = append(params, cur.String())
	}
	return params
}

// kernel version includes the kernel version, build data, buildhost, compiler version and an optional build date
func ParseLinuxKernelVersion(r io.Reader) (string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	values := strings.Split(string(data), " ")
	if len(values) > 2 && values[1] == "version" {
		return values[2], nil
	}

	return "", errors.New("cannot determine kernel version")
}

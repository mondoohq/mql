// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"bufio"
	"io"
	"path"
	"regexp"
	"strings"
)

// Compiled once: each of these is matched against every line of its command's
// output.
var (
	lsmodEntry       = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s*(\S*)$`)
	procModulesEntry = regexp.MustCompile(`^(\S+)\s(\S+)\s(\S+)\s(.*)$`)
	kldstatEntry     = regexp.MustCompile(`^\s+(\S+)\s+(\S+)\s+(\S+)\s*(\S*)\s*(\S*)$`)
	kextstatEntry    = regexp.MustCompile(`^\s+(\S+)\s+(\S+)\s+(\S+)\s*(\S*)\s*(\S*)\s*(\S*)`)
	genkexEntry      = regexp.MustCompile(`^\s*(\S+)\s+(\S+)\s+(\S+)\s*$`)
)

func ParseLsmod(r io.Reader) []*KernelModule {
	res := []*KernelModule{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		m := lsmodEntry.FindStringSubmatch(line)
		if len(m) == 5 {
			if m[1] == "Module" {
				continue
			}

			res = append(res, &KernelModule{
				Name:   strings.TrimSpace(m[1]),
				Size:   strings.TrimSpace(m[2]),
				UsedBy: strings.TrimSpace(m[3]),
			})
		}
	}

	return res
}

func ParseLinuxProcModules(r io.Reader) []*KernelModule {
	res := []*KernelModule{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		m := procModulesEntry.FindStringSubmatch(line)
		if len(m) == 5 {
			res = append(res, &KernelModule{
				Name:   strings.TrimSpace(m[1]),
				Size:   strings.TrimSpace(m[2]),
				UsedBy: strings.TrimSpace(m[3]),
			})
		}
	}

	return res
}

func ParseKldstat(r io.Reader) []*KernelModule {
	res := []*KernelModule{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		m := kldstatEntry.FindStringSubmatch(line)
		if len(m) == 6 {
			res = append(res, &KernelModule{
				Name:   strings.TrimSpace(m[5]),
				Size:   strings.TrimSpace(m[4]),
				UsedBy: strings.TrimSpace(m[2]),
			})
		}
	}

	return res
}

func ParseKextstat(r io.Reader) []*KernelModule {
	res := []*KernelModule{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		m := kextstatEntry.FindStringSubmatch(line)
		if len(m) == 7 {
			res = append(res, &KernelModule{
				Name:   strings.TrimSpace(m[6]),
				Size:   strings.TrimSpace(m[4]),
				UsedBy: strings.TrimSpace(m[2]),
			})
		}
	}

	return res
}

func ParseGenkex(stdout io.Reader) ([]*KernelModule, error) {
	res := []*KernelModule{}

	// genkex output is like this:
	// Text address     Size File

	// f10009d5b06d8000     d000 /usr/lib/drivers/bpf
	// f10009d5b06a2000    36000 /usr/lib/drivers/autofs.ext
	// f10009d5b0685000    1d000 /usr/lib/drivers/ahafs.ext

	scanner := bufio.NewScanner(stdout)
	scanner.Scan()
	for scanner.Scan() {
		line := scanner.Text()
		m := genkexEntry.FindStringSubmatch(line)
		if len(m) == 4 {
			// Get the last part file name
			// /usr/lib/drivers/bpf -> bpf
			name := path.Base(m[3])
			res = append(res, &KernelModule{
				Name: name,
				Size: strings.TrimSpace(m[2]),
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

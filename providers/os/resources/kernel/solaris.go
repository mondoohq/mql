// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// SolarisKernelManager reads the running kernel of Oracle Solaris and the
// illumos distributions, which share modinfo and prtconf.
type SolarisKernelManager struct {
	conn shared.Connection
}

func (s *SolarisKernelManager) Name() string {
	return "Solaris Kernel Manager"
}

// Info reports the kernel version from `uname -v`, which on Solaris 11 names
// the SRU (11.4.86.201.2) where `uname -r` only says 5.11, plus the boot
// properties prtconf lists for the root node.
func (s *SolarisKernelManager) Info() (KernelInfo, error) {
	cmd, err := s.conn.RunCommand("uname -v")
	if err != nil {
		return KernelInfo{}, errors.Wrap(err, "could not read kernel version")
	}
	if cmd.ExitStatus != 0 {
		return KernelInfo{}, errors.New("could not read kernel version: uname -v failed")
	}
	version, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return KernelInfo{}, errors.Wrap(err, "could not read kernel version")
	}

	cmd, err = s.conn.RunCommand("prtconf -v")
	if err != nil {
		return KernelInfo{}, errors.Wrap(err, "could not read boot properties")
	}
	if cmd.ExitStatus != 0 {
		return KernelInfo{}, errors.New("could not read boot properties: prtconf -v failed")
	}
	props, err := ParseSolarisPrtconfProperties(cmd.Stdout)
	if err != nil {
		return KernelInfo{}, err
	}

	return solarisKernelInfo(strings.TrimSpace(string(version)), props), nil
}

// solarisKernelInfo maps the boot properties onto KernelInfo: the kernel image
// the system booted (whoami), the root it booted from (the ZFS boot dataset, or
// the boot device path on a UFS root), and the boot arguments.
func solarisKernelInfo(version string, props map[string]string) KernelInfo {
	res := KernelInfo{
		Version:   version,
		Path:      props["whoami"],
		Device:    props["zfs-bootfs"],
		Arguments: map[string]string{},
	}
	if res.Device == "" {
		res.Device = props["bootpath"]
	}
	for arg := range strings.FieldsSeq(props["boot-args"]) {
		key, value, _ := strings.Cut(arg, "=")
		res.Arguments[key] = value
	}
	return res
}

// Parameters is empty: Solaris has no sysctl tree. Its tunables live in
// /etc/system and the ipadm protocol properties, neither of which is a
// key/value view of the running kernel.
func (s *SolarisKernelManager) Parameters() (map[string]string, error) {
	return map[string]string{}, nil
}

func (s *SolarisKernelManager) Modules() ([]*KernelModule, error) {
	cmd, err := s.conn.RunCommand("modinfo")
	if err != nil {
		return nil, errors.Wrap(err, "could not read kernel modules")
	}
	if cmd.ExitStatus != 0 {
		return nil, errors.New("could not read kernel modules: modinfo failed")
	}
	return ParseSolarisModinfo(cmd.Stdout)
}

// ID LOADADDR         SIZE   INFO SYS NAMEDESC
// 4  --               25b18  36   1   dtrace (Dynamic Tracing)
// 0  fffffffffb800000 3f8727 --   1   unix
var modinfoEntry = regexp.MustCompile(`^\s*\d+\s+\S+\s+([0-9a-fA-F]+)\s+\S+\s+\S+\s+(\S+)`)

// ParseSolarisModinfo reads `modinfo`. A module that registers several
// linkages (autofs is both a filesystem and a syscall) is listed once per
// linkage under the same ID; it is reported once. Sizes are hexadecimal in
// modinfo and converted to decimal to match what Linux reports.
func ParseSolarisModinfo(r io.Reader) ([]*KernelModule, error) {
	res := []*KernelModule{}
	seen := map[string]struct{}{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		m := modinfoEntry.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		name := m[2]
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}

		size := m[1]
		if n, err := strconv.ParseUint(m[1], 16, 64); err == nil {
			size = strconv.FormatUint(n, 10)
		}
		res = append(res, &KernelModule{Name: name, Size: size})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

var (
	prtconfName  = regexp.MustCompile(`^\s*name='([^']+)'\s+type=(\S+)`)
	prtconfValue = regexp.MustCompile(`^\s*value='(.*)'\s*$`)
)

// ParseSolarisPrtconfProperties reads the string properties of `prtconf -v`,
// each written as a name line followed by a value line:
//
//	name='whoami' type=string items=1
//	    value='/platform/i86pc/kernel/amd64/unix'
//
// Only the first occurrence of a name is kept: the system properties at the
// top of the listing come before any device node that reuses a name. Non-string
// properties (boot-args is `type=unknown value=00` when empty) are skipped.
func ParseSolarisPrtconfProperties(r io.Reader) (map[string]string, error) {
	res := map[string]string{}

	pending := ""
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if m := prtconfName.FindStringSubmatch(line); m != nil {
			pending = ""
			if m[2] == "string" {
				pending = m[1]
			}
			continue
		}
		if pending == "" {
			continue
		}
		if m := prtconfValue.FindStringSubmatch(line); m != nil {
			if _, ok := res[pending]; !ok {
				res[pending] = m[1]
			}
		}
		pending = ""
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

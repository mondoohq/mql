// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"archive/tar"
	"bufio"
	"io"
	"strings"

	"github.com/rs/zerolog/log"
)

// ParseSysctl reads `sysctl -a` output into a name to value map. sep is the
// string that follows the name on each line: "=" for Linux, OpenBSD, NetBSD
// and FreeBSD's `sysctl -e`, ":" for macOS and FreeBSD's default format.
//
// A line is split on its first separator only, since values may contain the
// separator themselves (macOS `kern.version` holds colons, a Linux value may
// hold an equals sign). A line whose text before the separator is not a
// sysctl name continues the value of the previous line: FreeBSD prints
// multi-line values such as `kern.msgbuf` (the kernel message buffer) or
// `vm.phys_segs` verbatim, and their lines are not parameters of their own.
func ParseSysctl(r io.Reader, sep string) (map[string]string, error) {
	kernelParameters := map[string]string{}

	var name string
	var value strings.Builder
	flush := func() {
		if name != "" {
			kernelParameters[name] = strings.TrimSpace(value.String())
		}
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		key, val, found := strings.Cut(line, sep)
		key = strings.TrimRight(key, " \t")
		if found && isSysctlName(key) {
			flush()
			name = key
			value.Reset()
			value.WriteString(val)
			continue
		}

		if name == "" {
			log.Debug().Str("line", line).Msg("cannot parse sysctl line")
			continue
		}
		value.WriteByte('\n')
		value.WriteString(line)
	}
	flush()

	return kernelParameters, scanner.Err()
}

// isSysctlName reports whether s is shaped like a sysctl name. It starts with
// a letter and has at least one dot, since every leaf sits below a top-level
// node (`kern.hostname`, `net.ipv4.ip_forward`); the dot is what keeps a
// continuation line such as `Features=0x1783fbff<FPU,VME>` from being read as
// a parameter. The rest is letters, digits, `_ . % - / @ +` and spaces: Linux
// writes a VLAN interface `eth0.100` as `eth0/100`, and OpenZFS names kstats
// like `kstat.zfs.zroot.misc.dmu_tx_assign.1024 ns`.
func isSysctlName(s string) bool {
	if s == "" || !isASCIILetter(s[0]) || !strings.Contains(s, ".") {
		return false
	}
	for i := 1; i < len(s); i++ {
		b := s[i]
		if isASCIILetter(b) || (b >= '0' && b <= '9') || strings.IndexByte("_.%-/@+ ", b) >= 0 {
			continue
		}
		return false
	}
	return true
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func ParseLinuxSysctlProc(sysctlRootPath string, reader io.Reader) (map[string]string, error) {
	kernelParameters := map[string]string{}

	// parse kernel parameters from tar stream
	tr := tar.NewReader(reader)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if !h.FileInfo().IsDir() {
			content, _ := io.ReadAll(tr)
			// remove leading sysctl path
			k := strings.ReplaceAll(h.Name, sysctlRootPath, "")
			k = strings.ReplaceAll(k, "/", ".")
			kernelParameters[k] = strings.TrimSpace(string(content))
		}
	}

	return kernelParameters, nil
}

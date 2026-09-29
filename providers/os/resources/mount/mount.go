// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mount

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/spf13/afero"
)

// Compiled once: each of these is matched against every line of its command's
// output.
var (
	linuxMountEntry     = regexp.MustCompile(`^(\S+)\son\s(\S+)\stype\s(\S+)\s\((\S+)\)$`)
	unixMountEntry      = regexp.MustCompile(`^(\S+)\son\s(\S+)\s\((.*)\)$`)
	linuxProcMountEntry = regexp.MustCompile(`^(\S+)\s(\S+)\s(\S+)\s(\S+)\s0\s0$`)
	// rpool/ROOT/s11 on / type zfs read/write/setuid/devices/dev=3610002 on Thu Jan  1 00:00:00 1970
	solarisMountEntry = regexp.MustCompile(`^(\S+) on (\S+) type (\S+) (.+) on (?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) .*$`)
)

// ParseSolarisMountCmd parses Solaris `mount -v`. Plain `mount` on Solaris
// writes the mount point first and leaves out the filesystem type, so -v is
// the form that carries every column.
//
// Options are slash-separated and spell the access mode as "read/write" or
// "read-only"; the first would otherwise split into two bogus options. They
// are rewritten to rw and ro, the names the mount command itself accepts. Every
// other option keeps its Solaris name (nosetuid, nodevices, noexec).
func ParseSolarisMountCmd(r io.Reader) []MountPoint {
	res := []MountPoint{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		m := solarisMountEntry.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		opts := m[4]
		opts = strings.Replace(opts, "read/write", "rw", 1)
		opts = strings.Replace(opts, "read-only", "ro", 1)
		res = append(res, MountPoint{
			Device:     m[1],
			MountPoint: m[2],
			FSType:     m[3],
			Options:    parseOptions(strings.ReplaceAll(opts, "/", ",")),
		})
	}

	return res
}

func ParseLinuxMountCmd(r io.Reader) []MountPoint {
	res := []MountPoint{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		m := linuxMountEntry.FindStringSubmatch(line)
		if len(m) == 5 {
			res = append(res, MountPoint{
				Device:     strings.TrimSpace(m[1]),
				MountPoint: strings.TrimSpace(m[2]),
				FSType:     strings.TrimSpace(m[3]),
				Options:    parseOptions(strings.TrimSpace(m[4])),
			})
		}
	}

	return res
}

// NOTE: we do not handle `map auto_home` on macos
func ParseUnixMountCmd(r io.Reader) []MountPoint {
	res := []MountPoint{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		m := unixMountEntry.FindStringSubmatch(line)
		if len(m) == 4 {
			opts := strings.TrimSpace(m[3])
			fstype := ""
			entries := strings.Split(opts, ",")
			if len(entries) > 1 {
				fstype = strings.TrimSpace(entries[0])
			}

			res = append(res, MountPoint{
				Device:     strings.TrimSpace(m[1]),
				MountPoint: strings.TrimSpace(m[2]),
				FSType:     fstype,
				Options:    parseOptions(opts),
			})
		}
	}

	return res
}

// see https://stackoverflow.com/questions/18122123/how-to-interpret-proc-mounts
func ParseLinuxProcMount(r io.Reader) []MountPoint {
	res := []MountPoint{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		m := linuxProcMountEntry.FindStringSubmatch(line)
		if len(m) == 5 {
			res = append(res, MountPoint{
				Device:     strings.TrimSpace(m[1]),
				MountPoint: strings.TrimSpace(m[2]),
				FSType:     strings.TrimSpace(m[3]),
				Options:    parseOptions(strings.TrimSpace(m[4])),
			})
		}
	}

	return res
}

func parseOptions(opts string) map[string]string {
	res := map[string]string{}
	entries := strings.Split(opts, ",")
	for i := range entries {
		entry := entries[i]
		// Split on the first `=` only: option values can themselves contain
		// `=` (e.g. SELinux context=...), and splitting on every `=` would
		// drop such options instead of recording their value.
		key, value, found := strings.Cut(entry, "=")
		if found {
			res[strings.TrimSpace(key)] = strings.TrimSpace(value)
		} else {
			res[strings.TrimSpace(entry)] = ""
		}
	}
	return res
}

func ParseFstab(r io.Reader) ([]MountPoint, error) {
	res := []MountPoint{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			// ignoring bad lines
			continue
		}
		res = append(res, MountPoint{
			Device:     fields[0],
			MountPoint: fields[1],
			FSType:     fields[2],
			Options:    parseOptions(fields[3]),
		})
	}
	return res, scanner.Err()
}

func mountsFromFSLinux(fs afero.Fs) ([]MountPoint, error) {
	// Check if we have /proc/mounts
	procMountExists, err := afero.Exists(fs, "/proc/mounts")
	if err != nil {
		return nil, err
	}
	if procMountExists {
		f, err := fs.Open("/proc/mounts")
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return ParseLinuxProcMount(f), nil
	}

	fstabExists, err := afero.Exists(fs, "/etc/fstab")
	if err != nil {
		return nil, err
	}
	if fstabExists {
		f, err := fs.Open("/etc/fstab")
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return ParseFstab(f)
	}
	return nil, errors.New("could not find mounts")
}

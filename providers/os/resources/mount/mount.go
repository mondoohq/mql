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
	"go.mondoo.com/mql/providers/os/resources/fstab"
)

// Compiled once: each of these is matched against every line of its command's
// output.
var (
	// The mount command prints the device and the mount point unescaped, so
	// either can hold spaces: g05sp on /mnt/sp ace type tmpfs (rw,size=8192k)
	linuxMountEntry = regexp.MustCompile(`^(.+?) on (.+) type (\S+) \((\S+)\)$`)
	// /dev/disk3s5 on /Volumes/Macintosh HD (apfs, local, journaled)
	unixMountEntry = regexp.MustCompile(`^(.+?) on (.+) \((.*)\)$`)
	// /proc/mounts escapes space, tab, newline and backslash as \040, \011,
	// \012 and \134, so every field is free of whitespace.
	linuxProcMountEntry = regexp.MustCompile(`^(\S+)\s(\S+)\s(\S+)\s(\S+)\s0\s0$`)
	// rpool/ROOT/s11 on / type zfs read/write/setuid/devices/dev=3610002 on Thu Jan  1 00:00:00 1970
	solarisMountEntry = regexp.MustCompile(`^(\S+) on (\S+) type (\S+) (.+) on (?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) .*$`)
)

// aixMountDate matches the month of the date column of AIX `mount`, which is
// followed by the day and the time: Oct 09 10:23
var (
	aixMountMonth = regexp.MustCompile(`^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$`)
	aixMountTime  = regexp.MustCompile(`^\d{1,2}:\d{2}$`)
)

// ParseAixMountCmd parses AIX `mount`, which prints a table:
//
//	  node       mounted        mounted over    vfs       date        options
//	-------- ---------------  ---------------  ------ ------------ ---------------
//	         /dev/hd4         /                jfs2   Oct 09 10:23 rw,log=/dev/hd8
//	localhost /export/mqlro    /mnt/nfsmql      nfs3   Oct 09 10:39 ro,soft
//
// The node column is empty for a local mount and names the server of a remote
// one. A long mount point pushes the later columns out of alignment, so rows
// are split on whitespace and anchored on the date, which always takes three
// fields. A remote device is reported as node:path, the way df writes it.
func ParseAixMountCmd(r io.Reader) []MountPoint {
	res := []MountPoint{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		date := -1
		for i := 2; i+2 < len(fields); i++ {
			if aixMountMonth.MatchString(fields[i]) && aixMountTime.MatchString(fields[i+2]) {
				date = i
				break
			}
		}
		// device, mount point and vfs come before the date
		if date < 3 {
			continue
		}

		head := fields[:date-1]
		device := head[0]
		mountPoint := strings.Join(head[1:], " ")
		// a row with a node starts in the first column
		if !strings.HasPrefix(line, " ") && len(head) > 2 {
			device = head[0] + ":" + head[1]
			mountPoint = strings.Join(head[2:], " ")
		}

		res = append(res, MountPoint{
			Device:     device,
			MountPoint: mountPoint,
			FSType:     fields[date-1],
			Options:    parseOptions(strings.Join(fields[date+3:], " ")),
		})
	}

	return res
}

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

// macOS names automounter maps with a space: map auto_home on /System/Volumes/Data/home
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
				Device:     unescapeOctal(m[1]),
				MountPoint: unescapeOctal(m[2]),
				FSType:     strings.TrimSpace(m[3]),
				Options:    parseOptions(strings.TrimSpace(m[4])),
			})
		}
	}

	return res
}

// unescapeOctal reverses the kernel's escaping of mount table fields, which
// writes space, tab, newline and backslash as a backslash and three octal
// digits (\040, \011, \012, \134).
func unescapeOctal(s string) string {
	return fstab.UnescapeOctal(s)
}

// MarkOvermounted flags every mount that a later mount on the same path
// hides. Mount tables list mounts in the order they were made, so of several
// mounts on one path only the last one is visible; the earlier ones are
// still mounted underneath it.
func MarkOvermounted(mounts []MountPoint) {
	last := make(map[string]int, len(mounts))
	for i := range mounts {
		last[mounts[i].MountPoint] = i
	}
	for i := range mounts {
		mounts[i].Overmounted = last[mounts[i].MountPoint] != i
	}
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
		mounts, err := ParseFstab(f)
		if err != nil {
			return nil, err
		}
		// fstab lists what would be mounted at boot. With no /proc/mounts
		// there is no running system to say what is mounted, and an entry
		// such as a noauto cdrom never is, so none reads as mounted.
		for i := range mounts {
			mounts[i].Unmounted = true
		}
		return mounts, nil
	}
	return nil, errors.New("could not find mounts")
}

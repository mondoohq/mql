// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	dpkgInfoDir = "/var/lib/dpkg/info"

	// dpkgListMtimesCmd prints "<mtime> <basename>" for every file list in one
	// round trip. GNU find is part of findutils, which Debian and Ubuntu ship
	// as an essential package.
	dpkgListMtimesCmd = "find " + dpkgInfoDir + " -maxdepth 1 -name '*.list' -printf '%T@ %f\\n'"
)

// DpkgListMtimes maps a dpkg file-list name, as it appears under
// /var/lib/dpkg/info without the .list suffix, to that file's modification
// time. A Multi-Arch: same package carries its architecture in the name
// (libc6:amd64); every other package uses the bare name.
type DpkgListMtimes map[string]time.Time

// Get returns the file-list time for a package. The architecture-qualified
// name is tried first because that is the name dpkg gives a Multi-Arch: same
// package, then the bare name.
func (m DpkgListMtimes) Get(name, arch string) (time.Time, bool) {
	if len(m) == 0 {
		return time.Time{}, false
	}
	if arch != "" {
		if t, ok := m[name+":"+arch]; ok {
			return t, true
		}
	}
	t, ok := m[name]
	return t, ok
}

// dpkgInfoLists is what one listing of /var/lib/dpkg/info says about the
// package file lists in it.
type dpkgInfoLists struct {
	// names holds the name of every file list, without the .list suffix,
	// whether or not it reports a modification time.
	names map[string]struct{}
	// mtimes holds the modification time of every list that has one.
	mtimes DpkgListMtimes
}

// has reports whether the file list <name>.list exists.
func (l dpkgInfoLists) has(name string) bool {
	_, ok := l.names[name]
	return ok
}

// ParseDpkgListMtimes reads the output of dpkgListMtimesCmd. Each line is a
// Unix time with an optional fractional part, one space, and the file name.
// Times are truncated to the second, the precision rpm and dpkg.log record.
// Lines that do not have that shape are skipped.
func ParseDpkgListMtimes(r io.Reader) DpkgListMtimes {
	return parseDpkgInfoLists(r).mtimes
}

// parseDpkgInfoLists reads the output of dpkgListMtimesCmd into the names of
// all file lists and the times of those that carry a valid one. A list whose
// time does not parse, or is the epoch (an image built with its timestamps
// zeroed), still exists.
func parseDpkgInfoLists(r io.Reader) dpkgInfoLists {
	res := dpkgInfoLists{names: map[string]struct{}{}, mtimes: DpkgListMtimes{}}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		ts, file, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		name, ok := strings.CutSuffix(file, ".list")
		if !ok || name == "" {
			continue
		}
		res.names[name] = struct{}{}
		secs, _, _ := strings.Cut(ts, ".")
		sec, err := strconv.ParseInt(secs, 10, 64)
		if err != nil || sec <= 0 {
			continue
		}
		res.mtimes[name] = time.Unix(sec, 0).UTC()
	}
	return res
}

// dpkgInfoListsFromFS lists /var/lib/dpkg/info through the asset's
// filesystem. It serves connections that cannot run commands (a mounted
// snapshot, a container image), where a directory read is local and cheap.
// It reports false when the directory cannot be read.
func dpkgInfoListsFromFS(fs afero.Fs) (dpkgInfoLists, bool) {
	res := dpkgInfoLists{names: map[string]struct{}{}, mtimes: DpkgListMtimes{}}
	entries, err := afero.ReadDir(fs, dpkgInfoDir)
	if err != nil {
		log.Debug().Err(err).Str("path", dpkgInfoDir).Msg("mql[packages]> cannot list dpkg file lists")
		return res, false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name, ok := strings.CutSuffix(e.Name(), ".list")
		if !ok || name == "" {
			continue
		}
		res.names[name] = struct{}{}
		if e.ModTime().IsZero() {
			continue
		}
		res.mtimes[name] = e.ModTime().Truncate(time.Second).UTC()
	}
	return res, true
}

// readDpkgInfoLists lists every dpkg file list and its modification time.
//
// A connection that runs commands gets one batched find. Over SSH with sudo
// or docker exec the filesystem stats each file with its own remote command,
// so a directory read there costs one round trip per installed package.
// Connections without commands read the directory through the filesystem.
//
// It reports false when the listing failed, so that callers needing to know
// whether a list exists can fall back to asking for it by name. Install dates
// never fall back: a host without GNU find stays undated rather than paying
// the per-file round trips.
func readDpkgInfoLists(conn shared.Connection) (dpkgInfoLists, bool) {
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return dpkgInfoListsFromFS(conn.FileSystem())
	}
	empty := dpkgInfoLists{names: map[string]struct{}{}, mtimes: DpkgListMtimes{}}
	cmd, err := conn.RunCommand(dpkgListMtimesCmd)
	if err != nil {
		log.Debug().Err(err).Msg("mql[packages]> cannot list dpkg file lists")
		return empty, false
	}
	if cmd.ExitStatus != 0 {
		log.Debug().Int("exit", cmd.ExitStatus).Msg("mql[packages]> listing dpkg file lists failed")
		return empty, false
	}
	return parseDpkgInfoLists(cmd.Stdout), true
}

// dpkgStateHasCurrentFileList reports whether a dpkg status triple describes a
// package whose file list was last written by unpacking its installed version.
//
// dpkg writes the list when it unpacks a package, so the states from unpacked
// onward qualify. A removed package (config-files) keeps a list that removal
// rewrote, half-installed means the unpack did not finish, and not-installed
// has no list at all.
func dpkgStateHasCurrentFileList(status string) bool {
	fields := strings.Fields(status)
	if len(fields) != 3 {
		return false
	}
	switch fields[2] {
	case "installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending":
		return true
	}
	return false
}

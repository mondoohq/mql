// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/ulikunitz/xz"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// LastUpdateSourceZyppHistory is a completed zypper update, patch or
// dist-upgrade run that installed at least one package, as libzypp records it
// in /var/log/zypp/history. Like LastUpdateSourceAptHistory it upgrades
// whatever the configured repositories offer, which on SUSE are the vendor's
// own but can include a third-party one.
const LastUpdateSourceZyppHistory = "zypp-history"

const (
	// zyppHistoryDir holds libzypp's history log and its logrotate copies.
	// The directory is 0750 root, so a scan without root cannot read it.
	zyppHistoryDir = "/var/log/zypp"

	// zyppHistoryPath is libzypp's history log. Every libzypp commit appends
	// a command line naming the program and its arguments, then one line per
	// package it installed or removed:
	//
	//	2026-10-02 15:07:02|command|root@host|'zypper' '-n' 'up' 'ca-certificates-mozilla'|
	//	2026-10-02 15:07:03|install|ca-certificates-mozilla|2.84-160000.1.1|noarch||repo-oss|<sha256>|
	//	2026-10-02 15:07:04|patch  |openSUSE-Leap-16.0-1790|1|noarch|repo-oss|moderate|recommended|needed|applied|
	zyppHistoryPath = zyppHistoryDir + "/history"

	// zyppHistoryTimeLayout is the timestamp libzypp writes: local time with
	// no zone, like apt's history log.
	zyppHistoryTimeLayout = "2006-01-02 15:04:05"

	// zyppHistoryMaxLine caps a single line. A command line carries the full
	// argument vector, which for an image build names every package.
	zyppHistoryMaxLine = 4 * 1024 * 1024
)

// zyppRotatedHistory matches the copies SUSE's logrotate configuration
// (/etc/logrotate.d/zypp-history.lr: dateext, compress with xz) leaves next to
// the live log: history-20260101.xz, or .gz and uncompressed when an operator
// changed the compression.
var zyppRotatedHistory = regexp.MustCompile(`^history-(\d{8})(\.xz|\.gz)?$`)

// zyppUpdateCommands are the zypper commands that upgrade what the configured
// repositories offer, with their short aliases. `zypper patch` installs the
// vendor's patches; `zypper update` and `zypper dist-upgrade` move packages
// to the newest version available. `zypper install`, even of a newer build,
// is aimed at a package the operator named and does not count.
var zyppUpdateCommands = map[string]struct{}{
	"update":       {},
	"up":           {},
	"patch":        {},
	"dist-upgrade": {},
	"dup":          {},
}

// zyppValueOptions are zypper's global options that take their value as the
// next argument. Their value is skipped when looking for the command, so
// `zypper --root /mnt up` reads as an update and not as a command named
// "/mnt".
var zyppValueOptions = map[string]struct{}{
	"-c": {}, "--config": {},
	"-R": {}, "--root": {},
	"-D": {}, "--reposd-dir": {},
	"-C": {}, "--cache-dir": {},
	"--raw-cache-dir":  {},
	"--solv-cache-dir": {},
	"--pkg-cache-dir":  {},
	"--installroot":    {},
	"--userdata":       {},
	"-p":               {}, "--plus-repo": {},
	"--plus-content": {},
}

// lastInstalledZypp reads the newest completed zypper update run libzypp
// recorded on a SUSE host.
func lastInstalledZypp(conn shared.Connection) (*LastInstalledUpdate, error) {
	return lastInstalledZyppFS(conn.FileSystem(), assetTimeZone(conn))
}

// lastInstalledZyppFS is lastInstalledZypp's filesystem-only body.
//
// The live log answers first, then its logrotate copies newest-first. The
// copies matter because the rotation runs with nocreate: right after one, the
// live log does not exist until libzypp next commits.
//
// A history that cannot be read for lack of permission is a refusal, not an
// absence: the directory is root-only, so a scan without root sees nothing
// even on a host patched this morning. Any other read failure ends the walk
// with no answer, as walkRotatedLogs does, so an older copy never stands in
// for an unreadable newer one.
func lastInstalledZyppFS(logFS afero.Fs, loc *time.Location) (*LastInstalledUpdate, error) {
	update, err := readZyppHistory(logFS, zyppHistoryPath, loc)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return zyppHistoryReadError(zyppHistoryPath, err)
		}
	} else if update != nil {
		return update, nil
	}

	rotated, err := zyppRotatedHistoryPaths(logFS)
	if err != nil {
		return zyppHistoryReadError(zyppHistoryDir, err)
	}
	for _, p := range rotated {
		update, err := readZyppHistory(logFS, p, loc)
		if err != nil {
			return zyppHistoryReadError(p, err)
		}
		if update != nil {
			return update, nil
		}
	}
	return nil, nil
}

// zyppHistoryReadError turns a failed read into the field's answer. A refusal
// is forbidden (v13 read null here, so it stays null unless structured errors
// are on); anything else is logged and reads null.
func zyppHistoryReadError(p string, err error) (*LastInstalledUpdate, error) {
	if errors.Is(err, fs.ErrPermission) {
		if !plugin.StructuredErrors() {
			return nil, nil
		}
		var pathErr *fs.PathError
		if !errors.As(err, &pathErr) {
			err = fmt.Errorf("%s: %w", p, err)
		}
		return nil, llx.Forbidden(err)
	}
	log.Debug().Err(err).Str("path", p).
		Msg("mql[os.lastUpdate]> zypp history exists but cannot be read, reporting no answer")
	return nil, nil
}

// zyppRotatedHistoryPaths lists the logrotate copies of the history log,
// newest first. A missing directory has none.
func zyppRotatedHistoryPaths(logFS afero.Fs) ([]string, error) {
	entries, err := afero.ReadDir(logFS, zyppHistoryDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	type rotation struct{ date, name string }
	var rotations []rotation
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if m := zyppRotatedHistory.FindStringSubmatch(entry.Name()); m != nil {
			rotations = append(rotations, rotation{date: m[1], name: entry.Name()})
		}
	}
	sort.SliceStable(rotations, func(i, j int) bool { return rotations[i].date > rotations[j].date })
	paths := make([]string, 0, len(rotations))
	for _, r := range rotations {
		paths = append(paths, path.Join(zyppHistoryDir, r.name))
	}
	return paths, nil
}

// readZyppHistory opens one history file, decompressing an xz or gzip copy,
// and parses it.
func readZyppHistory(logFS afero.Fs, p string, loc *time.Location) (*LastInstalledUpdate, error) {
	f, err := logFS.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var r io.Reader = f
	switch {
	case strings.HasSuffix(p, ".xz"):
		xr, err := xz.NewReader(f)
		if err != nil {
			return nil, err
		}
		r = xr
	case strings.HasSuffix(p, ".gz"):
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	}
	return ParseZyppHistory(r, loc)
}

// ParseZyppHistory returns the newest completed zypper update run in a libzypp
// history log, timestamped by the last package it installed.
//
// A run is the command line libzypp writes when a commit starts and the
// package lines that follow it, up to the next command line. It qualifies
// when its program is zypper, its command is update, patch or dist-upgrade
// (see zyppCommand), and it installed at least one package. The last install
// line is when the run finished moving packages; libzypp writes an install
// line only once rpm reports the package installed, so a failed package
// leaves none.
//
// The patch lines are deliberately not evidence. libzypp writes one whenever
// a patch's status changes, and installing any package that happens to
// satisfy a patch flips it to applied: `zypper install openvswitch` logs a
// dozen security patches as applied. Reading those would make an operator's
// install look like patching.
//
// Package lines before the first command line (libzypp older than 2014
// logged no command) cannot be attributed to a run and do not count.
func ParseZyppHistory(r io.Reader, loc *time.Location) (*LastInstalledUpdate, error) {
	if loc == nil {
		loc = time.UTC
	}

	var newest time.Time
	inUpdate := false
	var lastInstall time.Time

	flush := func() {
		if inUpdate && lastInstall.After(newest) {
			newest = lastInstall
		}
		inUpdate = false
		lastInstall = time.Time{}
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), zyppHistoryMaxLine)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 3 {
			continue
		}
		switch strings.TrimSpace(fields[1]) {
		case "command":
			flush()
			if len(fields) >= 4 {
				inUpdate = isZyppUpdateCommandline(fields[3])
			}
		case "install":
			if !inUpdate {
				continue
			}
			t, err := time.ParseInLocation(zyppHistoryTimeLayout, fields[0], loc)
			if err != nil {
				continue
			}
			if t.After(lastInstall) {
				lastInstall = t
			}
		}
	}
	if err := scanner.Err(); err != nil {
		// The rest of the log is lost, and with it possibly the newest run.
		return nil, err
	}
	flush()

	if newest.IsZero() {
		return nil, nil
	}
	return &LastInstalledUpdate{Time: newest.UTC(), Source: LastUpdateSourceZyppHistory}, nil
}

// isZyppUpdateCommandline reports whether a command line libzypp logged is a
// zypper update, patch or dist-upgrade run.
func isZyppUpdateCommandline(cmdline string) bool {
	args := splitZyppCommandline(cmdline)
	if len(args) < 2 || path.Base(args[0]) != "zypper" {
		return false
	}
	_, ok := zyppUpdateCommands[zyppCommand(args[1:])]
	return ok
}

// zyppCommand returns zypper's command: the first argument that is neither a
// global option nor the value of one.
func zyppCommand(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			return arg
		}
		if _, ok := zyppValueOptions[arg]; ok {
			i++
		}
	}
	return ""
}

// splitZyppCommandline splits the argument vector libzypp logs, where every
// argument is wrapped in single quotes and separated by a space:
// 'zypper' '-n' 'up'. An argument holding a quote of its own is written
// shell-style ('it'\”s'), and quoting is undone the same way.
func splitZyppCommandline(cmdline string) []string {
	var args []string
	var cur strings.Builder
	inArg, quoted := false, false
	for i := 0; i < len(cmdline); i++ {
		c := cmdline[i]
		switch {
		case c == '\'':
			quoted = !quoted
			inArg = true
		case c == '\\' && !quoted && i+1 < len(cmdline):
			i++
			cur.WriteByte(cmdline[i])
			inArg = true
		case c == ' ' && !quoted:
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		default:
			cur.WriteByte(c)
			inArg = true
		}
	}
	if inArg {
		args = append(args, cur.String())
	}
	return args
}

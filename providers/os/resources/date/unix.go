// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package date

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
)

// unixDateCmd gets the current UTC time. Used when RunCommand is available.
const unixDateCmd = `date -u +%Y-%m-%dT%H:%M:%SZ`

type Unix struct {
	conn shared.Connection
}

func (u *Unix) Name() string {
	return "Unix Date"
}

func (u *Unix) Get() (*Result, error) {
	canRunCmd := u.conn.Capabilities().Has(shared.Capability_RunCommand)

	// Get UTC time only if we can actually ask the remote system.
	// For static targets (EBS snapshots, Docker images) there is no
	// meaningful current time, so we leave it nil.
	var utcTime *time.Time
	if canRunCmd {
		cmd, err := u.conn.RunCommand(unixDateCmd)
		if err != nil {
			return nil, fmt.Errorf("failed to get system date: %w", err)
		}
		t, err := parseUTCTime(cmd.Stdout)
		if err != nil {
			return nil, err
		}
		utcTime = &t
	}

	// Get timezone: try filesystem first (works on EBS snapshots, Docker images),
	// fall back to command if filesystem detection fails
	tz, err := timezoneFromFS(u.conn.FileSystem())
	if err != nil && canRunCmd {
		tz, err = timezoneFromCmd(u.conn)
	}
	if err != nil {
		// If all methods fail, default to UTC
		return &Result{
			Time:     utcTime,
			Timezone: "UTC",
		}, nil
	}

	loc, err := time.LoadLocation(tz)
	if err != nil {
		return &Result{
			Time:     utcTime,
			Timezone: tz,
		}, nil
	}

	if utcTime != nil {
		t := utcTime.In(loc)
		utcTime = &t
	}

	return &Result{
		Time:     utcTime,
		Timezone: tz,
	}, nil
}

// timezoneFromFS detects the IANA timezone by reading filesystem artifacts.
// It tries these approaches in order:
//  1. readlink /etc/localtime → extract IANA name from symlink target
//  2. Read /etc/timezone (Debian/Ubuntu)
//  3. Parse TZ= from /etc/TIMEZONE (Solaris/AIX)
//  4. Match /etc/localtime contents against the system zoneinfo database
func timezoneFromFS(fs afero.Fs) (string, error) {
	// 1. Try readlink on /etc/localtime
	if lr, ok := fs.(afero.LinkReader); ok {
		if target, err := lr.ReadlinkIfPossible("/etc/localtime"); err == nil {
			if tz := extractTZFromPath(target); tz != "" {
				return tz, nil
			}
		}
	}

	// 2. Try /etc/timezone (Debian/Ubuntu)
	if f, err := fs.Open("/etc/timezone"); err == nil {
		defer f.Close()
		content, err := io.ReadAll(f)
		if err == nil {
			if tz := strings.TrimSpace(string(content)); tz != "" {
				return tz, nil
			}
		}
	}

	// 3. Try /etc/TIMEZONE (Solaris/AIX) - look for TZ=<value>
	if f, err := fs.Open("/etc/TIMEZONE"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if tz, ok := strings.CutPrefix(line, "TZ="); ok && tz != "" {
				return tz, nil
			}
		}
	}

	// 4. Try matching /etc/localtime binary content against zoneinfo database
	if tz, err := matchLocaltimeToZoneinfo(fs); err == nil {
		return tz, nil
	}

	return "", fmt.Errorf("could not detect timezone from filesystem")
}

// extractTZFromPath extracts the IANA timezone name from a symlink target path.
// e.g., "/usr/share/zoneinfo/America/New_York" → "America/New_York"
func extractTZFromPath(path string) string {
	const marker = "zoneinfo/"
	if idx := strings.LastIndex(path, marker); idx >= 0 {
		tz := path[idx+len(marker):]
		if tz == "" || tz == "localtime" {
			return ""
		}
		// Strip posix/ and right/ prefixes — these are alternate
		// representations of the same zones, not valid IANA names.
		tz = strings.TrimPrefix(tz, "posix/")
		tz = strings.TrimPrefix(tz, "right/")
		if tz == "" {
			return ""
		}
		return tz
	}
	return ""
}

// matchLocaltimeToZoneinfo reads /etc/localtime and tries to find a matching
// zoneinfo file. This handles cases where /etc/localtime is a regular file
// (copy, not symlink), common in Docker images.
func matchLocaltimeToZoneinfo(fs afero.Fs) (string, error) {
	localtime, err := afero.ReadFile(fs, "/etc/localtime")
	if err != nil {
		return "", err
	}
	if len(localtime) < 4 || string(localtime[:4]) != "TZif" {
		return "", fmt.Errorf("/etc/localtime is not a valid TZif file")
	}

	// Fast path: parse the TZif v2/v3 footer for a POSIX TZ string.
	// This avoids walking the entire zoneinfo tree, which is extremely
	// expensive on tar-backed filesystems (Docker images, EBS snapshots).
	if tz, err := tzFromTZifFooter(localtime); err == nil {
		return tz, nil
	}

	// Slow path: compare file contents against known zoneinfo files.
	// Use direct reads of common timezone paths instead of walking the
	// entire directory tree, which would extract every file from a tar.
	if tz, err := matchLocaltimeByCommonPaths(fs, localtime); err == nil {
		return tz, nil
	}

	// Last resort: walk the zoneinfo tree with a file count cap.
	for _, base := range []string{"/usr/share/zoneinfo", "/usr/share/lib/zoneinfo"} {
		tz, err := findMatchingZoneinfo(fs, base, localtime)
		if err == nil {
			return tz, nil
		}
	}
	return "", fmt.Errorf("no matching zoneinfo file found")
}

// tzFromTZifFooter extracts the POSIX TZ string from a TZif version 2 or 3
// file's footer and maps it to an IANA timezone name when possible.
func tzFromTZifFooter(data []byte) (string, error) {
	if len(data) < 5 {
		return "", fmt.Errorf("data too short")
	}

	version := data[4]
	if version != '2' && version != '3' && version != '4' {
		return "", fmt.Errorf("TZif version %c has no footer", version)
	}

	// The v2/v3 footer is at the very end: \n<posix-tz-string>\n
	// Search backwards for the pattern.
	end := len(data)
	if data[end-1] != '\n' {
		return "", fmt.Errorf("no trailing newline in TZif footer")
	}
	// Find the preceding newline
	start := end - 2
	for start >= 0 && data[start] != '\n' {
		start--
	}
	if start < 0 {
		return "", fmt.Errorf("no footer found")
	}

	posixTZ := strings.TrimSpace(string(data[start+1 : end-1]))
	if posixTZ == "" || posixTZ == "UTC" || posixTZ == "UTC0" || posixTZ == "UTC-0" {
		return "UTC", nil
	}

	// Try mapping common POSIX TZ strings to IANA names
	if iana, ok := posixToIANA[posixTZ]; ok {
		return iana, nil
	}

	return "", fmt.Errorf("unmapped POSIX TZ string: %s", posixTZ)
}

// posixToIANA maps common POSIX TZ strings (from TZif footers) to IANA names.
// This covers the most common timezones; the walk fallback handles the rest.
// Note: some mappings are ambiguous (e.g., "CST-8" matches Asia/Shanghai,
// Asia/Taipei, and Asia/Hong_Kong). We pick a representative zone for each
// POSIX string. This is a best-effort fast path — the walk fallback will
// find the exact match if the footer mapping is wrong for a given system.
var posixToIANA = map[string]string{
	"EST5EDT,M3.2.0,M11.1.0":       "America/New_York",
	"CST6CDT,M3.2.0,M11.1.0":       "America/Chicago",
	"MST7MDT,M3.2.0,M11.1.0":       "America/Denver",
	"PST8PDT,M3.2.0,M11.1.0":       "America/Los_Angeles",
	"MST7":                         "America/Phoenix",
	"HST10":                        "Pacific/Honolulu",
	"AKST9AKDT,M3.2.0,M11.1.0":     "America/Anchorage",
	"GMT0BST,M3.5.0/1,M10.5.0":     "Europe/London",
	"CET-1CEST,M3.5.0,M10.5.0/3":   "Europe/Berlin",
	"EET-2EEST,M3.5.0/3,M10.5.0/4": "Europe/Helsinki",
	"IST-5:30":                     "Asia/Kolkata",
	"JST-9":                        "Asia/Tokyo",
	"CST-8":                        "Asia/Shanghai",
	"KST-9":                        "Asia/Seoul",
	"AEST-10AEDT,M10.1.0,M4.1.0/3": "Australia/Sydney",
	"NZST-12NZDT,M9.5.0,M4.1.0/3":  "Pacific/Auckland",
	"<-03>3":                       "America/Sao_Paulo",
	"WET0WEST,M3.5.0/1,M10.5.0":    "Europe/Lisbon",
	"<+07>-7":                      "Asia/Bangkok",
	"<+05>-5":                      "Asia/Tashkent",
	"<+04>-4":                      "Asia/Dubai",
	"<+03>-3":                      "Europe/Moscow",
	"<+02>-2":                      "Africa/Cairo",
	"<+01>-1":                      "Africa/Lagos",
	"<-05>5":                       "America/Bogota",
	"<-06>6":                       "America/Mexico_City",
}

// commonTimezones is a list of frequently-used IANA timezone names, tried
// before falling back to a full directory walk.
var commonTimezones = []string{
	"UTC", "US/Eastern", "US/Central", "US/Mountain", "US/Pacific",
	"America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles",
	"America/Phoenix", "America/Anchorage", "Pacific/Honolulu",
	"Europe/London", "Europe/Berlin", "Europe/Paris", "Europe/Moscow",
	"Asia/Tokyo", "Asia/Shanghai", "Asia/Kolkata", "Asia/Dubai",
	"Australia/Sydney", "Pacific/Auckland",
	"America/Toronto", "America/Vancouver", "America/Sao_Paulo", "America/Mexico_City",
	"America/Argentina/Buenos_Aires", "America/Bogota", "America/Lima",
	"Europe/Rome", "Europe/Madrid", "Europe/Amsterdam", "Europe/Helsinki",
	"Europe/Istanbul", "Europe/Warsaw", "Europe/Zurich",
	"Asia/Seoul", "Asia/Singapore", "Asia/Hong_Kong", "Asia/Bangkok",
	"Asia/Jakarta", "Asia/Taipei", "Asia/Tashkent",
	"Africa/Cairo", "Africa/Lagos", "Africa/Johannesburg",
	"Australia/Melbourne", "Australia/Perth", "Australia/Brisbane",
	"Etc/UTC", "Etc/GMT",
}

// matchLocaltimeByCommonPaths checks /etc/localtime against a curated list of
// common timezone files by direct path, avoiding a full directory walk.
func matchLocaltimeByCommonPaths(fs afero.Fs, localtime []byte) (string, error) {
	for _, base := range []string{"/usr/share/zoneinfo", "/usr/share/lib/zoneinfo"} {
		for _, tz := range commonTimezones {
			candidate, err := afero.ReadFile(fs, base+"/"+tz)
			if err != nil {
				continue
			}
			if bytes.Equal(candidate, localtime) {
				return tz, nil
			}
		}
	}
	return "", fmt.Errorf("no common timezone matched")
}

// errWalkDone is a sentinel error used to stop walking the zoneinfo tree
// early, either because a match was found or the file count limit was reached.
var errWalkDone = errors.New("walk done")

// maxZoneinfoFiles limits the number of files compared during a full zoneinfo
// tree walk. This prevents pathological performance on tar-backed filesystems
// where each file read requires extraction. 600 covers the ~350 real IANA
// zones plus overhead for legacy aliases and alternate directory layouts.
const maxZoneinfoFiles = 600

// findMatchingZoneinfo walks a zoneinfo directory tree comparing file contents
// to the given localtime data.
func findMatchingZoneinfo(fs afero.Fs, base string, localtime []byte) (string, error) {
	var match string
	var filesChecked int
	err := afero.Walk(fs, base, func(path string, info os.FileInfo, err error) error {
		if err != nil || match != "" {
			return err
		}
		if info.IsDir() {
			// Skip directories that aren't timezone data
			name := info.Name()
			if name == "posix" || name == "right" {
				return filepath.SkipDir
			}
			return nil
		}
		// Only compare regular files
		if !info.Mode().IsRegular() {
			return nil
		}

		filesChecked++
		if filesChecked > maxZoneinfoFiles {
			return errWalkDone // bail out, we've checked enough
		}

		candidate, err := afero.ReadFile(fs, path)
		if err != nil {
			return nil // skip unreadable files
		}
		if bytes.Equal(candidate, localtime) {
			rel := strings.TrimPrefix(path, base+"/")
			// Validate it looks like an IANA name (contains a slash, e.g. "America/New_York")
			if strings.Contains(rel, "/") {
				match = rel
				return errWalkDone
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, errWalkDone) {
		return "", err
	}
	if match == "" {
		return "", fmt.Errorf("no match found in %s", base)
	}
	return match, nil
}

// timezoneFromCmd gets the abbreviated timezone name via `date +%Z`.
// This is a last resort — it only returns short names like "EST", not IANA names.
func timezoneFromCmd(conn shared.Connection) (string, error) {
	cmd, err := conn.RunCommand("date +%Z")
	if err != nil {
		return "", fmt.Errorf("failed to get system timezone: %w", err)
	}
	return parseTimezone(cmd.Stdout)
}

func parseUTCTime(r io.Reader) (time.Time, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read date output: %w", err)
	}

	s := strings.TrimSpace(string(content))
	if s == "" {
		return time.Time{}, fmt.Errorf("empty date output")
	}

	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse date %q: %w", s, err)
	}
	return t, nil
}

func parseTimezone(r io.Reader) (string, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("failed to read timezone output: %w", err)
	}

	s := strings.TrimSpace(string(content))
	if s == "" {
		return "UTC", nil
	}
	return s, nil
}

// LocationFromFS resolves the asset's own timezone from its filesystem, so a
// timestamp a tool wrote without an offset can be read in the zone the asset
// keeps rather than the scanner's. It is filesystem-only, which means it also
// answers on a container image or a mounted snapshot.
//
// Returns nil when the filesystem carries no usable zone, leaving the caller to
// decide what to fall back to.
func LocationFromFS(fs afero.Fs) *time.Location {
	tz, err := timezoneFromFS(fs)
	if err != nil {
		return nil
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return nil
	}
	return loc
}

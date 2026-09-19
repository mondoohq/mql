// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/plist"
)

// /Library/Managed Preferences/ takes precedence over /Library/Preferences/
// — the former is populated by an MDM Configuration Profile and reflects
// effective policy, the latter is the system-default location written by
// `softwareupdate --schedule on` and friends.
var softwareUpdatePlistPaths = []string{
	"/Library/Managed Preferences/com.apple.SoftwareUpdate.plist",
	"/Library/Preferences/com.apple.SoftwareUpdate.plist",
}

type mqlMacosSoftwareupdateInternal struct {
	settingsLock    sync.Mutex
	settingsFetched bool
	settings        softwareupdateSettings
}

type softwareupdateSettings struct {
	autoCheckEnabled         bool
	autoCheckKeyPresent      bool
	autoDownloadEnabled      bool
	autoInstallMacOSUpdates  bool
	installSystemDataFiles   bool
	installSecurityResponses bool
	lastSuccessfulCheck      *time.Time
}

func (s *mqlMacosSoftwareupdate) id() (string, error) {
	return "macos.softwareupdate", nil
}

// fetchSettings reads the SoftwareUpdate preferences plist and caches
// the parsed settings on the resource. Missing files (Mac on which no
// SoftwareUpdate preference has ever been set, or a non-Darwin host)
// leave the settings struct at its zero value — every accessor will
// then read `false`/`nil`, which is what an auditor wants for an
// un-policied device.
func (s *mqlMacosSoftwareupdate) fetchSettings() (softwareupdateSettings, error) {
	if s.settingsFetched {
		return s.settings, nil
	}
	s.settingsLock.Lock()
	defer s.settingsLock.Unlock()
	if s.settingsFetched {
		return s.settings, nil
	}

	parsed, err := s.readSoftwareUpdatePlist()
	if err != nil {
		return softwareupdateSettings{}, err
	}
	s.settings = parsed
	s.settingsFetched = true
	return s.settings, nil
}

func (s *mqlMacosSoftwareupdate) readSoftwareUpdatePlist() (softwareupdateSettings, error) {
	for _, path := range softwareUpdatePlistPaths {
		res, err := NewResource(s.MqlRuntime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return softwareupdateSettings{}, err
		}
		f := res.(*mqlFile)
		if exists := f.GetExists(); !exists.Data {
			continue
		}
		content := f.GetContent()
		if content.Error != nil {
			return softwareupdateSettings{}, content.Error
		}
		if content.Data == "" {
			continue
		}
		data, err := plist.Decode(bytes.NewReader([]byte(content.Data)))
		if err != nil {
			// If the managed prefs file is malformed for some reason,
			// don't give up — fall through to the system prefs file.
			continue
		}
		return parseSoftwareUpdateSettings(data), nil
	}
	// Neither file exists — return zero-valued settings.
	return softwareupdateSettings{}, nil
}

// parseSoftwareUpdateSettings extracts the well-known keys from a
// decoded SoftwareUpdate plist. Through the plist.Decode helper,
// boolean keys come back as Go bools and dates round-trip through
// JSON as RFC3339 strings, so the conversions here are straightforward.
func parseSoftwareUpdateSettings(d map[string]any) softwareupdateSettings {
	return softwareupdateSettings{
		autoCheckEnabled:         boolFromPlist(d, "AutomaticCheckEnabled"),
		autoCheckKeyPresent:      keyPresentInPlist(d, "AutomaticCheckEnabled"),
		autoDownloadEnabled:      boolFromPlist(d, "AutomaticDownload"),
		autoInstallMacOSUpdates:  boolFromPlist(d, "AutomaticallyInstallMacOSUpdates"),
		installSystemDataFiles:   boolFromPlist(d, "ConfigDataInstall"),
		installSecurityResponses: boolFromPlist(d, "CriticalUpdateInstall"),
		lastSuccessfulCheck:      timeFromPlist(d, "LastSuccessfulDate"),
	}
}

// autoCheckEnabled reports whether macOS checks for updates on its own.
//
// The preference key is only written once someone changes the setting, and its
// absence does not mean "off" -- automatic checking is on by default, so a Mac
// that has never been touched reads as compliant while the plist says nothing.
// When the key is missing, ask softwareupdate what the schedule actually is
// rather than inferring a value from the silence.
func (s *mqlMacosSoftwareupdate) autoCheckEnabled() (bool, error) {
	v, err := s.fetchSettings()
	if err != nil {
		return false, err
	}
	if v.autoCheckKeyPresent {
		return v.autoCheckEnabled, nil
	}
	return s.scheduleEnabled()
}

// errUpdateScheduleUnavailable reports that neither source could answer.
var errUpdateScheduleUnavailable = errors.New(
	"cannot determine the software update schedule: AutomaticCheckEnabled is unset and `softwareupdate --schedule` did not return a readable answer")

// scheduleEnabled parses `softwareupdate --schedule`, which prints
// "Automatic checking for updates is turned on" or "... turned off".
func (s *mqlMacosSoftwareupdate) scheduleEnabled() (bool, error) {
	res, err := NewResource(s.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("softwareupdate --schedule"),
	})
	if err != nil {
		return false, err
	}
	cmd := res.(*mqlCommand)
	run, err := commandResult(cmd)
	if err != nil {
		return false, err
	}
	if run.exitcode != 0 {
		return false, errUpdateScheduleUnavailable
	}
	v, ok := parseSoftwareUpdateSchedule(run.stdout)
	if !ok {
		return false, errUpdateScheduleUnavailable
	}
	return v, nil
}

// parseSoftwareUpdateSchedule reads the `softwareupdate --schedule` sentence.
// Anything it does not recognise returns ok=false, so an unreadable schedule
// surfaces as an error and never as a confident "automatic checking is off".
func parseSoftwareUpdateSchedule(stdout string) (bool, bool) {
	l := strings.ToLower(stdout)
	if !strings.Contains(l, "automatic checking") {
		return false, false
	}
	switch {
	case strings.Contains(l, "turned on"), strings.Contains(l, "is on"):
		return true, true
	case strings.Contains(l, "turned off"), strings.Contains(l, "is off"):
		return false, true
	}
	return false, false
}

func (s *mqlMacosSoftwareupdate) autoDownloadEnabled() (bool, error) {
	v, err := s.fetchSettings()
	return v.autoDownloadEnabled, err
}

func (s *mqlMacosSoftwareupdate) autoInstallMacOSUpdates() (bool, error) {
	v, err := s.fetchSettings()
	return v.autoInstallMacOSUpdates, err
}

func (s *mqlMacosSoftwareupdate) installSystemDataFiles() (bool, error) {
	v, err := s.fetchSettings()
	return v.installSystemDataFiles, err
}

func (s *mqlMacosSoftwareupdate) installSecurityResponses() (bool, error) {
	v, err := s.fetchSettings()
	return v.installSecurityResponses, err
}

func (s *mqlMacosSoftwareupdate) lastSuccessfulCheck() (*time.Time, error) {
	v, err := s.fetchSettings()
	if err != nil {
		return nil, err
	}
	if v.lastSuccessfulCheck == nil {
		// No successful check has ever been recorded (or the key is
		// missing from the plist). Mark the field as resolved-and-null
		// so the runtime doesn't treat it as unresolved and re-invoke
		// this accessor on every read.
		s.LastSuccessfulCheck.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return v.lastSuccessfulCheck, nil
}

// =============================================================================
// updates() — `softwareupdate -l --no-scan`
// =============================================================================

func (s *mqlMacosSoftwareupdate) updates() ([]any, error) {
	// --no-scan reads from the local cache rather than initiating a
	// network check. A fresh network scan can take 30+ seconds; auditing
	// shouldn't pay that cost on every query.
	res, err := NewResource(s.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("softwareupdate -l --no-scan"),
	})
	if err != nil {
		return nil, err
	}
	cmd := res.(*mqlCommand)
	run, err := commandResult(cmd)
	if err != nil {
		return nil, err
	}
	stdout := run.stdout
	stderr := run.stderr
	if run.exitcode != 0 {
		// softwareupdate exits non-zero on Darwin in two well-known
		// "no updates" situations that should still return an empty
		// list rather than fail the query:
		//   * exit 1 with stderr "No new software available." (and
		//     newer variants like "No updates available.")
		//   * the binary missing on non-Darwin hosts (handled via the
		//     surrounding command resource — stderr typically mentions
		//     "command not found" or "executable file not found").
		// Anything else is surfaced as an error so misconfiguration
		// (missing entitlements, broken catalog) doesn't masquerade as
		// a clean device.
		if isSoftwareUpdateNoUpdatesSignal(stdout, stderr) {
			log.Debug().
				Int64("exitcode", run.exitcode).
				Str("stderr", stderr).
				Msg("macos.softwareupdate: no updates available")
			return []any{}, nil
		}
		log.Warn().
			Int64("exitcode", run.exitcode).
			Str("stderr", stderr).
			Msg("macos.softwareupdate: `softwareupdate -l --no-scan` failed")
		return nil, errors.New("softwareupdate failed: " + strings.TrimSpace(stderr))
	}

	parsed := parseSoftwareUpdateList(stdout)
	out := make([]any, 0, len(parsed))
	for _, u := range parsed {
		entry, err := CreateResource(s.MqlRuntime, "macos.softwareupdate.entry", map[string]*llx.RawData{
			"label":       llx.StringData(u.label),
			"title":       llx.StringData(u.title),
			"version":     llx.StringData(u.version),
			"size":        llx.IntData(u.size),
			"recommended": llx.BoolData(u.recommended),
			"action":      llx.StringData(u.action),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

// isSoftwareUpdateNoUpdatesSignal reports whether a non-zero exit from
// `softwareupdate -l --no-scan` actually means "nothing to install"
// rather than a real failure. Apple has used a few different phrasings
// over time; match them all case-insensitively against stdout+stderr.
func isSoftwareUpdateNoUpdatesSignal(stdout, stderr string) bool {
	combined := strings.ToLower(stdout + "\n" + stderr)
	for _, marker := range []string{
		"no new software available",
		"no updates available",
		"no new updates available",
	} {
		if strings.Contains(combined, marker) {
			return true
		}
	}
	return false
}

func (e *mqlMacosSoftwareupdateEntry) id() (string, error) {
	if e.Label.Data == "" {
		return "", errors.New("software update entry missing label")
	}
	return "macos.softwareupdate.entry:" + e.Label.Data, nil
}

type parsedSoftwareUpdate struct {
	label       string
	title       string
	version     string
	size        int64 // in KiB, parsed from the `K`-suffixed token
	recommended bool
	action      string
}

// parseSoftwareUpdateList parses the text output of `softwareupdate -l`.
// The format has been stable across recent macOS versions:
//
//	Software Update Tool
//
//	Finding available software
//	Software Update found the following new or updated software:
//	* Label: macOS Sonoma 14.5-23F79
//		Title: macOS Sonoma 14.5, Version: 14.5, Size: 7180348K, Recommended: YES, Action: restart,
//	* Label: Safari17.5MajorSU-17.5
//		Title: Safari, Version: 17.5, Size: 138648K, Recommended: YES,
//
// A `* Label:` line opens a new entry; the immediately following
// indented line carries comma-separated metadata. Fields not present
// in the metadata stay at their zero values.
func parseSoftwareUpdateList(stdout string) []parsedSoftwareUpdate {
	var out []parsedSoftwareUpdate
	var current *parsedSoftwareUpdate

	lines := strings.Split(stdout, "\n")
	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}

		if rest, ok := stripPrefix(trimmed, "* Label:"); ok {
			if current != nil {
				out = append(out, *current)
			}
			current = &parsedSoftwareUpdate{label: strings.TrimSpace(rest)}
			continue
		}

		if current == nil {
			continue
		}

		// Metadata line lives at one indent level below `* Label:`. If
		// the trimmed line still starts with `* Label:` we'd have
		// caught it above, so anything else here is metadata.
		applySoftwareUpdateMetadata(trimmed, current)
	}
	if current != nil {
		out = append(out, *current)
	}
	return out
}

// applySoftwareUpdateMetadata parses one metadata line — comma-
// separated `Key: value` pairs — and writes the recognized fields onto
// the in-progress entry. Unknown keys (some macOS versions add `Build`
// or extra annotations) are quietly ignored.
func applySoftwareUpdateMetadata(line string, u *parsedSoftwareUpdate) {
	for _, field := range strings.Split(line, ", ") {
		field = strings.TrimRight(field, ",")
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		idx := strings.Index(field, ": ")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(field[:idx])
		value := strings.TrimSpace(field[idx+2:])

		switch key {
		case "Title":
			u.title = value
		case "Version":
			u.version = value
		case "Size":
			u.size = parseSoftwareUpdateSize(value)
		case "Recommended":
			// macOS emits YES/NO; be tolerant of casing.
			u.recommended = strings.EqualFold(value, "YES")
		case "Action":
			u.action = value
		}
	}
}

// stripPrefix returns the substring after `prefix` plus true, or the
// original string plus false when the prefix is absent. Saves a
// `strings.HasPrefix` + `strings.TrimPrefix` pair at each call site.
func stripPrefix(s, prefix string) (string, bool) {
	if !strings.HasPrefix(s, prefix) {
		return s, false
	}
	return s[len(prefix):], true
}

// parseSoftwareUpdateSize parses a size token from `softwareupdate -l`
// output. The tool reports sizes as a base-10 integer followed by a `K`
// suffix (e.g. `132456K`), historically meaning kibibytes. Unknown or
// missing values return 0 so callers can filter with `size > 0` without
// having to handle a sentinel.
func parseSoftwareUpdateSize(raw string) int64 {
	s := strings.TrimSpace(raw)
	s = strings.TrimSuffix(s, "K")
	s = strings.TrimSuffix(s, "k")
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// =============================================================================
// shared plist helpers
// =============================================================================

// keyPresentInPlist reports whether the key carries a value the caller can
// read. A missing key is not the same as a false one: several SoftwareUpdate
// preferences default to on and are only written once someone changes them, so
// the caller has to tell "nobody set this" apart from "somebody set it off".
//
// A key present with a nil value counts as absent, because it answers the
// question no better than a missing key does: boolFromPlist has no case for
// nil and would hand back false, which is the wrong-by-default reading this
// helper exists to prevent. Reporting it as absent routes the caller to the
// live `softwareupdate --schedule` lookup instead. Note this is about a nil
// decoded value, not a written `<false/>`, which is a real answer and is
// reported as present.
func keyPresentInPlist(d map[string]any, key string) bool {
	v, ok := d[key]
	return ok && v != nil
}

// boolFromPlist coerces a plist key to bool. Through the plist.Decode
// helper, real plist booleans arrive as `bool`; integer 0/1 fallbacks
// (used historically by `defaults write -int`) arrive as `float64`
// after the helper's JSON round-trip. Both shapes count.
func boolFromPlist(d map[string]any, key string) bool {
	switch v := d[key].(type) {
	case bool:
		return v
	case float64:
		return v != 0
	case int64:
		return v != 0
	case int:
		return v != 0
	case string:
		// MDM-managed preferences sometimes encode booleans as
		// "true"/"false" strings. Be tolerant.
		return strings.EqualFold(v, "true") || v == "1"
	}
	return false
}

// timeFromPlist parses an RFC3339 timestamp from a plist key. Plist
// `<date>` values come through plist.Decode as strings after the JSON
// round-trip — Go's `time.Time` MarshalJSON emits RFC3339. Missing,
// empty, or unparseable values yield nil so the resource field stays
// null rather than reporting `0001-01-01` to auditors.
func timeFromPlist(d map[string]any, key string) *time.Time {
	v, ok := d[key].(string)
	if !ok || v == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		// Fall back to RFC3339 with sub-second precision — Go's parser
		// accepts both via the same layout, but some encoders may use
		// a slightly different shape (e.g. `Z` vs `+00:00`).
		t, err = time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return nil
		}
	}
	return &t
}

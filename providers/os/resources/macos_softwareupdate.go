// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"cmp"
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

// Software Update settings come from three places, highest precedence first:
//
//  1. A Declarative Device Management `com.apple.configuration.softwareupdate.settings`
//     declaration. macOS persists the resolved declaration in
//     softwareUpdateDDMStatePath; it is not written to either preferences plist.
//  2. A legacy `com.apple.SoftwareUpdate` configuration profile, which macOS
//     writes to /Library/Managed Preferences/.
//  3. The local preference in /Library/Preferences/, written by System Settings
//     and `defaults write`.
//
// Precedence is resolved per key: a profile that sets only AutomaticCheckEnabled
// leaves every other key to the local preference.
const (
	softwareUpdateDDMStatePath     = "/private/var/db/softwareupdate/SoftwareUpdateDDMStatePersistence.plist"
	softwareUpdateManagedPlistPath = "/Library/Managed Preferences/com.apple.SoftwareUpdate.plist"
	softwareUpdatePrefsPlistPath   = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
)

type mqlMacosSoftwareupdateInternal struct {
	settingsLock    sync.Mutex
	settingsFetched bool
	settings        softwareupdateSettings
}

// softwareupdateSettings holds what the configuration sources say. A nil field
// means no source set that key, which lets a lower-precedence source or, for
// autoCheckEnabled, the live schedule answer instead.
type softwareupdateSettings struct {
	autoCheckEnabled         *bool
	autoDownloadEnabled      *bool
	autoInstallMacOSUpdates  *bool
	installSystemDataFiles   *bool
	installSecurityResponses *bool
	lastSuccessfulCheck      *time.Time
}

func (s *mqlMacosSoftwareupdate) id() (string, error) {
	return "macos.softwareupdate", nil
}

// fetchSettings reads every Software Update configuration source once and
// caches the merged result on the resource.
func (s *mqlMacosSoftwareupdate) fetchSettings() (softwareupdateSettings, error) {
	if s.settingsFetched {
		return s.settings, nil
	}
	s.settingsLock.Lock()
	defer s.settingsLock.Unlock()
	if s.settingsFetched {
		return s.settings, nil
	}

	ddm, err := s.readPlist(softwareUpdateDDMStatePath)
	if err != nil {
		return softwareupdateSettings{}, err
	}
	managed, err := s.readPlist(softwareUpdateManagedPlistPath)
	if err != nil {
		return softwareupdateSettings{}, err
	}
	prefs, err := s.readPlist(softwareUpdatePrefsPlistPath)
	if err != nil {
		return softwareupdateSettings{}, err
	}

	s.settings = mergeSoftwareUpdateSettings(
		parseSoftwareUpdateDDMState(ddm),
		parseSoftwareUpdatePrefs(managed),
		parseSoftwareUpdatePrefs(prefs),
	)
	s.settingsFetched = true
	return s.settings, nil
}

// readPlist decodes a plist file. A missing, empty or malformed file returns a
// nil map, so that source contributes nothing and the next one is consulted.
func (s *mqlMacosSoftwareupdate) readPlist(path string) (map[string]any, error) {
	res, err := NewResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	f := res.(*mqlFile)
	if exists := f.GetExists(); !exists.Data {
		return nil, nil
	}
	content := f.GetContent()
	if content.Error != nil {
		return nil, content.Error
	}
	if content.Data == "" {
		return nil, nil
	}
	data, err := plist.Decode(bytes.NewReader([]byte(content.Data)))
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("macos.softwareupdate: cannot decode plist, ignoring it")
		return nil, nil
	}
	return data, nil
}

// parseSoftwareUpdatePrefs reads the keys of a `com.apple.SoftwareUpdate`
// preferences plist, managed or local.
func parseSoftwareUpdatePrefs(d map[string]any) softwareupdateSettings {
	return softwareupdateSettings{
		autoCheckEnabled:         optBoolFromPlist(d, "AutomaticCheckEnabled"),
		autoDownloadEnabled:      optBoolFromPlist(d, "AutomaticDownload"),
		autoInstallMacOSUpdates:  optBoolFromPlist(d, "AutomaticallyInstallMacOSUpdates"),
		installSystemDataFiles:   optBoolFromPlist(d, "ConfigDataInstall"),
		installSecurityResponses: optBoolFromPlist(d, "CriticalUpdateInstall"),
		lastSuccessfulCheck:      timeFromPlist(d, "LastSuccessfulDate"),
	}
}

// parseSoftwareUpdateDDMState reads the software update settings declaration
// from the persisted DDM state, found under
// SUCorePersistedStatePolicyFields.SUCoreDDMDeclarationGlobalSettings.
//
// The declaration's Automatic.Download, Automatic.InstallOSUpdates and
// Automatic.InstallSecurityUpdate take the values Allowed, AlwaysOn and
// AlwaysOff. macOS stores AlwaysOn as 1 and AlwaysOff as 0, and stores nothing
// for Allowed, which leaves the choice to the user and so to the lower sources.
//
// InstallSecurityUpdate covers both Security Responses and system data files,
// the two settings the legacy plist splits into CriticalUpdateInstall and
// ConfigDataInstall.
//
// The file format is not documented by Apple. Anything other than the expected
// shape contributes nothing rather than a value.
func parseSoftwareUpdateDDMState(d map[string]any) softwareupdateSettings {
	policy, _ := d["SUCorePersistedStatePolicyFields"].(map[string]any)
	global, _ := policy["SUCoreDDMDeclarationGlobalSettings"].(map[string]any)
	if global == nil {
		return softwareupdateSettings{}
	}
	installSecurity := ddmSettingFromPlist(global, "automaticallyInstallSystemAndSecurityUpdates")
	return softwareupdateSettings{
		autoDownloadEnabled:      ddmSettingFromPlist(global, "automaticallyDownload"),
		autoInstallMacOSUpdates:  ddmSettingFromPlist(global, "automaticallyInstallOSUpdates"),
		installSystemDataFiles:   installSecurity,
		installSecurityResponses: installSecurity,
	}
}

// mergeSoftwareUpdateSettings resolves each key to the first source, in the
// order given, that sets it.
func mergeSoftwareUpdateSettings(sources ...softwareupdateSettings) softwareupdateSettings {
	var out softwareupdateSettings
	for _, src := range sources {
		out.autoCheckEnabled = cmp.Or(out.autoCheckEnabled, src.autoCheckEnabled)
		out.autoDownloadEnabled = cmp.Or(out.autoDownloadEnabled, src.autoDownloadEnabled)
		out.autoInstallMacOSUpdates = cmp.Or(out.autoInstallMacOSUpdates, src.autoInstallMacOSUpdates)
		out.installSystemDataFiles = cmp.Or(out.installSystemDataFiles, src.installSystemDataFiles)
		out.installSecurityResponses = cmp.Or(out.installSecurityResponses, src.installSecurityResponses)
		out.lastSuccessfulCheck = cmp.Or(out.lastSuccessfulCheck, src.lastSuccessfulCheck)
	}
	return out
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
	if v.autoCheckEnabled != nil {
		return *v.autoCheckEnabled, nil
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
	if exit := cmd.GetExitcode(); exit.Data != 0 {
		return false, errUpdateScheduleUnavailable
	}
	v, ok := parseSoftwareUpdateSchedule(cmd.GetStdout().Data)
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

// A key no source sets reads false in the accessors below.

func (s *mqlMacosSoftwareupdate) autoDownloadEnabled() (bool, error) {
	v, err := s.fetchSettings()
	return v.autoDownloadEnabled != nil && *v.autoDownloadEnabled, err
}

func (s *mqlMacosSoftwareupdate) autoInstallMacOSUpdates() (bool, error) {
	v, err := s.fetchSettings()
	return v.autoInstallMacOSUpdates != nil && *v.autoInstallMacOSUpdates, err
}

func (s *mqlMacosSoftwareupdate) installSystemDataFiles() (bool, error) {
	v, err := s.fetchSettings()
	return v.installSystemDataFiles != nil && *v.installSystemDataFiles, err
}

func (s *mqlMacosSoftwareupdate) installSecurityResponses() (bool, error) {
	v, err := s.fetchSettings()
	return v.installSecurityResponses != nil && *v.installSecurityResponses, err
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
	exit := cmd.GetExitcode()
	stdout := cmd.GetStdout().Data
	stderr := cmd.GetStderr().Data
	if exit.Data != 0 {
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
				Int64("exitcode", exit.Data).
				Str("stderr", stderr).
				Msg("macos.softwareupdate: no updates available")
			return []any{}, nil
		}
		log.Warn().
			Int64("exitcode", exit.Data).
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

	lines := strings.SplitSeq(stdout, "\n")
	for raw := range lines {
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
	for field := range strings.SplitSeq(line, ", ") {
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

// optBoolFromPlist coerces a plist key to a bool, or nil when the key is absent
// or holds something that is not a boolean. A missing key is not the same as a
// false one: several SoftwareUpdate preferences default to on and are only
// written once someone changes them, so "nobody set this" must stay
// distinguishable from "somebody set it off".
//
// Through plist.Decode, plist booleans arrive as `bool` and integers written
// with `defaults write -int` arrive as `float64` after its JSON round-trip.
// MDM-managed preferences sometimes encode booleans as "true"/"false" strings.
func optBoolFromPlist(d map[string]any, key string) *bool {
	var b bool
	switch v := d[key].(type) {
	case bool:
		b = v
	case float64:
		b = v != 0
	case int64:
		b = v != 0
	case int:
		b = v != 0
	case string:
		switch {
		case strings.EqualFold(v, "true"), v == "1":
			b = true
		case strings.EqualFold(v, "false"), v == "0":
			b = false
		default:
			return nil
		}
	default:
		return nil
	}
	return &b
}

// ddmSettingFromPlist reads one persisted DDM AlwaysOn (1) / AlwaysOff (0)
// setting. Any other value is reported as unset rather than guessed at.
func ddmSettingFromPlist(d map[string]any, key string) *bool {
	var b bool
	switch v := d[key].(type) {
	case float64:
		if v != 0 && v != 1 {
			return nil
		}
		b = v == 1
	case bool:
		b = v
	default:
		return nil
	}
	return &b
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

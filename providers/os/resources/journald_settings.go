// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/parsers"
)

// journaldSettings holds the effective values journald applies for the
// [Journal] settings exposed as typed fields.
type journaldSettings struct {
	storage         string
	compress        bool
	forwardToSyslog bool
}

// journaldBinaryPaths are the locations systemd installs systemd-journald
// to. A system without any of them does not run journald, so its typed
// settings are null instead of systemd's defaults.
var journaldBinaryPaths = []string{
	"/usr/lib/systemd/systemd-journald",
	"/lib/systemd/systemd-journald",
}

// journaldStorageModes are the values journald accepts for Storage=. The
// lookup is case-sensitive in systemd (storage_from_string).
var journaldStorageModes = []string{"volatile", "persistent", "auto", "none"}

// journaldSizeRe matches the values systemd's parse_size accepts with a
// base of 1024, e.g. "512", "512K", "1.5M" or "1G 512M".
var journaldSizeRe = regexp.MustCompile(`^(\d+(\.\d+)?\s*[EPTGMKB]?\s*)+$`)

func (s *mqlJournaldConfig) storage(file *mqlFile) (string, error) {
	settings, err := s.effectiveSettings(file)
	if err != nil {
		return "", err
	}
	if settings == nil {
		s.Storage.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return settings.storage, nil
}

func (s *mqlJournaldConfig) compress(file *mqlFile) (bool, error) {
	settings, err := s.effectiveSettings(file)
	if err != nil {
		return false, err
	}
	if settings == nil {
		s.Compress.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return settings.compress, nil
}

func (s *mqlJournaldConfig) forwardToSyslog(file *mqlFile) (bool, error) {
	settings, err := s.effectiveSettings(file)
	if err != nil {
		return false, err
	}
	if settings == nil {
		s.ForwardToSyslog.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return settings.forwardToSyslog, nil
}

// effectiveSettings resolves the typed [Journal] settings once and shares
// the result between the fields. A nil result means journald is not
// installed on the system.
func (s *mqlJournaldConfig) effectiveSettings(file *mqlFile) (*journaldSettings, error) {
	s.settingsLock.Lock()
	defer s.settingsLock.Unlock()

	if !s.settingsResolved {
		s.settings, s.settingsErr = s.resolveSettings(file)
		s.settingsResolved = true
	}
	return s.settings, s.settingsErr
}

func (s *mqlJournaldConfig) resolveSettings(file *mqlFile) (*journaldSettings, error) {
	if file == nil {
		return nil, errors.New("no base journald config file to read")
	}

	filePath := file.GetPath()
	if filePath.Error != nil {
		return nil, filePath.Error
	}

	// Without an explicit path, the answer is about the journald running on
	// this system, so a system without journald has no settings. An
	// explicitly requested file is read as it is.
	defaultSearch := isDefaultJournaldConfigPath(filePath.Data)
	if defaultSearch {
		installed, err := s.journaldInstalled()
		if err != nil {
			return nil, err
		}
		if !installed {
			return nil, nil
		}
	}

	files, err := s.configFiles(file)
	if err != nil {
		return nil, err
	}

	assignments := []parsers.UnitParam{}
	for i, configFile := range files {
		// Without an explicit path the main file is optional: journald runs
		// on its defaults and drop-ins when no journald.conf exists. An
		// explicitly requested file must exist.
		if i > 0 || defaultSearch {
			exists := configFile.GetExists()
			if exists.Error != nil {
				return nil, exists.Error
			}
			if !exists.Data {
				continue
			}
		}

		content, err := fileRequiredContent(configFile)
		if err != nil {
			return nil, err
		}

		unit, err := parsers.ParseUnit(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse journald config: %w", err)
		}

		assignments = append(assignments, journaldJournalAssignments(unit)...)
	}

	settings := resolveJournaldSettings(assignments)
	return &settings, nil
}

func (s *mqlJournaldConfig) journaldInstalled() (bool, error) {
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return false, nil
	}

	for _, binary := range journaldBinaryPaths {
		exists, err := afero.Exists(conn.FileSystem(), binary)
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

// journaldJournalAssignments returns every assignment in the unit's
// [Journal] sections, in file order. Section names are case-sensitive in
// systemd.
func journaldJournalAssignments(unit *parsers.Unit) []parsers.UnitParam {
	var res []parsers.UnitParam
	for _, section := range unit.Sections {
		if section.Name == "Journal" {
			res = append(res, section.Params...)
		}
	}
	return res
}

// resolveJournaldSettings applies the [Journal] assignments in the order
// journald reads them, starting from systemd's defaults. As in journald,
// the last valid assignment wins and an invalid value is ignored, so it does
// not undo an earlier valid one. Setting names are case-sensitive.
func resolveJournaldSettings(assignments []parsers.UnitParam) journaldSettings {
	res := journaldSettings{
		storage:         "auto",
		compress:        true,
		forwardToSyslog: false,
	}

	for _, assignment := range assignments {
		value := strings.TrimSpace(assignment.Value)
		switch assignment.Name {
		case "Storage":
			if slices.Contains(journaldStorageModes, value) {
				res.storage = value
			}
		case "Compress":
			if v, ok := parseJournaldCompress(value); ok {
				res.compress = v
			}
		case "ForwardToSyslog":
			if v, ok := parseSystemdBoolean(value); ok {
				res.forwardToSyslog = v
			}
		}
	}

	return res
}

// parseSystemdBoolean parses a boolean the way systemd's parse_boolean does:
// case-insensitive, accepting 1/yes/y/true/t/on and 0/no/n/false/f/off.
func parseSystemdBoolean(value string) (bool, bool) {
	switch strings.ToLower(value) {
	case "1", "yes", "y", "true", "t", "on":
		return true, true
	case "0", "no", "n", "false", "f", "off":
		return false, true
	}
	return false, false
}

// parseJournaldCompress follows journald's config_parse_compress: an empty
// value restores the default (enabled), a boolean sets it, and a size
// threshold enables compression.
func parseJournaldCompress(value string) (bool, bool) {
	if value == "" {
		return true, true
	}
	if v, ok := parseSystemdBoolean(value); ok {
		return v, true
	}
	if journaldSizeRe.MatchString(value) {
		return true, true
	}
	return false, false
}

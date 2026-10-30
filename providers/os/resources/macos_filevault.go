// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
)

type mqlMacosFilevaultInternal struct {
	lock    sync.Mutex
	fetched bool
	output  string
}

func (m *mqlMacosFilevault) fetchStatus() (string, error) {
	if m.fetched {
		return m.output, nil
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.fetched {
		return m.output, nil
	}

	res, err := NewResource(m.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("fdesetup status"),
	})
	if err != nil {
		return "", err
	}
	cmd := res.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Data != 0 {
		return "", errors.New("fdesetup status failed: " + cmd.GetStderr().Data)
	}

	m.output = parseFdesetupStatus(cmd.GetStdout().Data)
	m.fetched = true
	return m.output, nil
}

// parseFdesetupStatus extracts the first non-empty line of `fdesetup status`
// output, which is the status sentence we care about. fdesetup may print
// additional lines (e.g. progress percentages, deferred-enablement notes);
// callers only need the headline.
//
// Examples of the leading line:
//
//	"FileVault is On."
//	"FileVault is Off."
//	"Encryption in progress: Percent completed = 50.0"
//	"Decryption in progress: Percent completed = 50.0"
func parseFdesetupStatus(raw string) string {
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// isFilevaultEnabled returns true for the "on" and "encrypting" states.
// Decryption-in-progress is treated as not enabled because the volume is
// transitioning to plaintext.
func isFilevaultEnabled(status string) bool {
	return strings.Contains(status, "FileVault is On") ||
		strings.Contains(status, "Encryption in progress")
}

// parseFdesetupList turns `fdesetup list` output into a list of usernames.
// Each line is "username,UUID"; blanks are skipped.
func parseFdesetupList(raw string) []any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []any{}
	}
	users := []any{}
	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, _, _ := strings.Cut(line, ",")
		users = append(users, name)
	}
	return users
}

func (m *mqlMacosFilevault) status() (string, error) {
	return m.fetchStatus()
}

func (m *mqlMacosFilevault) enabled() (bool, error) {
	status, err := m.fetchStatus()
	if err != nil {
		return false, err
	}
	return isFilevaultEnabled(status), nil
}

func (m *mqlMacosFilevault) runFdesetup(subcmd string) (string, error) {
	res, err := NewResource(m.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("fdesetup " + subcmd),
	})
	if err != nil {
		return "", err
	}
	cmd := res.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Data != 0 {
		return "", errors.New("fdesetup " + subcmd + " failed: " + cmd.GetStderr().Data)
	}
	return strings.TrimSpace(cmd.GetStdout().Data), nil
}

func (m *mqlMacosFilevault) hasPersonalRecoveryKey() (bool, error) {
	enabled, err := m.enabled()
	if err != nil {
		return false, err
	}
	if !enabled {
		return false, nil
	}
	// fdesetup haspersonalrecoverykey outputs "true" or "false"
	output, err := m.runFdesetup("haspersonalrecoverykey")
	if err != nil {
		return false, err
	}
	return output == "true", nil
}

func (m *mqlMacosFilevault) hasInstitutionalRecoveryKey() (bool, error) {
	enabled, err := m.enabled()
	if err != nil {
		return false, err
	}
	if !enabled {
		return false, nil
	}
	// fdesetup hasinstitutionalrecoverykey outputs "true" or "false"
	output, err := m.runFdesetup("hasinstitutionalrecoverykey")
	if err != nil {
		return false, err
	}
	return output == "true", nil
}

func (m *mqlMacosFilevault) users() ([]any, error) {
	enabled, err := m.enabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return []any{}, nil
	}
	// fdesetup list outputs lines like:
	// "user1,85632A00-1234-5678-ABCD-123456789ABC"
	// "user2,95632A00-1234-5678-ABCD-123456789ABC"
	output, err := m.runFdesetup("list")
	if err != nil {
		return nil, err
	}

	return parseFdesetupList(output), nil
}

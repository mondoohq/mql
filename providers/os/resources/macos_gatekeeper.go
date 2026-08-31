// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
)

type mqlMacosGatekeeperInternal struct {
	lock    sync.Mutex
	fetched bool
	output  string
}

func (m *mqlMacosGatekeeper) fetchStatus() (string, error) {
	if m.fetched {
		return m.output, nil
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.fetched {
		return m.output, nil
	}

	res, err := NewResource(m.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("spctl --status"),
	})
	if err != nil {
		return "", err
	}
	cmd := res.(*mqlCommand)
	stdout, err := commandOutput(cmd, "spctl --status")
	if err != nil {
		return "", err
	}

	m.output = parseSpctlStatus(stdout)
	m.fetched = true
	return m.output, nil
}

// parseSpctlStatus normalizes `spctl --status` output. The command prints a
// single line such as "assessments enabled" or "assessments disabled"; trim
// and use the first non-empty line so trailing newlines or stray banner
// lines don't trip up downstream matchers.
func parseSpctlStatus(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// isGatekeeperEnabled returns true only for the exact "assessments enabled"
// marker. parseSpctlStatus has already trimmed and picked one line, so an
// exact match is safer than a substring check against future spctl output.
func isGatekeeperEnabled(status string) bool {
	return status == "assessments enabled"
}

func (m *mqlMacosGatekeeper) status() (string, error) {
	return m.fetchStatus()
}

func (m *mqlMacosGatekeeper) enabled() (bool, error) {
	status, err := m.fetchStatus()
	if err != nil {
		return false, err
	}
	return isGatekeeperEnabled(status), nil
}

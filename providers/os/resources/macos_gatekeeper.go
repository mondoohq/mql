// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
)

const (
	spctlEnabled  = "assessments enabled"
	spctlDisabled = "assessments disabled"
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
	status, err := spctlStatus(cmd.GetStdout().Data, cmd.GetStderr().Data, cmd.GetExitcode().Data)
	if err != nil {
		return "", err
	}

	m.output = status
	m.fetched = true
	return m.output, nil
}

// spctlStatus turns the result of `spctl --status` into the status line.
// spctl exits 1 when assessments are disabled, so the exit code alone does not
// mean the command failed: "assessments disabled" on stdout with exit 1 is the
// answer, not an error. Any other non-zero exit is an error.
//
// Measured on macOS 26.6.2:
//
//	enabled:  stdout "assessments enabled\n",  exit 0
//	disabled: stdout "assessments disabled\n", exit 1
func spctlStatus(stdout string, stderr string, exitCode int64) (string, error) {
	status := parseSpctlStatus(stdout)
	if exitCode == 0 || status == spctlDisabled {
		return status, nil
	}
	msg := strings.TrimSpace(stderr)
	if msg == "" {
		msg = status
	}
	return "", fmt.Errorf("spctl --status failed (exit %d): %s", exitCode, msg)
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
	return status == spctlEnabled
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

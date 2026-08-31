// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
)

type mqlMacosSipInternal struct {
	lock    sync.Mutex
	fetched bool
	output  string
}

func (m *mqlMacosSip) fetchStatus() (string, error) {
	if m.fetched {
		return m.output, nil
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.fetched {
		return m.output, nil
	}

	res, err := NewResource(m.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("csrutil status"),
	})
	if err != nil {
		return "", err
	}
	cmd := res.(*mqlCommand)
	stdout, err := commandOutput(cmd, "csrutil status")
	if err != nil {
		return "", err
	}

	// csrutil status outputs:
	// "System Integrity Protection status: enabled."
	// "System Integrity Protection status: disabled."
	// May also include individual configuration flags on separate lines
	output := strings.TrimSpace(stdout)
	lines := strings.SplitN(output, "\n", 2)

	m.output = strings.TrimSpace(lines[0])
	m.fetched = true
	return m.output, nil
}

func (m *mqlMacosSip) status() (string, error) {
	return m.fetchStatus()
}

func (m *mqlMacosSip) enabled() (bool, error) {
	status, err := m.fetchStatus()
	if err != nil {
		return false, err
	}

	return strings.Contains(status, "status: enabled"), nil
}

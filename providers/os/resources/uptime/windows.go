// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package uptime

import (
	"encoding/json"
	"io"
	"time"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

type WindowsUptime struct {
	TotalMilliseconds float64 `json:"TotalMilliseconds"`
}

// ParseWindowsUptime parses the json output of gcim LastBootUpTime
// (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime | ConvertTo-Json
func ParseWindowsUptime(uptime string) (time.Duration, error) {
	var winUptime WindowsUptime
	err := json.Unmarshal([]byte(uptime), &winUptime)
	if err != nil {
		return 0, err
	}

	milli := winUptime.TotalMilliseconds * float64(time.Millisecond)
	return time.Duration(int64(milli)), nil
}

const WindowsUptimeCmd = "(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime | ConvertTo-Json"

type Windows struct {
	conn shared.Connection
}

func (s *Windows) Name() string {
	return "Windows Uptime"
}

func (s *Windows) Duration() (time.Duration, error) {
	cmd, err := s.conn.RunCommand(powershell.Wrap(WindowsUptimeCmd))
	if err != nil {
		return 0, err
	}

	return s.parse(cmd.Stdout)
}

func (s *Windows) parse(r io.Reader) (time.Duration, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	return ParseWindowsUptime(string(content))
}

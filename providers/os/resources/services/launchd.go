// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"io"
	"regexp"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// launchctl list prints three tab-separated columns: PID, the last exit
// status, and the label. PID is a number or "-" when the job is not running.
// The status is a signed integer: 0 for a clean exit, a positive exit code,
// or a negative signal number (-9 for SIGKILL, -15 for SIGTERM). Matching it
// as a single digit dropped every job that had ever been killed or exited
// non-zero -- around 40% of the list on a normal macOS install. A trailing
// carriage return is not part of the label: "." matches it, so CRLF line
// endings (a fixture checked out on Windows) would otherwise end up in the name.
var LAUNCHD_REGEX = regexp.MustCompile(`(?m)^\s*(-|\d+)\s+(-?\d+)\s+(\S.*?)\r?$`)

func ParseServiceLaunchD(input io.Reader) ([]*Service, error) {
	var services []*Service
	content, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	m := LAUNCHD_REGEX.FindAllStringSubmatch(string(content), -1)
	for i := range m {
		s := &Service{
			Name:      m[i][3],
			Enabled:   true,
			Installed: true,
			Running:   m[i][1] != "-",
			Type:      "launchd",
		}
		services = append(services, s)
	}
	return services, nil
}

// macOS is using launchd as default service manager
type LaunchDServiceManager struct {
	conn shared.Connection
}

func (s *LaunchDServiceManager) Name() string {
	return "launchd Service Manager"
}

func (s *LaunchDServiceManager) List() ([]*Service, error) {
	c, err := s.conn.RunCommand("launchctl list")
	if err != nil {
		return nil, err
	}
	return ParseServiceLaunchD(c.Stdout)
}

func (s *LaunchDServiceManager) Get(name string) (*Service, error) {
	return getServiceFromList(name, s.List)
}

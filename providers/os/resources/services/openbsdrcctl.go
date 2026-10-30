// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"bufio"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// https://man.openbsd.org/rcctl
type OpenBsdRcctlServiceManager struct {
	conn shared.Connection
}

func (s *OpenBsdRcctlServiceManager) Name() string {
	return "OpenBSD Service Manager"
}

func (s *OpenBsdRcctlServiceManager) List() ([]*Service, error) {
	// fetch individual service states
	c, err := s.conn.RunCommand("rcctl ls started")
	if err != nil {
		return nil, err
	}
	started := ParseOpenBsdServiceList(c.Stdout)

	c, err = s.conn.RunCommand("rcctl ls stopped")
	if err != nil {
		return nil, err
	}
	stopped := ParseOpenBsdServiceList(c.Stdout)

	c, err = s.conn.RunCommand("rcctl ls on")
	if err != nil {
		return nil, err
	}
	enabled := ParseOpenBsdServiceList(c.Stdout)

	c, err = s.conn.RunCommand("rcctl ls off")
	if err != nil {
		return nil, err
	}
	disabled := ParseOpenBsdServiceList(c.Stdout)

	srvs := map[string]*Service{}

	// compose results
	for k := range started {
		srvs[k] = &Service{
			Name:      k,
			Installed: true,
			Running:   true,
			State:     ServiceRunning,
			Type:      "openbsd",
		}
	}

	for k := range stopped {
		srvs[k] = &Service{
			Name:      k,
			Installed: true,
			Running:   false,
			State:     ServiceStopped,
			Type:      "openbsd",
		}
	}

	// now enrich enabled/disabled, enabled/disabled services must have a started or stopped state
	for k := range enabled {
		_, ok := srvs[k]
		if ok {
			srvs[k].Enabled = true
		}
	}
	for k := range disabled {
		_, ok := srvs[k]
		if ok {
			srvs[k].Enabled = false
		}
	}

	list := []*Service{}
	for k := range srvs {
		list = append(list, srvs[k])
	}
	return list, nil
}

func (s *OpenBsdRcctlServiceManager) Get(name string) (*Service, error) {
	return getServiceFromList(name, s.List)
}

func ParseOpenBsdServiceList(r io.Reader) map[string]struct{} {
	res := map[string]struct{}{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		name := strings.TrimSpace(line)
		if name != "" {
			res[name] = struct{}{}
		}
	}
	return res
}

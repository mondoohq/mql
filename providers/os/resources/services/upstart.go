// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"bufio"
	"io"
	"regexp"

	"github.com/rs/zerolog/log"
)

// see https://web.archive.org/web/20231231172843/https://wiki.ubuntu.com/SystemdForUpstartUsers
type UpstartServiceManager struct {
	SysVServiceManager
}

func (s *UpstartServiceManager) Name() string {
	return "Upstart Service Manager"
}

func (s *UpstartServiceManager) List() ([]*Service, error) {
	// gather sysv-managed services
	sysvservices, err := s.SysVServiceManager.List()
	if err != nil {
		return nil, err
	}

	// gather upstart-managed services
	upstartservices, err := s.upstartservices()
	if err != nil {
		return nil, err
	}

	services := []*Service{}

	for k := range upstartservices {
		services = append(services, upstartservices[k])
	}

	// some services are listed in upstart and sysv, we are filtering them here
	for i := range sysvservices {
		srv := sysvservices[i]

		_, ok := upstartservices[srv.Name]
		if ok {
			// ignore sysv entry
			continue
		}

		services = append(services, srv)
	}

	return services, nil
}

func (s *UpstartServiceManager) Get(name string) (*Service, error) {
	return getServiceFromList(name, s.List)
}

func (s *UpstartServiceManager) upstartservices() (map[string]*Service, error) {
	// NOTE: without /sbin prefix this command would fail on Amazon Linux 1
	c, err := s.conn.RunCommand("/sbin/initctl list")
	if err != nil {
		return nil, err
	}
	return ParseUpstartServices(c.Stdout)
}

var upstartServiceRegex = regexp.MustCompile(`^(.*?)\s(stop/waiting|start/running)(?:, process (\d+)){0,1}$`)

func ParseUpstartServices(r io.Reader) (map[string]*Service, error) {
	res := map[string]*Service{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		m := upstartServiceRegex.FindStringSubmatch(line)
		if len(m) != 4 {
			log.Error().Str("line", line).Msg("cannot parse upstart service")
			continue
		}

		service := m[1]
		srv := &Service{
			Name:      service,
			Enabled:   true,
			Installed: true,
			Running:   m[2] == "start/running",
			Type:      "upstart",
		}

		res[service] = srv
	}

	return res, nil
}

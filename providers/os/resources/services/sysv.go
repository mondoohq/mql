// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/stringx"
)

type SysVServiceManager struct {
	conn shared.Connection
}

func (s *SysVServiceManager) Name() string {
	return "SysV Service Manager"
}

func (s *SysVServiceManager) List() ([]*Service, error) {
	// 1. gather all services
	services, err := s.services()
	if err != nil {
		return nil, err
	}

	// 2. gather all run levels
	rl, err := s.serviceRunLevel()
	if err != nil {
		return nil, err
	}

	// eg. we ignore the following run levels since `service halt status` may shutdown the system
	ignored := []string{"boot", "boot.local", "functions", "halt", "halt.local", "killall", "rc", "reboot", "shutdown", "single", "skeleton", ".depend.boot", ".depend.start", ".depend.stop"}
	statusServices := []string{}
	for i := range services {
		service := services[i]
		if stringx.Contains(ignored, service) {
			continue
		}
		statusServices = append(statusServices, service)
	}

	// 3. mimic `service --status-all` by running `service x status` for each detected service
	running, err := s.running(statusServices)
	if err != nil {
		return nil, err
	}

	// aggregate data into service struct
	res := []*Service{}

	for i := range statusServices {
		service := statusServices[i]

		srv := &Service{
			Name:      service,
			Enabled:   len(rl[service]) > 0,
			Installed: true,
			Running:   running[service],
			Type:      "sysv",
		}

		if srv.Running {
			srv.State = ServiceRunning
		} else {
			srv.State = ServiceStopped
		}
		res = append(res, srv)
	}

	return res, nil
}

func (s *SysVServiceManager) Get(name string) (*Service, error) {
	return getServiceFromList(name, s.List)
}

func (s *SysVServiceManager) services() ([]string, error) {
	c, err := s.conn.RunCommand("ls -1 /etc/init.d/")
	if err != nil {
		return nil, err
	}

	services := ParseSysvServices(c.Stdout)
	return services, nil
}

func (s *SysVServiceManager) serviceRunLevel() (map[string][]SysVServiceRunlevel, error) {
	c, _ := s.conn.RunCommand("find /etc/rc*.d -name 'S*'")
	// it may happen that /etc/init.d/rc does not exist, eg on centos 6
	return ParseSysVRunlevel(c.Stdout)
}

func (s *SysVServiceManager) running(services []string) (map[string]bool, error) {
	res := map[string]bool{}

	for i := range services {
		service := services[i]
		running := true

		serviceStatusCmd, err := s.conn.RunCommand(fmt.Sprintf("service %s status", service))
		if err != nil || serviceStatusCmd.ExitStatus != 0 {
			running = false
		}
		res[service] = running
	}

	return res, nil
}

func ParseSysvServices(r io.Reader) []string {
	services := []string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		service := strings.TrimSpace(line)
		if service == "" {
			continue
		}
		services = append(services, service)
	}
	return services
}

var runlevelRegex = regexp.MustCompile(`rc([0-6])\.d\/S(\d+)(.*)$`)

type SysVServiceRunlevel struct {
	Level string
	Order string
}

func ParseSysVRunlevel(r io.Reader) (map[string][]SysVServiceRunlevel, error) {
	res := map[string][]SysVServiceRunlevel{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		m := runlevelRegex.FindStringSubmatch(line)
		if len(m) != 4 {
			log.Error().Str("line", line).Msg("cannot parse sysv runlevel")
			continue
		}

		service := m[3]
		srl := SysVServiceRunlevel{
			Level: m[1],
			Order: m[2],
		}

		entry, ok := res[service]
		if !ok {
			entry = []SysVServiceRunlevel{}
		}

		entry = append(entry, srl)
		res[service] = entry
	}
	return res, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"bufio"
	"io"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// https://man.netbsd.org/NetBSD-9.1/service.8
type NetBsdServiceManager struct {
	conn shared.Connection
}

func (s *NetBsdServiceManager) Name() string {
	return "NetBSD Service Manager"
}

func (s *NetBsdServiceManager) List() ([]*Service, error) {
	// Fetch all available services
	c, err := s.conn.RunCommand("/usr/sbin/service -l")
	if err != nil {
		return nil, err
	}
	allServices := ParseNetBsdServiceList(c.Stdout)

	// Fetch enabled services
	c, err = s.conn.RunCommand("/usr/sbin/service -e")
	if err != nil {
		return nil, err
	}
	enabledServices := ParseNetBsdServiceList(c.Stdout)

	srvs := map[string]*Service{}

	// Initialize all services as installed but disabled and stopped
	for name := range allServices {
		srvs[name] = &Service{
			Name:      name,
			Installed: true,
			Running:   false,
			Enabled:   false,
			State:     ServiceStopped,
			Type:      "netbsd",
			Path:      allServices[name],
		}
	}

	// Mark enabled services and check their running status
	for name := range enabledServices {
		if srv, ok := srvs[name]; ok {
			srv.Enabled = true

			// Check if the service is currently running
			running, err := s.checkServiceStatus(name)
			if err != nil {
				log.Debug().Err(err).Str("service", name).Msg("could not check service status")
				// Continue without failing - assume stopped if we can't determine status
				continue
			}

			if running {
				srv.Running = true
				srv.State = ServiceRunning
			}
		}
	}

	// Convert map to list
	list := []*Service{}
	for _, srv := range srvs {
		list = append(list, srv)
	}

	return list, nil
}

func (s *NetBsdServiceManager) Get(name string) (*Service, error) {
	return getServiceFromList(name, s.List)
}

// checkServiceStatus checks if a service is currently running by executing service <name> status
func (s *NetBsdServiceManager) checkServiceStatus(name string) (bool, error) {
	cmd := "/usr/sbin/service " + name + " status"
	c, err := s.conn.RunCommand(cmd)
	if err != nil {
		// Command execution failed (not just non-zero exit)
		return false, err
	}

	// Exit code 0 typically means service is running
	// Exit code != 0 typically means service is not running
	return c.ExitStatus == 0, nil
}

// ParseNetBsdServiceList parses the output of 'service -l' or 'service -e'
// Returns a map of service name to full path
func ParseNetBsdServiceList(r io.Reader) map[string]string {
	res := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line != "" {
			// Extract service name from path (e.g., /etc/rc.d/sshd -> sshd)
			name := filepath.Base(line)
			res[name] = line
		}
	}
	return res
}

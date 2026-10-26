// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// SolarisSmfServiceManager handles Solaris Service Management Facility (SMF)
// https://docs.oracle.com/cd/E23824_01/html/821-1451/hbrunlevels-25516.html
type SolarisSmfServiceManager struct {
	conn shared.Connection
}

func (s *SolarisSmfServiceManager) Name() string {
	return "Solaris Service Management Facility"
}

func (s *SolarisSmfServiceManager) List() ([]*Service, error) {
	cmd, err := s.conn.RunCommand("svcs -a")
	if err != nil {
		return nil, err
	}
	// without this an unavailable or failing svcs reports an empty service list
	// as if the system genuinely ran no services
	if cmd.ExitStatus != 0 {
		stderr, _ := io.ReadAll(cmd.Stderr)
		return nil, fmt.Errorf("svcs -a failed with exit code %d: %s",
			cmd.ExitStatus, strings.TrimSpace(string(stderr)))
	}

	return ParseSolarisSmfServices(cmd.Stdout), nil
}

func (s *SolarisSmfServiceManager) Get(name string) (*Service, error) {
	return getServiceFromList(name, s.List)
}

// smfService represents a parsed SMF service entry
type smfService struct {
	State string
	FMRI  string
}

// ParseSolarisSmfServices parses the output of `svcs -a`
// Example output:
//
//	STATE          STIME           FMRI
//	online         22:01:55        svc:/network/ssh:default
//	disabled       22:01:40        svc:/network/dns/client:default
//	legacy_run     22:02:03        lrc:/etc/rc2_d/S89PRESERVE
func ParseSolarisSmfServices(r io.Reader) []*Service {
	var services []*Service
	scanner := bufio.NewScanner(r)

	first := true
	for scanner.Scan() {
		line := scanner.Text()

		// Drop the header line ("STATE STIME FMRI") when it is present, but only
		// then. Skipping unconditionally loses the first service on headerless
		// output such as `svcs -aH`.
		if first {
			first = false
			if fields := strings.Fields(line); len(fields) > 0 && fields[0] == "STATE" {
				continue
			}
		}

		entry := parseSmfLine(line)
		if entry == nil {
			continue
		}

		running, enabled := smfStateToRunningEnabled(entry.State)
		services = append(services, &Service{
			Name: entry.FMRI,
			// An incomplete instance has no manifest of its own; it exists only
			// because a profile or another manifest names it, so no package
			// delivers it.
			Installed: normalizeSmfState(entry.State) != "incomplete",
			Running:   running,
			Enabled:   enabled,
			State:     smfStateToServiceState(entry.State),
			Type:      "smf",
		})
	}

	return services
}

// parseSmfLine parses a single line from svcs -a output
// Format: STATE          STIME           FMRI
// Fields are whitespace-separated, with STATE and STIME being fixed-width
func parseSmfLine(line string) *smfService {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil
	}

	return &smfService{
		State: fields[0],
		FMRI:  fields[2],
	}
}

// normalizeSmfState strips the asterisk suffix from transitioning states
// (e.g., "online*" -> "online" when a service is starting/stopping)
func normalizeSmfState(state string) string {
	return strings.TrimSuffix(state, "*")
}

// smfStateToRunningEnabled maps SMF states to running and enabled booleans
// SMF states: online, offline, disabled, maintenance, degraded, legacy_run, incomplete, uninitialized
func smfStateToRunningEnabled(state string) (running, enabled bool) {
	switch normalizeSmfState(state) {
	case "online":
		return true, true
	case "degraded":
		// Running but in a degraded state
		return true, true
	case "legacy_run":
		// Legacy init.d script is running
		return true, true
	case "offline":
		// Enabled but not running (waiting for dependencies)
		return false, true
	case "maintenance":
		// Enabled but in error state
		return false, true
	case "disabled", "uninitialized", "incomplete":
		// incomplete: the instance is defined only by a profile or another
		// manifest's dependency, has no general/enabled, and svcadm refuses to
		// enable or disable it until the package that delivers it is installed
		return false, false
	default:
		// Unknown state, assume not running
		return false, false
	}
}

// smfStateToServiceState maps SMF state to the generic ServiceState
func smfStateToServiceState(state string) State {
	switch normalizeSmfState(state) {
	case "online", "degraded", "legacy_run":
		return ServiceRunning
	case "offline", "disabled", "maintenance", "incomplete", "uninitialized":
		return ServiceStopped
	default:
		return ServiceUnknown
	}
}

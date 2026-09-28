// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"bufio"
	"io"
	"path/filepath"
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

func ParseBsdInit(input io.Reader) ([]*Service, error) {
	var services []*Service
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()
		services = append(services, &Service{
			Name:      filepath.Base(strings.TrimSpace(line)),
			Enabled:   true,
			Installed: true,
			Running:   true,
			Type:      "bsd",
			Path:      strings.TrimSpace(line),
		})
	}
	return services, nil
}

// freebsdServiceStatusScript lists the enabled rc.d scripts and asks each one
// for its status in a single round trip. Each output line is "<result> <path>",
// where result is the exit code of `service <name> status`, or "denied" when
// the script could not read what it needed to answer (a root-only pidfile such
// as /var/run/cron.pid when the scan does not run as root). rc.subr answers
// "<name> is running as pid N" with exit 0 and "<name> is not running" with 1;
// a script without a status directive (growfs, hostid, cleanvar, the other
// one-shot boot scripts) prints "unknown directive 'status'" and exits 1.
const freebsdServiceStatusScript = `for s in $(/usr/sbin/service -e); do ` +
	`out=$(/usr/sbin/service "${s##*/}" status 2>&1); rc=$?; ` +
	`case "$out" in *"Permission denied"*) rc=denied;; esac; ` +
	`echo "$rc $s"; done`

// ParseFreeBSDServiceStatus parses the output of freebsdServiceStatusScript.
// A service is running when its status command exits 0, which is what
// `service <name> status` reports. One-shot boot scripts have no status, run
// once at boot and leave nothing behind, so they are not running, like a
// systemd oneshot unit without RemainAfterExit. When the status could not be
// read for lack of permission, the service keeps the enabled-means-running
// answer this manager gave before status checks, rather than turning a
// permission problem into a stopped daemon.
func ParseFreeBSDServiceStatus(input io.Reader) []*Service {
	var services []*Service
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		result, path, ok := strings.Cut(strings.TrimSpace(scanner.Text()), " ")
		path = strings.TrimSpace(path)
		if !ok || !strings.HasPrefix(path, "/") || !isStatusResult(result) {
			continue
		}
		running := result == "0" || result == "denied"
		state := ServiceStopped
		if running {
			state = ServiceRunning
		}
		services = append(services, &Service{
			Name:      filepath.Base(path),
			Enabled:   true,
			Installed: true,
			Running:   running,
			State:     state,
			Type:      "bsd",
			Path:      path,
		})
	}
	return services
}

// isStatusResult reports whether s is a result freebsdServiceStatusScript
// writes: an exit code or "denied". Anything else is not from the loop (a sudo
// lecture, a warning from rc.conf) and is skipped.
func isStatusResult(s string) bool {
	if s == "denied" {
		return true
	}
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

type BsdInitServiceManager struct {
	conn shared.Connection
	// checkStatus asks every enabled script for its status (FreeBSD). Without
	// it every enabled service is reported as running (DragonFly, whose
	// status output has not been verified).
	checkStatus bool
}

func (s *BsdInitServiceManager) Name() string {
	return "Bsd Init Service Manager"
}

func (s *BsdInitServiceManager) List() ([]*Service, error) {
	if s.checkStatus {
		c, err := s.conn.RunCommand("sh -c " + shared.ShellEscape(freebsdServiceStatusScript))
		if err != nil {
			return nil, err
		}
		return ParseFreeBSDServiceStatus(c.Stdout), nil
	}
	c, err := s.conn.RunCommand("service -e")
	if err != nil {
		return nil, err
	}
	return ParseBsdInit(c.Stdout)
}

func (s *BsdInitServiceManager) Get(name string) (*Service, error) {
	return getServiceFromList(name, s.List)
}

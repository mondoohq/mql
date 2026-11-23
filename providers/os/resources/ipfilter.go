// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	ipfilterFMRI       = "svc:/network/ipfilter:default"
	ipfilterConfig     = "/etc/ipf/ipf.conf"
	ipfilterSvcsCmd    = "/usr/bin/svcs -H -o state " + ipfilterFMRI
	ipfilterIpfstatCmd = "/usr/sbin/ipfstat -io"
)

func (p *mqlIpfilter) id() (string, error) {
	return "ipfilter", nil
}

// conn returns the connection of a Solaris or illumos asset, which detection
// names "solaris" alike. IP Filter is not applicable anywhere else.
func (p *mqlIpfilter) conn() (shared.Connection, error) {
	conn, ok := p.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("ipfilter requires an operating system connection")
	}
	if pf := conn.Asset().GetPlatform(); pf == nil || pf.Name != "solaris" {
		return nil, llx.NotApplicable(errors.New("ipfilter is only available on Solaris and illumos"))
	}
	return conn, nil
}

// run runs cmd, which needs a running system.
func (p *mqlIpfilter) run(cmd string) (*mqlCommand, error) {
	conn, err := p.conn()
	if err != nil {
		return nil, err
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, llx.NotApplicable(errors.New("ipfilter requires a running system; this asset cannot run commands"))
	}
	o, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(cmd),
	})
	if err != nil {
		return nil, err
	}
	c := o.(*mqlCommand)
	if exit := c.GetExitcode(); exit.Error != nil {
		return nil, exit.Error
	}
	return c, nil
}

func (p *mqlIpfilter) enabled() (bool, error) {
	cmd, err := p.run(ipfilterSvcsCmd)
	if err != nil {
		return false, err
	}
	exit := cmd.GetExitcode().Data
	stderr := strings.TrimSpace(cmd.GetStderr().Data)
	if exit != 0 {
		// a system without the IP Filter package has no such service
		if isCommandNotFound(exit, stderr) || strings.Contains(stderr, "doesn't match any instances") {
			return false, nil
		}
		return false, fmt.Errorf("svcs failed (exit %d): %s", exit, stderr)
	}
	return parseIpfilterState(cmd.GetStdout().Data), nil
}

// parseIpfilterState reads `svcs -H -o state`, which prints the state alone:
// online, offline, disabled, maintenance, degraded, or uninitialized.
func parseIpfilterState(out string) bool {
	return strings.TrimSpace(out) == "online"
}

func (p *mqlIpfilter) rules() ([]any, error) {
	cmd, err := p.run(ipfilterIpfstatCmd)
	if err != nil {
		return nil, err
	}
	exit := cmd.GetExitcode().Data
	if exit != 0 {
		stderr := strings.TrimSpace(cmd.GetStderr().Data)
		if isCommandNotFound(exit, stderr) {
			return []any{}, nil
		}
		if strings.Contains(stderr, "Permission denied") {
			return nil, llx.Forbidden(fmt.Errorf("cannot read the IP Filter rules, ipfstat needs root: %s", stderr))
		}
		return nil, fmt.Errorf("ipfstat -io failed (exit %d): %s", exit, stderr)
	}
	return stringsToAny(parseIpfstatRules(cmd.GetStdout().Data)), nil
}

// parseIpfstatRules reads `ipfstat -io`, which prints one rule per line,
// outbound rules first. A direction without rules prints
// "empty list for ipfilter(out)" (or "ipfilter (out)" on some releases)
// instead. Comments and blank lines are dropped.
func parseIpfstatRules(out string) []string {
	rules := []string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty list for ") {
			continue
		}
		rules = append(rules, line)
	}
	return rules
}

func (p *mqlIpfilter) file() (*mqlFile, error) {
	if _, err := p.conn(); err != nil {
		return nil, err
	}
	f, err := CreateResource(p.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(ipfilterConfig),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

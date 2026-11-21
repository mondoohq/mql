// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	ipfwEnableSysctl          = "net.inet.ip.fw.enable"
	ipfwDefaultToAcceptSysctl = "net.inet.ip.fw.default_to_accept"
	ipfwListCommand           = "ipfw list"
)

func (p *mqlIpfw) id() (string, error) {
	return "ipfw", nil
}

type ipfwSysctl struct {
	value  string
	absent bool
	err    error
}

// mqlIpfwInternal caches the platform check and each sysctl read, so
// evaluating enabled, rules and defaultAccept together runs every command
// once.
type mqlIpfwInternal struct {
	lock         sync.Mutex
	checked      bool
	supportedErr error
	sysctls      map[string]ipfwSysctl
}

func (p *mqlIpfw) checkSupported() error {
	p.lock.Lock()
	defer p.lock.Unlock()
	if !p.checked {
		p.supportedErr = ipfwSupported(p.MqlRuntime.Connection.(shared.Connection))
		p.checked = true
	}
	return p.supportedErr
}

func ipfwSupported(conn shared.Connection) error {
	if pf := conn.Asset().GetPlatform(); pf == nil || pf.Name != "freebsd" {
		return llx.NotApplicable(errors.New("ipfw is only available on FreeBSD"))
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return llx.NotApplicable(errors.New("ipfw needs a running system, and this connection cannot run commands"))
	}
	return nil
}

// sysctl reads an ipfw sysctl. absent is true when the kernel does not know
// the sysctl, which means the ipfw module is not loaded.
func (p *mqlIpfw) sysctl(name string) (value string, absent bool, err error) {
	if err := p.checkSupported(); err != nil {
		return "", false, err
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	if r, ok := p.sysctls[name]; ok {
		return r.value, r.absent, r.err
	}
	value, absent, err = p.readSysctl(name)
	if p.sysctls == nil {
		p.sysctls = map[string]ipfwSysctl{}
	}
	p.sysctls[name] = ipfwSysctl{value: value, absent: absent, err: err}
	return value, absent, err
}

func (p *mqlIpfw) readSysctl(name string) (value string, absent bool, err error) {
	cmd, err := runSbinCommand(p.MqlRuntime, "sysctl -n "+name)
	if err != nil {
		return "", false, err
	}
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return "", false, exit.Error
	}
	if exit.Data != 0 {
		stderr := strings.TrimSpace(cmd.GetStderr().Data)
		if strings.Contains(stderr, "unknown oid") {
			return "", true, nil
		}
		return "", false, fmt.Errorf("could not read %s (exit %d): %s", name, exit.Data, stderr)
	}
	return strings.TrimSpace(cmd.GetStdout().Data), false, nil
}

// sysctlBool reads an ipfw sysctl that is 0 or 1. An absent sysctl is false.
func (p *mqlIpfw) sysctlBool(name string) (bool, error) {
	value, absent, err := p.sysctl(name)
	if err != nil || absent {
		return false, err
	}
	switch value {
	case "0":
		return false, nil
	case "1":
		return true, nil
	}
	return false, fmt.Errorf("unexpected value %q for %s", value, name)
}

func (p *mqlIpfw) enabled() (bool, error) {
	return p.sysctlBool(ipfwEnableSysctl)
}

func (p *mqlIpfw) defaultAccept() (bool, error) {
	return p.sysctlBool(ipfwDefaultToAcceptSysctl)
}

// parseIpfwList returns one rule per line of `ipfw list`, as printed with
// its rule number.
func parseIpfwList(out string) []string {
	res := []string{}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			res = append(res, line)
		}
	}
	return res
}

func (p *mqlIpfw) rules() ([]any, error) {
	// without the module there is no ruleset, and ipfw itself would fail
	_, absent, err := p.sysctl(ipfwEnableSysctl)
	if err != nil {
		return nil, err
	}
	if absent {
		return []any{}, nil
	}

	cmd, err := runSbinCommand(p.MqlRuntime, ipfwListCommand)
	if err != nil {
		return nil, err
	}
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return nil, exit.Error
	}
	if exit.Data != 0 {
		stderr := strings.TrimSpace(cmd.GetStderr().Data)
		// Reading the ruleset opens a raw socket, which needs root. ipfw
		// exits non-zero for any failure to open or use that socket, so the
		// errno text in its message is what tells a refusal apart.
		if strings.Contains(stderr, "Operation not permitted") || strings.Contains(stderr, "Permission denied") {
			return nil, llx.Forbidden(fmt.Errorf("cannot read the ipfw rules, ipfw needs root: %s", stderr))
		}
		return nil, fmt.Errorf("ipfw list failed (exit %d): %s", exit.Data, stderr)
	}
	return stringsToAny(parseIpfwList(cmd.GetStdout().Data)), nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/pfctl"
)

// pfctlPaths are where pfctl is installed: /sbin on FreeBSD, OpenBSD and
// macOS, /usr/sbin on Solaris.
var pfctlPaths = []string{"/sbin/pfctl", "/usr/sbin/pfctl"}

const (
	pfDefaultConfig        = "/etc/pf.conf"
	pfSolarisDefaultConfig = "/etc/firewall/pf.conf"
	pfSolarisFirewallFMRI  = "svc:/network/firewall:default"
)

type mqlPfInternal struct {
	lock           sync.Mutex
	located        bool
	binary         string
	servicesLoaded bool
	services       pfctl.Services
}

func (p *mqlPf) id() (string, error) {
	return "pf", nil
}

func (p *mqlPf) conn() (shared.Connection, error) {
	conn, ok := p.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("pf requires an operating system connection")
	}
	return conn, nil
}

// pfctlBinary returns the path of pfctl, or "" when it is not installed.
func (p *mqlPf) pfctlBinary(conn shared.Connection) (string, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.located {
		return p.binary, nil
	}
	if !conn.Capabilities().Has(shared.Capability_File) {
		return "", llx.NotApplicable(errors.New("pf requires file system access"))
	}
	afs := afero.Afero{Fs: conn.FileSystem()}
	for _, path := range pfctlPaths {
		ok, err := afs.Exists(path)
		if err != nil {
			return "", err
		}
		if ok {
			p.binary = path
			break
		}
	}
	p.located = true
	return p.binary, nil
}

// pfctl runs pfctl with args and returns what it printed. absent is true
// when there is no PF to ask: pfctl is not installed, or the kernel has no
// /dev/pf because the pf module is not loaded.
func (p *mqlPf) pfctl(args string) (stdout string, absent bool, err error) {
	conn, err := p.conn()
	if err != nil {
		return "", false, err
	}
	binary, err := p.pfctlBinary(conn)
	if err != nil {
		return "", false, err
	}
	if binary == "" {
		return "", true, nil
	}
	if !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return "", false, llx.NotApplicable(errors.New("pf requires a running system; this asset cannot run commands"))
	}

	o, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(binary + " " + args),
	})
	if err != nil {
		return "", false, err
	}
	cmd := o.(*mqlCommand)
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return "", false, exit.Error
	}
	if exit.Data == 0 {
		return cmd.GetStdout().Data, false, nil
	}

	stderr := strings.TrimSpace(cmd.GetStderr().Data)
	switch pfctl.ClassifyError(stderr) {
	case pfctl.ErrorNotLoaded:
		return "", true, nil
	case pfctl.ErrorRefused:
		return "", false, llx.Forbidden(fmt.Errorf("cannot read the PF state, pfctl needs root: %s", stderr))
	}
	if stderr == "" {
		stderr = strings.TrimSpace(cmd.GetStdout().Data)
	}
	return "", false, fmt.Errorf("pfctl %s failed (exit %d): %s", args, exit.Data, stderr)
}

// portServices loads /etc/services, which resolves the port names pfctl
// prints. A host without the file keeps the names.
func (p *mqlPf) portServices() pfctl.Services {
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.servicesLoaded {
		return p.services
	}
	p.servicesLoaded = true
	conn, err := p.conn()
	if err != nil {
		return nil
	}
	data, err := afero.ReadFile(conn.FileSystem(), "/etc/services")
	if err != nil {
		return nil
	}
	p.services = pfctl.ParseServices(string(data))
	return p.services
}

func (p *mqlPf) enabled() (bool, error) {
	out, absent, err := p.pfctl("-s info")
	if err != nil {
		return false, err
	}
	if absent {
		return false, nil
	}
	return pfctl.ParseInfo(out)
}

func (p *mqlPf) rules() ([]any, error) {
	out, absent, err := p.pfctl("-s rules")
	if err != nil {
		return nil, err
	}
	res := []any{}
	if absent {
		return res, nil
	}
	for i, r := range pfctl.ParseRules(out, p.portServices()) {
		o, err := CreateResource(p.MqlRuntime, "pf.rule", map[string]*llx.RawData{
			"__id":          llx.StringData("pf.rule/" + strconv.Itoa(i) + "/" + r.Raw),
			"raw":           llx.StringData(r.Raw),
			"action":        llx.StringData(r.Action),
			"blockPolicy":   llx.StringData(r.BlockPolicy),
			"direction":     llx.StringData(r.Direction),
			"quick":         llx.BoolData(r.Quick),
			"log":           llx.BoolData(r.Log),
			"interface":     llx.StringData(r.Interface),
			"addressFamily": llx.StringData(r.AddressFamily),
			"protocol":      llx.StringData(r.Protocol),
			"from":          llx.StringData(r.From),
			"fromPort":      llx.StringData(r.FromPort),
			"to":            llx.StringData(r.To),
			"toPort":        llx.StringData(r.ToPort),
			"state":         llx.StringData(r.State),
			"label":         llx.StringData(r.Label),
			"anchor":        llx.StringData(r.Anchor),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (p *mqlPf) tables() ([]any, error) {
	out, absent, err := p.pfctl("-s Tables")
	if err != nil {
		return nil, err
	}
	res := []any{}
	if absent {
		return res, nil
	}
	for _, name := range pfctl.ParseTables(out) {
		o, err := CreateResource(p.MqlRuntime, "pf.table", map[string]*llx.RawData{
			"__id": llx.StringData("pf.table/" + name),
			"name": llx.StringData(name),
		})
		if err != nil {
			return nil, err
		}
		o.(*mqlPfTable).pf = p
		res = append(res, o)
	}
	return res, nil
}

func (p *mqlPf) skipInterfaces() ([]any, error) {
	out, absent, err := p.pfctl("-s Interfaces -v")
	if err != nil {
		return nil, err
	}
	if absent {
		return []any{}, nil
	}
	return stringsToAny(pfctl.ParseSkipInterfaces(out)), nil
}

func (p *mqlPf) file() (*mqlFile, error) {
	path, err := p.configPath()
	if err != nil {
		return nil, err
	}
	f, err := CreateResource(p.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// configPath finds the ruleset file PF loads at boot. Solaris is matched by
// platform name, never by family: 11.4 ships an os-release and is detected
// into the linux family.
func (p *mqlPf) configPath() (string, error) {
	conn, err := p.conn()
	if err != nil {
		return "", err
	}
	asset := conn.Asset()
	if asset == nil || asset.Platform == nil {
		return pfDefaultConfig, nil
	}
	canRun := conn.Capabilities().Has(shared.Capability_RunCommand)
	switch asset.Platform.Name {
	case "solaris":
		if canRun {
			if path := p.commandOutput("/usr/bin/svcprop -p firewall/rules " + pfSolarisFirewallFMRI); path != "" {
				return path, nil
			}
		}
		return pfSolarisDefaultConfig, nil
	case "freebsd":
		if canRun {
			if path := p.commandOutput("/usr/sbin/sysrc -n pf_rules"); path != "" {
				return path, nil
			}
		}
	}
	return pfDefaultConfig, nil
}

// commandOutput runs cmd and returns its trimmed output when it is a single
// absolute path, or "" when it failed or printed anything else.
func (p *mqlPf) commandOutput(cmd string) string {
	o, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(cmd),
	})
	if err != nil {
		return ""
	}
	c := o.(*mqlCommand)
	if exit := c.GetExitcode(); exit.Error != nil || exit.Data != 0 {
		return ""
	}
	return singleAbsolutePath(c.GetStdout().Data)
}

func singleAbsolutePath(out string) string {
	out = strings.TrimSpace(out)
	if !strings.HasPrefix(out, "/") || strings.ContainsAny(out, "\n ") {
		return ""
	}
	return out
}

type mqlPfTableInternal struct {
	pf *mqlPf
}

func (t *mqlPfTable) addresses() ([]any, error) {
	if t.pf == nil {
		return nil, errors.New("pf.table is missing its pf")
	}
	out, absent, err := t.pf.pfctl("-t " + shellQuote(t.Name.Data) + " -T show")
	if err != nil {
		return nil, err
	}
	if absent {
		return []any{}, nil
	}
	return stringsToAny(pfctl.ParseTableAddresses(out)), nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	ufwConfPath     = "/etc/ufw/ufw.conf"
	ufwDefaultsPath = "/etc/default/ufw"
)

// ufwRulesDirs are where ufw keeps user.rules and user6.rules, the rules added
// with the ufw command. Debian and Ubuntu build ufw with its state in /etc/ufw;
// the Fedora and EPEL packages keep it in /var/lib/ufw and ship no rules files
// in /etc/ufw.
var ufwRulesDirs = []string{"/etc/ufw", "/var/lib/ufw"}

type mqlUfwInternal struct {
	fetched          bool
	cacheStatus      string // from ufw.conf, status() asks ufw where it can
	cacheBinary      string
	cacheDefIncoming string
	cacheDefOutgoing string
	cacheDefRouted   string
	cacheLogging     string
	lock             sync.Mutex
}

func (u *mqlUfw) id() (string, error) {
	return "ufw", nil
}

func (u *mqlUfw) getFs() (afero.Afero, error) {
	conn, ok := u.MqlRuntime.Connection.(shared.Connection)
	if !ok || !conn.Capabilities().Has(shared.Capability_File) {
		return afero.Afero{}, fmt.Errorf("ufw requires file system capability")
	}
	return afero.Afero{Fs: conn.FileSystem()}, nil
}

func (u *mqlUfw) fetchStatus() error {
	if u.fetched {
		return nil
	}
	u.lock.Lock()
	defer u.lock.Unlock()
	if u.fetched {
		return nil
	}

	afs, err := u.getFs()
	if err != nil {
		return err
	}

	st, err := readUfwState(afs)
	if err != nil {
		return err
	}

	u.cacheStatus = st.status
	u.cacheBinary = st.binary
	u.cacheLogging = st.logging
	u.cacheDefIncoming = st.defIncoming
	u.cacheDefOutgoing = st.defOutgoing
	u.cacheDefRouted = st.defRouted
	u.fetched = true
	return nil
}

// ufwBinaryPaths are where the ufw package installs its command. /sbin/ufw
// is the same file on usrmerged systems.
var ufwBinaryPaths = []string{"/usr/sbin/ufw", "/sbin/ufw"}

type ufwState struct {
	// binary is the ufw command that was found, empty when ufw is not installed
	binary      string
	status      string
	logging     string
	defIncoming string
	defOutgoing string
	defRouted   string
}

// readUfwState reads the UFW configuration. Removing the ufw package without
// purging it (dpkg state "rc") deletes the ufw command and unloads its rules
// but keeps /etc/ufw/ufw.conf, often with ENABLED=yes, so the configuration
// alone is not proof that UFW is installed.
func readUfwState(afs afero.Afero) (ufwState, error) {
	var st ufwState

	// Read /etc/ufw/ufw.conf for ENABLED and LOGLEVEL
	confData, err := afs.ReadFile(ufwConfPath)
	if err != nil {
		if os.IsNotExist(err) {
			st.status = "not installed"
			return st, nil
		}
		return st, err
	}

	for _, p := range ufwBinaryPaths {
		ok, err := afs.Exists(p)
		if err != nil {
			return st, err
		}
		if ok {
			st.binary = p
			break
		}
	}
	if st.binary == "" {
		st.status = "not installed"
		return st, nil
	}

	conf := parseUfwKeyValue(string(confData))
	if strings.EqualFold(conf["ENABLED"], "yes") {
		st.status = "active"
	} else {
		st.status = "inactive"
	}
	st.logging = strings.ToLower(conf["LOGLEVEL"])

	// Read /etc/default/ufw for default policies
	defaultsData, err := afs.ReadFile(ufwDefaultsPath)
	if err != nil && !os.IsNotExist(err) {
		return st, err
	}
	if err == nil {
		defaults := parseUfwKeyValue(string(defaultsData))
		st.defIncoming = ufwPolicyName(defaults["DEFAULT_INPUT_POLICY"])
		st.defOutgoing = ufwPolicyName(defaults["DEFAULT_OUTPUT_POLICY"])
		st.defRouted = ufwPolicyName(defaults["DEFAULT_FORWARD_POLICY"])
	}
	return st, nil
}

// runtimeStatus asks the installed ufw command whether the firewall is loaded.
func (u *mqlUfw) runtimeStatus(binary string) (string, error) {
	o, err := CreateResource(u.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(ufwStatusCommand(binary)),
	})
	if err != nil {
		return "", err
	}
	cmd := o.(*mqlCommand)
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return "", exit.Error
	}
	return parseUfwStatus(exit.Data, cmd.GetStdout().Data, cmd.GetStderr().Data)
}

// ufwStatusCommand runs ufw status in the C locale. ufw translates through
// Python's gettext, which reads LANGUAGE before LC_ALL, so LC_ALL=C alone
// still prints "Status: Inaktiv" under LANGUAGE=de. gettext skips an empty
// LANGUAGE. binary is unquoted because it is always one of ufwBinaryPaths.
func ufwStatusCommand(binary string) string {
	return "env LANGUAGE= LC_ALL=C LANG=C " + binary + " status"
}

// parseUfwStatus reads the first line of `ufw status`, which ufw derives
// from whether its ufw-user-input chain is loaded, not from ufw.conf.
// ufw refuses to answer anyone but root.
func parseUfwStatus(exitcode int64, stdout, stderr string) (string, error) {
	if exitcode != 0 {
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = strings.TrimSpace(stdout)
		}
		err := fmt.Errorf("cannot determine whether ufw is active: %s", msg)
		if strings.Contains(msg, "You need to be root") {
			return "", llx.Forbidden(err)
		}
		return "", err
	}
	first, _, _ := strings.Cut(strings.TrimSpace(stdout), "\n")
	switch strings.TrimSpace(first) {
	case "Status: active":
		return "active", nil
	case "Status: inactive":
		return "inactive", nil
	}
	return "", fmt.Errorf("cannot determine whether ufw is active: unexpected ufw status output %q", first)
}

func (u *mqlUfw) status() (string, error) {
	if err := u.fetchStatus(); err != nil {
		return "", err
	}
	if u.cacheBinary == "" {
		return u.cacheStatus, nil
	}

	// ENABLED=yes in ufw.conf says ufw should start at boot, not that it is
	// running: the Fedora and EPEL packages ship ENABLED=yes on a firewall
	// that was never enabled, and `systemctl stop ufw` unloads the rules
	// without touching the file. Where commands run, ask ufw itself, which
	// checks that its chains are loaded. Image and other offline scans keep
	// the configured state.
	conn, ok := u.MqlRuntime.Connection.(shared.Connection)
	if !ok || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return u.cacheStatus, nil
	}
	status, err := u.runtimeStatus(u.cacheBinary)
	if err != nil {
		// v13 answered from ufw.conf when ufw refused a non-root caller.
		// ENABLED=yes alone is not an answer, so only keep a value where
		// the systemd unit backs it. Any other failure, such as output that
		// cannot be read, is an error.
		if !plugin.StructuredErrors() {
			return ufwStatusWithoutUfw(u.cacheStatus, err, u.unitState)
		}
		return "", err
	}
	return status, nil
}

// unitState runs `systemctl is-active ufw`, which any user may run.
func (u *mqlUfw) unitState() (string, int64, error) {
	o, err := CreateResource(u.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("systemctl is-active ufw.service"),
	})
	if err != nil {
		return "", 0, err
	}
	cmd := o.(*mqlCommand)
	exit := cmd.GetExitcode()
	if exit.Error != nil {
		return "", 0, exit.Error
	}
	return cmd.GetStdout().Data, exit.Data, nil
}

// ufwStatusWithoutUfw answers ufw.status when ufw itself refused to, from
// the configured state (confStatus, read from ENABLED in ufw.conf) and the
// output of `systemctl is-active ufw` (unitState). ENABLED=no means
// `ufw disable` ran, which also unloads the chains. ENABLED=yes reads active
// only while the unit that loads the chains at boot is running:
// `systemctl stop ufw` unloads them without touching ufw.conf, and the
// Fedora and EPEL packages ship ENABLED=yes on a unit that was never
// started. An inactive unit does not prove the reverse, since `ufw enable`
// loads the chains without starting the unit, so every other case returns
// ufwErr. So does any ufwErr that is not a refusal.
func ufwStatusWithoutUfw(confStatus string, ufwErr error, unitState func() (string, int64, error)) (string, error) {
	if !errors.Is(ufwErr, llx.ErrForbidden) {
		return "", ufwErr
	}
	if confStatus == "inactive" {
		return "inactive", nil
	}
	if confStatus != "active" {
		return "", ufwErr
	}
	stdout, exit, err := unitState()
	if err == nil && exit == 0 && strings.TrimSpace(stdout) == "active" {
		return "active", nil
	}
	return "", ufwErr
}

func (u *mqlUfw) defaultIncoming() (string, error) {
	if err := u.fetchStatus(); err != nil {
		return "", err
	}
	return u.cacheDefIncoming, nil
}

func (u *mqlUfw) defaultOutgoing() (string, error) {
	if err := u.fetchStatus(); err != nil {
		return "", err
	}
	return u.cacheDefOutgoing, nil
}

func (u *mqlUfw) defaultRouted() (string, error) {
	if err := u.fetchStatus(); err != nil {
		return "", err
	}
	return u.cacheDefRouted, nil
}

func (u *mqlUfw) logging() (string, error) {
	if err := u.fetchStatus(); err != nil {
		return "", err
	}
	return u.cacheLogging, nil
}

func (u *mqlUfw) rules() ([]any, error) {
	if err := u.fetchStatus(); err != nil {
		return nil, err
	}
	if u.cacheStatus == "not installed" {
		return []any{}, nil
	}

	afs, err := u.getFs()
	if err != nil {
		return nil, err
	}

	parsed, err := readUfwRules(afs)
	if err != nil {
		return nil, err
	}

	rules := make([]any, 0, len(parsed))
	for _, t := range parsed {
		res, err := createUfwRuleResource(u.MqlRuntime, t)
		if err != nil {
			return nil, err
		}
		rules = append(rules, res)
	}
	return rules, nil
}

// ufwRulesFile returns the first of ufwRulesDirs that holds the named rules
// file, or "" when none does.
func ufwRulesFile(afs afero.Afero, name string) (string, error) {
	for _, dir := range ufwRulesDirs {
		p := dir + "/" + name
		ok, err := afs.Exists(p)
		if err != nil {
			return "", err
		}
		if ok {
			return p, nil
		}
	}
	return "", nil
}

// readUfwRules parses the IPv4 rules, then the IPv6 rules, numbered in that
// order.
func readUfwRules(afs afero.Afero) ([]ufwParsedRule, error) {
	var rules []ufwParsedRule
	num := int64(1)
	for _, f := range []struct {
		name string
		ipv6 bool
	}{{"user.rules", false}, {"user6.rules", true}} {
		p, err := ufwRulesFile(afs, f.name)
		if err != nil {
			return nil, err
		}
		if p == "" {
			continue
		}
		data, err := afs.ReadFile(p)
		if err != nil {
			return nil, err
		}
		for _, t := range parseUfwTuples(string(data)) {
			t.number = num
			t.ipv6 = f.ipv6
			rules = append(rules, t)
			num++
		}
	}
	return rules, nil
}

const ufwAppsDir = "/etc/ufw/applications.d"

func (u *mqlUfw) applications() ([]any, error) {
	if err := u.fetchStatus(); err != nil {
		return nil, err
	}
	if u.cacheStatus == "not installed" {
		return []any{}, nil
	}

	afs, err := u.getFs()
	if err != nil {
		return nil, err
	}

	entries, err := afs.ReadDir(ufwAppsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []any{}, nil
		}
		return nil, err
	}

	var apps []any
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := afs.ReadFile(ufwAppsDir + "/" + entry.Name())
		if err != nil {
			continue
		}
		parsed := parseUfwApplications(string(data))
		for _, app := range parsed {
			res, err := CreateResource(u.MqlRuntime, "ufw.application", map[string]*llx.RawData{
				"name":        llx.StringData(app.name),
				"title":       llx.StringData(app.title),
				"description": llx.StringData(app.description),
				"ports":       llx.StringData(app.ports),
			})
			if err != nil {
				return nil, err
			}
			apps = append(apps, res)
		}
	}
	return apps, nil
}

func (a *mqlUfwApplication) id() (string, error) {
	return "ufw/application/" + a.Name.Data, nil
}

type ufwParsedApp struct {
	name        string
	title       string
	description string
	ports       string
}

// parseUfwApplications parses a UFW application profile file (INI-like format).
//
// Example:
//
//	[Nginx Full]
//	title=Web Server (Nginx, HTTP + HTTPS)
//	description=Small, but very powerful and efficient web server
//	ports=80,443/tcp
func parseUfwApplications(data string) []ufwParsedApp {
	var apps []ufwParsedApp
	var current *ufwParsedApp

	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if current != nil {
				apps = append(apps, *current)
			}
			current = &ufwParsedApp{
				name: line[1 : len(line)-1],
			}
			continue
		}
		if current == nil {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "title":
			current.title = strings.TrimSpace(val)
		case "description":
			current.description = strings.TrimSpace(val)
		case "ports":
			current.ports = strings.TrimSpace(val)
		}
	}
	if current != nil {
		apps = append(apps, *current)
	}
	return apps
}

func createUfwRuleResource(runtime *plugin.Runtime, rule ufwParsedRule) (plugin.Resource, error) {
	return CreateResource(runtime, "ufw.rule", map[string]*llx.RawData{
		"number":    llx.IntData(rule.number),
		"action":    llx.StringData(rule.action),
		"direction": llx.StringData(rule.direction),
		"protocol":  llx.StringData(rule.protocol),
		"port":      llx.StringData(rule.port),
		"interface": llx.StringData(rule.iface),
		"from":      llx.StringData(rule.from),
		"to":        llx.StringData(rule.to),
		"ipv6":      llx.BoolData(rule.ipv6),
		"raw":       llx.StringData(rule.raw),
	})
}

func (r *mqlUfwRule) id() (string, error) {
	// Use the raw tuple line as the ID so that caching is stable even if
	// rules are reordered or new rules are inserted between invocations.
	return "ufw/rule/" + r.Raw.Data, nil
}

// parseUfwKeyValue parses a simple KEY=VALUE config file (with optional quotes).
// Lines starting with # are comments.
func parseUfwKeyValue(data string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), "\"'")
		result[strings.TrimSpace(key)] = val
	}
	return result
}

// ufwPolicyName translates iptables policy names from /etc/default/ufw
// to UFW-style names that users expect (e.g., DROP -> deny, ACCEPT -> allow).
func ufwPolicyName(raw string) string {
	switch strings.ToLower(raw) {
	case "drop":
		return "deny"
	case "accept":
		return "allow"
	default:
		return strings.ToLower(raw)
	}
}

type ufwParsedRule struct {
	number    int64
	action    string
	direction string
	protocol  string
	port      string
	iface     string
	from      string
	to        string
	ipv6      bool
	raw       string
}

// parseUfwTuples parses UFW tuple comments from a user.rules or user6.rules file.
//
// Tuple format:
//
//	### tuple ### ACTION PROTOCOL DPORT DST SPORT SRC DIRECTION
//	### tuple ### ACTION PROTOCOL DPORT DST SPORT SRC DAPP SAPP DIRECTION
//
// Direction is always the last field and may include an interface: "in", "out", "in_eth0".
// Routed rules prefix the action with "route:" and may name both interfaces
// ("in_eth0!out_eth1"). A rule with a comment ends in "comment=<hex>".
//
// Examples:
//
//	### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
//	### tuple ### deny tcp 3306 0.0.0.0/0 any 0.0.0.0/0 in
//	### tuple ### allow tcp 443 0.0.0.0/0 any 10.0.0.0/8 in_eth0
//	### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
//	### tuple ### allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in_ens5 comment=77656220616c74
//	### tuple ### route:allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in_ens5!out_lo
func parseUfwTuples(data string) []ufwParsedRule {
	var rules []ufwParsedRule
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "### tuple ###") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "### tuple ###"))
		fields := strings.Fields(rest)
		if len(fields) < 7 {
			continue
		}

		rule := ufwParsedRule{raw: line}

		// A rule added with `comment '...'` carries a trailing
		// "comment=<hex>" field after the direction.
		if strings.HasPrefix(fields[len(fields)-1], "comment=") {
			fields = fields[:len(fields)-1]
			if len(fields) < 7 {
				continue
			}
		}

		// Action is first field. Routed rules are prefixed with "route:",
		// and logging rules carry a _log or _log-all suffix.
		action, routed := strings.CutPrefix(fields[0], "route:")
		if i := strings.Index(action, "_log"); i != -1 {
			action = action[:i]
		}
		rule.action = strings.ToUpper(action)

		rule.protocol = fields[1]
		rule.port = fields[2]
		rule.to = fields[3]
		// fields[4] is sport (source port), usually "any"
		rule.from = fields[5]

		// Direction is always the last field: "in", "out", "in_eth0", or
		// for routed rules with both interfaces "in_eth0!out_eth1".
		dirField := fields[len(fields)-1]
		inPart, outPart, _ := strings.Cut(dirField, "!")
		dir, iface, hasIface := strings.Cut(inPart, "_")
		rule.direction = strings.ToUpper(dir)
		if hasIface {
			rule.iface = iface
		} else if _, outIface, ok := strings.Cut(outPart, "_"); ok {
			rule.iface = outIface
		}
		if routed {
			rule.direction = "FWD"
		}

		rules = append(rules, rule)
	}
	return rules
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"slices"
	"strings"
	"sync"

	"github.com/spf13/afero"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func (r *mqlSystemdResolved) id() (string, error) {
	return "systemd.resolved", nil
}

func (r *mqlSystemdResolved) active() (bool, error) {
	return isSystemdUnitActive(r.MqlRuntime, "systemd-resolved")
}

type resolvedGlobal struct {
	dns              []string
	currentDnsServer string
	fallbackDns      []string
	domains          []string
	dnssec           string
	dnsOverTls       string
	llmnr            string
	multicastDns     string
	resolvConfMode   string
	cache            bool
}

func (r *mqlSystemdResolved) resolveGlobal() (*resolvedGlobal, error) {
	if r.fetched {
		return r.cachedGlobal, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched {
		return r.cachedGlobal, nil
	}
	// Both status commands ask org.freedesktop.resolve1 over D-Bus, which
	// starts systemd-resolved, and its DNS listener, on a host where it is
	// installed but not running (stock Debian 9 to 11). So only a running
	// resolved is asked; otherwise the settings come from the configuration.
	running, err := isSystemdUnitActive(r.MqlRuntime, "systemd-resolved")
	if err != nil {
		return nil, err
	}
	g := &resolvedGlobal{}
	if running {
		// resolvectl arrived in systemd 239. Ubuntu 18.04 (systemd 237) has
		// the same report as `systemd-resolve --status`; systemd 229 (Ubuntu
		// 16.04) has neither, and its settings come from the configuration
		// alone.
		stdout, ok, err := runSystemctl(r.MqlRuntime, "resolvectl status --no-pager")
		if err != nil {
			return nil, err
		}
		if !ok {
			stdout, ok, err = runSystemctl(r.MqlRuntime, "systemd-resolve --status --no-pager")
			if err != nil {
				return nil, err
			}
		}
		if ok {
			parseResolvectlGlobal(stdout, g)
		}
	}

	// The status report never carries the cache setting, and older releases
	// leave out the protocol settings and fallback servers too, so those come
	// from resolved.conf and its drop-ins, the way systemd-resolved reads them.
	conf, err := r.readResolvedConf()
	if err != nil {
		return nil, err
	}
	applyResolvedConf(g, conf)

	r.fetched = true
	r.cachedGlobal = g
	return g, nil
}

// readResolvedConf reads the [Resolve] settings from resolved.conf and its
// drop-ins in the order systemd-resolved applies them.
func (r *mqlSystemdResolved) readResolvedConf() (*resolvedConf, error) {
	conf := newResolvedConf()

	conn, ok := r.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return conf, nil
	}
	fs := conn.FileSystem()
	if fs == nil {
		return conf, nil
	}

	mainPath, err := findSystemdMainConfig(fs, "resolved.conf")
	if err != nil {
		return conf, err
	}
	dropins, err := findSystemdConfigDropins(fs, "resolved.conf")
	if err != nil {
		return conf, err
	}

	if mainPath != "" {
		content, err := afero.ReadFile(fs, mainPath)
		if err != nil {
			return conf, err
		}
		conf.applyCompiledDefaults(string(content))
		conf.apply(string(content))
	}
	for _, dropin := range dropins {
		content, err := afero.ReadFile(fs, dropin)
		if err != nil {
			return conf, err
		}
		conf.apply(string(content))
	}

	return conf, nil
}

// resolvedConfListKeys are the settings that accumulate across assignments,
// where an empty assignment clears what came before.
var resolvedConfListKeys = []string{"DNS", "FallbackDNS", "Domains"}

// resolvedConfKeys are the [Resolve] settings read from the configuration.
var resolvedConfKeys = []string{"DNS", "FallbackDNS", "Domains", "LLMNR", "MulticastDNS", "DNSSEC", "DNSOverTLS", "Cache"}

// resolvedConf holds the [Resolve] settings in effect after resolved.conf and
// its drop-ins. A key is present once a file or a compiled default sets it.
type resolvedConf struct {
	values map[string]string
	// assigned records the list settings a file assigned, as opposed to the
	// compiled default, which the first assignment replaces rather than
	// extends
	assigned map[string]bool
}

func newResolvedConf() *resolvedConf {
	return &resolvedConf{values: map[string]string{}, assigned: map[string]bool{}}
}

// applyCompiledDefaults takes the defaults systemd-resolved was built with
// from the commented-out assignments in the main resolved.conf. systemd
// generates that file at build time and says so in its header ("Entries in
// this file show the compile time defaults"): Ubuntu documents #DNSSEC=no and
// #LLMNR=no there, where upstream defaults are allow-downgrade and yes.
func (c *resolvedConf) applyCompiledDefaults(content string) {
	inResolve := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inResolve = line == "[Resolve]"
			continue
		}
		if !inResolve {
			continue
		}
		commented, ok := strings.CutPrefix(line, "#")
		if !ok {
			continue
		}
		key, value, ok := strings.Cut(commented, "=")
		if !ok || !slices.Contains(resolvedConfKeys, key) {
			continue
		}
		if _, seen := c.values[key]; seen {
			continue
		}
		c.values[key] = strings.TrimSpace(value)
	}
}

// apply folds the [Resolve] assignments of one file into the settings. Keys
// and section names are case-sensitive, as systemd reads them.
func (c *resolvedConf) apply(content string) {
	inResolve := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			inResolve = line == "[Resolve]"
			continue
		}
		if !inResolve {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !slices.Contains(resolvedConfKeys, key) {
			continue
		}

		if !slices.Contains(resolvedConfListKeys, key) {
			c.values[key] = value
			continue
		}
		// a list setting appends, an empty assignment clears it, and the
		// first assignment replaces the compiled default
		if value == "" || !c.assigned[key] {
			c.values[key] = value
		} else if existing := c.values[key]; existing == "" {
			c.values[key] = value
		} else {
			c.values[key] = existing + " " + value
		}
		c.assigned[key] = true
	}
}

// applyResolvedConf fills in what the status report did not say from the
// configuration. The cache setting always comes from the configuration.
func applyResolvedConf(g *resolvedGlobal, conf *resolvedConf) {
	if v, ok := conf.values["Cache"]; ok {
		g.cache = parseResolvedCache(v, g.cache)
	}

	if g.dns == nil {
		if v, ok := conf.values["DNS"]; ok {
			g.dns = strings.Fields(v)
		}
	}
	if g.fallbackDns == nil {
		if v, ok := conf.values["FallbackDNS"]; ok {
			g.fallbackDns = strings.Fields(v)
		}
	}
	if g.domains == nil {
		if v, ok := conf.values["Domains"]; ok {
			g.domains = strings.Fields(v)
		}
	}
	if g.dnssec == "" {
		g.dnssec = resolvedMode(conf.values["DNSSEC"])
	}
	if g.dnsOverTls == "" {
		g.dnsOverTls = resolvedMode(conf.values["DNSOverTLS"])
	}
	if g.llmnr == "" {
		g.llmnr = resolvedMode(conf.values["LLMNR"])
	}
	if g.multicastDns == "" {
		g.multicastDns = resolvedMode(conf.values["MulticastDNS"])
	}
}

// resolvedMode spells a configured mode the way the status report does: a
// boolean as yes or no, anything else (resolve, allow-downgrade,
// opportunistic) lowercased. An absent value returns "", which callers read as
// not configured.
func resolvedMode(value string) string {
	if v, ok := parseSystemdBoolean(strings.TrimSpace(value)); ok {
		if v {
			return "yes"
		}
		return "no"
	}
	return strings.ToLower(value)
}

// parseResolvedCache reads a Cache= value. systemd accepts a boolean plus
// `no-negative`, which still caches positive answers. An unknown or empty
// value leaves fallback in place.
func parseResolvedCache(value string, fallback bool) bool {
	if strings.EqualFold(strings.TrimSpace(value), "no-negative") {
		return true
	}
	if v, ok := parseSystemdBoolean(strings.TrimSpace(value)); ok {
		return v
	}
	return fallback
}

func (r *mqlSystemdResolved) dns() ([]any, error) {
	g, err := r.resolveGlobal()
	if err != nil {
		return nil, err
	}
	return stringsToAny(g.dns), nil
}

func (r *mqlSystemdResolved) currentDnsServer() (string, error) {
	g, err := r.resolveGlobal()
	if err != nil {
		return "", err
	}
	return g.currentDnsServer, nil
}

func (r *mqlSystemdResolved) fallbackDns() ([]any, error) {
	g, err := r.resolveGlobal()
	if err != nil {
		return nil, err
	}
	return stringsToAny(g.fallbackDns), nil
}

func (r *mqlSystemdResolved) domains() ([]any, error) {
	g, err := r.resolveGlobal()
	if err != nil {
		return nil, err
	}
	return stringsToAny(g.domains), nil
}

func (r *mqlSystemdResolved) dnssec() (string, error) {
	g, err := r.resolveGlobal()
	if err != nil {
		return "", err
	}
	return g.dnssec, nil
}

func (r *mqlSystemdResolved) dnsOverTls() (string, error) {
	g, err := r.resolveGlobal()
	if err != nil {
		return "", err
	}
	return g.dnsOverTls, nil
}

func (r *mqlSystemdResolved) llmnr() (string, error) {
	g, err := r.resolveGlobal()
	if err != nil {
		return "", err
	}
	return g.llmnr, nil
}

func (r *mqlSystemdResolved) multicastDns() (string, error) {
	g, err := r.resolveGlobal()
	if err != nil {
		return "", err
	}
	return g.multicastDns, nil
}

func (r *mqlSystemdResolved) resolvConfMode() (string, error) {
	g, err := r.resolveGlobal()
	if err != nil {
		return "", err
	}
	return g.resolvConfMode, nil
}

func (r *mqlSystemdResolved) cache() (bool, error) {
	g, err := r.resolveGlobal()
	if err != nil {
		return false, err
	}
	return g.cache, nil
}

type mqlSystemdResolvedInternal struct {
	cachedGlobal *resolvedGlobal
	fetched      bool
	lock         sync.Mutex
}

// parseResolvectlGlobal extracts the Global-scope fields from
// `resolvectl status` (or, before systemd 239, `systemd-resolve --status`)
// output. The Global block ends at the first blank line or at the first
// "Link N (name)" header. Field lines are right-aligned by resolvectl, and a
// value too long for one line continues on the next lines, indented to the
// value column:
//
//	Global
//	         Protocols: -LLMNR -mDNS DNSOverTLS=opportunistic
//	                    DNSSEC=no/unsupported
//	  resolv.conf mode: stub
//	Current DNS Server: 1.1.1.1
//	       DNS Servers: 1.1.1.1 1.0.0.1
//	        DNS Domain: corp.example.com ~example.com
//
// systemd 245 (Ubuntu 20.04) prints one server or domain per line and reports
// the protocols as separate "LLMNR setting:", "DNSSEC setting:" lines:
//
//	Global
//	       LLMNR setting: no
//	  DNSOverTLS setting: opportunistic
//	      DNSSEC setting: no
//	         DNS Servers: 172.17.0.2
//	                      169.254.169.253
//
// systemd 252 (Debian 12) leaves the colon out of the Global server and domain
// labels:
//
//	Global
//	          Protocols: -LLMNR -mDNS DNSOverTLS=opportunistic DNSSEC=no/unsupported
//	   resolv.conf mode: uplink
//	         DNS Servers 192.0.2.53
//	Fallback DNS Servers 192.0.2.54 2001:db8::54
//	          DNS Domain g04.example ~corp.example
func parseResolvectlGlobal(stdout string, g *resolvedGlobal) {
	// Default cache to true — systemd-resolved caches by default. resolvectl
	// status does not reliably report the cache setting, so the authoritative
	// value is resolved from resolved.conf by the caller (resolveGlobal).
	g.cache = true

	fields := map[string][]string{}
	order := []string{}

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	inGlobal := false
	currentKey := ""
	valueColumn := 0
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)

		if trimmed == "Global" {
			inGlobal = true
			continue
		}
		if !inGlobal {
			continue
		}
		// Global block ends at first blank line or any "Link N" header.
		if trimmed == "" || strings.HasPrefix(trimmed, "Link ") {
			break
		}

		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		if key, value, ok := cutResolvectlColonlessKey(trimmed); ok {
			currentKey = key
			valueColumn = indent + len(trimmed) - len(value)
			if _, seen := fields[currentKey]; !seen {
				order = append(order, currentKey)
			}
			fields[currentKey] = append(fields[currentKey], strings.Fields(value)...)
			continue
		}
		idx := strings.Index(trimmed, ":")
		// a continuation line starts at the value column; checking the
		// indentation rather than looking for a colon keeps an IPv6 address
		// on its own line from reading as a key
		if currentKey != "" && (indent >= valueColumn || idx <= 0) {
			fields[currentKey] = append(fields[currentKey], strings.Fields(trimmed)...)
			continue
		}
		if idx <= 0 {
			continue
		}

		currentKey = strings.TrimSpace(trimmed[:idx])
		value := strings.TrimSpace(trimmed[idx+1:])
		valueColumn = strings.Index(raw, ":") + 1
		for valueColumn < len(raw) && raw[valueColumn] == ' ' {
			valueColumn++
		}
		if _, seen := fields[currentKey]; !seen {
			order = append(order, currentKey)
		}
		fields[currentKey] = append(fields[currentKey], strings.Fields(value)...)
	}

	for _, key := range order {
		values := fields[key]
		value := strings.Join(values, " ")
		switch key {
		case "Protocols":
			parseResolvectlProtocols(value, g)
		case "resolv.conf mode":
			g.resolvConfMode = value
		case "DNS Servers":
			g.dns = values
		case "Current DNS Server":
			g.currentDnsServer = value
		case "Fallback DNS Servers":
			g.fallbackDns = values
		case "DNS Domain":
			g.domains = values
		case "Cache":
			g.cache = parseYesNo(value, true)
		case "LLMNR setting":
			g.llmnr = value
		case "MulticastDNS setting":
			g.multicastDns = value
		case "DNSOverTLS setting":
			g.dnsOverTls = value
		case "DNSSEC setting":
			g.dnssec = resolvedDnssecMode(value)
		}
	}
}

// resolvectlColonlessKeys are the Global labels systemd 252 prints without a
// colon ("DNS Servers 192.0.2.53"); its link sections and every other release
// print them with one.
var resolvectlColonlessKeys = []string{"Current DNS Server", "Fallback DNS Servers", "DNS Servers", "DNS Domain"}

// cutResolvectlColonlessKey splits a systemd 252 Global line such as
// "DNS Servers 192.0.2.53" into its label and value. The value starts after
// the spaces that follow the label, so an IPv6 address in it is not mistaken
// for a key separator.
func cutResolvectlColonlessKey(line string) (string, string, bool) {
	for _, key := range resolvectlColonlessKeys {
		rest, ok := strings.CutPrefix(line, key+" ")
		if !ok {
			continue
		}
		return key, strings.TrimLeft(rest, " "), true
	}
	return "", "", false
}

// resolvedDnssecMode reduces a DNSSEC report such as "no/unsupported" or
// "allow-downgrade/supported" to the configured mode before the slash. The
// part after it says whether the current server handles DNSSEC, not what the
// host asks for, and comparing against the combined value made
// dnssec == "yes" fail on every host that enforces DNSSEC.
func resolvedDnssecMode(value string) string {
	mode, _, _ := strings.Cut(strings.TrimSpace(value), "/")
	return mode
}

// parseYesNo interprets the small vocabulary of boolean tokens that
// resolvectl/systemd output uses ("yes"/"no", and the variants "on"/"off"
// and "true"/"false" used by adjacent tools). Unknown values fall back to
// `fallback` so the caller's default semantics are preserved.
func parseYesNo(value string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "on", "true", "1":
		return true
	case "no", "off", "false", "0":
		return false
	}
	return fallback
}

// parseResolvectlProtocols parses the `Protocols:` line from `resolvectl
// status`. The format is a space-separated list of `+FLAG`/`-FLAG`
// tokens followed by `KEY=VALUE` pairs:
//
//	-LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
//
// We translate the +/- prefixes into the same `yes`/`no` string vocabulary
// the corresponding configuration directives use.
func parseResolvectlProtocols(value string, g *resolvedGlobal) {
	for _, tok := range strings.Fields(value) {
		if eq := strings.Index(tok, "="); eq > 0 {
			k := tok[:eq]
			v := tok[eq+1:]
			switch k {
			case "DNSSEC":
				g.dnssec = resolvedDnssecMode(v)
			case "DNSOverTLS":
				g.dnsOverTls = v
			case "LLMNR":
				g.llmnr = v
			case "MulticastDNS":
				g.multicastDns = v
			}
			continue
		}
		if len(tok) < 2 {
			continue
		}
		state := "no"
		if tok[0] == '+' {
			state = "yes"
		}
		switch tok[1:] {
		case "LLMNR":
			g.llmnr = state
		case "mDNS":
			g.multicastDns = state
		case "DNSOverTLS":
			g.dnsOverTls = state
		}
	}
}

// isSystemdUnitActive returns true if `systemctl is-active <unit>` exits 0.
// `systemctl is-active` exits non-zero for inactive/failed/unknown units —
// those are not connection failures, so we surface them as (false, nil).
// A genuine error from the command resource (failure to launch the
// connection, missing binary in a way that produces an error rather than
// a non-zero exit, etc.) propagates back to the caller so connectivity
// problems aren't silently rendered as "inactive".
func isSystemdUnitActive(runtime *plugin.Runtime, unit string) (bool, error) {
	o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData("systemctl is-active -- " + shellQuoteUnit(unit)),
	})
	if err != nil {
		return false, err
	}
	cmd := o.(*mqlCommand)
	return cmd.GetExitcode().Data == 0, nil
}

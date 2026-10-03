// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package haproxy

import (
	"strconv"
	"strings"
)

// Bind is the parsed shape of a `bind <addrs> [params]` directive.
//
// The first positional argument carries one or more comma-separated
// "address forms" (e.g. `*:80`, `192.0.2.1:443`, `[2001:db8::1]:443`,
// `unix:/run/haproxy/admin.sock`, or a port range `*:80-89`). Remaining
// tokens are parameters; only the audit-relevant ones get their own
// typed field, the full set is preserved in Params.
type Bind struct {
	Raw            string
	Address        string
	Port           int64
	PortRangeStart int64
	PortRangeEnd   int64
	SSL            bool
	ALPN           string
	Ciphers        string
	Ciphersuites   string
	Curves         string
	Crt            string
	CrtList        string
	CAFile         string
	Verify         string // none|optional|required
	SSLMinVer      string
	SSLMaxVer      string
	NoSSLv3        bool
	NoTLSv10       bool
	NoTLSv11       bool
	NoTLSv12       bool
	NoTLSv13       bool
	AcceptProxy    bool
	Transparent    bool
	V4V6           bool
	V6Only         bool
	Params         map[string]string
}

// ParseBindLines turns every `bind` directive in dirs into a list of Bind
// structs — one Bind per address form, so a `bind *:80,*:443 ssl crt ...`
// produces two entries sharing the same parameter set.
func ParseBindLines(dirs []Directive) []Bind {
	var out []Bind
	for _, d := range dirs {
		if d.Name != "bind" || len(d.Args) == 0 {
			continue
		}
		// First arg may be a comma-separated list of addresses.
		addrList := strings.Split(d.Args[0], ",")
		base := parseBindParams(d.Args[1:])
		base.Raw = strings.Join(d.Args, " ")
		for _, addr := range addrList {
			b := base
			fillBindAddress(&b, strings.TrimSpace(addr))
			// Copy Params so downstream mutations don't bleed across forms.
			if base.Params != nil {
				b.Params = make(map[string]string, len(base.Params))
				for k, v := range base.Params {
					b.Params[k] = v
				}
			}
			out = append(out, b)
		}
	}
	return out
}

func fillBindAddress(b *Bind, addr string) {
	if addr == "" {
		return
	}
	if strings.HasPrefix(addr, "unix@") || strings.HasPrefix(addr, "unix:") || strings.HasPrefix(addr, "abns@") || strings.HasPrefix(addr, "fd@") || strings.HasPrefix(addr, "sockpair@") {
		b.Address = addr
		return
	}
	// IPv6 form: [::]:port
	if strings.HasPrefix(addr, "[") {
		end := strings.LastIndex(addr, "]")
		if end > 0 {
			b.Address = addr[:end+1]
			if end+2 <= len(addr) && addr[end+1] == ':' {
				fillPortOrRange(b, addr[end+2:])
			}
			return
		}
	}
	// Try splitting at the LAST colon for IPv4 / hostname forms.
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		b.Address = addr[:i]
		fillPortOrRange(b, addr[i+1:])
		return
	}
	// Bare port or bare address.
	if p, ok := parsePort(addr); ok {
		b.Port = p
		return
	}
	b.Address = addr
}

func fillPortOrRange(b *Bind, s string) {
	if i := strings.Index(s, "-"); i > 0 {
		if start, ok := parsePort(s[:i]); ok {
			if end, ok := parsePort(s[i+1:]); ok {
				b.PortRangeStart = start
				b.PortRangeEnd = end
				return
			}
		}
	}
	if p, ok := parsePort(s); ok {
		b.Port = p
	}
}

func parseBindParams(args []string) Bind {
	b := Bind{Params: map[string]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		// `<name> <value>` two-token params.
		switch a {
		case "ssl":
			b.SSL = true
			b.Params[a] = ""
		case "alpn":
			if i+1 < len(args) {
				b.ALPN = args[i+1]
				b.Params[a] = args[i+1]
				i++
			}
		case "ciphers":
			if i+1 < len(args) {
				b.Ciphers = args[i+1]
				b.Params[a] = args[i+1]
				i++
			}
		case "ciphersuites":
			if i+1 < len(args) {
				b.Ciphersuites = args[i+1]
				b.Params[a] = args[i+1]
				i++
			}
		case "curves":
			if i+1 < len(args) {
				b.Curves = args[i+1]
				b.Params[a] = args[i+1]
				i++
			}
		case "crt":
			if i+1 < len(args) {
				b.Crt = args[i+1]
				b.Params[a] = args[i+1]
				i++
			}
		case "crt-list":
			if i+1 < len(args) {
				b.CrtList = args[i+1]
				b.Params[a] = args[i+1]
				i++
			}
		case "ca-file":
			if i+1 < len(args) {
				b.CAFile = args[i+1]
				b.Params[a] = args[i+1]
				i++
			}
		case "verify":
			if i+1 < len(args) {
				b.Verify = args[i+1]
				b.Params[a] = args[i+1]
				i++
			}
		case "ssl-min-ver":
			if i+1 < len(args) {
				b.SSLMinVer = args[i+1]
				b.Params[a] = args[i+1]
				i++
			}
		case "ssl-max-ver":
			if i+1 < len(args) {
				b.SSLMaxVer = args[i+1]
				b.Params[a] = args[i+1]
				i++
			}
		case "no-sslv3":
			b.NoSSLv3 = true
			b.Params[a] = ""
		case "no-tlsv10":
			b.NoTLSv10 = true
			b.Params[a] = ""
		case "no-tlsv11":
			b.NoTLSv11 = true
			b.Params[a] = ""
		case "no-tlsv12":
			b.NoTLSv12 = true
			b.Params[a] = ""
		case "no-tlsv13":
			b.NoTLSv13 = true
			b.Params[a] = ""
		case "accept-proxy":
			b.AcceptProxy = true
			b.Params[a] = ""
		case "transparent":
			b.Transparent = true
			b.Params[a] = ""
		case "v4v6":
			b.V4V6 = true
			b.Params[a] = ""
		case "v6only":
			b.V6Only = true
			b.Params[a] = ""
		default:
			// Generic `name value` collection: if the next token doesn't
			// look like a known param keyword, treat it as the value.
			if i+1 < len(args) && !isBindFlag(args[i+1]) {
				b.Params[a] = args[i+1]
				i++
			} else {
				b.Params[a] = ""
			}
		}
	}
	return b
}

func isBindFlag(a string) bool {
	switch a {
	case "ssl", "no-sslv3", "no-tlsv10", "no-tlsv11", "no-tlsv12", "no-tlsv13",
		"accept-proxy", "transparent", "v4v6", "v6only":
		return true
	}
	return false
}

// Server is a parsed `server <name> <addr>[:<port>] [...flags]` line.
type Server struct {
	Raw         string
	Name        string
	Address     string
	Port        int64
	Check       bool
	SSL         bool
	Verify      string
	CAFile      string
	Crt         string
	SNI         string
	ALPN        string
	Weight      int64
	WeightSet   bool
	Backup      bool
	Disabled    bool
	Maxconn     int64
	Maxqueue    int64
	Inter       string
	FastInter   string
	DownInter   string
	Rise        int64
	Fall        int64
	SlowStart   string
	Observe     string
	OnError     string
	OnMarkedUp  string
	OnMarkedDwn string
	Cookie      string
	Resolvers   string
	InitAddr    string
	SendProxy   bool
	SendProxyV2 bool
	AgentCheck  bool
	AgentPort   int64
	AgentAddr   string
	AgentInter  string
	Params      map[string]string
}

// ParseServerLines extracts every `server` and `default-server` directive
// in dirs into a list of Server structs. `default-server` lines have an
// empty Name and Address so callers can recognize them.
func ParseServerLines(dirs []Directive) []Server {
	var out []Server
	for _, d := range dirs {
		if d.Name != "server" {
			continue
		}
		out = append(out, parseServerArgs(d.Args, d.Raw))
	}
	return out
}

// ParsePeerLines extracts the peers of a `peers` section: both the
// classic `peer <name> <addr>:<port>` lines and the `server <name>
// [<addr>:<port>]` lines HAProxy 2.0+ also accepts, in source order.
func ParsePeerLines(dirs []Directive) []Server {
	var out []Server
	for _, d := range dirs {
		if d.Name != "peer" && d.Name != "server" {
			continue
		}
		out = append(out, parseServerArgs(d.Args, d.Raw))
	}
	return out
}

// ParseDefaultServer returns the parsed `default-server` directive (the
// last one wins, matching HAProxy semantics), or nil when absent.
func ParseDefaultServer(dirs []Directive) *Server {
	var out *Server
	for _, d := range dirs {
		if d.Name != "default-server" {
			continue
		}
		// default-server doesn't carry name/address — feed parseServerArgs a
		// synthetic head so the same code handles flags.
		s := parseServerArgs(append([]string{"", ""}, d.Args...), d.Raw)
		s.Name = ""
		s.Address = ""
		s.Port = 0
		out = &s
	}
	return out
}

func parseServerArgs(args []string, raw string) Server {
	s := Server{Raw: raw, Params: map[string]string{}}
	if len(args) >= 1 {
		s.Name = args[0]
	}
	if len(args) >= 2 {
		addr := args[1]
		if strings.HasPrefix(addr, "unix@") || strings.HasPrefix(addr, "unix:") || strings.HasPrefix(addr, "abns@") {
			s.Address = addr
		} else if strings.HasPrefix(addr, "[") {
			if end := strings.LastIndex(addr, "]"); end > 0 {
				s.Address = addr[:end+1]
				if end+2 < len(addr) && addr[end+1] == ':' {
					s.Port, _ = parsePort(addr[end+2:])
				}
			} else {
				s.Address = addr
			}
		} else if i := strings.LastIndex(addr, ":"); i >= 0 {
			s.Address = addr[:i]
			s.Port, _ = parsePort(addr[i+1:])
		} else {
			s.Address = addr
		}
	}
	for i := 2; i < len(args); i++ {
		a := args[i]
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		switch a {
		case "check":
			s.Check = true
			s.Params[a] = ""
		case "no-check":
			s.Check = false
			s.Params[a] = ""
		case "ssl":
			s.SSL = true
			s.Params[a] = ""
		case "no-ssl":
			s.SSL = false
			s.Params[a] = ""
		case "verify":
			s.Verify = next
			s.Params[a] = next
			i++
		case "ca-file":
			s.CAFile = next
			s.Params[a] = next
			i++
		case "crt":
			s.Crt = next
			s.Params[a] = next
			i++
		case "sni":
			s.SNI = next
			s.Params[a] = next
			i++
		case "alpn":
			s.ALPN = next
			s.Params[a] = next
			i++
		case "weight":
			if n, ok := parseInt(next); ok {
				s.Weight = n
				s.WeightSet = true
			}
			s.Params[a] = next
			i++
		case "backup":
			s.Backup = true
			s.Params[a] = ""
		case "disabled":
			s.Disabled = true
			s.Params[a] = ""
		case "enabled":
			s.Disabled = false
			s.Params[a] = ""
		case "maxconn":
			s.Maxconn, _ = parseInt(next)
			s.Params[a] = next
			i++
		case "maxqueue":
			s.Maxqueue, _ = parseInt(next)
			s.Params[a] = next
			i++
		case "inter":
			s.Inter = next
			s.Params[a] = next
			i++
		case "fastinter":
			s.FastInter = next
			s.Params[a] = next
			i++
		case "downinter":
			s.DownInter = next
			s.Params[a] = next
			i++
		case "rise":
			s.Rise, _ = parseInt(next)
			s.Params[a] = next
			i++
		case "fall":
			s.Fall, _ = parseInt(next)
			s.Params[a] = next
			i++
		case "slowstart":
			s.SlowStart = next
			s.Params[a] = next
			i++
		case "observe":
			s.Observe = next
			s.Params[a] = next
			i++
		case "on-error":
			s.OnError = next
			s.Params[a] = next
			i++
		case "on-marked-up":
			s.OnMarkedUp = next
			s.Params[a] = next
			i++
		case "on-marked-down":
			s.OnMarkedDwn = next
			s.Params[a] = next
			i++
		case "cookie":
			s.Cookie = next
			s.Params[a] = next
			i++
		case "resolvers":
			s.Resolvers = next
			s.Params[a] = next
			i++
		case "init-addr":
			s.InitAddr = next
			s.Params[a] = next
			i++
		case "send-proxy":
			s.SendProxy = true
			s.Params[a] = ""
		case "send-proxy-v2":
			s.SendProxyV2 = true
			s.Params[a] = ""
		case "agent-check":
			s.AgentCheck = true
			s.Params[a] = ""
		case "agent-port":
			s.AgentPort, _ = parseInt(next)
			s.Params[a] = next
			i++
		case "agent-addr":
			s.AgentAddr = next
			s.Params[a] = next
			i++
		case "agent-inter":
			s.AgentInter = next
			s.Params[a] = next
			i++
		default:
			// Generic `key value` capture for anything we don't model.
			// Server flags that take no value are unusual outside the list
			// above, so treat the next token as a value unless it itself
			// looks like a known flag (heuristic: hyphen-prefixed or in the
			// no-value set above).
			if next != "" && !isStandaloneServerFlag(next) {
				s.Params[a] = next
				i++
			} else {
				s.Params[a] = ""
			}
		}
	}
	return s
}

func isStandaloneServerFlag(a string) bool {
	switch a {
	case "check", "no-check", "ssl", "no-ssl", "backup", "disabled", "enabled",
		"send-proxy", "send-proxy-v2", "agent-check":
		return true
	}
	return false
}

// ACL is a parsed `acl <name> <criterion> [args ...]` line.
type ACL struct {
	Name      string
	Criterion string
	Args      []string
	Line      int
	Raw       string
}

func ParseACLs(dirs []Directive) []ACL {
	var out []ACL
	for _, d := range dirs {
		if d.Name != "acl" || len(d.Args) < 2 {
			continue
		}
		out = append(out, ACL{
			Name:      d.Args[0],
			Criterion: d.Args[1],
			Args:      append([]string{}, d.Args[2:]...),
			Line:      d.Line,
			Raw:       d.Raw,
		})
	}
	return out
}

// UseBackend is a parsed `use_backend <name> [if|unless <cond>]` line.
type UseBackend struct {
	Backend   string
	Condition string // "if foo bar" / "unless baz" or empty
	Line      int
	Raw       string
}

func ParseUseBackends(dirs []Directive) []UseBackend {
	var out []UseBackend
	for _, d := range dirs {
		if d.Name != "use_backend" || len(d.Args) == 0 {
			continue
		}
		ub := UseBackend{Backend: d.Args[0], Line: d.Line, Raw: d.Raw}
		if len(d.Args) > 1 {
			ub.Condition = strings.Join(d.Args[1:], " ")
		}
		out = append(out, ub)
	}
	return out
}

// HTTPCheck represents the consolidated `option httpchk` + `http-check`
// directives for a backend or listen.
type HTTPCheck struct {
	Method  string // GET, POST, OPTIONS, ...
	URI     string // /healthz
	Version string // HTTP/1.1 + Host header tail
	Send    []string
	Expect  []string
	Disable bool
}

// ParseHTTPCheck folds `option httpchk` and `http-check ...` directives
// into a single structured view. `option httpchk [[<method>] <uri>
// [<version>]]` defaults to OPTIONS / HTTP/1.0, and the meth, uri (or
// uri-lf) and ver of `http-check send` (haproxy 2.2+) override it.
func ParseHTTPCheck(dirs []Directive) HTTPCheck {
	var hc HTTPCheck
	var sendMethod, sendURI, sendVersion string
	for _, d := range dirs {
		switch d.Name {
		case "option":
			if len(d.Args) >= 1 && d.Args[0] == "httpchk" {
				hc.Method, hc.URI, hc.Version = "OPTIONS", "/", "HTTP/1.0"
				switch len(d.Args) {
				case 1:
				case 2:
					hc.URI = d.Args[1]
				case 3:
					hc.Method = d.Args[1]
					hc.URI = d.Args[2]
				default:
					hc.Method = d.Args[1]
					hc.URI = d.Args[2]
					hc.Version = strings.Join(d.Args[3:], " ")
				}
			}
		case "no":
			if len(d.Args) >= 2 && d.Args[0] == "option" && d.Args[1] == "httpchk" {
				hc.Disable = true
			}
		case "http-check":
			if len(d.Args) == 0 {
				continue
			}
			switch d.Args[0] {
			case "send":
				hc.Send = append(hc.Send, strings.Join(d.Args[1:], " "))
				args := d.Args[1:]
				for i := 0; i+1 < len(args); i++ {
					switch args[i] {
					case "meth":
						sendMethod = args[i+1]
					case "uri", "uri-lf":
						sendURI = args[i+1]
					case "ver":
						sendVersion = args[i+1]
					case "hdr":
						// hdr <name> <value>
						i += 2
						continue
					}
					i++
				}
			case "expect":
				hc.Expect = append(hc.Expect, strings.Join(d.Args[1:], " "))
			}
		}
	}
	if sendMethod != "" {
		hc.Method = sendMethod
	}
	if sendURI != "" {
		hc.URI = sendURI
	}
	if sendVersion != "" {
		hc.Version = sendVersion
	}
	return hc
}

// CollectOptions returns the list of enabled `option <name> [args]` directives
// and disabled `no option <name>` directives.
func CollectOptions(dirs []Directive) (enabled []string, disabled []string) {
	for _, d := range dirs {
		switch d.Name {
		case "option":
			enabled = append(enabled, strings.Join(d.Args, " "))
		case "no":
			if len(d.Args) >= 1 && d.Args[0] == "option" {
				disabled = append(disabled, strings.Join(d.Args[1:], " "))
			}
		}
	}
	return enabled, disabled
}

// CollectTimeouts returns a map of `timeout <kind> <value>` entries.
// HAProxy uses `timeout connect`, `timeout client`, `timeout server`,
// `timeout http-request`, `timeout queue`, etc.
func CollectTimeouts(dirs []Directive) map[string]string {
	out := map[string]string{}
	for _, d := range dirs {
		if d.Name != "timeout" || len(d.Args) < 2 {
			continue
		}
		out[d.Args[0]] = strings.Join(d.Args[1:], " ")
	}
	return out
}

// CollectRules returns the raw arg strings for every directive matching
// any of the given names, in source order. Useful for `http-request`,
// `http-response`, `tcp-request`, `tcp-response`, `redirect`, `capture`.
func CollectRules(dirs []Directive, name string) []string {
	var out []string
	for _, d := range dirs {
		if d.Name == name {
			out = append(out, strings.Join(d.Args, " "))
		}
	}
	return out
}

// CollectLog returns every `log <line>` directive verbatim. A bare
// `log global` is included so audits can see whether a section opted in
// to global logging.
func CollectLog(dirs []Directive) []string {
	var out []string
	for _, d := range dirs {
		if d.Name == "log" {
			out = append(out, strings.Join(d.Args, " "))
		}
	}
	return out
}

// FindFirst returns the joined args of the first directive matching name,
// or "" if none. Useful for single-valued directives.
func FindFirst(dirs []Directive, name string) string {
	for _, d := range dirs {
		if d.Name == name {
			return strings.Join(d.Args, " ")
		}
	}
	return ""
}

// FindLast returns the joined args of the last directive matching name —
// HAProxy's "last wins" semantics apply to most scalar directives.
func FindLast(dirs []Directive, name string) string {
	var out string
	for _, d := range dirs {
		if d.Name == name {
			out = strings.Join(d.Args, " ")
		}
	}
	return out
}

// FindStickOn returns the `<expr>` of the last `stick on <expr> ...`
// directive, or "" if no `stick on` line was present. Other `stick`
// variants (`match`, `store-request`, `store-response`) are skipped.
// The trailing tokens after `<expr>` (e.g. `table <t>`, `if <cond>`)
// are preserved so the captured value mirrors what the user wrote.
func FindStickOn(dirs []Directive) string {
	var out string
	for _, d := range dirs {
		if d.Name != "stick" || len(d.Args) < 2 {
			continue
		}
		if d.Args[0] != "on" {
			continue
		}
		out = strings.Join(d.Args[1:], " ")
	}
	return out
}

// FindFirstInt returns the integer value of the first directive matching
// name, or (0, false) if absent or unparseable.
func FindFirstInt(dirs []Directive, name string) (int64, bool) {
	for _, d := range dirs {
		if d.Name == name && len(d.Args) >= 1 {
			return parseInt(d.Args[0])
		}
	}
	return 0, false
}

// ParamsMap returns a flat map of every directive name to its joined
// args. Directives that appear multiple times are comma-concatenated so
// callers can still see all values without losing information.
func ParamsMap(dirs []Directive) map[string]string {
	out := map[string]string{}
	for _, d := range dirs {
		args := strings.Join(d.Args, " ")
		if v, ok := out[d.Name]; ok {
			out[d.Name] = v + "," + args
		} else {
			out[d.Name] = args
		}
	}
	return out
}

// DirectivesAsDicts converts a directive slice into []map[string]any for
// llx.ArrayData(... types.Dict) consumption.
func DirectivesAsDicts(dirs []Directive) []any {
	out := make([]any, len(dirs))
	for i, d := range dirs {
		argsAny := make([]any, len(d.Args))
		for j, a := range d.Args {
			argsAny[j] = a
		}
		out[i] = map[string]any{
			"name": d.Name,
			"args": argsAny,
			"line": int64(d.Line),
			"file": d.File,
			"raw":  d.Raw,
		}
	}
	return out
}

func parsePort(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
		if n > 65535 {
			return 0, false
		}
	}
	return n, true
}

func parseInt(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ParseAddrPort splits an `address[:port]` token into its parts. It handles
// IPv6 bracketed forms (`[2001:db8::1]:443`), IPv4/hostname forms split at
// the last colon, and bare addresses (no port → 0). Used by both bind-line
// parsing and section-level directives that carry an `addr:port` argument.
func ParseAddrPort(s string) (addr string, port int64) {
	if s == "" {
		return "", 0
	}
	if strings.HasPrefix(s, "[") {
		if end := strings.LastIndex(s, "]"); end > 0 {
			addr = s[:end+1]
			if end+2 <= len(s) && s[end+1] == ':' {
				if p, ok := parseInt(s[end+2:]); ok {
					return addr, p
				}
			}
			return addr, 0
		}
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		if p, ok := parseInt(s[i+1:]); ok {
			return s[:i], p
		}
	}
	return s, 0
}

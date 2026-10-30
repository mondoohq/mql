// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package squid parses Squid proxy configuration files.
//
// Squid's grammar is line-based: each directive starts a new line, with
// a trailing backslash continuing the directive onto the next line.
// Lines starting with '#' are comments and are discarded together with
// blank lines. Directives are space-separated; a quoted argument keeps
// its inner whitespace together.
//
// 'include' directives are expanded in place. Squid accepts both bare
// paths and glob patterns (e.g., `include /etc/squid/conf.d/*.conf`);
// expansion of relative paths is left to the caller via the GlobFunc
// because the connection-backed filesystem (afero) can't be reached
// from a leaf package.
package squid

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Config is the parsed result of one or more squid.conf files.
type Config struct {
	// Params is the flattened directive map. Single-value directives
	// overwrite; directives that can repeat (acl, http_access, ...) are
	// comma-joined in source order.
	Params map[string]string
	// HTTPPorts collects every `http_port` line.
	HTTPPorts []Listen
	// HTTPSPorts collects every `https_port` line.
	HTTPSPorts []Listen
	// ACLs is one entry per unique acl name with values merged across
	// repeated `acl NAME ...` lines.
	ACLs []ACL
	// AccessRules collects every *_access rule (and cache/always_direct/
	// never_direct) in source order across the merged configuration.
	AccessRules []AccessRule
	// CachePeers collects every `cache_peer` entry.
	CachePeers []CachePeer
	// CacheDirs collects every `cache_dir` entry.
	CacheDirs []CacheDir
	// RefreshPatterns collects every `refresh_pattern` entry in source order.
	RefreshPatterns []RefreshPattern
	// AuthParams groups `auth_param SCHEME PARAM VALUE...` by scheme.
	AuthParams map[string]map[string]string
	// AccessLogs collects every `access_log` entry.
	AccessLogs []AccessLog
	// Files lists every file actually read (root first, then includes in
	// the order they were expanded).
	Files []string
	// Errors collects non-fatal lookup / glob errors.
	Errors []string
}

// Listen is a parsed http_port / https_port directive.
type Listen struct {
	Directive string            // "http_port" or "https_port"
	Address   string            // "" / IPv4 / IPv6 literal / "unix:/path"
	Port      int64             // 0 when target is a unix socket
	TLS       bool              // https_port, or http_port with ssl-bump / tls-cert= / cert=
	Flags     []string          // bare-flag tokens (transparent, intercept, accel, ssl-bump, tproxy, ssl, ...)
	Cert      string            // value of `cert=` or `tls-cert=`
	Key       string            // value of `key=` or `tls-key=`
	Options   map[string]string // all `key=value` tokens
	Raw       string            // original args joined by space
}

// ACL is one logical Squid Access Control List (all `acl NAME ...`
// lines with the same name fold into a single entry).
type ACL struct {
	Name   string
	Type   string
	Flags  []string
	Values []string
}

// AccessRule is one *_access (or cache/always_direct/never_direct) rule.
type AccessRule struct {
	Kind   string   // directive name
	Index  int      // 0-based position within Kind, in source order
	Action string   // "allow" / "deny"
	ACLs   []string // ACL names (a leading "!" denotes negation)
	Raw    string
}

// CachePeer is a parsed cache_peer entry.
type CachePeer struct {
	Host     string
	Type     string
	HTTPPort int64
	ICPPort  int64
	Options  []string
	Raw      string
}

// CacheDir is a parsed cache_dir entry.
type CacheDir struct {
	Type    string
	Path    string
	SizeMB  int64
	L1      int64
	L2      int64
	Options []string
	Raw     string
}

// RefreshPattern is a parsed refresh_pattern entry.
type RefreshPattern struct {
	Pattern         string
	CaseInsensitive bool
	Min             int64
	Percent         int64
	Max             int64
	Options         []string
	Raw             string
}

// AccessLog is a parsed access_log entry.
type AccessLog struct {
	Target string
	Format string
	ACLs   []string
	Raw    string
}

type (
	fileContentFunc func(string) (string, error)
	globExpandFunc  func(string) ([]string, error)
)

// Parse parses a single squid.conf content string with no include
// expansion. Useful for tests.
func Parse(content string) *Config {
	cfg := newConfig()
	parseContent(cfg, "", content, nil, nil, map[string]bool{})
	return cfg
}

// ParseWithGlob reads `rootPath`, parses it, and recursively expands
// every `include` directive (with glob support via the caller-supplied
// `globExpand`). Errors reading or globbing included files are recorded
// in Config.Errors but do not abort parsing — Squid itself logs and
// continues in this situation.
func ParseWithGlob(rootPath string, fileContent fileContentFunc, globExpand globExpandFunc) (*Config, error) {
	if fileContent == nil {
		return nil, fmt.Errorf("squid.ParseWithGlob: fileContent is required")
	}
	cfg := newConfig()
	visited := map[string]bool{}
	if err := parseFile(cfg, rootPath, fileContent, globExpand, visited); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func newConfig() *Config {
	return &Config{
		Params:     map[string]string{},
		AuthParams: map[string]map[string]string{},
	}
}

func parseFile(cfg *Config, path string, fileContent fileContentFunc, globExpand globExpandFunc, visited map[string]bool) error {
	if visited[path] {
		return nil
	}
	visited[path] = true
	cfg.Files = append(cfg.Files, path)

	content, err := fileContent(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	parseContent(cfg, path, content, fileContent, globExpand, visited)
	return nil
}

func parseContent(cfg *Config, sourcePath, content string, fileContent fileContentFunc, globExpand globExpandFunc, visited map[string]bool) {
	for _, line := range splitAndClean(content) {
		name, args := splitDirective(line)
		if name == "" {
			continue
		}

		switch strings.ToLower(name) {
		case "include":
			if len(args) != 1 {
				cfg.Errors = append(cfg.Errors, fmt.Sprintf("%s: 'include' expects exactly one argument, got %d", sourcePath, len(args)))
				continue
			}
			if fileContent == nil {
				continue
			}
			expandInclude(cfg, args[0], fileContent, globExpand, visited)

		case "http_port":
			cfg.HTTPPorts = append(cfg.HTTPPorts, parseListen(name, args))
			setMultiParam(cfg.Params, name, strings.Join(args, " "))

		case "https_port":
			l := parseListen(name, args)
			l.TLS = true
			cfg.HTTPSPorts = append(cfg.HTTPSPorts, l)
			setMultiParam(cfg.Params, name, strings.Join(args, " "))

		case "acl":
			mergeACL(cfg, args)
			setMultiParam(cfg.Params, name, strings.Join(args, " "))

		case "http_access", "adapted_http_access", "http_reply_access",
			"icp_access", "htcp_access", "htcp_clr_access",
			"miss_access", "ident_access", "snmp_access",
			"url_rewrite_access", "store_id_access",
			"log_access", "cache", "always_direct", "never_direct":
			lower := strings.ToLower(name)
			rule := parseAccessRule(lower, args, accessRuleCount(cfg, lower))
			cfg.AccessRules = append(cfg.AccessRules, rule)
			setMultiParam(cfg.Params, name, strings.Join(args, " "))

		case "cache_peer":
			cfg.CachePeers = append(cfg.CachePeers, parseCachePeer(args))
			setMultiParam(cfg.Params, name, strings.Join(args, " "))

		case "cache_dir":
			cfg.CacheDirs = append(cfg.CacheDirs, parseCacheDir(args))
			setMultiParam(cfg.Params, name, strings.Join(args, " "))

		case "refresh_pattern":
			cfg.RefreshPatterns = append(cfg.RefreshPatterns, parseRefreshPattern(args))
			setMultiParam(cfg.Params, name, strings.Join(args, " "))

		case "auth_param":
			parseAuthParam(cfg, args)
			setMultiParam(cfg.Params, name, strings.Join(args, " "))

		case "access_log":
			cfg.AccessLogs = append(cfg.AccessLogs, parseAccessLog(args))
			setMultiParam(cfg.Params, name, strings.Join(args, " "))

		default:
			setMultiParam(cfg.Params, name, strings.Join(args, " "))
		}
	}
}

func expandInclude(cfg *Config, pattern string, fileContent fileContentFunc, globExpand globExpandFunc, visited map[string]bool) {
	paths, err := expandGlob(pattern, globExpand)
	if err != nil {
		cfg.Errors = append(cfg.Errors, fmt.Sprintf("glob %q: %v", pattern, err))
		return
	}
	for _, p := range paths {
		if err := parseFile(cfg, p, fileContent, globExpand, visited); err != nil {
			cfg.Errors = append(cfg.Errors, err.Error())
		}
	}
}

func expandGlob(pattern string, glob globExpandFunc) ([]string, error) {
	if glob != nil {
		return glob(pattern)
	}
	// A literal path with no glob meta-characters is returned verbatim
	// so the caller sees a missing-file error at the open step rather
	// than a silent skip.
	if !strings.ContainsAny(pattern, "*?[") {
		return []string{pattern}, nil
	}
	return nil, nil
}

func accessRuleCount(cfg *Config, kind string) int {
	n := 0
	for i := range cfg.AccessRules {
		if cfg.AccessRules[i].Kind == kind {
			n++
		}
	}
	return n
}

// ----------------------------------------------------------------------
// Per-directive parsers
// ----------------------------------------------------------------------

func parseListen(directive string, args []string) Listen {
	l := Listen{
		Directive: directive,
		Options:   map[string]string{},
		Raw:       strings.Join(args, " "),
	}
	if len(args) == 0 {
		return l
	}

	// First positional arg is the listen target.
	target := args[0]
	rest := args[1:]

	switch {
	case strings.HasPrefix(target, "unix:"):
		l.Address = target
	case strings.HasPrefix(target, "[") && strings.Contains(target, "]"):
		// IPv6 form: [::]:3128
		idx := strings.LastIndex(target, "]")
		l.Address = target[:idx+1]
		if idx+2 < len(target) && target[idx+1] == ':' {
			if p, ok := parsePort(target[idx+2:]); ok {
				l.Port = p
			}
		}
	default:
		if before, after, found := strings.CutLast(target, ":"); found {
			l.Address = before
			if p, ok := parsePort(after); ok {
				l.Port = p
			}
		} else if p, ok := parsePort(target); ok {
			l.Port = p
		} else {
			l.Address = target
		}
	}

	for _, tok := range rest {
		if eq := strings.IndexByte(tok, '='); eq > 0 {
			k := tok[:eq]
			v := tok[eq+1:]
			l.Options[k] = v
			switch strings.ToLower(k) {
			case "cert", "tls-cert":
				l.Cert = v
				l.TLS = true
			case "key", "tls-key":
				l.Key = v
			}
			continue
		}
		l.Flags = append(l.Flags, tok)
		switch strings.ToLower(tok) {
		case "ssl", "ssl-bump":
			l.TLS = true
		}
	}
	return l
}

// mergeACL folds repeated `acl NAME ...` lines that share a name into a
// single ACL entry, accumulating values. Per Squid's rules, all lines
// with a given name must agree on type; we keep the first type we saw
// and append any new values.
func mergeACL(cfg *Config, args []string) {
	if len(args) < 2 {
		return
	}
	name := args[0]
	typ := args[1]
	rest := args[2:]

	var flags []string
	values := rest
	if len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
		flags = []string{rest[0]}
		values = rest[1:]
	}

	for i := range cfg.ACLs {
		if cfg.ACLs[i].Name == name {
			// Merge flags (preserve order, drop dupes) and append values.
			for _, f := range flags {
				if !containsString(cfg.ACLs[i].Flags, f) {
					cfg.ACLs[i].Flags = append(cfg.ACLs[i].Flags, f)
				}
			}
			cfg.ACLs[i].Values = append(cfg.ACLs[i].Values, values...)
			return
		}
	}
	cfg.ACLs = append(cfg.ACLs, ACL{
		Name:   name,
		Type:   typ,
		Flags:  flags,
		Values: values,
	})
}

func parseAccessRule(kind string, args []string, index int) AccessRule {
	r := AccessRule{
		Kind:  kind,
		Index: index,
		Raw:   strings.Join(args, " "),
	}
	if len(args) == 0 {
		return r
	}
	r.Action = strings.ToLower(args[0])
	if len(args) > 1 {
		r.ACLs = append(r.ACLs, args[1:]...)
	}
	return r
}

func parseCachePeer(args []string) CachePeer {
	p := CachePeer{Raw: strings.Join(args, " ")}
	if len(args) >= 1 {
		p.Host = args[0]
	}
	if len(args) >= 2 {
		p.Type = args[1]
	}
	if len(args) >= 3 {
		if n, ok := parsePort(args[2]); ok {
			p.HTTPPort = n
		}
	}
	if len(args) >= 4 {
		// ICP port is sometimes "0" meaning "disabled". parsePort returns
		// (0, true) for "0", which is exactly what we want.
		if n, ok := parsePort(args[3]); ok {
			p.ICPPort = n
		}
	}
	if len(args) > 4 {
		p.Options = append(p.Options, args[4:]...)
	}
	return p
}

func parseCacheDir(args []string) CacheDir {
	d := CacheDir{Raw: strings.Join(args, " ")}
	if len(args) >= 1 {
		d.Type = args[0]
	}
	if len(args) >= 2 {
		d.Path = args[1]
	}
	if len(args) >= 3 {
		if n, err := strconv.ParseInt(args[2], 10, 64); err == nil {
			d.SizeMB = n
		}
	}

	// `rock` and a few other schemes have no L1/L2; the next arg is
	// already a key=value option. `ufs` / `aufs` / `diskd` take
	// `<size> <L1> <L2> [options...]`.
	var rest []string
	if len(args) > 3 {
		rest = args[3:]
	}
	if len(rest) >= 2 && isNumeric(rest[0]) && isNumeric(rest[1]) {
		if n, err := strconv.ParseInt(rest[0], 10, 64); err == nil {
			d.L1 = n
		}
		if n, err := strconv.ParseInt(rest[1], 10, 64); err == nil {
			d.L2 = n
		}
		rest = rest[2:]
	}
	d.Options = append(d.Options, rest...)
	return d
}

func parseRefreshPattern(args []string) RefreshPattern {
	r := RefreshPattern{Raw: strings.Join(args, " ")}
	if len(args) == 0 {
		return r
	}
	i := 0
	if args[i] == "-i" {
		r.CaseInsensitive = true
		i++
	}
	if i >= len(args) {
		return r
	}
	r.Pattern = args[i]
	i++

	parseIntAt := func(s string) int64 {
		// Trim a trailing "%" the percent slot sometimes wears literally.
		s = strings.TrimSuffix(s, "%")
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n
		}
		return 0
	}
	if i < len(args) {
		r.Min = parseIntAt(args[i])
		i++
	}
	if i < len(args) {
		r.Percent = parseIntAt(args[i])
		i++
	}
	if i < len(args) {
		r.Max = parseIntAt(args[i])
		i++
	}
	if i < len(args) {
		r.Options = append(r.Options, args[i:]...)
	}
	return r
}

func parseAuthParam(cfg *Config, args []string) {
	if len(args) < 3 {
		return
	}
	scheme := args[0]
	param := args[1]
	value := strings.Join(args[2:], " ")
	bucket, ok := cfg.AuthParams[scheme]
	if !ok {
		bucket = map[string]string{}
		cfg.AuthParams[scheme] = bucket
	}
	// `program` may legitimately appear once; `realm` once; others (like
	// `children`) may be overwritten if repeated. Squid's last-write-wins
	// semantics match this: later values supersede earlier ones.
	bucket[param] = value
}

func parseAccessLog(args []string) AccessLog {
	a := AccessLog{Raw: strings.Join(args, " ")}
	if len(args) == 0 {
		return a
	}
	a.Target = args[0]
	a.Format = "squid"
	if len(args) >= 2 {
		a.Format = args[1]
	}
	if len(args) > 2 {
		a.ACLs = append(a.ACLs, args[2:]...)
	}
	return a
}

// ----------------------------------------------------------------------
// Line / token helpers
// ----------------------------------------------------------------------

// splitAndClean returns the logical directive lines for content: it
// strips full-line comments, joins backslash-continuations, and drops
// blank lines. Trailing comments are handled one layer down, in
// tokenize, because Squid strips them at the token layer — after
// continuations have been joined.
func splitAndClean(content string) []string {
	raw := strings.Split(content, "\n")
	var lines []string
	var continued strings.Builder

	for _, line := range raw {
		line = strings.TrimRight(line, "\r")
		// Comments are determined after leading whitespace is trimmed.
		trim := strings.TrimSpace(line)
		// Always discard full-line comments, even mid-continuation: a `#`
		// line interleaved between a backslash-continued directive and
		// its tail is not part of the directive's tokens.
		if trim != "" && trim[0] == '#' {
			continue
		}
		if continued.Len() == 0 && trim == "" {
			continue
		}

		// Continuation: a single trailing backslash means "join with next".
		if before, ok := strings.CutSuffix(trim, "\\"); ok {
			continued.WriteString(before)
			continued.WriteByte(' ')
			continue
		}
		if continued.Len() > 0 {
			continued.WriteString(trim)
			lines = append(lines, strings.TrimSpace(continued.String()))
			continued.Reset()
			continue
		}
		lines = append(lines, trim)
	}
	if continued.Len() > 0 {
		lines = append(lines, strings.TrimSpace(continued.String()))
	}
	return lines
}

// splitDirective tokenizes one logical line into a directive name plus
// args. Quoted arguments (`"..."` or `'...'`) keep their inner
// whitespace together; the surrounding quotes are stripped.
func splitDirective(line string) (string, []string) {
	tokens := tokenize(line)
	if len(tokens) == 0 {
		return "", nil
	}
	return tokens[0], tokens[1:]
}

func tokenize(line string) []string {
	var tokens []string
	var buf strings.Builder
	inQuote := byte(0)

	flush := func() {
		if buf.Len() > 0 {
			tokens = append(tokens, buf.String())
			buf.Reset()
		}
	}

	for i := 0; i < len(line); i++ {
		c := line[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
				continue
			}
			if c == '\\' && i+1 < len(line) {
				buf.WriteByte(line[i+1])
				i++
				continue
			}
			buf.WriteByte(c)
			continue
		}
		switch c {
		case ' ', '\t':
			flush()
		case '"', '\'':
			inQuote = c
		case '#':
			// An unquoted `#` at a token boundary starts a trailing
			// comment: the rest of the line is discarded. This mirrors
			// ConfigParser::TokenParse in src/ConfigParser.cc, which
			// skips leading whitespace and bails on `#`.
			//
			// A `#` *inside* a token is data, not a comment marker, so
			// values such as a password containing `#` survive intact.
			if buf.Len() == 0 {
				return tokens
			}
			buf.WriteByte(c)
		default:
			buf.WriteByte(c)
		}
	}
	flush()
	return tokens
}

func parsePort(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || n > 65535 {
		return 0, false
	}
	return n, true
}

func isNumeric(s string) bool {
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

func containsString(s []string, v string) bool {
	return slices.Contains(s, v)
}

// setMultiParam stores a directive value in the flat params map.
// Directives that can repeat get their values comma-joined in source
// order; single-value directives overwrite (matching nginx/apache2).
func setMultiParam(m map[string]string, key, value string) {
	if isMultiParam[strings.ToLower(key)] {
		if v, ok := m[key]; ok && v != "" {
			m[key] = v + "," + value
			return
		}
	}
	m[key] = value
}

// isMultiParam lists Squid directives that can appear multiple times.
// Anything not in this list overwrites on repeat (last wins) — which
// matches Squid's own "later value supersedes" semantics for scalars.
var isMultiParam = map[string]bool{
	"http_port":             true,
	"https_port":            true,
	"acl":                   true,
	"http_access":           true,
	"adapted_http_access":   true,
	"http_reply_access":     true,
	"icp_access":            true,
	"htcp_access":           true,
	"htcp_clr_access":       true,
	"miss_access":           true,
	"ident_access":          true,
	"snmp_access":           true,
	"url_rewrite_access":    true,
	"store_id_access":       true,
	"log_access":            true,
	"cache":                 true,
	"always_direct":         true,
	"never_direct":          true,
	"cache_peer":            true,
	"cache_dir":             true,
	"refresh_pattern":       true,
	"auth_param":            true,
	"access_log":            true,
	"logformat":             true,
	"request_header_access": true,
	"reply_header_access":   true,
	"request_header_add":    true,
	"reply_header_add":      true,
	"reply_body_max_size":   true,
	"delay_access":          true,
	"delay_class":           true,
	"delay_parameters":      true,
}

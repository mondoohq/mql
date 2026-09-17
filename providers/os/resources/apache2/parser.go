// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apache2

import (
	"strings"

	"github.com/rs/zerolog/log"
)

// Module represents a LoadModule directive.
type Module struct {
	Name string // e.g., "ssl_module"
	Path string // e.g., "modules/mod_ssl.so"
}

// VirtualHost represents a <VirtualHost> block.
type VirtualHost struct {
	Address                 string         // e.g., "*:443"
	ServerName              string         // ServerName directive
	ServerAliases           []string       // one entry per ServerAlias arg across one or more lines
	DocumentRoot            string         // DocumentRoot directive
	SSL                     bool           // SSLEngine on
	SSLProtocol             string         // SSLProtocol directive
	SSLCipherSuite          string         // SSLCipherSuite directive
	SSLHonorCipherOrder     bool           // SSLHonorCipherOrder on
	SSLCertificateFile      string         // SSLCertificateFile path
	SSLCertificateKeyFile   string         // SSLCertificateKeyFile path
	SSLCertificateChainFile string         // SSLCertificateChainFile path (deprecated)
	Redirects               []Redirect     // Redirect / RedirectMatch directives
	Params                  map[string]any // all directives in this block
}

// Redirect represents a Redirect or RedirectMatch directive inside a VirtualHost.
type Redirect struct {
	Status string // optional status ("permanent", "temp", "303", ...). Empty if unspecified.
	Match  string // URL or regex (depending on Type)
	Target string // target URL
	Type   string // "Redirect" or "RedirectMatch"
}

// Directory represents a <Directory> block.
type Directory struct {
	Path          string         // e.g., "/var/www/html"
	Options       string         // Options directive
	AllowOverride string         // AllowOverride directive
	Require       []string       // each Require directive captured verbatim (e.g., "all granted")
	Params        map[string]any // all directives in this block
}

// Location represents a <Location> or <LocationMatch> block.
type Location struct {
	Path      string         // e.g., "/admin" or a regex
	IsMatch   bool           // true if <LocationMatch>, false if <Location>
	AuthType  string         // AuthType directive value
	AuthName  string         // AuthName directive value
	Require   []string       // each Require directive captured verbatim
	ProxyPass string         // ProxyPass target
	Params    map[string]any // all directives in this block
}

// Config is the parsed result of Apache configuration files.
type Config struct {
	Params    map[string]any      // top-level directives (key → value)
	Modules   []Module            // LoadModule directives
	VHosts    []VirtualHost       // <VirtualHost> blocks
	Dirs      []Directory         // <Directory> blocks
	Locations []Location          // <Location> / <LocationMatch> blocks at top-level scope
	Headers   map[string][]string // headers added via `Header always set` at any scope
	Includes  []string            // Include/IncludeOptional paths (unexpanded)
}

type (
	fileContentFunc func(string) (string, error)
	globExpandFunc  func(string) ([]string, error)
)

// Parse parses a single Apache config file content.
func Parse(content string) *Config {
	cfg := &Config{
		Params: map[string]any{},
	}

	lines := splitAndClean(content)
	parseLines(cfg, lines, 0)
	return cfg
}

// ParseWithGlob parses Apache config files, recursively expanding Include and
// IncludeOptional directives using the provided glob and file-content functions.
// The optional vars map provides initial variable definitions (e.g. parsed from
// Debian's /etc/apache2/envvars). `Define` directives encountered during
// parsing extend this map, and `${VAR}` references in directive values are
// substituted in-place.
func ParseWithGlob(rootPath string, fileContent fileContentFunc, globExpand globExpandFunc, vars map[string]string) (*Config, error) {
	content, err := fileContent(rootPath)
	if err != nil {
		return nil, err
	}

	// Copy the caller's map so we don't mutate it when handling Define.
	working := make(map[string]string, len(vars))
	for k, v := range vars {
		working[k] = v
	}

	cfg := &Config{
		Params: map[string]any{},
	}

	// visited guards against include cycles (a file that includes itself, or a
	// loop across files), which would otherwise recurse until the stack
	// overflows. The root file is seeded as already-visited.
	visited := map[string]bool{rootPath: true}

	parseWithGlobRecursive(cfg, rootPath, content, fileContent, globExpand, working, visited)
	return cfg, nil
}

func parseWithGlobRecursive(cfg *Config, filePath, content string, fileContent fileContentFunc, globExpand globExpandFunc, vars map[string]string, visited map[string]bool) {
	lines := flattenTransparentBlocks(splitAndClean(content))
	i := 0
	for i < len(lines) {
		line := lines[i]

		// Block directives: <VirtualHost>, <Directory>, etc.
		if strings.HasPrefix(line, "<") {
			blockTag, blockArg := parseBlockOpen(line)
			blockArg = expandApacheVars(blockArg, vars)
			blockLines, end := collectBlock(lines, i+1, blockTag)
			i = end + 1

			switch strings.ToLower(blockTag) {
			case "virtualhost":
				vh := parseVirtualHost(blockArg, blockLines, vars)
				cfg.VHosts = append(cfg.VHosts, vh)
				// VirtualHosts can contain their own <Directory>/<Location>
				// blocks and Header directives.
				collectScopedBlocks(cfg, blockLines, vars)
			case "directory", "directorymatch":
				d := parseDirectory(blockArg, blockLines, vars)
				cfg.Dirs = append(cfg.Dirs, d)
			case "location", "locationmatch":
				loc := parseLocation(blockArg, blockLines, vars, strings.EqualFold(blockTag, "locationmatch"))
				cfg.Locations = append(cfg.Locations, loc)
			}
			// Other block types (Files, etc.) are silently skipped for now
			continue
		}

		key, value := parseDirective(line)
		if key == "" {
			i++
			continue
		}

		value = expandApacheVars(value, vars)
		keyLower := strings.ToLower(key)

		switch keyLower {
		case "include", "includeoptional":
			cfg.Includes = append(cfg.Includes, value)
			if globExpand != nil && fileContent != nil {
				expandInclude(cfg, value, fileContent, globExpand, keyLower == "includeoptional", vars, visited)
			}
		case "loadmodule":
			parts := strings.Fields(value)
			if len(parts) >= 2 {
				cfg.Modules = append(cfg.Modules, Module{Name: parts[0], Path: parts[1]})
			}
		case "header":
			if name, val, ok := parseHeaderAlwaysSet(value); ok {
				if cfg.Headers == nil {
					cfg.Headers = map[string][]string{}
				}
				cfg.Headers[name] = append(cfg.Headers[name], val)
			}
		case "define":
			// `Define VAR value` adds an Apache-level variable usable as ${VAR}.
			if name, val, ok := splitDefine(value); ok {
				vars[name] = val
			}
		default:
			setParam(cfg.Params, key, value)
		}

		i++
	}
}

// collectScopedBlocks walks the lines inside a containing block (typically a
// VirtualHost) and extracts any nested <Directory> and <Location> blocks and
// `Header always set` directives so they're reachable from the top-level
// Config aggregates without forcing the caller to walk the tree again.
func collectScopedBlocks(cfg *Config, lines []string, vars map[string]string) {
	lines = flattenTransparentBlocks(lines)
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(line, "<") {
			blockTag, blockArg := parseBlockOpen(line)
			blockArg = expandApacheVars(blockArg, vars)
			blockLines, end := collectBlock(lines, i+1, blockTag)
			switch strings.ToLower(blockTag) {
			case "location", "locationmatch":
				loc := parseLocation(blockArg, blockLines, vars, strings.EqualFold(blockTag, "locationmatch"))
				cfg.Locations = append(cfg.Locations, loc)
			case "directory", "directorymatch":
				d := parseDirectory(blockArg, blockLines, vars)
				cfg.Dirs = append(cfg.Dirs, d)
			}
			i = end
			continue
		}
		key, value := parseDirective(line)
		if key == "" {
			continue
		}
		if strings.EqualFold(key, "header") {
			if name, val, ok := parseHeaderAlwaysSet(value); ok {
				if cfg.Headers == nil {
					cfg.Headers = map[string][]string{}
				}
				cfg.Headers[name] = append(cfg.Headers[name], val)
			}
		}
	}
}

// parseHeaderAlwaysSet decodes a `Header always set NAME VALUE` directive
// argument, returning the (name, value) pair. Returns ok=false for any other
// shape (e.g. `Header set ...`, `Header unset ...`) which we deliberately
// ignore — security audits care about the "always set" rule that survives
// proxy intermediaries.
func parseHeaderAlwaysSet(arg string) (string, string, bool) {
	parts := strings.Fields(arg)
	if len(parts) < 4 {
		return "", "", false
	}
	if !strings.EqualFold(parts[0], "always") || !strings.EqualFold(parts[1], "set") {
		return "", "", false
	}
	name := parts[2]
	// Reassemble the remaining tokens; strip a surrounding pair of quotes if present.
	rest := strings.TrimSpace(strings.Join(parts[3:], " "))
	if len(rest) >= 2 && rest[0] == '"' && rest[len(rest)-1] == '"' {
		rest = rest[1 : len(rest)-1]
	}
	return name, rest, true
}

// splitDefine splits a Define directive argument into name and value. When
// only a name is given, the value is empty (Apache treats this as "defined").
func splitDefine(s string) (string, string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	idx := strings.IndexAny(s, " \t")
	if idx < 0 {
		return s, "", true
	}
	name := s[:idx]
	val := strings.TrimSpace(s[idx+1:])
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	return name, val, true
}

func expandInclude(cfg *Config, pattern string, fileContent fileContentFunc, globExpand globExpandFunc, optional bool, vars map[string]string, visited map[string]bool) {
	paths, err := globExpand(pattern)
	if err != nil {
		if !optional {
			log.Warn().Err(err).Str("pattern", pattern).Msg("unable to expand Include directive")
		}
		return
	}

	for _, p := range paths {
		// Skip files already parsed to avoid infinite recursion on include cycles.
		if visited[p] {
			continue
		}
		visited[p] = true

		content, err := fileContent(p)
		if err != nil {
			if !optional {
				log.Warn().Err(err).Str("path", p).Msg("unable to read included file")
			}
			continue
		}
		parseWithGlobRecursive(cfg, p, content, fileContent, globExpand, vars, visited)
	}
}

// parseLines parses lines at the top level (no glob expansion).
func parseLines(cfg *Config, lines []string, start int) {
	lines = flattenTransparentBlocks(lines[start:])
	i := 0
	for i < len(lines) {
		line := lines[i]

		if strings.HasPrefix(line, "<") {
			blockTag, blockArg := parseBlockOpen(line)
			blockLines, end := collectBlock(lines, i+1, blockTag)
			i = end + 1

			switch strings.ToLower(blockTag) {
			case "virtualhost":
				vh := parseVirtualHost(blockArg, blockLines, nil)
				cfg.VHosts = append(cfg.VHosts, vh)
				collectScopedBlocks(cfg, blockLines, nil)
			case "directory", "directorymatch":
				d := parseDirectory(blockArg, blockLines, nil)
				cfg.Dirs = append(cfg.Dirs, d)
			case "location", "locationmatch":
				loc := parseLocation(blockArg, blockLines, nil, strings.EqualFold(blockTag, "locationmatch"))
				cfg.Locations = append(cfg.Locations, loc)
			}
			continue
		}

		key, value := parseDirective(line)
		if key == "" {
			i++
			continue
		}

		keyLower := strings.ToLower(key)
		switch keyLower {
		case "include", "includeoptional":
			cfg.Includes = append(cfg.Includes, value)
		case "loadmodule":
			parts := strings.Fields(value)
			if len(parts) >= 2 {
				cfg.Modules = append(cfg.Modules, Module{Name: parts[0], Path: parts[1]})
			}
		case "header":
			if name, val, ok := parseHeaderAlwaysSet(value); ok {
				if cfg.Headers == nil {
					cfg.Headers = map[string][]string{}
				}
				cfg.Headers[name] = append(cfg.Headers[name], val)
			}
		default:
			setParam(cfg.Params, key, value)
		}

		i++
	}
}

// parseVirtualHost parses the lines inside a <VirtualHost> block.
func parseVirtualHost(address string, lines []string, vars map[string]string) VirtualHost {
	vh := VirtualHost{
		Address: address,
		Params:  map[string]any{},
	}

	lines = flattenTransparentBlocks(lines)
	depth := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "<") {
			if strings.HasPrefix(line, "</") {
				if depth > 0 {
					depth--
				}
			} else {
				depth++
			}
			continue
		}
		if depth > 0 {
			continue // inside a nested block — skip
		}

		key, value := parseDirective(line)
		if key == "" {
			continue
		}

		value = expandApacheVars(value, vars)
		setParam(vh.Params, key, value)

		switch strings.ToLower(key) {
		case "servername":
			vh.ServerName = value
		case "serveralias":
			// Apache allows multiple aliases per line and multiple ServerAlias lines.
			vh.ServerAliases = append(vh.ServerAliases, strings.Fields(value)...)
		case "documentroot":
			vh.DocumentRoot = value
		case "sslengine":
			vh.SSL = strings.EqualFold(value, "on")
		case "sslprotocol":
			vh.SSLProtocol = value
		case "sslciphersuite":
			vh.SSLCipherSuite = value
		case "sslhonorcipherorder":
			vh.SSLHonorCipherOrder = strings.EqualFold(value, "on")
		case "sslcertificatefile":
			vh.SSLCertificateFile = value
			vh.SSL = true
		case "sslcertificatekeyfile":
			vh.SSLCertificateKeyFile = value
		case "sslcertificatechainfile":
			vh.SSLCertificateChainFile = value
		case "redirect", "redirectmatch":
			if r, ok := parseRedirect(key, value); ok {
				vh.Redirects = append(vh.Redirects, r)
			}
		}
	}

	return vh
}

// parseRedirect decodes a `Redirect [status] match target` or
// `RedirectMatch [status] regex target` directive argument. Returns
// ok=false when the directive doesn't have the expected number of args.
func parseRedirect(directive, arg string) (Redirect, bool) {
	parts := strings.Fields(arg)
	if len(parts) < 2 {
		return Redirect{}, false
	}
	r := Redirect{Type: directive}
	// Detect an optional status token: keyword (permanent/temp/seeother/gone) or a 3-digit code.
	first := parts[0]
	isStatus := false
	switch strings.ToLower(first) {
	case "permanent", "temp", "seeother", "gone":
		isStatus = true
	}
	if !isStatus && len(first) == 3 && first[0] >= '1' && first[0] <= '9' {
		// crude 3xx/4xx/etc check; good enough for this surface
		allDigits := true
		for _, c := range first {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		isStatus = allDigits
	}
	if isStatus {
		r.Status = first
		parts = parts[1:]
	}
	if len(parts) == 1 {
		// Redirect target — no match (legacy "Redirect URL" form)
		r.Target = parts[0]
		return r, true
	}
	if len(parts) >= 2 {
		r.Match = parts[0]
		r.Target = parts[1]
		return r, true
	}
	return Redirect{}, false
}

// parseDirectory parses the lines inside a <Directory> block.
func parseDirectory(path string, lines []string, vars map[string]string) Directory {
	d := Directory{
		Path:   path,
		Params: map[string]any{},
	}

	lines = flattenTransparentBlocks(lines)
	depth := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "<") {
			if strings.HasPrefix(line, "</") {
				if depth > 0 {
					depth--
				}
			} else {
				depth++
			}
			continue
		}
		if depth > 0 {
			continue // inside a nested block — skip
		}

		key, value := parseDirective(line)
		if key == "" {
			continue
		}

		value = expandApacheVars(value, vars)
		setParam(d.Params, key, value)

		switch strings.ToLower(key) {
		case "options":
			d.Options = value
		case "allowoverride":
			d.AllowOverride = value
		case "require":
			d.Require = append(d.Require, value)
		}
	}

	return d
}

// parseLocation parses the lines inside a <Location> or <LocationMatch> block.
func parseLocation(path string, lines []string, vars map[string]string, isMatch bool) Location {
	loc := Location{
		Path:    path,
		IsMatch: isMatch,
		Params:  map[string]any{},
	}

	lines = flattenTransparentBlocks(lines)
	depth := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "<") {
			if strings.HasPrefix(line, "</") {
				if depth > 0 {
					depth--
				}
			} else {
				depth++
			}
			continue
		}
		if depth > 0 {
			continue
		}

		key, value := parseDirective(line)
		if key == "" {
			continue
		}

		value = expandApacheVars(value, vars)
		setParam(loc.Params, key, value)

		switch strings.ToLower(key) {
		case "authtype":
			loc.AuthType = value
		case "authname":
			loc.AuthName = strings.Trim(value, `"`)
		case "require":
			loc.Require = append(loc.Require, value)
		case "proxypass":
			loc.ProxyPass = value
		}
	}

	return loc
}

// splitAndClean splits content into lines, strips comments and blank lines,
// and handles continuation lines (trailing backslash).
func splitAndClean(content string) []string {
	raw := strings.Split(content, "\n")
	var lines []string
	var continued string

	for _, line := range raw {
		line = strings.TrimRight(line, "\r")
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || line[0] == '#' {
			continue
		}

		// Strip inline comments (but not inside quotes)
		line = stripInlineComment(line)
		if line == "" {
			continue
		}

		// Handle continuation lines
		if strings.HasSuffix(line, "\\") {
			continued += strings.TrimSuffix(line, "\\") + " "
			continue
		}
		if continued != "" {
			line = continued + line
			continued = ""
		}

		lines = append(lines, line)
	}

	// Flush any trailing continuation
	if continued != "" {
		lines = append(lines, strings.TrimSpace(continued))
	}

	return lines
}

// stripInlineComment removes # comments that aren't inside quotes.
func stripInlineComment(line string) string {
	inQuote := false
	for i, c := range line {
		switch c {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return strings.TrimSpace(line[:i])
			}
		}
	}
	return line
}

// parseDirective splits "Key value" or "Key" into key and value.
func parseDirective(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}

	// Find the key (first whitespace-delimited token)
	idx := strings.IndexAny(line, " \t")
	if idx < 0 {
		return line, ""
	}

	key := line[:idx]
	value := strings.TrimSpace(line[idx+1:])

	// Remove surrounding quotes from value
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}

	return key, value
}

// parseBlockOpen parses "<Tag arg>" returning tag and arg.
func parseBlockOpen(line string) (string, string) {
	line = strings.TrimSpace(line)
	// Remove < and >
	if len(line) < 2 {
		return "", ""
	}
	line = line[1:] // remove <
	if line[len(line)-1] == '>' {
		line = line[:len(line)-1]
	}

	idx := strings.IndexAny(line, " \t")
	if idx < 0 {
		return line, ""
	}

	arg := strings.TrimSpace(line[idx+1:])
	// Remove surrounding quotes from argument
	if len(arg) >= 2 && arg[0] == '"' && arg[len(arg)-1] == '"' {
		arg = arg[1 : len(arg)-1]
	}

	return line[:idx], arg
}

// collectBlock collects lines until the matching </tag> closing tag.
// Returns the inner lines and the index of the closing tag line.
// transparentContainers are block directives whose contents belong to the
// enclosing scope rather than introducing a scope of their own.
//
// The conditional containers cannot be evaluated from the configuration text
// alone — whether a module is loaded or a define is set is runtime state — so
// their contents are always included. That matches the daemon whenever the
// condition holds, which is the case for any config that ships them: Debian's
// default-ssl.conf wraps its entire <VirtualHost> in <IfModule mod_ssl.c>, and
// ports.conf wraps `Listen 443` in <IfModule ssl_module>.
//
// The Require containers group access-control directives; the grants inside
// them are the access-control answer, so they are hoisted into the parent
// <Directory>/<Location> rather than dropped.
var transparentContainers = map[string]bool{
	"ifmodule":    true,
	"ifdefine":    true,
	"ifversion":   true,
	"iffile":      true,
	"ifdirective": true,
	"ifsection":   true,
	"requireall":  true,
	"requireany":  true,
	"requirenone": true,
}

// maxTransparentNesting bounds the recursion in flattenTransparentBlocks so a
// pathologically nested config cannot exhaust the stack.
const maxTransparentNesting = 64

// flattenTransparentBlocks splices the contents of transparent container blocks
// into the enclosing level, dropping the container's own open/close lines. Any
// other block is passed through untouched — open and close lines included — so
// scope-aware callers still see it as a block.
func flattenTransparentBlocks(lines []string) []string {
	return flattenTransparentBlocksDepth(lines, 0)
}

func flattenTransparentBlocksDepth(lines []string, depth int) []string {
	if depth > maxTransparentNesting {
		return lines
	}

	out := make([]string, 0, len(lines))
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if !strings.HasPrefix(line, "<") || strings.HasPrefix(line, "</") {
			out = append(out, line)
			continue
		}

		tag, _ := parseBlockOpen(line)
		if !transparentContainers[strings.ToLower(tag)] {
			out = append(out, line)
			continue
		}

		inner, end := collectBlock(lines, i+1, tag)
		out = append(out, flattenTransparentBlocksDepth(inner, depth+1)...)
		i = end
	}
	return out
}

func collectBlock(lines []string, start int, tag string) ([]string, int) {
	closeTag := "</" + strings.ToLower(tag)
	depth := 1
	var inner []string

	for i := start; i < len(lines); i++ {
		lower := strings.ToLower(strings.TrimSpace(lines[i]))
		if strings.HasPrefix(lower, "<"+strings.ToLower(tag)) {
			depth++
		} else if strings.HasPrefix(lower, closeTag) {
			depth--
			if depth == 0 {
				return inner, i
			}
		}
		inner = append(inner, lines[i])
	}

	// Unclosed block — return what we have
	return inner, len(lines) - 1
}

// setParam sets a directive value. For directives that can appear multiple
// times (Listen, Header, etc.), values are comma-concatenated.
func setParam(m map[string]any, key string, value string) {
	// Apache directive names are case-insensitive, so fold onto whichever
	// spelling was seen first. Without this, `Listen 80` in ports.conf and
	// `listen 443` in a fragment land in two different keys, so neither the
	// multi-value join below nor a lookup by either spelling finds both.
	canonical := key
	for k := range m {
		if strings.EqualFold(k, key) {
			canonical = k
			break
		}
	}

	if isMultiParam[strings.ToLower(key)] {
		if v, ok := m[canonical]; ok {
			if s, ok := v.(string); ok {
				m[canonical] = s + "," + value
				return
			}
		}
	}
	m[canonical] = value
}

// ParamValue looks up a directive value case-insensitively, matching Apache's
// case-insensitive directive names.
func ParamValue(m map[string]any, key string) (string, bool) {
	for k, v := range m {
		if !strings.EqualFold(k, key) {
			continue
		}
		s, ok := v.(string)
		return s, ok
	}
	return "", false
}

// isMultiParam lists directives that can appear multiple times and should
// be concatenated rather than overwritten.
var isMultiParam = map[string]bool{
	"listen":          true,
	"header":          true,
	"loadmodule":      true,
	"alias":           true,
	"redirect":        true,
	"rewriterule":     true,
	"rewritecond":     true,
	"setenvif":        true,
	"customlog":       true,
	"logformat":       true,
	"serveralias":     true,
	"allowmethods":    true,
	"require":         true,
	"addtype":         true,
	"addhandler":      true,
	"addoutputfilter": true,
}

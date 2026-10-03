// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package apache2

import (
	"path"
	"regexp"
	"strconv"
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

// ParseOptions carries the runtime state that conditional containers test
// and that the configuration text alone does not contain.
type ParseOptions struct {
	// StaticModules are the modules compiled into the httpd binary, as
	// `httpd -l` prints them (source file names such as "mod_so.c"). They
	// satisfy <IfModule> without a LoadModule line.
	StaticModules []string
	// Defines are parameters passed on the command line with -D. They
	// satisfy <IfDefine> like a Define directive does.
	Defines []string
	// PreDirectives are directives passed with -C, which httpd processes
	// before the configuration file, and PostDirectives those passed with
	// -c, processed after it. SUSE's start_apache2 loads its modules and
	// sysconfig settings this way.
	PreDirectives  []string
	PostDirectives []string
	// Version is the httpd version ("2.4.62") that <IfVersion> is evaluated
	// against. When empty, <IfVersion> contents always apply.
	Version string
	// FileExists reports whether a path exists, for <IfFile>. A relative path
	// is relative to ServerRoot and left to FileExists to resolve. When nil,
	// <IfFile> contents always apply.
	FileExists func(string) bool
}

// parseState is the evaluation state threaded through a parse: what has been
// loaded and defined so far, in the order Apache reads the configuration.
type parseState struct {
	fileContent fileContentFunc
	globExpand  globExpandFunc
	// vars resolves ${VAR}: Define'd names plus the environment (envvars).
	vars map[string]string
	// defines are the names <IfDefine> tests: -D parameters and Define
	// directives, but not environment variables.
	defines map[string]bool
	// modules holds every name <IfModule> accepts for a loaded module: the
	// module identifier ("ssl_module") and its source file ("mod_ssl.c").
	modules map[string]bool
	// version is ParseOptions.Version, and fileExists ParseOptions.FileExists.
	version    string
	fileExists func(string) bool
	// visited guards against include cycles (a file that includes itself, or
	// a loop across files), which would otherwise recurse until the stack
	// overflows.
	visited map[string]bool
}

func newParseState(fileContent fileContentFunc, globExpand globExpandFunc, vars map[string]string, opts ParseOptions) *parseState {
	// Copy the caller's map so we don't mutate it when handling Define.
	working := make(map[string]string, len(vars))
	for k, v := range vars {
		working[k] = v
	}
	st := &parseState{
		fileContent: fileContent,
		globExpand:  globExpand,
		vars:        working,
		defines:     map[string]bool{},
		modules:     map[string]bool{},
		visited:     map[string]bool{},
		version:     opts.Version,
		fileExists:  opts.FileExists,
	}
	for _, d := range opts.Defines {
		st.defines[d] = true
	}
	for _, m := range opts.StaticModules {
		st.addStaticModule(m)
	}
	return st
}

// addLoadedModule registers a LoadModule directive. <IfModule> accepts the
// identifier or the module's source file name. The source name is not in the
// directive, so it is derived from both the identifier (php_module is built
// from mod_php.c, even though the object is libphp8.3.so) and the object file
// (mod_ssl.so is built from mod_ssl.c).
func (st *parseState) addLoadedModule(m Module) {
	st.modules[m.Name] = true
	if src := moduleSourceFromIdentifier(m.Name); src != "" {
		st.modules[src] = true
	}
	base := path.Base(m.Path)
	if strings.HasPrefix(base, "mod_") && strings.HasSuffix(base, ".so") {
		st.modules[strings.TrimSuffix(base, ".so")+".c"] = true
	}
}

// addStaticModule registers a compiled-in module named by its source file.
func (st *parseState) addStaticModule(src string) {
	st.modules[src] = true
	if id := moduleIdentifierFromSource(src); id != "" {
		st.modules[id] = true
	}
}

// The two core modules do not follow the mod_<name>.c / <name>_module
// convention.
var coreModuleSources = map[string]string{
	"core_module": "core.c",
	"http_module": "http_core.c",
}

func moduleSourceFromIdentifier(id string) string {
	if src, ok := coreModuleSources[id]; ok {
		return src
	}
	base, ok := strings.CutSuffix(id, "_module")
	if !ok || base == "" {
		return ""
	}
	return "mod_" + base + ".c"
}

func moduleIdentifierFromSource(src string) string {
	for id, s := range coreModuleSources {
		if s == src {
			return id
		}
	}
	base, ok := strings.CutSuffix(src, ".c")
	if !ok {
		return ""
	}
	base = strings.TrimPrefix(base, "mod_")
	if base == "" {
		return ""
	}
	return base + "_module"
}

// holds reports whether a conditional container's contents apply. Apache
// decides <IfModule> and <IfDefine> when it reads the container, against what
// has been loaded and defined up to that point; names are case-sensitive and
// a leading "!" negates the test. <IfVersion> is decided against the httpd
// version and <IfFile> against the filesystem, when those are known. The
// other containers are not evaluated and their contents always apply.
func (st *parseState) holds(tag, arg string) bool {
	if st == nil {
		return true
	}
	switch strings.ToLower(tag) {
	case "ifmodule":
		name, negate := conditionArg(arg)
		return st.modules[name] != negate
	case "ifdefine":
		name, negate := conditionArg(arg)
		return st.defines[name] != negate
	case "ifversion":
		return st.versionHolds(arg)
	case "iffile":
		if st.fileExists == nil {
			return true
		}
		name, negate := conditionArg(arg)
		name = strings.Trim(name, `"`)
		return st.fileExists(name) != negate
	}
	return true
}

// versionHolds evaluates <IfVersion [[!]operator] version> the way mod_version
// does: the operator defaults to "=", a version given as major or major.minor
// reads the missing parts as 0, "=" with /regex/ and "~" with regex match the
// version string, and "!" negates. An argument httpd would reject, or an
// unknown httpd version, leaves the contents applying.
func (st *parseState) versionHolds(arg string) bool {
	if st.version == "" {
		return true
	}
	fields := strings.Fields(arg)
	op, want := "=", ""
	switch len(fields) {
	case 1:
		want = fields[0]
	case 2:
		op, want = fields[0], fields[1]
	default:
		return true
	}
	negate := false
	if rest, ok := strings.CutPrefix(op, "!"); ok && rest != "" {
		negate, op = true, rest
	}

	var result bool
	switch op {
	case "=", "==":
		if len(want) >= 2 && want[0] == '/' && want[len(want)-1] == '/' {
			re, err := regexp.Compile(want[1 : len(want)-1])
			if err != nil {
				return true
			}
			result = re.MatchString(st.version)
			break
		}
		cmp, ok := compareVersion(st.version, want)
		if !ok {
			return true
		}
		result = cmp == 0
	case "~":
		re, err := regexp.Compile(want)
		if err != nil {
			return true
		}
		result = re.MatchString(st.version)
	case "<", "<=", ">", ">=":
		cmp, ok := compareVersion(st.version, want)
		if !ok {
			return true
		}
		switch op {
		case "<":
			result = cmp < 0
		case "<=":
			result = cmp <= 0
		case ">":
			result = cmp > 0
		case ">=":
			result = cmp >= 0
		}
	default:
		return true
	}
	return result != negate
}

// compareVersion compares the httpd version have with want, both
// major[.minor[.patch]] with missing parts read as 0. It reports false when
// either is not of that form.
func compareVersion(have, want string) (int, bool) {
	h, ok := versionTriple(have)
	if !ok {
		return 0, false
	}
	w, ok := versionTriple(want)
	if !ok {
		return 0, false
	}
	for i := range h {
		if h[i] != w[i] {
			if h[i] > w[i] {
				return 1, true
			}
			return -1, true
		}
	}
	return 0, true
}

func versionTriple(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p == "" || p[0] == '+' {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func conditionArg(arg string) (string, bool) {
	arg = strings.TrimSpace(arg)
	if rest, ok := strings.CutPrefix(arg, "!"); ok {
		return strings.TrimSpace(rest), true
	}
	return arg, false
}

// ParseStaticModuleList extracts the compiled-in modules from the output of
// `httpd -l` / `apache2 -l` ("Compiled in modules:" followed by one source
// file per line).
func ParseStaticModuleList(out string) []string {
	var mods []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.ContainsAny(line, " \t:") || !strings.HasSuffix(line, ".c") {
			continue
		}
		mods = append(mods, line)
	}
	return mods
}

// DefinesFromArguments returns the -D parameters in an httpd argument string,
// such as Debian's APACHE_ARGUMENTS ("-D NAME" or "-DNAME").
func DefinesFromArguments(args string) []string {
	var defines []string
	fields := strings.Fields(args)
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if f == "-D" {
			if i+1 < len(fields) {
				defines = append(defines, fields[i+1])
				i++
			}
			continue
		}
		if name, ok := strings.CutPrefix(f, "-D"); ok && name != "" {
			defines = append(defines, name)
		}
	}
	return defines
}

// Parse parses a single Apache config file content. Include directives are
// recorded but not followed, and no module is known to be loaded other than
// through LoadModule lines in the content.
func Parse(content string) *Config {
	cfg := &Config{
		Params: map[string]any{},
	}
	st := newParseState(nil, nil, nil, ParseOptions{})
	st.parseLines(cfg, splitAndClean(content), 0)
	return cfg
}

// ParseWithGlob parses Apache config files, recursively expanding Include and
// IncludeOptional directives using the provided glob and file-content functions.
// The optional vars map provides initial variable definitions (e.g. parsed from
// Debian's /etc/apache2/envvars). `Define` directives encountered during
// parsing extend this map, and `${VAR}` references in directive values are
// substituted in-place.
func ParseWithGlob(rootPath string, fileContent fileContentFunc, globExpand globExpandFunc, vars map[string]string) (*Config, error) {
	return ParseWithGlobOptions(rootPath, fileContent, globExpand, vars, ParseOptions{})
}

// ParseWithGlobOptions is ParseWithGlob with the compiled-in modules and
// command-line defines that <IfModule> and <IfDefine> are evaluated against.
func ParseWithGlobOptions(rootPath string, fileContent fileContentFunc, globExpand globExpandFunc, vars map[string]string, opts ParseOptions) (*Config, error) {
	content, err := fileContent(rootPath)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Params: map[string]any{},
	}

	st := newParseState(fileContent, globExpand, vars, opts)
	// The root file is seeded as already-visited.
	st.visited[rootPath] = true
	lines := splitAndClean(strings.Join(opts.PreDirectives, "\n"))
	lines = append(lines, splitAndClean(content)...)
	lines = append(lines, splitAndClean(strings.Join(opts.PostDirectives, "\n"))...)
	st.parseLines(cfg, lines, 0)
	return cfg, nil
}

// parseLines processes server-level configuration lines in order. Conditional
// containers are evaluated where they appear, so a LoadModule or Define read
// earlier (including through an Include) is visible to them.
func (st *parseState) parseLines(cfg *Config, lines []string, depth int) {
	i := 0
	for i < len(lines) {
		line := lines[i]

		// A closing tag with no opener: nothing to collect.
		if strings.HasPrefix(line, "</") {
			i++
			continue
		}

		// Block directives: <VirtualHost>, <Directory>, etc.
		if strings.HasPrefix(line, "<") {
			blockTag, blockArg := parseBlockOpen(line)
			blockArg = expandApacheVars(blockArg, st.vars)
			blockLines, end := collectBlock(lines, i+1, blockTag)
			i = end + 1

			tagLower := strings.ToLower(blockTag)
			if transparentContainers[tagLower] {
				if depth < maxTransparentNesting && st.holds(tagLower, blockArg) {
					st.parseLines(cfg, blockLines, depth+1)
				}
				continue
			}

			switch tagLower {
			case "virtualhost":
				vh := parseVirtualHost(blockArg, blockLines, st.vars, st.holds)
				cfg.VHosts = append(cfg.VHosts, vh)
				// VirtualHosts can contain their own <Directory>/<Location>
				// blocks and Header directives.
				collectScopedBlocks(cfg, blockLines, st.vars, st.holds)
			case "directory", "directorymatch":
				d := parseDirectory(blockArg, blockLines, st.vars, st.holds)
				cfg.Dirs = append(cfg.Dirs, d)
			case "location", "locationmatch":
				loc := parseLocation(blockArg, blockLines, st.vars, strings.EqualFold(blockTag, "locationmatch"), st.holds)
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

		value = expandApacheVars(value, st.vars)
		keyLower := strings.ToLower(key)

		switch keyLower {
		case "include", "includeoptional":
			cfg.Includes = append(cfg.Includes, value)
			if st.globExpand != nil && st.fileContent != nil {
				st.expandInclude(cfg, value, keyLower == "includeoptional")
			}
		case "loadmodule":
			parts := strings.Fields(value)
			if len(parts) >= 2 {
				m := Module{Name: parts[0], Path: parts[1]}
				cfg.Modules = append(cfg.Modules, m)
				st.addLoadedModule(m)
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
				st.vars[name] = val
				st.defines[name] = true
			}
		case "undefine":
			if name, _, ok := splitDefine(value); ok {
				delete(st.vars, name)
				delete(st.defines, name)
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
func collectScopedBlocks(cfg *Config, lines []string, vars map[string]string, cond blockCondition) {
	lines = flattenTransparentBlocks(lines, cond)
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(line, "<") {
			blockTag, blockArg := parseBlockOpen(line)
			blockArg = expandApacheVars(blockArg, vars)
			blockLines, end := collectBlock(lines, i+1, blockTag)
			switch strings.ToLower(blockTag) {
			case "location", "locationmatch":
				loc := parseLocation(blockArg, blockLines, vars, strings.EqualFold(blockTag, "locationmatch"), cond)
				cfg.Locations = append(cfg.Locations, loc)
			case "directory", "directorymatch":
				d := parseDirectory(blockArg, blockLines, vars, cond)
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

func (st *parseState) expandInclude(cfg *Config, pattern string, optional bool) {
	paths, err := st.globExpand(pattern)
	if err != nil {
		if !optional {
			log.Warn().Err(err).Str("pattern", pattern).Msg("unable to expand Include directive")
		}
		return
	}

	for _, p := range paths {
		// Skip files already parsed to avoid infinite recursion on include cycles.
		if st.visited[p] {
			continue
		}
		st.visited[p] = true

		content, err := st.fileContent(p)
		if err != nil {
			if !optional {
				log.Warn().Err(err).Str("path", p).Msg("unable to read included file")
			}
			continue
		}
		st.parseLines(cfg, splitAndClean(content), 0)
	}
}

// parseVirtualHost parses the lines inside a <VirtualHost> block.
func parseVirtualHost(address string, lines []string, vars map[string]string, cond blockCondition) VirtualHost {
	vh := VirtualHost{
		Address: address,
		Params:  map[string]any{},
	}

	lines = flattenTransparentBlocks(lines, cond)
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
func parseDirectory(path string, lines []string, vars map[string]string, cond blockCondition) Directory {
	d := Directory{
		Path:   path,
		Params: map[string]any{},
	}

	lines = flattenTransparentBlocks(lines, cond)
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
func parseLocation(path string, lines []string, vars map[string]string, isMatch bool, cond blockCondition) Location {
	loc := Location{
		Path:    path,
		IsMatch: isMatch,
		Params:  map[string]any{},
	}

	lines = flattenTransparentBlocks(lines, cond)
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
//
// Apache has no inline comments: only a line whose first non-blank character
// is `#` is a comment. A `#` anywhere else is part of an argument (the stock
// autoindex.conf has `IndexIgnore .??* *~ *# RCS CVS *,v *,t`).
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

// transparentContainers are block directives whose contents belong to the
// enclosing scope rather than introducing a scope of their own.
//
// <IfModule>, <IfDefine>, <IfVersion> and <IfFile> are evaluated (see
// parseState.holds); a container whose test fails contributes nothing.
// <IfDirective> and <IfSection> are not evaluated and their contents always
// apply.
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

// blockCondition reports whether a transparent container's contents apply.
// A nil blockCondition treats every container as applying.
type blockCondition func(tag, arg string) bool

// flattenTransparentBlocks splices the contents of transparent container blocks
// into the enclosing level, dropping the container's own open/close lines, and
// drops containers whose condition does not hold. Any other block is passed
// through untouched — open and close lines included — so scope-aware callers
// still see it as a block.
func flattenTransparentBlocks(lines []string, cond blockCondition) []string {
	return flattenTransparentBlocksDepth(lines, cond, 0)
}

func flattenTransparentBlocksDepth(lines []string, cond blockCondition, depth int) []string {
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

		tag, arg := parseBlockOpen(line)
		if !transparentContainers[strings.ToLower(tag)] {
			out = append(out, line)
			continue
		}

		inner, end := collectBlock(lines, i+1, tag)
		i = end
		if cond != nil && !cond(tag, arg) {
			continue
		}
		out = append(out, flattenTransparentBlocksDepth(inner, cond, depth+1)...)
	}
	return out
}

// collectBlock collects lines until the matching </tag> closing tag.
// Returns the inner lines and the index of the closing tag line.
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

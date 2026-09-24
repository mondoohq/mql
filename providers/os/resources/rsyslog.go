// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"go.mondoo.com/mql/checksums"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// rsyslogConfPaths maps platform names to their rsyslog.conf location.
// BSD variants install rsyslog via package managers to non-default prefixes.
var rsyslogConfPaths = map[string]string{
	"freebsd":      "/usr/local/etc/rsyslog.conf",
	"dragonflybsd": "/usr/local/etc/rsyslog.conf",
	"openbsd":      "/usr/local/etc/rsyslog.conf",
	"netbsd":       "/usr/pkg/etc/rsyslog.conf",
}

func rsyslogConfPath(conn shared.Connection) string {
	asset := conn.Asset()
	if asset != nil && asset.Platform != nil {
		if p, ok := rsyslogConfPaths[asset.Platform.Name]; ok {
			return p
		}
	}
	return "/etc/rsyslog.conf"
}

func (s *mqlRsyslogConf) id() (string, error) {
	files := s.GetFiles()
	if files.Error != nil {
		return "", files.Error
	}

	checksum := checksums.New
	for i := range files.Data {
		path := files.Data[i].(*mqlFile).Path.Data
		checksum = checksum.Add(path)
	}

	return checksum.String(), nil
}

func (s *mqlRsyslogConf) path() (string, error) {
	conn := s.MqlRuntime.Connection.(shared.Connection)
	return rsyslogConfPath(conn), nil
}

// rsyslogIncludeDirective matches the legacy `$IncludeConfig path` form,
// case-insensitively. The path captured is everything after the directive
// up to end-of-line.
var rsyslogIncludeDirective = regexp.MustCompile(`(?i)^\s*\$IncludeConfig\s+(\S.*?)\s*$`)

// rsyslogModernInclude matches the modern RainerScript `include(...)` block.
// Inner args are parsed separately to handle key=value pairs in any order.
// Multi-line blocks are pre-coalesced into a single line before matching,
// so this anchored form sees the joined text.
var rsyslogModernInclude = regexp.MustCompile(`^\s*include\s*\((.*)\)\s*$`)

// rsyslogModernIncludeOpen recognizes a line that begins an `include(...)`
// directive, used to detect the start of a possibly multi-line block.
var rsyslogModernIncludeOpen = regexp.MustCompile(`^\s*include\s*\(`)

// rsyslogIncludeFileKV pulls the file="..." (or unquoted) value out of a
// modern include() argument list.
var rsyslogIncludeFileKV = regexp.MustCompile(`\bfile\s*=\s*(?:"([^"]*)"|'([^']*)'|(\S+))`)

// parseRsyslogIncludes extracts file-glob patterns referenced by
// $IncludeConfig (legacy) and include(file="...") (modern RainerScript)
// directives from a single rsyslog config blob. Returned patterns are in
// source order with duplicates removed. The include(text="...") form is
// skipped because it inlines content rather than referencing a file.
//
// rsyslog itself ignores `#` comments anywhere on a line outside of quoted
// strings. We strip everything from the first unquoted `#` to EOL before
// matching, so a comment hanging off an include directive does not pollute
// the pattern. Multi-line include() blocks (common in Ansible-templated
// configs) are coalesced into a single logical line before matching.
func parseRsyslogIncludes(content string) []string {
	var out []string
	seen := map[string]bool{}

	for _, line := range coalesceIncludeBlocks(content) {
		var pat string
		if m := rsyslogIncludeDirective.FindStringSubmatch(line); m != nil {
			pat = strings.Trim(strings.TrimSpace(m[1]), `"'`)
		} else if m := rsyslogModernInclude.FindStringSubmatch(line); m != nil {
			if kv := rsyslogIncludeFileKV.FindStringSubmatch(m[1]); kv != nil {
				// Exactly one of the three capture groups (quoted-double,
				// quoted-single, unquoted) is non-empty.
				for _, v := range kv[1:] {
					if v != "" {
						pat = v
						break
					}
				}
			}
		}

		if pat == "" || seen[pat] {
			continue
		}
		seen[pat] = true
		out = append(out, pat)
	}

	return out
}

// coalesceIncludeBlocks strips comments and trims each line, then joins
// continuation lines inside an unterminated `include(...)` block into a
// single logical line. Tools like Ansible templates routinely emit:
//
//	include(
//	    file="/etc/rsyslog.d/*.conf"
//	)
//
// which rsyslog accepts. Lines outside an open `include(` are returned
// one per source line so the line-anchored `$IncludeConfig` regex still
// matches correctly. Blank lines outside a block are dropped.
func coalesceIncludeBlocks(content string) []string {
	lines := coalesceParenBlocks("", content, rsyslogModernIncludeOpen.MatchString)
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l.text
	}
	return out
}

// countUnquotedParens returns (# of `(`) - (# of `)`) on a line,
// ignoring parens inside double- or single-quoted strings.
func countUnquotedParens(line string) int {
	count := 0
	inDouble, inSingle := false, false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '(':
			if !inDouble && !inSingle {
				count++
			}
		case ')':
			if !inDouble && !inSingle {
				count--
			}
		}
	}
	return count
}

// stripRsyslogComment removes everything from the first unquoted `#` to
// end-of-line, mirroring rsyslog's own lexer behaviour. Quotes can be
// double or single.
func stripRsyslogComment(line string) string {
	inDouble, inSingle := false, false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '#':
			if !inDouble && !inSingle {
				return line[:i]
			}
		}
	}
	return line
}

// resolveRsyslogInclude turns a (possibly relative, possibly globbed) include
// pattern into the directory to search and the basename glob to match inside
// it. A pattern with no glob meta-characters yields a glob that matches that
// single name exactly.
func resolveRsyslogInclude(parentDir, pattern string) (dir, baseGlob string) {
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(parentDir, pattern)
	}
	return filepath.Dir(pattern), filepath.Base(pattern)
}

// rsyslogIncludeMatches reports whether a path's basename satisfies an
// include's glob. A malformed glob matches nothing, mirroring glob(3), which
// reports no matches rather than failing.
func rsyslogIncludeMatches(baseGlob, path string) bool {
	ok, err := filepath.Match(baseGlob, filepath.Base(path))
	return err == nil && ok
}

// maxRsyslogIncludeDepth bounds how many levels of nested includes we
// follow. rsyslog itself has no documented limit, but real configurations
// rarely nest beyond two or three levels — a deeper chain is almost
// certainly a misconfiguration or a self-reference we missed.
const maxRsyslogIncludeDepth = 32

func (s *mqlRsyslogConf) files(path string) ([]any, error) {
	if !strings.HasSuffix(path, ".conf") {
		return nil, errors.New("failed to initialize, path must end in `.conf` so we can find files in `.d` directory")
	}

	visited := map[string]bool{}
	var out []any

	type queued struct {
		path  string
		depth int
	}
	var queue []queued

	// drain walks the queue, following includes out of every file it reads.
	// It runs once for the main config and again for the `.d` fragments, so a
	// fragment reached only by auto-discovery still gets its own includes
	// followed instead of being listed as a leaf.
	drain := func() error {
		for len(queue) > 0 {
			head := queue[0]
			queue = queue[1:]

			clean := filepath.Clean(head.path)
			if visited[clean] {
				continue
			}
			visited[clean] = true

			f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
				"path": llx.StringData(clean),
			})
			if err != nil {
				return err
			}
			mf := f.(*mqlFile)
			out = append(out, mf)

			if head.depth >= maxRsyslogIncludeDepth {
				continue
			}

			content := mf.GetContent()
			if content.Error != nil {
				if errors.Is(content.Error, resources.NotFoundError{}) {
					continue
				}
				// Other read errors (permission denied, IO) are non-fatal here:
				// the file is still listed via the resource, and the caller can
				// inspect it for the error. Don't abort the whole walk.
				continue
			}

			patterns := parseRsyslogIncludes(content.Data)
			parentDir := filepath.Dir(clean)
			for _, pat := range patterns {
				matches, err := s.expandIncludePattern(parentDir, pat)
				if err != nil {
					continue
				}
				for _, m := range matches {
					if !visited[filepath.Clean(m)] {
						queue = append(queue, queued{path: m, depth: head.depth + 1})
					}
				}
			}
		}
		return nil
	}

	queue = append(queue, queued{path: path, depth: 0})
	if err := drain(); err != nil {
		return nil, err
	}

	// Legacy `.d` auto-discovery: configurations that rely on the
	// distribution's default to drop fragments into `<conf>.d/` without
	// an explicit `$IncludeConfig` should still surface those files.
	// Skip entries already visited via include traversal so the list
	// doesn't double-count when both paths reach the same fragment.
	//
	// No depth bound here: distro packages drop fragments directly into
	// `<conf>.d/` (no subdirs in practice), and this matches the original
	// behaviour of the resource — narrowing it now would silently change
	// the file list for callers relying on it.
	confD := path[0:len(path)-5] + ".d"
	o, err := CreateResource(s.MqlRuntime, "files.find", map[string]*llx.RawData{
		"from": llx.StringData(confD),
		"type": llx.StringData("file"),
	})
	if err == nil {
		list := o.(*mqlFilesFind).GetList()
		if list.Error == nil {
			for _, item := range list.Data {
				mf, ok := item.(*mqlFile)
				if !ok {
					continue
				}
				if visited[filepath.Clean(mf.Path.Data)] {
					continue
				}
				// Queue rather than append: a fragment dropped into `<conf>.d`
				// may carry its own $IncludeConfig, and appending it directly
				// left those nested files out of the list entirely.
				queue = append(queue, queued{path: mf.Path.Data, depth: 0})
			}
		}
	}

	if err := drain(); err != nil {
		return nil, err
	}

	return out, nil
}

// reRsyslogGlob detects filepath glob meta-characters in a path segment.
var reRsyslogGlob = regexp.MustCompile(`[*?\[]`)

// expandIncludePattern resolves a single include pattern (relative to
// parentDir if not absolute) into the list of files it matches, using
// files.find against the asset's filesystem.
//
// The glob is applied here rather than handed to files.find's `name`, whose
// meaning differs by backend: the command backends read it as a glob on the
// basename (`find -name`, PowerShell `-like`), while the native backend
// compiles it as a regex matched against the whole path. Matching locally
// keeps rsyslog's own glob(3) semantics identical on every connection type.
//
// A glob may appear in any path segment, not just the basename: rsyslog
// expands `$IncludeConfig /etc/rsyslog.d/*/out.conf` by matching every
// immediate subdirectory in turn. The directory portion is resolved
// segment-by-segment (`resolveIncludeDirs`) so a mid-path glob fans out to
// the set of concrete directories it names; the basename glob is then
// matched against the files in each. Each glob segment consumes exactly one
// level, matching rsyslog's own glob(3) semantics: a `*` does not descend
// past a single directory boundary.
func (s *mqlRsyslogConf) expandIncludePattern(parentDir, pattern string) ([]string, error) {
	dir, baseGlob := resolveRsyslogInclude(parentDir, pattern)

	dirs, err := s.resolveIncludeDirs(dir)
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, d := range dirs {
		files, err := s.findChildren(d, "file")
		if err != nil {
			return nil, err
		}
		for _, p := range files {
			if rsyslogIncludeMatches(baseGlob, p) {
				paths = append(paths, p)
			}
		}
	}
	return paths, nil
}

// resolveIncludeDirs turns an absolute directory path that may contain glob
// segments into the concrete directories it names. Non-glob segments are
// appended literally (no listing, so a plain directory path collapses to a
// single result without any filesystem access); a glob segment lists the
// immediate subdirectories of each current path and keeps the ones whose
// name matches. Paths naming a directory that doesn't exist simply drop out,
// mirroring glob(3)'s "no match" behaviour.
func (s *mqlRsyslogConf) resolveIncludeDirs(dir string) ([]string, error) {
	paths := []string{"/"}
	for _, seg := range strings.Split(dir, "/") {
		if seg == "" {
			continue
		}
		if !reRsyslogGlob.MatchString(seg) {
			for i := range paths {
				paths[i] = filepath.Join(paths[i], seg)
			}
			continue
		}

		var next []string
		for _, p := range paths {
			subdirs, err := s.findChildren(p, "directory")
			if err != nil {
				return nil, err
			}
			for _, sd := range subdirs {
				// `find -maxdepth 1 -type d` also lists the search root
				// itself; only its children are candidates for the segment.
				if filepath.Clean(sd) == filepath.Clean(p) {
					continue
				}
				if rsyslogIncludeMatches(seg, sd) {
					next = append(next, sd)
				}
			}
		}
		paths = next
	}
	return paths, nil
}

// findChildren lists the immediate children of `dir` of the given find type
// ("file" or "directory") via files.find with depth=1, returning their
// paths. A missing directory yields an empty list rather than an error,
// matching how the command backends report an absent search root.
func (s *mqlRsyslogConf) findChildren(dir, typ string) ([]string, error) {
	o, err := CreateResource(s.MqlRuntime, "files.find", map[string]*llx.RawData{
		"from":  llx.StringData(dir),
		"type":  llx.StringData(typ),
		"depth": llx.IntData(1),
	})
	if err != nil {
		return nil, err
	}

	list := o.(*mqlFilesFind).GetList()
	if list.Error != nil {
		return nil, list.Error
	}

	out := make([]string, 0, len(list.Data))
	for _, item := range list.Data {
		if mf, ok := item.(*mqlFile); ok {
			out = append(out, mf.Path.Data)
		}
	}
	return out, nil
}

func (s *mqlRsyslogConf) content(files []any) (string, error) {
	var res strings.Builder

	// TODO: this can be heavily improved once we do it right, since this is constantly
	// re-registered as the file changes
	for i := range files {
		file := files[i].(*mqlFile)
		content := file.GetContent()
		if content.Error != nil {
			// Skip files that cannot be read (not found, permission denied,
			// IO errors) rather than appending an empty block for them.
			continue
		}

		res.WriteString(content.Data)
		res.WriteString("\n")
	}

	return res.String(), nil
}

func (s *mqlRsyslogConf) settings(content string) ([]any, error) {
	lines := strings.Split(content, "\n")

	settings := []any{}
	var line string
	for i := range lines {
		line = lines[i]
		line = stripRsyslogComment(line)
		line = strings.Trim(line, " \t\r")

		if line != "" {
			settings = append(settings, line)
		}
	}

	return settings, nil
}

// params parses the legacy `$Directive value` settings across all included
// config fragments into key/value pairs. The leading `$` is stripped from each
// key and the value is trimmed of surrounding whitespace; when the same
// directive appears more than once the last occurrence wins.
func (s *mqlRsyslogConf) params(content string) (map[string]any, error) {
	params := map[string]any{}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.Trim(stripRsyslogComment(raw), " \t\r")
		if !strings.HasPrefix(line, "$") {
			continue
		}

		directive := line[1:]
		idx := strings.IndexAny(directive, " \t")
		if idx < 0 {
			// a bare `$Directive` with no value — skip rather than record an
			// empty value, since legacy directives always carry a value
			continue
		}

		key := directive[:idx]
		params[key] = strings.TrimSpace(directive[idx:])
	}
	return params, nil
}

// parsedEntries walks every fragment in `files` and returns the unified
// list of typed entries from all of them. The result is memoized on the
// Internal struct so the four typed accessors share one parse pass per
// resource instance.
func (s *mqlRsyslogConf) parsedEntries(files []any) ([]rsyslogEntry, error) {
	s.parsedLock.Lock()
	defer s.parsedLock.Unlock()
	if s.parsedDone {
		return s.parsedCache, nil
	}

	var all []rsyslogEntry
	for _, f := range files {
		file := f.(*mqlFile)
		path := file.Path.Data
		c := file.GetContent()
		if c.Error != nil {
			if errors.Is(c.Error, resources.NotFoundError{}) {
				continue
			}
			// Read errors on a single fragment shouldn't abort the whole
			// parse — surface what we can and skip the unreadable file.
			continue
		}
		all = append(all, parseRsyslogFile(path, c.Data)...)
	}
	applyModuleDefaults(all)
	assignRsyslogEntryIDs(all)

	s.parsedCache = all
	s.parsedDone = true
	return all, nil
}

// rsyslogEntryID builds a deterministic resource cache key for typed entries
// scoped by kind, source file, and source line. Multi-selector rules and
// the actions they fan out to share a sourceFile:sourceLine pair but get
// disambiguated via an index suffix so each row has a unique __id.
func rsyslogEntryID(kind string, e rsyslogEntry, idx int) string {
	return fmt.Sprintf("%s/%s:%d/%d", kind, e.sourceFile, e.sourceLine, idx)
}

// assignRsyslogEntryIDs numbers the entries of each kind in order, so a rule
// and the `actions` list resolve its backing action to the same resource.
func assignRsyslogEntryIDs(entries []rsyslogEntry) {
	counts := map[rsyslogEntryKind]int{}
	for i := range entries {
		e := &entries[i]
		var kind string
		switch e.kind {
		case rsyslogKindModule:
			kind = "module"
		case rsyslogKindInput:
			kind = "input"
		case rsyslogKindAction:
			kind = "action"
		case rsyslogKindRule:
			kind = "rule"
		default:
			continue
		}
		e.id = rsyslogEntryID(kind, *e, counts[e.kind])
		counts[e.kind]++
	}
}

func (s *mqlRsyslogConf) modules(files []any) ([]any, error) {
	entries, err := s.parsedEntries(files)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, e := range entries {
		if e.kind != rsyslogKindModule {
			continue
		}
		res, err := CreateResource(s.MqlRuntime, "rsyslog.module", map[string]*llx.RawData{
			"__id":       llx.StringData(e.id),
			"name":       llx.StringData(e.moduleName),
			"parameters": llx.DictData(anyMap(e.parameters)),
			"sourceFile": llx.StringData(e.sourceFile),
			"sourceLine": llx.IntData(int64(e.sourceLine)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (s *mqlRsyslogConf) inputs(files []any) ([]any, error) {
	entries, err := s.parsedEntries(files)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, e := range entries {
		if e.kind != rsyslogKindInput {
			continue
		}
		res, err := CreateResource(s.MqlRuntime, "rsyslog.input", map[string]*llx.RawData{
			"__id":             llx.StringData(e.id),
			"type":             llx.StringData(e.moduleType),
			"port":             llx.IntData(e.port),
			"address":          llx.StringData(e.address),
			"ruleset":          llx.StringData(e.ruleset),
			"streamDriverMode": llx.StringData(e.streamDriverMode),
			"parameters":       llx.DictData(anyMap(e.parameters)),
			"sourceFile":       llx.StringData(e.sourceFile),
			"sourceLine":       llx.IntData(int64(e.sourceLine)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (s *mqlRsyslogConf) actions(files []any) ([]any, error) {
	entries, err := s.parsedEntries(files)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, e := range entries {
		if e.kind != rsyslogKindAction {
			continue
		}
		res, err := newRsyslogAction(s.MqlRuntime, e)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// newRsyslogAction creates the rsyslog.action resource for a parsed entry.
// `actions` and `rsyslog.rule.action` both go through here with the entry's
// id, so they share one cached resource.
func newRsyslogAction(runtime *plugin.Runtime, e rsyslogEntry) (*mqlRsyslogAction, error) {
	res, err := CreateResource(runtime, "rsyslog.action", map[string]*llx.RawData{
		"__id":       llx.StringData(e.id),
		"type":       llx.StringData(e.moduleType),
		"target":     llx.StringData(e.target),
		"protocol":   llx.StringData(e.protocol),
		"tlsEnabled": llx.BoolData(e.tlsEnabled),
		"template":   llx.StringData(e.template),
		"queue":      llx.DictData(anyMap(e.queue)),
		"parameters": llx.DictData(anyMap(e.parameters)),
		"sourceFile": llx.StringData(e.sourceFile),
		"sourceLine": llx.IntData(int64(e.sourceLine)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlRsyslogAction), nil
}

func (s *mqlRsyslogConf) rules(files []any) ([]any, error) {
	entries, err := s.parsedEntries(files)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for i, e := range entries {
		if e.kind != rsyslogKindRule {
			continue
		}
		mqlRule, err := CreateResource(s.MqlRuntime, "rsyslog.rule", map[string]*llx.RawData{
			"__id":       llx.StringData(e.id),
			"facilities": llx.ArrayData(stringsToAny(e.facilities), types.String),
			"severities": llx.ArrayData(stringsToAny(e.severities), types.String),
			"target":     llx.StringData(e.target),
			"negate":     llx.BoolData(e.negate),
			"sourceFile": llx.StringData(e.sourceFile),
			"sourceLine": llx.IntData(int64(e.sourceLine)),
		})
		if err != nil {
			return nil, err
		}
		if j := i + e.actionOffset; e.actionOffset > 0 && j < len(entries) && entries[j].kind == rsyslogKindAction {
			backing := entries[j]
			mqlRule.(*mqlRsyslogRule).backingAction = &backing
		}
		out = append(out, mqlRule)
	}
	return out, nil
}

// action returns the action this rule routes matching messages to: the
// legacy target or the `action(...)` statement that follows the selector.
// A target that could not be parsed into an action yields null.
func (r *mqlRsyslogRule) action() (*mqlRsyslogAction, error) {
	if r.backingAction == nil {
		r.Action.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newRsyslogAction(r.MqlRuntime, *r.backingAction)
}

// id methods for the typed sub-resources. The __id is set in the creator
// so these just echo it back.
func (m *mqlRsyslogModule) id() (string, error) { return m.__id, nil }
func (i *mqlRsyslogInput) id() (string, error)  { return i.__id, nil }
func (a *mqlRsyslogAction) id() (string, error) { return a.__id, nil }
func (r *mqlRsyslogRule) id() (string, error)   { return r.__id, nil }

// anyMap returns a value suitable for llx.DictData. It accepts a nil map
// safely (DictData rejects untyped nil) and otherwise just returns the
// argument as a generic map.
func anyMap(m map[string]any) any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// mqlRsyslogConfInternal caches the unified parse across the four typed
// accessors so each resource instance pays the parse cost only once.
type mqlRsyslogConfInternal struct {
	parsedLock  sync.Mutex
	parsedDone  bool
	parsedCache []rsyslogEntry
}

// mqlRsyslogRuleInternal holds the parsed action entry behind the rule, so
// action resolves without re-parsing the configuration.
type mqlRsyslogRuleInternal struct {
	backingAction *rsyslogEntry
}

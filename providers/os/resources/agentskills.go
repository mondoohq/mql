// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"sigs.k8s.io/yaml"
)

// agentSkillFile is the file that makes a directory a skill, per the Agent
// Skills specification (https://agentskills.io/specification).
const agentSkillFile = "SKILL.md"

// agentSkillsMaxDepth bounds the search below agentskills.path. Skills sit a
// few levels deep even in plugin marketplaces (plugins/<p>/skills/<s>), and the
// bound keeps a symlink cycle or a path like "/" from walking forever.
const agentSkillsMaxDepth = 10

// agentSkillsSkipDirs are never searched for skills: they hold history or
// third-party dependencies, not the skills under audit.
var agentSkillsSkipDirs = map[string]struct{}{
	".git":         {},
	"node_modules": {},
}

// agentSkillPackageExt marks a zip archive of one or more skill directories,
// the packaged form some agents install skills from.
const agentSkillPackageExt = ".skill"

// Limits on reading a skill package. A package is read into memory, so these
// bound what a large or hostile archive can cost.
const (
	agentSkillPackageMaxBytes   = 50 << 20
	agentSkillPackageMaxEntries = 1000
	agentSkillFileMaxBytes      = 5 << 20
)

// agentSkillSource is one SKILL.md to turn into an agentskills.skill, from a
// directory or from inside a skill package.
type agentSkillSource struct {
	path      string
	directory string
	archive   string
	content   []byte
	// exists reports whether a path relative to the skill directory exists.
	exists func(rel string) bool
	// errors are problems reading the skill before its frontmatter is parsed.
	// When set, content is not parsed.
	errors []string
}

func (r *mqlAgentskills) id() (string, error) {
	return "agentskills/" + r.Path.Data, nil
}

func (r *mqlAgentskills) skills() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	skillPaths, packages, err := findAgentSkills(afs, r.Path.Data)
	if err != nil {
		return nil, err
	}

	var sources []agentSkillSource
	for _, p := range skillPaths {
		data, err := afs.ReadFile(p)
		if err != nil {
			return nil, classifyFsError(err)
		}
		dir := filepath.Dir(p)
		sources = append(sources, agentSkillSource{
			path:      p,
			directory: filepath.Base(dir),
			content:   data,
			exists: func(rel string) bool {
				_, err := afs.Stat(filepath.Join(dir, filepath.FromSlash(rel)))
				return err == nil
			},
		})
	}
	for _, p := range packages {
		sources = append(sources, readAgentSkillPackage(afs, p)...)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].path < sources[j].path })

	result := make([]any, 0, len(sources))
	for _, src := range sources {
		res, err := newAgentSkillResource(r.MqlRuntime, src)
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func newAgentSkillResource(runtime *plugin.Runtime, src agentSkillSource) (plugin.Resource, error) {
	var skill agentSkill
	if len(src.errors) == 0 {
		skill = parseAgentSkill(string(src.content))
	}
	errs := append(append([]string{}, src.errors...), skill.errors...)

	refs := agentSkillReferences(skill.body)
	missing := agentSkillMissingReferences(refs, src.exists)

	return CreateResource(runtime, "agentskills.skill", map[string]*llx.RawData{
		"__id":              llx.StringData("agentskills.skill/" + src.path),
		"path":              llx.StringData(src.path),
		"directory":         llx.StringData(src.directory),
		"archive":           llx.StringData(src.archive),
		"name":              llx.StringData(skill.name),
		"description":       llx.StringData(skill.description),
		"license":           llx.StringData(skill.license),
		"compatibility":     llx.StringData(skill.compatibility),
		"metadata":          llx.DictData(dictOrNil(skill.metadata)),
		"allowedTools":      llx.ArrayData(llx.TArr2Raw(skill.allowedTools), types.String),
		"frontmatter":       llx.DictData(dictOrNil(skill.frontmatter)),
		"body":              llx.StringData(skill.body),
		"content":           llx.StringData(string(src.content)),
		"size":              llx.IntData(int64(len(src.content))),
		"lines":             llx.IntData(int64(countLines(skill.body))),
		"references":        llx.ArrayData(llx.TArr2Raw(refs), types.String),
		"missingReferences": llx.ArrayData(llx.TArr2Raw(missing), types.String),
		"errors":            llx.ArrayData(llx.TArr2Raw(errs), types.String),
	})
}

func (r *mqlAgentskillsSkill) id() (string, error) {
	return "agentskills.skill/" + r.Path.Data, nil
}

func (r *mqlAgentskillsSkill) sha256() (string, error) {
	return contentSHA256(r.Content.Data), nil
}

func (r *mqlAgentskillsSkill) files() ([]any, error) {
	// A packaged skill's files live inside the archive, not on the host.
	if r.Archive.Data != "" {
		return []any{}, nil
	}
	paths, err := agentSkillBundledFiles(connectionAfs(r.MqlRuntime), r.Path.Data)
	if err != nil {
		return nil, err
	}
	result := make([]any, 0, len(paths))
	for _, p := range paths {
		f, err := newFile(r.MqlRuntime, p)
		if err != nil {
			return nil, err
		}
		result = append(result, f)
	}
	return result, nil
}

// dictOrNil keeps an absent map null instead of an empty dict, so "not set"
// and "set to {}" stay distinguishable.
func dictOrNil(m map[string]any) any {
	if m == nil {
		return nil
	}
	return m
}

// findAgentSkills returns the SKILL.md paths and the skill packages below
// root, each in lexical order. A root that is itself a package is returned as
// the only package. A directory holding SKILL.md is a skill and is
// not searched further: what is below it are the skill's bundled files.
// Unreadable subdirectories are skipped; a missing or unreadable root is an
// error.
func findAgentSkills(afs *afero.Afero, root string) (skills []string, packages []string, err error) {
	info, err := afs.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, llx.NotFound(fmt.Errorf("agentskills path %q does not exist", root))
		}
		return nil, nil, classifyFsError(err)
	}
	if !info.IsDir() {
		if strings.HasSuffix(root, agentSkillPackageExt) {
			return nil, []string{root}, nil
		}
		return nil, nil, fmt.Errorf("agentskills path %q is not a directory or a %s package", root, agentSkillPackageExt)
	}

	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		entries, err := afs.ReadDir(dir)
		if err != nil {
			if depth == 0 {
				return classifyFsError(err)
			}
			log.Debug().Err(err).Str("path", dir).Msg("skipping unreadable directory while searching for agent skills")
			return nil
		}

		for _, e := range entries {
			if e.Name() == agentSkillFile && !e.IsDir() {
				skills = append(skills, filepath.Join(dir, agentSkillFile))
				return nil
			}
		}

		for _, e := range entries {
			if _, skip := agentSkillsSkipDirs[e.Name()]; skip {
				continue
			}
			p := filepath.Join(dir, e.Name())
			// Stat follows symlinks; ReadDir reports a symlinked directory as a file.
			fi, err := afs.Stat(p)
			if err != nil {
				continue
			}
			if !fi.IsDir() {
				if strings.HasSuffix(e.Name(), agentSkillPackageExt) {
					packages = append(packages, p)
				}
				continue
			}
			if depth >= agentSkillsMaxDepth {
				continue
			}
			if err := walk(p, depth+1); err != nil {
				return err
			}
		}
		return nil
	}

	if err := walk(root, 0); err != nil {
		return nil, nil, err
	}
	return skills, packages, nil
}

// readAgentSkillPackage reads the skills inside a skill package: a zip archive
// holding one or more skill directories, or a single skill at its root. The
// same rules as for directories apply, so a SKILL.md inside another skill is
// a bundled file. A package that cannot be read is returned as one skill whose
// errors say why, so a broken package is reported rather than dropped.
func readAgentSkillPackage(afs *afero.Afero, archive string) []agentSkillSource {
	rootName := strings.TrimSuffix(filepath.Base(archive), agentSkillPackageExt)
	fail := func(msg string) []agentSkillSource {
		return []agentSkillSource{{
			path:      archive,
			directory: rootName,
			archive:   archive,
			exists:    func(string) bool { return false },
			errors:    []string{msg},
		}}
	}

	info, err := afs.Stat(archive)
	if err != nil {
		return fail("cannot read skill package: " + err.Error())
	}
	if info.Size() > agentSkillPackageMaxBytes {
		return fail(fmt.Sprintf("skill package is %d bytes, over the %d byte limit", info.Size(), agentSkillPackageMaxBytes))
	}
	data, err := afs.ReadFile(archive)
	if err != nil {
		return fail("cannot read skill package: " + err.Error())
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fail("skill package is not a valid zip archive: " + err.Error())
	}
	if len(zr.File) > agentSkillPackageMaxEntries {
		return fail(fmt.Sprintf("skill package has %d entries, over the %d entry limit", len(zr.File), agentSkillPackageMaxEntries))
	}

	// Index entries by their cleaned, slash-separated path. Archives need not
	// hold directory entries, so directories are also derived from file paths.
	files := map[string]*zip.File{}
	dirs := map[string]bool{".": true}
	for _, f := range zr.File {
		name := strings.TrimPrefix(path.Clean("/"+strings.ReplaceAll(f.Name, "\\", "/")), "/")
		if name == "" {
			continue
		}
		if f.FileInfo().IsDir() {
			dirs[name] = true
			continue
		}
		files[name] = f
		for d := path.Dir(name); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}

	isSkillDir := map[string]bool{}
	for name := range files {
		if path.Base(name) != agentSkillFile {
			continue
		}
		dir := path.Dir(name)
		if zipDirSkipped(dir) {
			continue
		}
		isSkillDir[dir] = true
	}
	var skillDirs []string
	for dir := range isSkillDir {
		nested := false
		for a := dir; a != "."; {
			a = path.Dir(a)
			if isSkillDir[a] {
				nested = true
				break
			}
		}
		if !nested {
			skillDirs = append(skillDirs, dir)
		}
	}
	if len(skillDirs) == 0 {
		return fail("skill package contains no " + agentSkillFile)
	}
	sort.Strings(skillDirs)

	sources := make([]agentSkillSource, 0, len(skillDirs))
	for _, dir := range skillDirs {
		inner := path.Join(dir, agentSkillFile)
		directory := path.Base(dir)
		if dir == "." {
			directory = rootName
		}
		src := agentSkillSource{
			path:      filepath.Join(archive, filepath.FromSlash(inner)),
			directory: directory,
			archive:   archive,
			exists: func(rel string) bool {
				p := path.Join(dir, rel)
				_, isFile := files[p]
				return isFile || dirs[p]
			},
		}
		content, err := readZipEntry(files[inner], agentSkillFileMaxBytes)
		if err != nil {
			src.errors = []string{"cannot read " + inner + " from skill package: " + err.Error()}
		} else {
			src.content = content
		}
		sources = append(sources, src)
	}
	return sources
}

// zipDirSkipped reports whether a slash-separated directory inside a package
// is one findAgentSkills would not search: below a skipped directory or deeper
// than agentSkillsMaxDepth.
func zipDirSkipped(dir string) bool {
	if dir == "." {
		return false
	}
	parts := strings.Split(dir, "/")
	if len(parts) > agentSkillsMaxDepth {
		return true
	}
	for _, p := range parts {
		if _, skip := agentSkillsSkipDirs[p]; skip {
			return true
		}
	}
	return false
}

// readZipEntry reads one archive entry, refusing entries over limit bytes. The
// declared size is checked first, and the read is bounded too, since an
// archive can understate it.
func readZipEntry(f *zip.File, limit int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("entry is %d bytes, over the %d byte limit", f.UncompressedSize64, limit)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("entry is over the %d byte limit", limit)
	}
	return data, nil
}

// agentSkillBundledFiles returns every file in the skill directory of
// skillPath other than SKILL.md itself, in lexical order.
func agentSkillBundledFiles(afs *afero.Afero, skillPath string) ([]string, error) {
	dir := filepath.Dir(skillPath)
	var files []string
	err := afs.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			if p == dir {
				return classifyFsError(err)
			}
			log.Debug().Err(err).Str("path", p).Msg("skipping unreadable path in agent skill")
			return nil
		}
		if info.IsDir() || p == skillPath {
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// agentSkillLinkRe matches the target of a Markdown link or image:
// [text](target) or [text](<target> "title").
var agentSkillLinkRe = regexp.MustCompile(`\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)`)

// agentSkillBaseDir is the placeholder some agents replace with the skill's
// directory, as in "{baseDir}/references/guide.md".
const agentSkillBaseDir = "{baseDir}"

// agentSkillReferences returns the bundled files the body of a SKILL.md links
// to, cleaned and in order of first appearance: the targets of Markdown links
// and images that are not URLs, anchors, absolute paths, or placeholders. Code
// fences are skipped, since they hold examples rather than links. Paths only
// mentioned in prose are not references: skills mention example paths far more
// often than they rely on them.
func agentSkillReferences(body string) []string {
	var refs []string
	seen := map[string]bool{}
	fence := ""
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if fence == "" && (strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~")) {
			fence = trimmed[:3]
			continue
		}
		if fence != "" {
			if strings.HasPrefix(trimmed, fence) {
				fence = ""
			}
			continue
		}
		for _, m := range agentSkillLinkRe.FindAllStringSubmatch(line, -1) {
			ref, ok := cleanAgentSkillRef(m[1])
			if ok && !seen[ref] {
				seen[ref] = true
				refs = append(refs, ref)
			}
		}
	}
	return refs
}

// cleanAgentSkillRef turns a link target into a slash-separated path relative
// to the skill directory, or reports that it is not one.
func cleanAgentSkillRef(raw string) (string, bool) {
	raw = strings.TrimPrefix(raw, agentSkillBaseDir+"/")
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "/") ||
		strings.HasPrefix(raw, "~") || strings.HasPrefix(raw, "\\") {
		return "", false
	}
	// A placeholder the agent fills in, such as ${CLAUDE_PLUGIN_ROOT}/x or
	// <skill-dir>/x, cannot be resolved here.
	if strings.ContainsAny(raw, "{}$<>") {
		return "", false
	}
	// Any scheme (https:, mailto:, data:, file:) is not a bundled file.
	if u, err := url.Parse(raw); err != nil || u.Scheme != "" || u.Host != "" {
		return "", false
	}
	if i := strings.IndexAny(raw, "#?"); i != -1 {
		raw = raw[:i]
	}
	if unescaped, err := url.PathUnescape(raw); err == nil {
		raw = unescaped
	}
	ref := path.Clean(raw)
	if ref == "." || path.IsAbs(ref) {
		return "", false
	}
	return ref, true
}

// agentSkillMissingReferences returns the references that do not resolve. A
// reference may leave the skill directory: skills in a plugin link to sibling
// skills and plugin-level files, which resolve as long as the plugin is
// installed whole.
func agentSkillMissingReferences(refs []string, exists func(rel string) bool) []string {
	var missing []string
	for _, ref := range refs {
		if !exists(ref) {
			missing = append(missing, ref)
		}
	}
	return missing
}

// countLines counts the lines of text; a trailing newline does not start
// another line.
func countLines(text string) int {
	if text == "" {
		return 0
	}
	return strings.Count(strings.TrimSuffix(text, "\n"), "\n") + 1
}

// agentSkill is a SKILL.md file parsed against the Agent Skills specification.
// Fields hold what the file says, with no fallbacks; errors records why a
// value could not be read.
type agentSkill struct {
	name          string
	description   string
	license       string
	compatibility string
	metadata      map[string]any
	allowedTools  []string
	frontmatter   map[string]any
	body          string
	errors        []string
}

func parseAgentSkill(content string) agentSkill {
	var s agentSkill
	text := strings.TrimPrefix(content, "\uFEFF")
	text = strings.ReplaceAll(text, "\r\n", "\n")

	fm, body, err := splitSkillFrontmatter(text)
	if err != nil {
		s.errors = append(s.errors, err.Error())
		s.body = text
		return s
	}
	s.body = body

	var raw map[string]any
	if err := yaml.Unmarshal([]byte(fm), &raw); err != nil {
		s.errors = append(s.errors, "frontmatter is not valid YAML: "+err.Error())
		return s
	}
	if raw == nil {
		raw = map[string]any{}
	}
	s.frontmatter = raw

	s.name = s.stringField(raw, "name")
	s.description = s.stringField(raw, "description")
	s.license = s.stringField(raw, "license")
	s.compatibility = s.stringField(raw, "compatibility")

	if v, ok := raw["metadata"]; ok && v != nil {
		if m, ok := v.(map[string]any); ok {
			s.metadata = m
		} else {
			s.errors = append(s.errors, "metadata must be a map, not "+yamlTypeName(v))
		}
	}

	switch v := raw["allowed-tools"].(type) {
	case nil:
	case string:
		s.allowedTools = splitAllowedTools(v)
	case []any:
		// Not the specified form, but unambiguous: a YAML list of tool names.
		for _, item := range v {
			str, ok := item.(string)
			if !ok {
				s.errors = append(s.errors, "allowed-tools entries must be strings, not "+yamlTypeName(item))
				continue
			}
			s.allowedTools = append(s.allowedTools, splitAllowedTools(str)...)
		}
	default:
		s.errors = append(s.errors, "allowed-tools must be a string, not "+yamlTypeName(v))
	}

	return s
}

// stringField reads a string frontmatter field. An absent or null field is
// "", a value of another type is "" plus an error.
func (s *agentSkill) stringField(raw map[string]any, key string) string {
	v, ok := raw[key]
	if !ok || v == nil {
		return ""
	}
	str, ok := v.(string)
	if !ok {
		s.errors = append(s.errors, key+" must be a string, not "+yamlTypeName(v))
		return ""
	}
	return str
}

// splitSkillFrontmatter splits text into the YAML between the opening and
// closing "---" lines and the body after them. The opening line must be the
// first line.
func splitSkillFrontmatter(text string) (frontmatter string, body string, err error) {
	first, rest, hasRest := strings.Cut(text, "\n")
	if strings.TrimRight(first, " \t") != "---" {
		return "", "", errors.New("SKILL.md does not start with a --- frontmatter block")
	}
	if !hasRest {
		return "", "", errors.New("frontmatter block is not closed by a --- line")
	}

	pos := 0
	for {
		end := strings.IndexByte(rest[pos:], '\n')
		line, next := rest[pos:], len(rest)
		if end != -1 {
			line, next = rest[pos:pos+end], pos+end+1
		}
		if strings.TrimRight(line, " \t") == "---" {
			return rest[:pos], rest[next:], nil
		}
		if end == -1 {
			return "", "", errors.New("frontmatter block is not closed by a --- line")
		}
		pos = next
	}
}

// splitAllowedTools splits an allowed-tools value into tool entries. Entries
// are separated by whitespace, as the specification writes them, or by
// commas, as some agents do. Separators inside parentheses belong to the
// entry, so "Bash(git add:*)" stays one tool.
func splitAllowedTools(s string) []string {
	var tools []string
	var cur strings.Builder
	depth := 0
	flush := func() {
		if cur.Len() > 0 {
			tools = append(tools, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '(':
			depth++
		case r == ')' && depth > 0:
			depth--
		case depth == 0 && (r == ',' || unicode.IsSpace(r)):
			flush()
			continue
		}
		cur.WriteRune(r)
	}
	flush()
	return tools
}

// yamlTypeName names the YAML type of a decoded value for error messages.
func yamlTypeName(v any) string {
	switch v.(type) {
	case bool:
		return "a boolean"
	case float64, int, int64:
		return "a number"
	case []any:
		return "a list"
	case map[string]any:
		return "a map"
	default:
		return fmt.Sprintf("%T", v)
	}
}

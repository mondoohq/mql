// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
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

func (r *mqlAgentskills) id() (string, error) {
	return "agentskills/" + r.Path.Data, nil
}

func (r *mqlAgentskills) skills() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	paths, err := findAgentSkills(afs, r.Path.Data)
	if err != nil {
		return nil, err
	}

	result := make([]any, 0, len(paths))
	for _, p := range paths {
		data, err := afs.ReadFile(p)
		if err != nil {
			return nil, classifyFsError(err)
		}
		skill := parseAgentSkill(string(data))

		res, err := CreateResource(r.MqlRuntime, "agentskills.skill", map[string]*llx.RawData{
			"__id":          llx.StringData("agentskills.skill/" + p),
			"path":          llx.StringData(p),
			"directory":     llx.StringData(filepath.Base(filepath.Dir(p))),
			"name":          llx.StringData(skill.name),
			"description":   llx.StringData(skill.description),
			"license":       llx.StringData(skill.license),
			"compatibility": llx.StringData(skill.compatibility),
			"metadata":      llx.DictData(dictOrNil(skill.metadata)),
			"allowedTools":  llx.ArrayData(llx.TArr2Raw(skill.allowedTools), types.String),
			"frontmatter":   llx.DictData(dictOrNil(skill.frontmatter)),
			"body":          llx.StringData(skill.body),
			"content":       llx.StringData(string(data)),
			"errors":        llx.ArrayData(llx.TArr2Raw(skill.errors), types.String),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlAgentskillsSkill) id() (string, error) {
	return "agentskills.skill/" + r.Path.Data, nil
}

func (r *mqlAgentskillsSkill) sha256() (string, error) {
	return contentSHA256(r.Content.Data), nil
}

func (r *mqlAgentskillsSkill) files() ([]any, error) {
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

// findAgentSkills returns the SKILL.md paths below root, in lexical order. A
// directory holding SKILL.md is a skill and is not searched further: what is
// below it are the skill's bundled files. Unreadable subdirectories are
// skipped; a missing or unreadable root is an error.
func findAgentSkills(afs *afero.Afero, root string) ([]string, error) {
	info, err := afs.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, llx.NotFound(fmt.Errorf("agentskills path %q does not exist", root))
		}
		return nil, classifyFsError(err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("agentskills path %q is not a directory", root)
	}

	var found []string
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
				found = append(found, filepath.Join(dir, agentSkillFile))
				return nil
			}
		}
		if depth >= agentSkillsMaxDepth {
			return nil
		}

		for _, e := range entries {
			if _, skip := agentSkillsSkipDirs[e.Name()]; skip {
				continue
			}
			p := filepath.Join(dir, e.Name())
			// Stat follows symlinks; ReadDir reports a symlinked directory as a file.
			fi, err := afs.Stat(p)
			if err != nil || !fi.IsDir() {
				continue
			}
			if err := walk(p, depth+1); err != nil {
				return err
			}
		}
		return nil
	}

	if err := walk(root, 0); err != nil {
		return nil, err
	}
	return found, nil
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

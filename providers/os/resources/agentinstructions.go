// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
)

// agentInstructionNames are instruction files recognized by name alone, at any
// depth, mapped to the agent resource that reads them. AGENTS.md is read by
// many agents, so it names none.
var agentInstructionNames = map[string]string{
	"AGENTS.md":       "",
	"CLAUDE.md":       "claude.code",
	"CLAUDE.local.md": "claude.code",
	"GEMINI.md":       "gemini",
	"WARP.md":         "warp",
	".cursorrules":    "cursor",
	".windsurfrules":  "windsurf",
	".clinerules":     "cline",
}

// agentInstructionDirs are directories whose files are instructions, keyed by
// the directory path relative to the directory that holds it, with the agent
// that reads them and the file extensions accepted ("" for any).
var agentInstructionDirs = []struct {
	dir   string
	agent string
	exts  []string
	// recursive includes files in subdirectories.
	recursive bool
}{
	{".cursor/rules", "cursor", []string{".md", ".mdc"}, true},
	{".windsurf/rules", "windsurf", []string{".md"}, false},
	{".clinerules", "cline", []string{".md", ".txt"}, false},
	{".kiro/steering", "kiro", []string{".md"}, false},
	{".roo/rules", "roo", []string{""}, false},
	{".trae/rules", "trae", []string{".md"}, false},
	{".kilocode/rules", "kilocode", []string{".md"}, false},
	{".augment/rules", "augment", []string{".md"}, false},
	{".github/instructions", "github.copilot", []string{".instructions.md"}, false},
}

// agentInstructionFiles are single files at a fixed path relative to the
// directory that holds them.
var agentInstructionFiles = map[string]string{
	".github/copilot-instructions.md": "github.copilot",
	".junie/guidelines.md":            "junie",
}

func (r *mqlAgentinstructions) id() (string, error) {
	return "agentinstructions/" + r.Path.Data, nil
}

func (r *mqlAgentinstructions) files() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	found, err := findAgentInstructions(afs, r.Path.Data)
	if err != nil {
		return nil, err
	}

	result := make([]any, 0, len(found))
	for _, f := range found {
		data, err := afs.ReadFile(f.path)
		if err != nil {
			return nil, classifyFsError(err)
		}
		res, err := CreateResource(r.MqlRuntime, "agentinstructions.file", map[string]*llx.RawData{
			"__id":    llx.StringData("agentinstructions.file/" + f.path),
			"path":    llx.StringData(f.path),
			"name":    llx.StringData(filepath.Base(f.path)),
			"agent":   llx.StringData(f.agent),
			"content": llx.StringData(string(data)),
			"size":    llx.IntData(int64(len(data))),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlAgentinstructionsFile) id() (string, error) {
	return "agentinstructions.file/" + r.Path.Data, nil
}

func (r *mqlAgentinstructionsFile) sha256() (string, error) {
	return contentSHA256(r.Content.Data), nil
}

// agentInstructionFile is an instruction file found below the root, and the
// agent resource that reads it ("" when many agents do).
type agentInstructionFile struct {
	path  string
	agent string
}

// classifyAgentInstruction reports whether the file at rel, a slash-separated
// path relative to the searched root, is an agent instruction file, and which
// agent reads it. Every pattern matches at any depth, since monorepos keep
// instructions next to the code they describe.
func classifyAgentInstruction(rel string) (agent string, ok bool) {
	name := path.Base(rel)
	if agent, ok := agentInstructionNames[name]; ok {
		return agent, true
	}
	for suffix, agent := range agentInstructionFiles {
		if rel == suffix || strings.HasSuffix(rel, "/"+suffix) {
			return agent, true
		}
	}
	dir := path.Dir(rel)
	// Roo Code also reads mode-specific rules from .roo/rules-<mode>.
	if strings.HasPrefix(path.Base(dir), "rules-") && path.Base(path.Dir(dir)) == ".roo" {
		return "roo", true
	}
	for _, d := range agentInstructionDirs {
		if !hasExt(name, d.exts) {
			continue
		}
		if dirMatches(dir, d.dir) {
			return d.agent, true
		}
		if d.recursive && (strings.HasPrefix(dir, d.dir+"/") || strings.Contains(dir, "/"+d.dir+"/")) {
			return d.agent, true
		}
	}
	return "", false
}

// dirMatches reports whether dir is suffix or ends in /suffix.
func dirMatches(dir, suffix string) bool {
	return dir == suffix || strings.HasSuffix(dir, "/"+suffix)
}

// hasExt reports whether name ends in one of exts; "" accepts any name.
func hasExt(name string, exts []string) bool {
	for _, ext := range exts {
		if ext == "" || strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// findAgentInstructions returns the agent instruction files below root, in
// lexical order. It searches the same directories as findAgentSkills, hidden
// ones included, and skips the same ones. Unreadable subdirectories are
// skipped; a missing or unreadable root is an error.
func findAgentInstructions(afs *afero.Afero, root string) ([]agentInstructionFile, error) {
	info, err := afs.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, llx.NotFound(fmt.Errorf("agentinstructions path %q does not exist", root))
		}
		return nil, classifyFsError(err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("agentinstructions path %q is not a directory", root)
	}

	var found []agentInstructionFile
	var walk func(dir, rel string, depth int) error
	walk = func(dir, rel string, depth int) error {
		entries, err := afs.ReadDir(dir)
		if err != nil {
			if depth == 0 {
				return classifyFsError(err)
			}
			log.Debug().Err(err).Str("path", dir).Msg("skipping unreadable directory while searching for agent instructions")
			return nil
		}
		for _, e := range entries {
			if _, skip := agentSkillsSkipDirs[e.Name()]; skip {
				continue
			}
			p := filepath.Join(dir, e.Name())
			r := path.Join(rel, e.Name())
			// Stat follows symlinks; ReadDir reports a symlinked directory as a file.
			fi, err := afs.Stat(p)
			if err != nil {
				continue
			}
			if !fi.IsDir() {
				if agent, ok := classifyAgentInstruction(r); ok {
					found = append(found, agentInstructionFile{path: p, agent: agent})
				}
				continue
			}
			if depth >= agentSkillsMaxDepth {
				continue
			}
			if err := walk(p, r, depth+1); err != nil {
				return err
			}
		}
		return nil
	}

	if err := walk(root, "", 0); err != nil {
		return nil, err
	}
	return found, nil
}

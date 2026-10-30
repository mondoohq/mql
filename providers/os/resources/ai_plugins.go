// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// agentPluginManifest is the .claude-plugin/plugin.json manifest of a plugin
// in the Claude Code plugin format, which Copilot CLI installs as well. Each
// component field is optional and takes a path, a list of paths, or (for
// mcpServers and hooks) the definition inline; when absent the component's
// default location in the plugin directory applies.
type agentPluginManifest struct {
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Description string          `json:"description"`
	Author      json.RawMessage `json:"author"`
	Repository  json.RawMessage `json:"repository"`
	Homepage    string          `json:"homepage"`
	License     string          `json:"license"`
	Skills      json.RawMessage `json:"skills"`
	Commands    json.RawMessage `json:"commands"`
	Agents      json.RawMessage `json:"agents"`
	Hooks       json.RawMessage `json:"hooks"`
	McpServers  json.RawMessage `json:"mcpServers"`
}

// agentPlugin is a plugin directory read from disk: its manifest and the
// components it contributes.
type agentPlugin struct {
	dir        string
	manifest   agentPluginManifest
	author     string
	repository string
	skillsDirs []string
	commands   []string
	agents     []string
	hasHooks   bool
	mcpServers []mcpServerSpec
}

// readAgentPlugin reads the plugin installed in dir. rootEnvName is the
// placeholder the host substitutes with the plugin directory in MCP server
// commands (CLAUDE_PLUGIN_ROOT). A plugin without a manifest still has its
// default component locations read.
func readAgentPlugin(afs *afero.Afero, dir, rootEnvName string) agentPlugin {
	p := agentPlugin{dir: dir}
	if data, err := readBoundedRegularFile(afs, filepath.Join(dir, ".claude-plugin", "plugin.json"), maxConfigFileSize); err == nil {
		if err := decodeJSONC(data, &p.manifest); err != nil {
			log.Debug().Err(err).Str("plugin", dir).Msg("could not parse plugin manifest")
		}
	}
	p.author = pluginAuthorName(p.manifest.Author)
	p.repository = pluginRepositoryURL(p.manifest.Repository)
	p.skillsDirs = pluginPaths(dir, p.manifest.Skills, "skills")
	p.commands = pluginMarkdownNames(afs, pluginPaths(dir, p.manifest.Commands, "commands"))
	p.agents = pluginMarkdownNames(afs, pluginPaths(dir, p.manifest.Agents, "agents"))
	p.hasHooks = pluginHasHooks(afs, dir, p.manifest.Hooks)
	p.mcpServers = pluginMcpServers(afs, dir, p.manifest.McpServers, rootEnvName)
	return p
}

// pluginAuthorName reads the author, which manifests write as an object with
// a name or as a plain string.
func pluginAuthorName(raw json.RawMessage) string {
	var author struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &author); err == nil && author.Name != "" {
		return author.Name
	}
	var s string
	_ = json.Unmarshal(raw, &s)
	return s
}

// pluginRepositoryURL reads the repository, a URL string or an npm-style
// object with a url.
func pluginRepositoryURL(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var repo struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(raw, &repo)
	return repo.URL
}

// pluginPaths resolves a component path field (a string or a list of strings,
// relative to the plugin directory) to absolute paths. Without the field, the
// component's default directory is used.
func pluginPaths(dir string, raw json.RawMessage, defaultRel string) []string {
	var rels []string
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && s != "" {
		rels = []string{s}
	} else {
		_ = json.Unmarshal(raw, &rels)
	}
	if len(rels) == 0 {
		rels = []string{defaultRel}
	}
	paths := make([]string, 0, len(rels))
	for _, rel := range rels {
		paths = append(paths, filepath.Join(dir, filepath.FromSlash(rel)))
	}
	return paths
}

// pluginMarkdownNames returns the names of the Markdown files that define
// commands or agents: each path is a .md file or a directory of them. Names
// drop the extension and are sorted and deduplicated.
func pluginMarkdownNames(afs *afero.Afero, paths []string) []string {
	seen := map[string]struct{}{}
	add := func(file string) {
		if strings.EqualFold(filepath.Ext(file), ".md") {
			seen[strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))] = struct{}{}
		}
	}
	for _, p := range paths {
		info, err := afs.Stat(p)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			add(p)
			continue
		}
		entries, err := afs.ReadDir(p)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				add(e.Name())
			}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// pluginHasHooks reports whether the plugin registers hooks: inline in its
// manifest, through a manifest path, or in the default hooks/hooks.json.
func pluginHasHooks(afs *afero.Afero, dir string, raw json.RawMessage) bool {
	var inline map[string]json.RawMessage
	if err := json.Unmarshal(raw, &inline); err == nil && len(inline) > 0 {
		return true
	}
	for _, p := range pluginPaths(dir, raw, filepath.Join("hooks", "hooks.json")) {
		if ok, _ := afs.Exists(p); ok {
			return true
		}
	}
	return false
}

// pluginMcpServers reads the MCP servers a plugin declares: inline in the
// manifest, in the file(s) the manifest names, or in the default .mcp.json.
// ${<rootEnvName>} in a command or argument is replaced with the plugin
// directory, as the host does when it launches the server.
func pluginMcpServers(afs *afero.Afero, dir string, raw json.RawMessage, rootEnvName string) []mcpServerSpec {
	manifest := filepath.Join(dir, ".claude-plugin", "plugin.json")
	var specs []mcpServerSpec

	var inline map[string]json.RawMessage
	if err := json.Unmarshal(raw, &inline); err == nil && len(inline) > 0 {
		var err error
		specs, err = parseMcpServersJSON(raw, "", manifest)
		if err != nil {
			log.Debug().Err(err).Str("plugin", dir).Msg("could not parse inline plugin MCP servers")
		}
	} else {
		for _, p := range pluginPaths(dir, raw, ".mcp.json") {
			fileSpecs, err := readMcpServersFile(afs, p, "")
			if err != nil {
				log.Debug().Err(err).Str("path", p).Msg("could not parse plugin MCP servers")
				continue
			}
			specs = append(specs, fileSpecs...)
		}
	}

	if rootEnvName != "" {
		for i := range specs {
			specs[i] = specs[i].expandPlaceholder(rootEnvName, dir)
		}
	}
	return specs
}

// parseRFC3339Ptr parses an RFC 3339 timestamp, returning nil for an empty or
// malformed value so the field reads as null rather than as the zero time.
func parseRFC3339Ptr(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil
	}
	return &t
}

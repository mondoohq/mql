// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// claudeManagedSettingsDir is the system directory that holds Claude Code's
// managed-settings.json and managed-settings.d/ on the target's OS
// (code.claude.com/docs/en/managed-settings).
func claudeManagedSettingsDir(osFamily string) string {
	switch osFamily {
	case "darwin":
		return "/Library/Application Support/ClaudeCode"
	case "windows":
		return `C:\Program Files\ClaudeCode`
	default: // linux, WSL and other unix-likes
		return "/etc/claude-code"
	}
}

// joinTargetPath joins a file name to a directory with the separator of the
// target's OS, which need not be the one mql runs on.
func joinTargetPath(osFamily, dir, name string) string {
	if osFamily == "windows" {
		return strings.TrimSuffix(dir, `\`) + `\` + name
	}
	return strings.TrimSuffix(dir, "/") + "/" + name
}

// claudeManagedSettingsFiles returns the system's managed settings files in
// merge order: managed-settings.json, then every *.json file of
// managed-settings.d in alphabetical order, skipping hidden files
// (code.claude.com/docs/en/managed-settings). A missing drop-in directory has
// no files; one that cannot be listed is an error.
func claudeManagedSettingsFiles(afs *afero.Afero, osFamily string) ([]string, error) {
	managedDir := claudeManagedSettingsDir(osFamily)
	files := []string{joinTargetPath(osFamily, managedDir, "managed-settings.json")}

	dropInDir := joinTargetPath(osFamily, managedDir, "managed-settings.d")
	entries, err := afs.ReadDir(dropInDir)
	if err != nil && !isAbsentPath(err) {
		return nil, classifyFsError(err)
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		files = append(files, joinTargetPath(osFamily, dropInDir, name))
	}
	return files, nil
}

// claudeSettingsHookFiles returns the settings files Claude Code reads hooks
// from at user and managed level, in merge order: the user's settings.json,
// then the managed settings files.
func claudeSettingsHookFiles(afs *afero.Afero, configDir, osFamily string) ([]agentHookSet, error) {
	files := []agentHookSet{{source: filepath.Join(configDir, "settings.json")}}
	managed, err := claudeManagedSettingsFiles(afs, osFamily)
	if err != nil {
		return nil, err
	}
	for _, f := range managed {
		files = append(files, agentHookSet{source: f, managed: true})
	}
	return files, nil
}

// readClaudeSettingsHooks reads the hooks of the user and managed settings
// files. A missing file has none; a file that cannot be read or whose hooks
// are malformed is an error.
func readClaudeSettingsHooks(afs *afero.Afero, configDir, osFamily string) ([]agentHookSet, error) {
	files, err := claudeSettingsHookFiles(afs, configDir, osFamily)
	if err != nil {
		return nil, err
	}
	var sets []agentHookSet
	for _, f := range files {
		hooks, err := readAgentHooksFile(afs, f.source, unmarshalJSONConfig)
		if err != nil {
			return nil, err
		}
		if len(hooks) > 0 {
			f.key = f.source
			f.hooks = hooks
			sets = append(sets, f)
		}
	}
	return sets, nil
}

// readClaudePluginHooks reads the hooks a plugin registers: hooks/hooks.json,
// then what the manifest's `hooks` field declares, which is a path to a hooks
// file, an inline event map, or a list of either. Hooks files wrap the event
// map in a "hooks" key; an inline map is the event map itself
// (code.claude.com/docs/en/plugins-reference). A hooks file that cannot be
// parsed is skipped, as Claude Code skips it when loading the plugin.
func readClaudePluginHooks(afs *afero.Afero, dir string, manifestHooks json.RawMessage) []agentHookSet {
	var sets []agentHookSet
	addFile := func(path string) {
		hooks, err := readAgentHooksFile(afs, path, unmarshalJSONConfig)
		if err != nil {
			log.Debug().Err(err).Str("path", path).Msg("could not parse claude plugin hooks")
			return
		}
		if len(hooks) > 0 {
			sets = append(sets, agentHookSet{source: path, key: path, hooks: hooks})
		}
	}
	manifest := filepath.Join(dir, ".claude-plugin", "plugin.json")
	addInline := func(raw json.RawMessage, key string) {
		hooks, err := parseAgentHookEvents(raw)
		if err != nil {
			log.Debug().Err(err).Str("path", manifest).Msg("could not parse claude plugin inline hooks")
			return
		}
		if len(hooks) > 0 {
			sets = append(sets, agentHookSet{source: manifest, key: key, hooks: hooks})
		}
	}

	defaultFile := filepath.Join(dir, "hooks", "hooks.json")
	addFile(defaultFile)

	var entries []json.RawMessage
	if err := json.Unmarshal(manifestHooks, &entries); err != nil {
		entries = []json.RawMessage{manifestHooks}
	}
	for i, entry := range entries {
		if len(entry) == 0 || string(entry) == "null" {
			continue
		}
		var rel string
		if err := json.Unmarshal(entry, &rel); err == nil {
			if path := filepath.Join(dir, filepath.FromSlash(rel)); rel != "" && path != defaultFile {
				addFile(path)
			}
			continue
		}
		addInline(entry, manifest+"#"+strconv.Itoa(i))
	}
	return sets
}

// claudeHookResources creates a claude.code.hook for every hook of sets.
func claudeHookResources(runtime *plugin.Runtime, sets []agentHookSet) ([]any, error) {
	result := []any{}
	for _, set := range sets {
		for _, h := range set.hooks {
			res, err := CreateResource(runtime, "claude.code.hook", map[string]*llx.RawData{
				"__id":    llx.StringData(h.id("claude.code.hook", set.key)),
				"event":   llx.StringData(h.event),
				"matcher": llx.StringData(h.matcher),
				"type":    llx.StringData(h.handler.Type),
				"command": llx.StringData(h.handler.Command),
				"args":    mcpArgsData(h.handler.Args),
				"url":     llx.StringData(h.handler.URL),
				"timeout": llx.IntDataPtr(h.timeout()),
				"source":  llx.StringData(set.source),
				"managed": llx.BoolData(set.managed),
			})
			if err != nil {
				return nil, err
			}
			result = append(result, res)
		}
	}
	return result, nil
}

func (r *mqlClaudeCode) hooks() ([]any, error) {
	afs := r.afs()
	sets, err := readClaudeSettingsHooks(afs, r.configDir(), runtimeOSFamily(r.MqlRuntime))
	if err != nil {
		return nil, err
	}

	// Hooks of enabled plugins run as well. A plugin installed at several
	// scopes from one directory is read once.
	records, err := r.enabledPluginRecords()
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	for _, rec := range records {
		if _, ok := seen[rec.entry.InstallPath]; ok {
			continue
		}
		seen[rec.entry.InstallPath] = struct{}{}
		p := readAgentPlugin(afs, rec.entry.InstallPath, claudePluginRootVar)
		sets = append(sets, readClaudePluginHooks(afs, p.dir, p.manifest.Hooks)...)
	}
	return claudeHookResources(r.MqlRuntime, sets)
}

func (r *mqlClaudeCodePlugin) hooks() ([]any, error) {
	m := r.loadManifest()
	return claudeHookResources(r.MqlRuntime, readClaudePluginHooks(connectionAfs(r.MqlRuntime), m.dir, m.manifest.Hooks))
}

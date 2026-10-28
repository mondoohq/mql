// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/spf13/afero"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// codexHooksStateKey is the table under [hooks] in config.toml that records
// whether each hook is enabled and trusted. It is not an event.
const codexHooksStateKey = "state"

// parseCodexConfigHooks parses the inline [hooks] tables of a config.toml:
// [[hooks.<Event>]] matcher groups with [[hooks.<Event>.hooks]] handlers, in
// the same shape as hooks.json. The [hooks.state] table is skipped.
func parseCodexConfigHooks(data []byte) ([]agentHook, error) {
	var cfg struct {
		Hooks map[string]any `toml:"hooks"`
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse codex config.toml: %w", err)
	}
	delete(cfg.Hooks, codexHooksStateKey)
	if len(cfg.Hooks) == 0 {
		return nil, nil
	}
	raw, err := json.Marshal(cfg.Hooks)
	if err != nil {
		return nil, err
	}
	return parseAgentHookEvents(raw)
}

// readCodexHooks reads the hooks of the Codex configuration directory: the
// hooks.json file and the inline [hooks] tables of config.toml. A missing file
// has none; a file that cannot be read or whose hooks are malformed is an
// error.
func readCodexHooks(afs *afero.Afero, codexDir string) ([]agentHookSet, error) {
	var sets []agentHookSet

	hooksFile := filepath.Join(codexDir, "hooks.json")
	hooks, err := readAgentHooksFile(afs, hooksFile, unmarshalJSONConfig)
	if err != nil {
		return nil, err
	}
	if len(hooks) > 0 {
		sets = append(sets, agentHookSet{source: hooksFile, key: hooksFile, hooks: hooks})
	}

	configFile := filepath.Join(codexDir, "config.toml")
	data, err := readBoundedRegularFile(afs, configFile, maxConfigFileSize)
	if err != nil {
		if isAbsentPath(err) {
			return sets, nil
		}
		return nil, err
	}
	hooks, err = parseCodexConfigHooks(data)
	if err != nil {
		return nil, err
	}
	if len(hooks) > 0 {
		sets = append(sets, agentHookSet{source: configFile, key: configFile, hooks: hooks})
	}
	return sets, nil
}

func (r *mqlOpenaiCodex) hooks() ([]any, error) {
	sets, err := readCodexHooks(r.afs(), r.codexDir())
	if err != nil {
		return nil, err
	}
	return codexHookResources(r.MqlRuntime, sets)
}

// codexHookResources creates an openai.codex.hook for every hook of sets.
func codexHookResources(runtime *plugin.Runtime, sets []agentHookSet) ([]any, error) {
	result := []any{}
	for _, set := range sets {
		for _, h := range set.hooks {
			res, err := CreateResource(runtime, "openai.codex.hook", map[string]*llx.RawData{
				"__id":    llx.StringData(h.id("openai.codex.hook", set.key)),
				"event":   llx.StringData(h.event),
				"matcher": llx.StringData(h.matcher),
				"type":    llx.StringData(h.handler.Type),
				"command": llx.StringData(h.handler.Command),
				"timeout": llx.IntDataPtr(h.timeout()),
				"source":  llx.StringData(set.source),
			})
			if err != nil {
				return nil, err
			}
			result = append(result, res)
		}
	}
	return result, nil
}

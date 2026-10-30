// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// geminiSystemSettingsDir is the directory of the Gemini CLI system settings
// file and system defaults file on the target's OS
// (gemini-cli docs/reference/configuration.md).
func geminiSystemSettingsDir(osFamily string) string {
	switch osFamily {
	case "darwin":
		return "/Library/Application Support/GeminiCli"
	case "windows":
		return `C:\ProgramData\gemini-cli`
	default:
		return "/etc/gemini-cli"
	}
}

// geminiSettingsHookFiles returns the settings files Gemini CLI reads hooks
// from outside a project: the system defaults, the user's settings.json, and
// the system settings, which override the others.
func geminiSettingsHookFiles(configDir, osFamily string) []agentHookSet {
	systemDir := geminiSystemSettingsDir(osFamily)
	return []agentHookSet{
		{source: joinTargetPath(osFamily, systemDir, "system-defaults.json"), managed: true},
		{source: filepath.Join(configDir, "settings.json")},
		{source: joinTargetPath(osFamily, systemDir, "settings.json"), managed: true},
	}
}

// readGeminiSettingsHooks reads the hooks of the system and user settings
// files. A missing file has none; a file that cannot be read or whose hooks
// are malformed is an error.
func readGeminiSettingsHooks(afs *afero.Afero, configDir, osFamily string) ([]agentHookSet, error) {
	var sets []agentHookSet
	for _, f := range geminiSettingsHookFiles(configDir, osFamily) {
		hooks, err := readAgentHooksFile(afs, f.source, unmarshalGeminiJSON)
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

// readGeminiExtensionHooks reads hooks/hooks.json of the extension in dir,
// which wraps the event map in a "hooks" key. A file that cannot be parsed is
// skipped, as Gemini CLI skips it when loading the extension.
func readGeminiExtensionHooks(afs *afero.Afero, dir string) []agentHookSet {
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, "hooks", "hooks.json")
	hooks, err := readAgentHooksFile(afs, path, unmarshalGeminiJSON)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not parse gemini extension hooks")
		return nil
	}
	if len(hooks) == 0 {
		return nil
	}
	return []agentHookSet{{source: path, key: path, hooks: hooks}}
}

// geminiHookResources creates a gemini.hook for every hook of sets.
func geminiHookResources(runtime *plugin.Runtime, sets []agentHookSet) ([]any, error) {
	result := []any{}
	for _, set := range sets {
		for _, h := range set.hooks {
			res, err := CreateResource(runtime, "gemini.hook", map[string]*llx.RawData{
				"__id":        llx.StringData(h.id("gemini.hook", set.key)),
				"event":       llx.StringData(h.event),
				"matcher":     llx.StringData(h.matcher),
				"name":        llx.StringData(h.handler.Name),
				"description": llx.StringData(h.handler.Description),
				"type":        llx.StringData(h.handler.Type),
				"command":     llx.StringData(h.handler.Command),
				"timeout":     llx.IntDataPtr(h.timeout()),
				"source":      llx.StringData(set.source),
				"managed":     llx.BoolData(set.managed),
			})
			if err != nil {
				return nil, err
			}
			result = append(result, res)
		}
	}
	return result, nil
}

func (r *mqlGemini) hooks() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	sets, err := readGeminiSettingsHooks(afs, r.ConfigPath.Data, runtimeOSFamily(r.MqlRuntime))
	if err != nil {
		return nil, err
	}
	exts := r.GetExtensions()
	if exts.Error != nil {
		return nil, exts.Error
	}
	for _, e := range exts.Data {
		if ext := e.(*mqlGeminiExtension); ext.Enabled.Data {
			sets = append(sets, readGeminiExtensionHooks(afs, ext.ext.dir)...)
		}
	}
	return geminiHookResources(r.MqlRuntime, sets)
}

func (r *mqlGeminiExtension) hooks() ([]any, error) {
	return geminiHookResources(r.MqlRuntime, readGeminiExtensionHooks(connectionAfs(r.MqlRuntime), r.ext.dir))
}

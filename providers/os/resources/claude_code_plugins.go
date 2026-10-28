// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/afero"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// claudePluginRootVar is the placeholder Claude Code substitutes with a
// plugin's install directory in the commands of the MCP servers it declares.
const claudePluginRootVar = "CLAUDE_PLUGIN_ROOT"

// claudePluginRecord is one install record of installed_plugins.json, with
// the enabled state that applies to it.
type claudePluginRecord struct {
	name    string
	entry   installedPluginEntry
	enabled bool
}

// claudePluginScopeRank orders user installs before project and local ones,
// so a plugin's user install is the one reported when several apply.
func claudePluginScopeRank(scope string) int {
	switch scope {
	case "user":
		return 0
	case "project":
		return 1
	default:
		return 2
	}
}

// claudeEnabledPlugins reads the `enabledPlugins` map of a settings file. A
// missing or unreadable file contributes nothing.
func claudeEnabledPlugins(afs *afero.Afero, path string) map[string]bool {
	var settings struct {
		EnabledPlugins map[string]bool `json:"enabledPlugins"`
	}
	data, err := readBoundedRegularFile(afs, path, maxConfigFileSize)
	if err != nil {
		return nil
	}
	if err := unmarshalJSONConfig(data, &settings); err != nil {
		return nil
	}
	return settings.EnabledPlugins
}

// readClaudePluginRecords reads installed_plugins.json in configDir. Each
// record is enabled according to the settings that apply to its scope: for a
// project or local install the project's settings.local.json, then its
// settings.json, then the user's settings.json; for a user install only the
// user's settings.json. Records are sorted by name, scope and project.
func readClaudePluginRecords(afs *afero.Afero, configDir string) ([]claudePluginRecord, error) {
	var installed struct {
		Plugins map[string][]installedPluginEntry `json:"plugins"`
	}
	if err := readJSONFileAfero(afs, configDir, filepath.Join("plugins", "installed_plugins.json"), &installed); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	userEnabled := claudeEnabledPlugins(afs, filepath.Join(configDir, "settings.json"))
	projectEnabled := map[string][]map[string]bool{}
	settingsFor := func(projectPath string) []map[string]bool {
		if projectPath == "" {
			return []map[string]bool{userEnabled}
		}
		if s, ok := projectEnabled[projectPath]; ok {
			return s
		}
		s := []map[string]bool{
			claudeEnabledPlugins(afs, filepath.Join(projectPath, ".claude", "settings.local.json")),
			claudeEnabledPlugins(afs, filepath.Join(projectPath, ".claude", "settings.json")),
			userEnabled,
		}
		projectEnabled[projectPath] = s
		return s
	}

	var records []claudePluginRecord
	for name, entries := range installed.Plugins {
		for _, entry := range entries {
			enabled := false
			for _, settings := range settingsFor(entry.ProjectPath) {
				if v, ok := settings[name]; ok {
					enabled = v
					break
				}
			}
			records = append(records, claudePluginRecord{name: name, entry: entry, enabled: enabled})
		}
	}
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.name != b.name {
			return a.name < b.name
		}
		if ra, rb := claudePluginScopeRank(a.entry.Scope), claudePluginScopeRank(b.entry.Scope); ra != rb {
			return ra < rb
		}
		return a.entry.ProjectPath < b.entry.ProjectPath
	})
	return records, nil
}

// claudePluginID is the resource id of a plugin install record. A user
// install keeps the historical "<name>/<scope>" id; project and local installs
// add the project path, since one plugin is installed once per project.
func claudePluginID(name, scope, projectPath string) string {
	id := "claude.code.plugin/" + name + "/" + scope
	if projectPath != "" {
		id += "/" + projectPath
	}
	return id
}

// claudePluginMarketplace returns the marketplace part of a plugin name of
// the form "<plugin>@<marketplace>".
func claudePluginMarketplace(name string) string {
	if _, after, ok := strings.CutLast(name, "@"); ok {
		return after
	}
	return ""
}

func (r *mqlClaudeCode) loadPluginRecords() ([]claudePluginRecord, error) {
	r.pluginsOnce.Do(func() {
		r.pluginRecords, r.pluginsErr = readClaudePluginRecords(r.afs(), r.configDir())
	})
	return r.pluginRecords, r.pluginsErr
}

// enabledPluginRecords returns the enabled plugin install records that have
// an install directory.
func (r *mqlClaudeCode) enabledPluginRecords() ([]claudePluginRecord, error) {
	records, err := r.loadPluginRecords()
	if err != nil {
		return nil, err
	}
	var out []claudePluginRecord
	for _, rec := range records {
		if rec.enabled && rec.entry.InstallPath != "" {
			out = append(out, rec)
		}
	}
	return out, nil
}

func (r *mqlClaudeCode) plugins() ([]any, error) {
	records, err := r.loadPluginRecords()
	if err != nil {
		return nil, err
	}

	result := make([]any, 0, len(records))
	for _, rec := range records {
		res, err := NewResource(r.MqlRuntime, "claude.code.plugin", map[string]*llx.RawData{
			"__id":         llx.StringData(claudePluginID(rec.name, rec.entry.Scope, rec.entry.ProjectPath)),
			"name":         llx.StringData(rec.name),
			"version":      llx.StringData(rec.entry.Version),
			"scope":        llx.StringData(rec.entry.Scope),
			"installPath":  llx.StringData(rec.entry.InstallPath),
			"installedAt":  llx.StringData(rec.entry.InstalledAt),
			"lastUpdated":  llx.StringData(rec.entry.LastUpdated),
			"gitCommitSha": llx.StringData(rec.entry.GitCommitSha),
			"enabled":      llx.BoolData(rec.enabled),
			"projectPath":  llx.StringData(rec.entry.ProjectPath),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlClaudeCodePlugin).parent = r
		result = append(result, res)
	}
	return result, nil
}

// claudeMarketplaceEntry is one marketplace in known_marketplaces.json.
type claudeMarketplaceEntry struct {
	Source struct {
		Source string `json:"source"`
		Repo   string `json:"repo"`
		URL    string `json:"url"`
		Path   string `json:"path"`
	} `json:"source"`
	InstallLocation string `json:"installLocation"`
	LastUpdated     string `json:"lastUpdated"`
}

// readClaudeMarketplaces reads plugins/known_marketplaces.json in configDir,
// keyed by marketplace name. A missing file means no marketplaces.
func readClaudeMarketplaces(afs *afero.Afero, configDir string) (map[string]claudeMarketplaceEntry, error) {
	var markets map[string]claudeMarketplaceEntry
	if err := readJSONFileAfero(afs, configDir, filepath.Join("plugins", "known_marketplaces.json"), &markets); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return markets, nil
}

func (r *mqlClaudeCode) marketplaces() ([]any, error) {
	markets, err := readClaudeMarketplaces(r.afs(), r.configDir())
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(markets))
	for name := range markets {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]any, 0, len(names))
	for _, name := range names {
		m := markets[name]
		res, err := NewResource(r.MqlRuntime, "claude.code.marketplace", map[string]*llx.RawData{
			"__id":            llx.StringData("claude.code.marketplace/" + name),
			"name":            llx.StringData(name),
			"sourceType":      llx.StringData(m.Source.Source),
			"repo":            llx.StringData(m.Source.Repo),
			"url":             llx.StringData(m.Source.URL),
			"path":            llx.StringData(m.Source.Path),
			"installLocation": llx.StringData(m.InstallLocation),
			"lastUpdated":     llx.TimeDataPtr(parseRFC3339Ptr(m.LastUpdated)),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlClaudeCodeMarketplace).parent = r
		result = append(result, res)
	}
	return result, nil
}

// claudePluginMcpServerResource creates the claude.code.mcpServer for a
// server a plugin declares. Claude Code registers it as
// "plugin:<plugin>:<server>", which the id follows; the server keeps its own
// name. Plugin servers are scoped to the project of a project or local install.
func claudePluginMcpServerResource(runtime *plugin.Runtime, pluginName, project string, s mcpServerSpec) (plugin.Resource, error) {
	fields := map[string]*llx.RawData{
		"__id":        llx.StringData(claudeMcpServerID(project, "plugin:"+pluginName+":"+s.name)),
		"name":        llx.StringData(s.name),
		"project":     llx.StringData(project),
		"type":        llx.StringData(s.transport),
		"command":     llx.StringData(s.command),
		"args":        strSliceToArrayData(s.args),
		"url":         llx.StringData(s.url),
		"hasEnv":      llx.BoolData(s.hasEnv),
		"hasHeaders":  llx.BoolData(s.hasHeaders),
		"needsAuth":   llx.BoolData(false),
		"lastChecked": llx.StringData(""),
		"plugin":      llx.StringData(pluginName),

		"headerNames": mcpHeaderNamesData(s.headerNames),
		"source":      llx.StringData(s.source),
	}
	setMcpServerShape(fields, s.command, s.args, s.url, s.envNames)
	return NewResource(runtime, "claude.code.mcpServer", fields)
}

// --- claude.code.plugin

type mqlClaudeCodePluginInternal struct {
	parent       *mqlClaudeCode
	manifestOnce sync.Once
	manifest     agentPlugin
}

func (r *mqlClaudeCodePlugin) id() (string, error) {
	return claudePluginID(r.Name.Data, r.Scope.Data, r.ProjectPath.Data), nil
}

func (r *mqlClaudeCodePlugin) loadManifest() agentPlugin {
	r.manifestOnce.Do(func() {
		r.manifest = readAgentPlugin(connectionAfs(r.MqlRuntime), r.InstallPath.Data, claudePluginRootVar)
	})
	return r.manifest
}

func (r *mqlClaudeCodePlugin) description() (string, error) {
	return r.loadManifest().manifest.Description, nil
}

func (r *mqlClaudeCodePlugin) author() (string, error) {
	return r.loadManifest().author, nil
}

func (r *mqlClaudeCodePlugin) repository() (string, error) {
	return r.loadManifest().repository, nil
}

func (r *mqlClaudeCodePlugin) homepage() (string, error) {
	return r.loadManifest().manifest.Homepage, nil
}

func (r *mqlClaudeCodePlugin) license() (string, error) {
	return r.loadManifest().manifest.License, nil
}

func (r *mqlClaudeCodePlugin) commands() ([]any, error) {
	return llx.TArr2Raw(r.loadManifest().commands), nil
}

func (r *mqlClaudeCodePlugin) agents() ([]any, error) {
	return llx.TArr2Raw(r.loadManifest().agents), nil
}

func (r *mqlClaudeCodePlugin) hasHooks() (bool, error) {
	return r.loadManifest().hasHooks, nil
}

func (r *mqlClaudeCodePlugin) skills() ([]any, error) {
	return readSkillsFromDirs(r.MqlRuntime, r.loadManifest().skillsDirs, "claude.code.skill")
}

func (r *mqlClaudeCodePlugin) mcpServers() ([]any, error) {
	var result []any
	for _, s := range r.loadManifest().mcpServers {
		res, err := claudePluginMcpServerResource(r.MqlRuntime, r.Name.Data, r.ProjectPath.Data, s)
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlClaudeCodePlugin) marketplace() (*mqlClaudeCodeMarketplace, error) {
	want := claudePluginMarketplace(r.Name.Data)
	if want != "" && r.parent != nil {
		markets := r.parent.GetMarketplaces()
		if markets.Error != nil {
			return nil, markets.Error
		}
		for _, m := range markets.Data {
			if mp := m.(*mqlClaudeCodeMarketplace); mp.Name.Data == want {
				return mp, nil
			}
		}
	}
	r.Marketplace.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// --- claude.code.marketplace

type mqlClaudeCodeMarketplaceInternal struct {
	parent *mqlClaudeCode
}

func (r *mqlClaudeCodeMarketplace) id() (string, error) {
	return "claude.code.marketplace/" + r.Name.Data, nil
}

func (r *mqlClaudeCodeMarketplace) plugins() ([]any, error) {
	if r.parent == nil {
		return []any{}, nil
	}
	all := r.parent.GetPlugins()
	if all.Error != nil {
		return nil, all.Error
	}
	result := []any{}
	for _, p := range all.Data {
		if claudePluginMarketplace(p.(*mqlClaudeCodePlugin).Name.Data) == r.Name.Data {
			result = append(result, p)
		}
	}
	return result, nil
}

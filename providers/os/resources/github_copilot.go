// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/spf13/afero"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func initGithubCopilot(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initOSConfigPath(runtime, args, "github.copilot", gitHubCopilotConfigDir)
}

// gitHubCopilotConfigDir returns where the Copilot language server keeps
// apps.json, relative to the user's home: %USERPROFILE%\AppData\Local\github-copilot
// on Windows and ~/.config/github-copilot elsewhere (its getXdgConfigPath).
func gitHubCopilotConfigDir(osFamily string) string {
	if osFamily == "windows" {
		return filepath.Join("AppData", "Local", "github-copilot")
	}
	return filepath.Join(".config", "github-copilot")
}

func (r *mqlGithubCopilot) id() (string, error) {
	return "github.copilot/" + r.ConfigPath.Data, nil
}

func (r *mqlGithubCopilot) accounts() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	configDir := r.ConfigPath.Data

	data, err := afs.ReadFile(filepath.Join(configDir, "apps.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	// apps.json is a map of "host:appId" -> account info
	var apps map[string]copilotApp
	if err := unmarshalJSONConfig(data, &apps); err != nil {
		return nil, fmt.Errorf("failed to parse github-copilot apps.json: %w", err)
	}

	var result []any
	for key, app := range apps {
		res, err := NewResource(r.MqlRuntime, "github.copilot.account", map[string]*llx.RawData{
			"__id":        llx.StringData("github.copilot.account/" + key),
			"user":        llx.StringData(app.User),
			"githubAppId": llx.StringData(app.GitHubAppID),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlGithubCopilot) mcpServers() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	configDir := r.ConfigPath.Data

	// The language server's own files (VS Code and JetBrains integrations of
	// older releases) use a `servers` key.
	var specs []mcpServerSpec
	for _, path := range []string{
		filepath.Join(configDir, "mcp.json"),
		filepath.Join(configDir, "intellij", "mcp.json"),
	} {
		fileSpecs, err := readMcpServersFile(afs, path, "servers")
		if err != nil {
			continue // skip malformed files
		}
		specs = append(specs, fileSpecs...)
	}

	home, err := targetHomeDir(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	cli := readCopilotCLISettings(afs, home)

	// The Copilot CLI's user servers, which settings.json can disable.
	cliSpecs, err := readMcpServersFile(afs, filepath.Join(home, ".copilot", "mcp-config.json"), "mcpServers")
	if err != nil {
		return nil, err
	}
	for _, spec := range cliSpecs {
		spec.enabled = spec.enabled && !cli.disabled(spec.name)
		specs = append(specs, spec)
	}

	// VS Code's user-level mcp.json, which Copilot Chat's agent mode uses.
	vscodeSpecs, err := readMcpServersFile(afs,
		filepath.Join(vscodeUserDataDir(home, runtimeOSFamily(r.MqlRuntime), "Code"), "mcp.json"), "servers")
	if err != nil {
		return nil, err
	}
	specs = append(specs, vscodeSpecs...)

	var result []any
	for _, spec := range specs {
		res, err := NewResource(r.MqlRuntime, "github.copilot.mcpServer", copilotMcpServerArgs(spec))
		if err != nil {
			return nil, err
		}
		res.(*mqlGithubCopilotMcpServer).Plugin.State = plugin.StateIsSet | plugin.StateIsNull
		result = append(result, res)
	}

	// Servers declared by enabled Copilot CLI plugins.
	plugins := r.GetPlugins()
	if plugins.Error != nil {
		return nil, plugins.Error
	}
	for _, p := range plugins.Data {
		cp := p.(*mqlGithubCopilotPlugin)
		if !cp.Enabled.Data {
			continue
		}
		servers := cp.GetMcpServers()
		if servers.Error != nil {
			return nil, servers.Error
		}
		result = append(result, servers.Data...)
	}
	return result, nil
}

// copilotLegacyMcpSource reports whether a server comes from the language
// server's own mcp.json files, whose servers keep the historical name-only id.
func copilotLegacyMcpSource(source string) bool {
	dir := filepath.Base(filepath.Dir(source))
	return dir == "github-copilot" || dir == "intellij"
}

func copilotMcpServerID(source, name string) string {
	if copilotLegacyMcpSource(source) {
		return "github.copilot.mcpServer/" + name
	}
	return mcpServerResourceID("github.copilot.mcpServer", source, name)
}

func copilotMcpServerArgs(spec mcpServerSpec) map[string]*llx.RawData {
	args := mcpServerResourceArgs("github.copilot.mcpServer", spec)
	args["__id"] = llx.StringData(copilotMcpServerID(spec.source, spec.name))
	return args
}

// copilotCLISettings holds what ~/.copilot/settings.json says about MCP
// servers and plugins.
type copilotCLISettings struct {
	DisabledMcpServers []string        `json:"disabledMcpServers"`
	EnabledPlugins     map[string]bool `json:"enabledPlugins"`
}

func (c copilotCLISettings) disabled(name string) bool {
	return slices.Contains(c.DisabledMcpServers, name)
}

// readCopilotCLISettings reads ~/.copilot/settings.json under home. A missing
// or unreadable file means the defaults: nothing disabled.
func readCopilotCLISettings(afs *afero.Afero, home string) copilotCLISettings {
	var settings copilotCLISettings
	data, err := readBoundedRegularFile(afs, filepath.Join(home, ".copilot", "settings.json"), maxConfigFileSize)
	if err != nil {
		return settings
	}
	_ = decodeJSONC(data, &settings)
	return settings
}

// copilotInstalledPlugin is one plugin record in ~/.copilot/config.json.
type copilotInstalledPlugin struct {
	Name        string `json:"name"`
	Marketplace string `json:"marketplace"`
	Version     string `json:"version"`
	InstalledAt string `json:"installed_at"`
	CachePath   string `json:"cache_path"`
	SourceSha   string `json:"source_sha"`
	Enabled     *bool  `json:"enabled"`
}

// key is the "<name>@<marketplace>" form settings.json uses.
func (p copilotInstalledPlugin) key() string {
	if p.Marketplace == "" {
		return p.Name
	}
	return p.Name + "@" + p.Marketplace
}

// readCopilotPlugins reads the installed plugins from ~/.copilot/config.json
// under home, a file the CLI writes with leading comments. A missing file
// means no plugins.
func readCopilotPlugins(afs *afero.Afero, home string) ([]copilotInstalledPlugin, error) {
	data, err := readBoundedRegularFile(afs, filepath.Join(home, ".copilot", "config.json"), maxConfigFileSize)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var config struct {
		InstalledPlugins []copilotInstalledPlugin `json:"installedPlugins"`
	}
	if err := decodeJSONC(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse copilot config.json: %w", err)
	}
	return config.InstalledPlugins, nil
}

// enabled reports whether a plugin is enabled: settings.json's enabledPlugins
// decides when it names the plugin, otherwise the install record does.
func (c copilotCLISettings) pluginEnabled(p copilotInstalledPlugin) bool {
	if v, ok := c.EnabledPlugins[p.key()]; ok {
		return v
	}
	return p.Enabled == nil || *p.Enabled
}

func (r *mqlGithubCopilot) plugins() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	home, err := targetHomeDir(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	installed, err := readCopilotPlugins(afs, home)
	if err != nil {
		return nil, err
	}
	settings := readCopilotCLISettings(afs, home)

	result := make([]any, 0, len(installed))
	for _, p := range installed {
		res, err := NewResource(r.MqlRuntime, "github.copilot.plugin", map[string]*llx.RawData{
			"__id":        llx.StringData("github.copilot.plugin/" + p.CachePath),
			"name":        llx.StringData(p.Name),
			"marketplace": llx.StringData(p.Marketplace),
			"version":     llx.StringData(p.Version),
			"path":        llx.StringData(p.CachePath),
			"installedAt": llx.TimeDataPtr(parseRFC3339Ptr(p.InstalledAt)),
			"sourceSha":   llx.StringData(p.SourceSha),
			"enabled":     llx.BoolData(settings.pluginEnabled(p)),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlGithubCopilotPlugin).settings = settings
		result = append(result, res)
	}
	return result, nil
}

type mqlGithubCopilotPluginInternal struct {
	settings     copilotCLISettings
	manifestOnce sync.Once
	manifest     agentPlugin
}

func (r *mqlGithubCopilotPlugin) id() (string, error) {
	return "github.copilot.plugin/" + r.Path.Data, nil
}

func (r *mqlGithubCopilotPlugin) loadManifest() agentPlugin {
	r.manifestOnce.Do(func() {
		r.manifest = readAgentPlugin(connectionAfs(r.MqlRuntime), r.Path.Data, "")
	})
	return r.manifest
}

func (r *mqlGithubCopilotPlugin) description() (string, error) {
	return r.loadManifest().manifest.Description, nil
}

func (r *mqlGithubCopilotPlugin) author() (string, error) {
	return r.loadManifest().author, nil
}

func (r *mqlGithubCopilotPlugin) repository() (string, error) {
	return r.loadManifest().repository, nil
}

func (r *mqlGithubCopilotPlugin) agents() ([]any, error) {
	return llx.TArr2Raw(r.loadManifest().agents), nil
}

func (r *mqlGithubCopilotPlugin) hasHooks() (bool, error) {
	return r.loadManifest().hasHooks, nil
}

func (r *mqlGithubCopilotPlugin) skills() ([]any, error) {
	return readSkillsFromDirs(r.MqlRuntime, r.loadManifest().skillsDirs, "github.copilot.skill")
}

func (r *mqlGithubCopilotPlugin) mcpServers() ([]any, error) {
	var result []any
	for _, spec := range r.loadManifest().mcpServers {
		spec.enabled = r.Enabled.Data && !r.settings.disabled(spec.name)
		res, err := NewResource(r.MqlRuntime, "github.copilot.mcpServer", copilotMcpServerArgs(spec))
		if err != nil {
			return nil, err
		}
		srv := res.(*mqlGithubCopilotMcpServer)
		srv.Plugin = plugin.TValue[*mqlGithubCopilotPlugin]{Data: r, State: plugin.StateIsSet}
		result = append(result, srv)
	}
	return result, nil
}

func (r *mqlGithubCopilotMcpServer) plugin() (*mqlGithubCopilotPlugin, error) {
	r.Plugin.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (r *mqlGithubCopilot) skills() ([]any, error) {
	// Copilot skills live at ~/.copilot/skills/, independent of the config dir.
	users, err := targetUserHomes(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	dirs := make([]string, 0, len(users))
	for _, u := range users {
		dirs = append(dirs, filepath.Join(u.home, ".copilot", "skills"))
	}

	// Skills of enabled Copilot CLI plugins are available as well.
	plugins := r.GetPlugins()
	if plugins.Error != nil {
		return nil, plugins.Error
	}
	for _, p := range plugins.Data {
		if cp := p.(*mqlGithubCopilotPlugin); cp.Enabled.Data {
			dirs = append(dirs, cp.loadManifest().skillsDirs...)
		}
	}
	return readSkillsFromDirs(r.MqlRuntime, dirs, "github.copilot.skill")
}

// Child resource ID methods

func (r *mqlGithubCopilotAccount) id() (string, error) {
	return "github.copilot.account/" + r.User.Data, nil
}

func (r *mqlGithubCopilotMcpServer) running() (*llx.AssetValue, error) {
	return mcpServerAsset(r), nil
}

// MqlAsset implements plugin.AssetSource: the asset the `running` anchor stands
// for, with the connection needed to reach it. See mcpServerAssetFor.
func (r *mqlGithubCopilotMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

func (r *mqlGithubCopilotMcpServer) id() (string, error) {
	return copilotMcpServerID(r.Source.Data, r.Name.Data), nil
}

func (r *mqlGithubCopilotSkill) id() (string, error) {
	return "github.copilot.skill/" + r.Source.Data, nil
}

func (r *mqlGithubCopilotSkill) sha256() (string, error) {
	return contentSHA256(r.Content.Data), nil
}

func (r *mqlGithubCopilotSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// Helper types

type copilotApp struct {
	User        string `json:"user"`
	OAuthToken  string `json:"oauth_token"`
	GitHubAppID string `json:"githubAppId"`
}

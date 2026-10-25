// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// homeLinkTarget returns the target of the symlink at rel under the first
// user home that has one, as written in the link. Empty when no home does.
// The link is read, never followed into anything that runs.
func homeLinkTarget(runtime *plugin.Runtime, rel string) (string, error) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return "", nil
	}
	homes, err := targetUserHomes(runtime)
	if err != nil {
		return "", err
	}
	paths := make([]string, 0, len(homes))
	for _, u := range homes {
		paths = append(paths, filepath.Join(u.home, filepath.FromSlash(rel)))
	}
	targets, err := readSymlinkTargets(conn, paths)
	if err != nil {
		return "", nil
	}
	for _, p := range paths {
		if t := targets[p]; t != "" {
			return t, nil
		}
	}
	return "", nil
}

// --- Devin CLI ---

// devinCLIVersionLink is the symlink the Devin CLI's install script points at
// the active release directory, <home>/.local/share/devin/cli/_versions/<version>.
const devinCLIVersionLink = ".local/share/devin/cli/_versions/current"

func initDevinCli(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initOSConfigPath(runtime, args, "devin.cli", devinDesktopConfigDir)
}

func (r *mqlDevinCli) id() (string, error) {
	return "devin.cli/" + r.ConfigPath.Data, nil
}

func (r *mqlDevinCli) skills() ([]any, error) {
	defaultDir := devinDesktopConfigDir(runtimeOSFamily(r.MqlRuntime))
	return agentSkills(r.MqlRuntime, "devin.cli.skill", r.ConfigPath.Data, defaultDir,
		filepath.Join(defaultDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

// mcpServers reads mcp_config.json, then the `mcpServers` key of config.json,
// where releases before 3000.3 kept them (the CLI migrates them on start).
func (r *mqlDevinCli) mcpServers() ([]any, error) {
	specs, err := readMcpServersFiles(connectionAfs(r.MqlRuntime), []string{
		filepath.Join(r.ConfigPath.Data, "mcp_config.json"),
		filepath.Join(r.ConfigPath.Data, "config.json"),
	}, "mcpServers")
	if err != nil {
		return nil, err
	}
	return newMcpServerResources(r.MqlRuntime, "devin.cli.mcpServer", specs)
}

func (r *mqlDevinCliMcpServer) id() (string, error) {
	return mcpServerResourceID("devin.cli.mcpServer", r.Source.Data, r.Name.Data), nil
}

func (r *mqlDevinCliMcpServer) running() (*llx.AssetValue, error) { return mcpServerAsset(r), nil }

// MqlAsset implements plugin.AssetSource. See mcpServerAssetFor.
func (r *mqlDevinCliMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

func (r *mqlDevinCliSkill) id() (string, error)     { return "devin.cli.skill/" + r.Source.Data, nil }
func (r *mqlDevinCliSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlDevinCliSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// inferDevinCLIVersion reads the release the install script's
// _versions/current link points at. Homebrew installs resolve through the cask
// instead, and Windows installs keep no such link.
func inferDevinCLIVersion(runtime *plugin.Runtime, _ string) (string, error) {
	target, err := homeLinkTarget(runtime, devinCLIVersionLink)
	if err != nil {
		return "", err
	}
	return devinCLIVersionFromLink(target), nil
}

// devinCLIVersionFromLink returns the release a _versions/current link names
// ("3000.11.205"), or "" when the target is not a version.
func devinCLIVersionFromLink(target string) string {
	if target == "" {
		return ""
	}
	v := path.Base(filepath.ToSlash(target))
	if !isSemverVersion(v) {
		return ""
	}
	return v
}

// --- Cursor CLI ---

// defaultCursorCLIConfigFile is the Cursor CLI's own configuration file. The
// editor never writes it, so unlike the rest of ~/.cursor it marks the CLI.
var defaultCursorCLIConfigFile = filepath.Join(".cursor", "cli-config.json")

// cursorCLIBinLink is the link the install script puts on the PATH, pointing
// at <home>/.local/share/cursor-agent/versions/<version>/cursor-agent.
const cursorCLIBinLink = ".local/bin/cursor-agent"

type mqlCursorCliInternal struct {
	configOnce sync.Once
	config     *cursorCLIConfig
	configErr  error
}

// cursorCLIConfig holds the settings of cli-config.json that bound what the
// agent may do without asking.
type cursorCLIConfig struct {
	ApprovalMode string `json:"approvalMode"`
	Sandbox      struct {
		Mode          string          `json:"mode"`
		NetworkAccess json.RawMessage `json:"networkAccess"`
	} `json:"sandbox"`
	Permissions struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	} `json:"permissions"`
}

func initCursorCli(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "cursor.cli", defaultCursorCLIConfigFile)
}

func (r *mqlCursorCli) id() (string, error) {
	return "cursor.cli/" + r.ConfigPath.Data, nil
}

func (r *mqlCursorCli) loadConfig() (*cursorCLIConfig, error) {
	r.configOnce.Do(func() {
		data, err := readBoundedRegularFile(connectionAfs(r.MqlRuntime), r.ConfigPath.Data, maxConfigFileSize)
		if err != nil {
			if os.IsNotExist(err) {
				r.config = &cursorCLIConfig{}
				return
			}
			r.configErr = err
			return
		}
		r.config, r.configErr = parseCursorCLIConfig(data)
	})
	return r.config, r.configErr
}

func parseCursorCLIConfig(data []byte) (*cursorCLIConfig, error) {
	var cfg cursorCLIConfig
	if err := decodeJSONC(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// rawSetting renders a setting documented as a string, keeping a value of
// another JSON type as written rather than failing the whole file.
func rawSetting(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return strings.TrimSpace(string(raw))
}

func (r *mqlCursorCli) approvalMode() (string, error) {
	cfg, err := r.loadConfig()
	if err != nil {
		return "", err
	}
	return cfg.ApprovalMode, nil
}

func (r *mqlCursorCli) sandboxMode() (string, error) {
	cfg, err := r.loadConfig()
	if err != nil {
		return "", err
	}
	return cfg.Sandbox.Mode, nil
}

func (r *mqlCursorCli) sandboxNetworkAccess() (string, error) {
	cfg, err := r.loadConfig()
	if err != nil {
		return "", err
	}
	return rawSetting(cfg.Sandbox.NetworkAccess), nil
}

func (r *mqlCursorCli) allowedPermissions() ([]any, error) {
	cfg, err := r.loadConfig()
	if err != nil {
		return nil, err
	}
	return strSliceToAny(cfg.Permissions.Allow), nil
}

func (r *mqlCursorCli) deniedPermissions() ([]any, error) {
	cfg, err := r.loadConfig()
	if err != nil {
		return nil, err
	}
	return strSliceToAny(cfg.Permissions.Deny), nil
}

// inferCursorCLIVersion reads the release the install script's
// ~/.local/bin/cursor-agent link points into. Homebrew installs resolve
// through the cask instead.
func inferCursorCLIVersion(runtime *plugin.Runtime, _ string) (string, error) {
	target, err := homeLinkTarget(runtime, cursorCLIBinLink)
	if err != nil {
		return "", err
	}
	return cursorCLIVersionFromLink(target), nil
}

// cursorCLIVersionFromLink returns <version> from a link target of the form
// .../cursor-agent/versions/<version>/cursor-agent, or "" for any other shape.
// Versions are date stamps with the commit appended ("2026.10.22-27dcf5f").
func cursorCLIVersionFromLink(target string) string {
	dir := path.Dir(filepath.ToSlash(target))
	if target == "" || path.Base(path.Dir(dir)) != "versions" {
		return ""
	}
	return path.Base(dir)
}

// --- CodeRabbit CLI ---

// defaultCoderabbitCLIConfigDir holds the CLI's login, review history and
// findings. Only the CLI creates it.
const defaultCoderabbitCLIConfigDir = ".coderabbit"

func initCoderabbitCli(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "coderabbit.cli", defaultCoderabbitCLIConfigDir)
}

func (r *mqlCoderabbitCli) id() (string, error) {
	return "coderabbit.cli/" + r.ConfigPath.Data, nil
}

// --- DeepSeek Harness ---

// defaultDeepseekHarnessConfigDir is the harness home (DSH_HOME), .dsh under
// the user's home on every platform.
const defaultDeepseekHarnessConfigDir = ".dsh"

// dshMcpClientPlugin is the plugin a cordis.patch.yml row names to declare one
// MCP server; the server's definition is the row's config.
const dshMcpClientPlugin = "@deepseek-ai/dsh-mcp-client"

func initDeepseekHarness(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "deepseek.harness", defaultDeepseekHarnessConfigDir)
}

func (r *mqlDeepseekHarness) id() (string, error) {
	return "deepseek.harness/" + r.ConfigPath.Data, nil
}

func (r *mqlDeepseekHarness) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "deepseek.harness.skill", r.ConfigPath.Data, defaultDeepseekHarnessConfigDir,
		filepath.Join(defaultDeepseekHarnessConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

// mcpServers reads the machine-wide cordis.patch.yml at the harness home, then
// each profile's (the desktop app runs the "desktop" profile).
func (r *mqlDeepseekHarness) mcpServers() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	paths := []string{filepath.Join(r.ConfigPath.Data, "cordis.patch.yml")}
	profiles, err := listSubdirsAfero(afs, filepath.Join(r.ConfigPath.Data, "profiles"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, p := range profiles {
		paths = append(paths, filepath.Join(p.path, "cordis.patch.yml"))
	}

	var specs []mcpServerSpec
	for _, p := range paths {
		data, err := readBoundedRegularFile(afs, p, maxConfigFileSize)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		fileSpecs, err := parseDshPatchMcpServers(data, p)
		if err != nil {
			return nil, err
		}
		specs = append(specs, fileSpecs...)
	}
	return newMcpServerResources(r.MqlRuntime, "deepseek.harness.mcpServer", specs)
}

// dshPluginRow is one plugin row of a cordis.patch.yml `insert` patch. Values
// the harness evaluates (`cwd: !!js process.cwd()`) stay yaml nodes, so a tag
// the decoder does not know never fails the row.
type dshPluginRow struct {
	ID     string `yaml:"id"`
	Name   string `yaml:"name"`
	Config struct {
		ServerName string    `yaml:"serverName"`
		Transport  string    `yaml:"transport"`
		Command    string    `yaml:"command"`
		Args       yaml.Node `yaml:"args"`
		URL        string    `yaml:"url"`
		Env        yaml.Node `yaml:"env"`
		Headers    yaml.Node `yaml:"headers"`
	} `yaml:"config"`
}

// parseDshPatchMcpServers returns the MCP servers a cordis.patch.yml inserts,
// sorted by name: every row of an `insert` patch that names the harness's MCP
// client plugin. The file is a list of patches; other patch kinds and other
// plugins are skipped.
func parseDshPatchMcpServers(data []byte, source string) ([]mcpServerSpec, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, nil
	}
	patches := []*yaml.Node{doc.Content[0]}
	if doc.Content[0].Kind == yaml.SequenceNode {
		patches = doc.Content[0].Content
	}

	var specs []mcpServerSpec
	for _, patch := range patches {
		rows := yamlMappingValue(patch, "insert")
		if rows == nil || rows.Kind != yaml.SequenceNode {
			continue
		}
		for _, node := range rows.Content {
			var row dshPluginRow
			if err := node.Decode(&row); err != nil || row.Name != dshMcpClientPlugin {
				continue
			}
			name := row.Config.ServerName
			if name == "" {
				name = row.ID
			}
			specs = append(specs, mcpServerSpec{
				name:       name,
				transport:  deriveMcpTransport(row.Config.Transport, row.Config.Command, row.Config.URL),
				command:    row.Config.Command,
				args:       yamlScalars(&row.Config.Args),
				url:        row.Config.URL,
				hasEnv:     yamlNonEmpty(&row.Config.Env),
				hasHeaders: yamlNonEmpty(&row.Config.Headers),
				enabled:    true,
				source:     source,
			})
		}
	}
	sort.SliceStable(specs, func(i, j int) bool { return specs[i].name < specs[j].name })
	return specs, nil
}

// yamlMappingValue returns the value node of key in a mapping node, nil when
// the node is not a mapping or has no such key.
func yamlMappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// yamlScalars returns the scalar items of a sequence node, as written.
func yamlScalars(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]string, 0, len(n.Content))
	for _, item := range n.Content {
		if item.Kind == yaml.ScalarNode {
			out = append(out, item.Value)
		}
	}
	return out
}

// yamlNonEmpty reports whether a node holds a value: a mapping or sequence
// with entries, or a scalar other than null (an expression the harness
// evaluates counts).
func yamlNonEmpty(n *yaml.Node) bool {
	if n == nil {
		return false
	}
	switch n.Kind {
	case yaml.MappingNode, yaml.SequenceNode:
		return len(n.Content) > 0
	case yaml.ScalarNode:
		return n.Tag != "!!null" && n.Value != ""
	}
	return false
}

func (r *mqlDeepseekHarnessMcpServer) id() (string, error) {
	return mcpServerResourceID("deepseek.harness.mcpServer", r.Source.Data, r.Name.Data), nil
}

func (r *mqlDeepseekHarnessMcpServer) running() (*llx.AssetValue, error) {
	return mcpServerAsset(r), nil
}

// MqlAsset implements plugin.AssetSource. See mcpServerAssetFor.
func (r *mqlDeepseekHarnessMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

func (r *mqlDeepseekHarnessSkill) id() (string, error) {
	return "deepseek.harness.skill/" + r.Source.Data, nil
}
func (r *mqlDeepseekHarnessSkill) sha256() (string, error) { return contentSHA256(r.Content.Data), nil }
func (r *mqlDeepseekHarnessSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

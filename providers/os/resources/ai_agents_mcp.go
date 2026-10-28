// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/spf13/afero"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// MCP servers of the AI agents whose configuration is a single file of a
// common shape. Every file layout here was written by the agent's own
// `mcp add` command.

// readMcpServersFiles reads the MCP servers of several JSON config files,
// each under the same key, in order.
func readMcpServersFiles(afs *afero.Afero, paths []string, key string) ([]mcpServerSpec, error) {
	var specs []mcpServerSpec
	for _, path := range paths {
		fileSpecs, err := readMcpServersFile(afs, path, key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", path, err)
		}
		specs = append(specs, fileSpecs...)
	}
	return specs, nil
}

// --- Augment: `mcpServers` in ~/.augment/settings.json

func (r *mqlAugment) mcpServers() ([]any, error) {
	specs, err := readMcpServersFiles(connectionAfs(r.MqlRuntime),
		[]string{filepath.Join(r.ConfigPath.Data, "settings.json")}, "mcpServers")
	if err != nil {
		return nil, err
	}
	return newMcpServerResources(r.MqlRuntime, "augment.mcpServer", specs)
}

func (r *mqlAugmentMcpServer) id() (string, error) {
	return mcpServerResourceID("augment.mcpServer", r.Source.Data, r.Name.Data), nil
}

func (r *mqlAugmentMcpServer) running() (*llx.AssetValue, error) { return mcpServerAsset(r), nil }

// MqlAsset implements plugin.AssetSource. See mcpServerAssetFor.
func (r *mqlAugmentMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

// --- OpenHands: `mcpServers` in ~/.openhands/mcp.json

func (r *mqlOpenhands) mcpServers() ([]any, error) {
	specs, err := readMcpServersFiles(connectionAfs(r.MqlRuntime),
		[]string{filepath.Join(r.ConfigPath.Data, "mcp.json")}, "mcpServers")
	if err != nil {
		return nil, err
	}
	return newMcpServerResources(r.MqlRuntime, "openhands.mcpServer", specs)
}

func (r *mqlOpenhandsMcpServer) id() (string, error) {
	return mcpServerResourceID("openhands.mcpServer", r.Source.Data, r.Name.Data), nil
}

func (r *mqlOpenhandsMcpServer) running() (*llx.AssetValue, error) { return mcpServerAsset(r), nil }

// MqlAsset implements plugin.AssetSource. See mcpServerAssetFor.
func (r *mqlOpenhandsMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

// --- Cline CLI: `mcpServers` in ~/.cline/data/settings/cline_mcp_settings.json

func (r *mqlCline) mcpServers() ([]any, error) {
	specs, err := readMcpServersFiles(connectionAfs(r.MqlRuntime),
		[]string{filepath.Join(r.ConfigPath.Data, "data", "settings", "cline_mcp_settings.json")}, "mcpServers")
	if err != nil {
		return nil, err
	}
	return newMcpServerResources(r.MqlRuntime, "cline.mcpServer", specs)
}

func (r *mqlClineMcpServer) id() (string, error) {
	return mcpServerResourceID("cline.mcpServer", r.Source.Data, r.Name.Data), nil
}

func (r *mqlClineMcpServer) running() (*llx.AssetValue, error) { return mcpServerAsset(r), nil }

// MqlAsset implements plugin.AssetSource. See mcpServerAssetFor.
func (r *mqlClineMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

// --- Mistral Vibe: [[mcp_servers]] tables in ~/.vibe/config.toml

type vibeConfig struct {
	McpServers []vibeMcpServer `toml:"mcp_servers"`
}

// vibeMcpServer is one [[mcp_servers]] table. A remote server's static
// headers sit in `headers` or, as `vibe mcp add --header` writes them, in
// auth.headers; api_key_env names an environment variable holding a token.
type vibeMcpServer struct {
	Name      string            `toml:"name"`
	Transport string            `toml:"transport"`
	Command   string            `toml:"command"`
	Args      []string          `toml:"args"`
	URL       string            `toml:"url"`
	Env       map[string]string `toml:"env"`
	Headers   map[string]string `toml:"headers"`
	APIKeyEnv string            `toml:"api_key_env"`
	Disabled  bool              `toml:"disabled"`
	Auth      struct {
		Type    string            `toml:"type"`
		Headers map[string]string `toml:"headers"`
	} `toml:"auth"`
}

// parseVibeMcpServers reads the MCP servers of a Mistral Vibe config.toml, in
// file order.
func parseVibeMcpServers(data []byte, source string) ([]mcpServerSpec, error) {
	var config vibeConfig
	if err := toml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	specs := make([]mcpServerSpec, 0, len(config.McpServers))
	for _, s := range config.McpServers {
		specs = append(specs, mcpServerSpec{
			name:       s.Name,
			transport:  deriveMcpTransport(s.Transport, s.Command, s.URL),
			command:    s.Command,
			args:       s.Args,
			url:        s.URL,
			hasEnv:     len(s.Env) > 0,
			hasHeaders: len(s.Headers) > 0 || len(s.Auth.Headers) > 0 || s.APIKeyEnv != "",
			enabled:    !s.Disabled,
			source:     source,

			envNames:    mcpNames(mapKeys(s.Env)),
			headerNames: mcpNames(mapKeys(s.Headers), mapKeys(s.Auth.Headers)),
		})
	}
	return specs, nil
}

func (r *mqlMistralVibe) mcpServers() ([]any, error) {
	path := filepath.Join(r.ConfigPath.Data, "config.toml")
	data, err := readBoundedRegularFile(connectionAfs(r.MqlRuntime), path, maxConfigFileSize)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	specs, err := parseVibeMcpServers(data, path)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return newMcpServerResources(r.MqlRuntime, "mistral.vibe.mcpServer", specs)
}

func (r *mqlMistralVibeMcpServer) id() (string, error) {
	return mcpServerResourceID("mistral.vibe.mcpServer", r.Source.Data, r.Name.Data), nil
}

func (r *mqlMistralVibeMcpServer) running() (*llx.AssetValue, error) { return mcpServerAsset(r), nil }

// MqlAsset implements plugin.AssetSource. See mcpServerAssetFor.
func (r *mqlMistralVibeMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

// --- OpenCode and Kilo: `mcp` and `plugin` in opencode.json(c) / kilo.json(c)

// opencodeConfigFiles are the OpenCode config files of a configuration
// directory, in the order OpenCode merges them.
func opencodeConfigFiles(dir string) []string {
	return []string{filepath.Join(dir, "opencode.json"), filepath.Join(dir, "opencode.jsonc")}
}

// kiloConfigFiles are the config files of the Kilo CLI, a fork of OpenCode
// that reads its own kilo.json(c) and OpenCode's files in ~/.config/kilo.
// `kilo mcp add` writes kilo.jsonc and `kilo plugin` writes opencode.json.
func kiloConfigFiles(home string) []string {
	dir := filepath.Join(home, ".config", "kilo")
	return []string{
		filepath.Join(dir, "kilo.json"), filepath.Join(dir, "kilo.jsonc"),
		filepath.Join(dir, "opencode.json"), filepath.Join(dir, "opencode.jsonc"),
	}
}

// readOpencodePlugins returns the `plugin` entries of OpenCode-format config
// files, deduplicated in file order.
func readOpencodePlugins(afs *afero.Afero, paths []string) ([]string, error) {
	seen := map[string]struct{}{}
	var plugins []string
	for _, path := range paths {
		data, err := readBoundedRegularFile(afs, path, maxConfigFileSize)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		var config struct {
			Plugin []string `json:"plugin"`
		}
		if err := decodeJSONC(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", path, err)
		}
		for _, p := range config.Plugin {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				plugins = append(plugins, p)
			}
		}
	}
	return plugins, nil
}

func (r *mqlOpencode) mcpServers() ([]any, error) {
	specs, err := readMcpServersFiles(connectionAfs(r.MqlRuntime), opencodeConfigFiles(r.ConfigPath.Data), "mcp")
	if err != nil {
		return nil, err
	}
	return newMcpServerResources(r.MqlRuntime, "opencode.mcpServer", specs)
}

func (r *mqlOpencode) plugins() ([]any, error) {
	plugins, err := readOpencodePlugins(connectionAfs(r.MqlRuntime), opencodeConfigFiles(r.ConfigPath.Data))
	if err != nil {
		return nil, err
	}
	return llx.TArr2Raw(plugins), nil
}

func (r *mqlOpencodeMcpServer) id() (string, error) {
	return mcpServerResourceID("opencode.mcpServer", r.Source.Data, r.Name.Data), nil
}

func (r *mqlOpencodeMcpServer) running() (*llx.AssetValue, error) { return mcpServerAsset(r), nil }

// MqlAsset implements plugin.AssetSource. See mcpServerAssetFor.
func (r *mqlOpencodeMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

// kiloHome is the home directory that owns the Kilo Code configuration
// directory (~/.kilocode), where ~/.config/kilo of the Kilo CLI also lives.
func (r *mqlKilocode) kiloHome() string {
	return filepath.Dir(r.ConfigPath.Data)
}

func (r *mqlKilocode) mcpServers() ([]any, error) {
	specs, err := readMcpServersFiles(connectionAfs(r.MqlRuntime), kiloConfigFiles(r.kiloHome()), "mcp")
	if err != nil {
		return nil, err
	}
	return newMcpServerResources(r.MqlRuntime, "kilocode.mcpServer", specs)
}

func (r *mqlKilocode) plugins() ([]any, error) {
	plugins, err := readOpencodePlugins(connectionAfs(r.MqlRuntime), kiloConfigFiles(r.kiloHome()))
	if err != nil {
		return nil, err
	}
	return llx.TArr2Raw(plugins), nil
}

func (r *mqlKilocodeMcpServer) id() (string, error) {
	return mcpServerResourceID("kilocode.mcpServer", r.Source.Data, r.Name.Data), nil
}

func (r *mqlKilocodeMcpServer) running() (*llx.AssetValue, error) { return mcpServerAsset(r), nil }

// MqlAsset implements plugin.AssetSource. See mcpServerAssetFor.
func (r *mqlKilocodeMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

// --- Qwen Code: `mcpServers` in ~/.qwen/settings.json, plus extensions

func (r *mqlQwenCode) mcpServers() ([]any, error) {
	specs, err := readMcpServersFiles(connectionAfs(r.MqlRuntime),
		[]string{filepath.Join(r.ConfigPath.Data, "settings.json")}, "mcpServers")
	if err != nil {
		return nil, err
	}
	result, err := newMcpServerResources(r.MqlRuntime, "qwen.code.mcpServer", specs)
	if err != nil {
		return nil, err
	}
	for _, res := range result {
		res.(*mqlQwenCodeMcpServer).Extension.State = plugin.StateIsSet | plugin.StateIsNull
	}

	exts := r.GetExtensions()
	if exts.Error != nil {
		return nil, exts.Error
	}
	extServers, err := enabledExtensionServers[*mqlQwenCodeExtension](exts.Data)
	if err != nil {
		return nil, err
	}
	return append(result, extServers...), nil
}

func (r *mqlQwenCodeMcpServer) id() (string, error) {
	return mcpServerResourceID("qwen.code.mcpServer", r.Source.Data, r.Name.Data), nil
}

func (r *mqlQwenCodeMcpServer) running() (*llx.AssetValue, error) { return mcpServerAsset(r), nil }

// MqlAsset implements plugin.AssetSource. See mcpServerAssetFor.
func (r *mqlQwenCodeMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"sigs.k8s.io/yaml"
)

func initGoose(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initOSConfigPath(runtime, args, "goose", gooseConfigDir)
}

// gooseConfigDir returns Goose's configuration directory relative to the
// user's home. Goose resolves it with etcetera's choose_app_strategy (author
// "Block", app "goose"): the Windows strategy puts it under the roaming
// application-data directory, the XDG one, used on macOS too, under ~/.config.
func gooseConfigDir(osFamily string) string {
	if osFamily == "windows" {
		return filepath.Join("AppData", "Roaming", "Block", "goose", "config")
	}
	return filepath.Join(".config", "goose")
}

func (r *mqlGoose) id() (string, error) {
	return "goose/" + r.ConfigPath.Data, nil
}

func (r *mqlGoose) loadConfig() (*gooseConfig, error) {
	afs := connectionAfs(r.MqlRuntime)
	data, err := afs.ReadFile(filepath.Join(r.ConfigPath.Data, "config.yaml"))
	if err != nil {
		return nil, err
	}

	var config gooseConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse goose config.yaml: %w", err)
	}
	return &config, nil
}

func (r *mqlGoose) provider() (string, error) {
	config, err := r.loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return config.activeProvider(), nil
}

func (r *mqlGoose) model() (string, error) {
	config, err := r.loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return config.activeModel(), nil
}

func (r *mqlGoose) telemetryEnabled() (bool, error) {
	config, err := r.loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			// No configuration file: nothing says whether Goose is here at all.
			r.TelemetryEnabled.State = plugin.StateIsSet | plugin.StateIsNull
			return false, nil
		}
		return false, err
	}
	return gooseTelemetryEnabled(config), nil
}

// gooseTelemetryEnabled is Goose's is_telemetry_enabled for a configuration
// file: telemetry is opt-in, so it is off until GOOSE_TELEMETRY_ENABLED says
// otherwise.
func gooseTelemetryEnabled(config *gooseConfig) bool {
	return config.TelemetryEnabled != nil && *config.TelemetryEnabled
}

func (r *mqlGoose) extensions() ([]any, error) {
	config, err := r.loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []any
	for name, ext := range config.Extensions {
		res, err := NewResource(r.MqlRuntime, "goose.extension", map[string]*llx.RawData{
			"__id":        llx.StringData("goose.extension/" + name),
			"name":        llx.StringData(name),
			"enabled":     llx.BoolData(ext.Enabled),
			"type":        llx.StringData(ext.Type),
			"description": llx.StringData(ext.Description),
			"bundled":     llx.BoolData(ext.Bundled),
			"timeout":     llx.IntData(int64(ext.Timeout)),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

// gooseMcpExtensionTypes are the extension types Goose runs as Model Context
// Protocol servers.
var gooseMcpExtensionTypes = map[string]bool{"stdio": true, "sse": true, "streamable_http": true}

// gooseMcpServers returns the extensions of a config that are MCP servers,
// sorted by name. Goose stores an extension's environment variable values in
// its secret store and lists only their names under env_keys, so either one
// being set means the server has environment variables.
func gooseMcpServers(config *gooseConfig, source string) []mcpServerSpec {
	names := make([]string, 0, len(config.Extensions))
	for name, ext := range config.Extensions {
		if gooseMcpExtensionTypes[ext.Type] {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	specs := make([]mcpServerSpec, 0, len(names))
	for _, name := range names {
		ext := config.Extensions[name]
		specs = append(specs, mcpServerSpec{
			name:       name,
			transport:  deriveMcpTransport(ext.Type, ext.Cmd, ext.URI),
			command:    ext.Cmd,
			args:       ext.Args,
			url:        ext.URI,
			hasEnv:     len(ext.Envs) > 0 || len(ext.EnvKeys) > 0,
			hasHeaders: len(ext.Headers) > 0,
			enabled:    ext.Enabled,
			source:     source,

			envNames:    mcpNames(mapKeys(ext.Envs), ext.EnvKeys),
			headerNames: mcpNames(mapKeys(ext.Headers)),
		})
	}
	return specs
}

func (r *mqlGoose) mcpServers() ([]any, error) {
	config, err := r.loadConfig()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return newMcpServerResources(r.MqlRuntime, "goose.mcpServer", gooseMcpServers(config, filepath.Join(r.ConfigPath.Data, "config.yaml")))
}

func (r *mqlGooseMcpServer) id() (string, error) {
	return mcpServerResourceID("goose.mcpServer", r.Source.Data, r.Name.Data), nil
}

func (r *mqlGooseMcpServer) running() (*llx.AssetValue, error) {
	return mcpServerAsset(r), nil
}

// MqlAsset implements plugin.AssetSource: the asset the `running` anchor stands
// for, with the connection needed to reach it. See mcpServerAssetFor.
func (r *mqlGooseMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

func (r *mqlGoose) skills() ([]any, error) {
	dir := gooseConfigDir(runtimeOSFamily(r.MqlRuntime))
	return agentSkills(r.MqlRuntime, "goose.skill", r.ConfigPath.Data, dir,
		filepath.Join(dir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

// Child resource ID methods

func (r *mqlGooseExtension) id() (string, error) {
	return "goose.extension/" + r.Name.Data, nil
}

func (r *mqlGooseSkill) id() (string, error) {
	return "goose.skill/" + r.Source.Data, nil
}

func (r *mqlGooseSkill) sha256() (string, error) {
	return contentSHA256(r.Content.Data), nil
}

func (r *mqlGooseSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// Helper types

type gooseConfig struct {
	Extensions       map[string]gooseExtension `json:"extensions"`
	Provider         string                    `json:"GOOSE_PROVIDER"`
	Model            string                    `json:"GOOSE_MODEL"`
	TelemetryEnabled *bool                     `json:"GOOSE_TELEMETRY_ENABLED"`
	// ActiveProvider and Providers are where `goose configure` keeps the
	// provider and its model in current releases, replacing GOOSE_PROVIDER
	// and GOOSE_MODEL.
	ActiveProvider string `json:"active_provider"`
	Providers      map[string]struct {
		Model string `json:"model"`
	} `json:"providers"`
}

// activeProvider returns the configured provider, from GOOSE_PROVIDER when set
// and from active_provider otherwise.
func (c *gooseConfig) activeProvider() string {
	if c.Provider != "" {
		return c.Provider
	}
	return c.ActiveProvider
}

// activeModel returns the configured model, from GOOSE_MODEL when set and
// from the active provider's entry under providers otherwise.
func (c *gooseConfig) activeModel() string {
	if c.Model != "" {
		return c.Model
	}
	return c.Providers[c.activeProvider()].Model
}

type gooseExtension struct {
	Enabled     bool           `json:"enabled"`
	Type        string         `json:"type"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Bundled     bool           `json:"bundled"`
	Timeout     int            `json:"timeout"`
	Cmd         string         `json:"cmd"`
	Args        []string       `json:"args"`
	URI         string         `json:"uri"`
	Envs        map[string]any `json:"envs"`
	EnvKeys     []string       `json:"env_keys"`
	Headers     map[string]any `json:"headers"`
}

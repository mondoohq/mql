// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/afero"
	"github.com/tailscale/hujson"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const defaultGeminiConfigDir = ".gemini"

func initGemini(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "gemini", defaultGeminiConfigDir)
}

func (r *mqlGemini) id() (string, error) {
	return "gemini/" + r.ConfigPath.Data, nil
}

func (r *mqlGemini) authType() (string, error) {
	afs := connectionAfs(r.MqlRuntime)
	var settings geminiSettings
	err := readGeminiSettings(afs, r.ConfigPath.Data, &settings)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return settings.authType(), nil
}

func (r *mqlGemini) model() (string, error) {
	afs := connectionAfs(r.MqlRuntime)
	var settings geminiSettings
	err := readGeminiSettings(afs, r.ConfigPath.Data, &settings)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return settings.Model.Name, nil
}

func (r *mqlGemini) settings() (interface{}, error) {
	afs := connectionAfs(r.MqlRuntime)
	var settings map[string]interface{}
	err := readGeminiSettings(afs, r.ConfigPath.Data, &settings)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]interface{}{}, nil
		}
		return nil, err
	}
	return settings, nil
}

func (r *mqlGemini) mcpServers() ([]interface{}, error) {
	servers, err := geminiMCPServers(connectionAfs(r.MqlRuntime), r.ConfigPath.Data)
	if err != nil {
		return nil, err
	}

	var result []interface{}
	for name, server := range servers {
		url := server.URL
		if url == "" {
			url = server.HTTPURL
		}

		res, err := NewResource(r.MqlRuntime, "gemini.mcpServer", map[string]*llx.RawData{
			"__id":    llx.StringData("gemini.mcpServer/" + name),
			"name":    llx.StringData(name),
			"type":    llx.StringData(deriveMcpTransport(server.Type, server.Command, url)),
			"command": llx.StringData(server.Command),
			"args":    strSliceToArrayData(server.Args),
			"url":     llx.StringData(url),
			"hasEnv":  llx.BoolData(len(server.Env) > 0),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlGemini) skills() ([]interface{}, error) {
	return agentSkills(r.MqlRuntime, "gemini.skill", r.ConfigPath.Data, defaultGeminiConfigDir,
		filepath.Join(defaultGeminiConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

// Child resource ID methods

func (r *mqlGeminiMcpServer) running() (*llx.AssetValue, error) {
	return mcpServerAsset(r), nil
}

// MqlAsset implements plugin.AssetSource: the asset the `running` anchor stands
// for, with the connection needed to reach it. See mcpServerAssetFor.
func (r *mqlGeminiMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

func (r *mqlGeminiMcpServer) id() (string, error) {
	return "gemini.mcpServer/" + r.Name.Data, nil
}

func (r *mqlGeminiSkill) id() (string, error) {
	return "gemini.skill/" + r.Source.Data, nil
}

func (r *mqlGeminiSkill) sha256() (string, error) {
	return contentSHA256(r.Content.Data), nil
}

func (r *mqlGeminiSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// geminiMCPServers returns the MCP servers Gemini is configured with, keyed by
// name. The Gemini CLI reads them from the `mcpServers` key of settings.json;
// Antigravity keeps its own list in antigravity/mcp_config.json. Both are read,
// and settings.json wins when both name the same server. A missing file is not
// an error; a file that exists but does not parse is.
func geminiMCPServers(afs *afero.Afero, configDir string) (map[string]geminiMCPServer, error) {
	servers := map[string]geminiMCPServer{}
	for _, rel := range []string{filepath.Join("antigravity", "mcp_config.json"), "settings.json"} {
		data, err := afs.ReadFile(filepath.Join(configDir, rel))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		var config geminiMCPConfig
		if err := unmarshalGeminiJSON(data, &config); err != nil {
			return nil, fmt.Errorf("failed to parse gemini %s: %w", rel, err)
		}
		for name, server := range config.McpServers {
			servers[name] = server
		}
	}
	return servers, nil
}

// readGeminiSettings reads settings.json. gemini-cli strips // and /* */
// comments before parsing it, so a commented file is a valid configuration
// and must not read as malformed.
func readGeminiSettings(afs *afero.Afero, configDir string, v any) error {
	data, err := afs.ReadFile(filepath.Join(configDir, "settings.json"))
	if err != nil {
		return err
	}
	return unmarshalGeminiJSON(data, v)
}

// unmarshalGeminiJSON parses a Gemini config file that may carry comments.
func unmarshalGeminiJSON(data []byte, v any) error {
	if len(bytes.TrimSpace(data)) == 0 {
		// An empty file reads like a missing one: an empty configuration.
		data = []byte("{}")
	}
	clean, err := hujson.Standardize(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(clean, v)
}

// Helper types

type geminiSettings struct {
	Theme string `json:"theme"`
	// SelectedAuthType is the flat key older Gemini CLI releases wrote.
	SelectedAuthType string `json:"selectedAuthType"`
	// Security.Auth.SelectedType is where current releases keep it.
	Security struct {
		Auth struct {
			SelectedType string `json:"selectedType"`
		} `json:"auth"`
	} `json:"security"`
	Model struct {
		Name string `json:"name"`
	} `json:"model"`
}

// authType returns the configured authentication type, preferring the nested
// security.auth.selectedType key of current settings.json files and falling
// back to the flat selectedAuthType key older releases wrote.
func (s geminiSettings) authType() string {
	if s.Security.Auth.SelectedType != "" {
		return s.Security.Auth.SelectedType
	}
	return s.SelectedAuthType
}

type geminiMCPConfig struct {
	McpServers map[string]geminiMCPServer `json:"mcpServers"`
}

type geminiMCPServer struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	HTTPURL string            `json:"httpUrl"`
	Env     map[string]string `json:"env"`
}

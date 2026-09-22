// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"os"
	"path/filepath"

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
	err := readJSONFileAfero(afs, r.ConfigPath.Data, "settings.json", &settings)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return settings.SelectedAuthType, nil
}

func (r *mqlGemini) model() (string, error) {
	afs := connectionAfs(r.MqlRuntime)
	var settings geminiSettings
	err := readJSONFileAfero(afs, r.ConfigPath.Data, "settings.json", &settings)
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
	err := readJSONFileAfero(afs, r.ConfigPath.Data, "settings.json", &settings)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]interface{}{}, nil
		}
		return nil, err
	}
	return settings, nil
}

func (r *mqlGemini) mcpServers() ([]interface{}, error) {
	afs := connectionAfs(r.MqlRuntime)
	configDir := r.ConfigPath.Data

	// Gemini stores MCP config in antigravity/mcp_config.json
	data, err := afs.ReadFile(filepath.Join(configDir, "antigravity", "mcp_config.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var config geminiMCPConfig
	if err := unmarshalJSONConfig(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse gemini mcp_config.json: %w", err)
	}

	var result []interface{}
	for name, server := range config.McpServers {
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

// Helper types

type geminiSettings struct {
	Theme            string `json:"theme"`
	SelectedAuthType string `json:"selectedAuthType"`
	Model            struct {
		Name string `json:"name"`
	} `json:"model"`
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

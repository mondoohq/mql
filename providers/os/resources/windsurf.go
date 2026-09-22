// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const defaultWindsurfConfigDir = ".codeium/windsurf"

func initWindsurf(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "windsurf", defaultWindsurfConfigDir)
}

func (r *mqlWindsurf) id() (string, error) {
	return "windsurf/" + r.ConfigPath.Data, nil
}

func (r *mqlWindsurf) rules() ([]interface{}, error) {
	afs := connectionAfs(r.MqlRuntime)
	memoriesDir := filepath.Join(r.ConfigPath.Data, "memories")

	entries, err := afs.ReadDir(memoriesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []interface{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".md" && ext != ".txt" && ext != "" {
			continue
		}

		rulePath := filepath.Join(memoriesDir, name)
		data, err := afs.ReadFile(rulePath)
		if err != nil {
			continue
		}

		ruleName := strings.TrimSuffix(name, filepath.Ext(name))
		res, err := NewResource(r.MqlRuntime, "windsurf.rule", map[string]*llx.RawData{
			"__id":    llx.StringData("windsurf.rule/" + name),
			"name":    llx.StringData(ruleName),
			"content": llx.StringData(string(data)),
			"source":  llx.StringData(rulePath),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlWindsurf) mcpServers() ([]interface{}, error) {
	afs := connectionAfs(r.MqlRuntime)
	configDir := r.ConfigPath.Data

	// Windsurf stores MCP config in mcp_config.json
	data, err := afs.ReadFile(filepath.Join(configDir, "mcp_config.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var config windsurfMCPConfig
	if err := unmarshalJSONConfig(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse windsurf mcp_config.json: %w", err)
	}

	var result []interface{}
	for name, server := range config.McpServers {
		url := server.URL
		if url == "" {
			url = server.ServerURL
		}

		res, err := NewResource(r.MqlRuntime, "windsurf.mcpServer", map[string]*llx.RawData{
			"__id":    llx.StringData("windsurf.mcpServer/" + name),
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

func (r *mqlWindsurf) skills() ([]interface{}, error) {
	return agentSkills(r.MqlRuntime, "windsurf.skill", r.ConfigPath.Data, defaultWindsurfConfigDir,
		filepath.Join(defaultWindsurfConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

// Child resource ID methods

func (r *mqlWindsurfRule) id() (string, error) {
	return "windsurf.rule/" + r.Name.Data, nil
}

func (r *mqlWindsurf) repos() ([]interface{}, error) {
	return gitReposFromPaths(r.MqlRuntime, "windsurf.repo", vscodeWorkspaceFolders(r.MqlRuntime, "Windsurf"))
}

func (r *mqlWindsurfRepo) id() (string, error) {
	return "windsurf.repo/" + r.Path.Data, nil
}

func (r *mqlWindsurfMcpServer) running() (*llx.AssetValue, error) {
	return mcpServerAsset(r), nil
}

// MqlAsset implements plugin.AssetSource: the asset the `running` anchor stands
// for, with the connection needed to reach it. See mcpServerAssetFor.
func (r *mqlWindsurfMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

func (r *mqlWindsurfMcpServer) id() (string, error) {
	return "windsurf.mcpServer/" + r.Name.Data, nil
}

func (r *mqlWindsurfSkill) id() (string, error) {
	return "windsurf.skill/" + r.Source.Data, nil
}

func (r *mqlWindsurfSkill) sha256() (string, error) {
	return contentSHA256(r.Content.Data), nil
}

func (r *mqlWindsurfSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// Helper types

type windsurfMCPConfig struct {
	McpServers map[string]windsurfMCPServer `json:"mcpServers"`
}

type windsurfMCPServer struct {
	Type      string            `json:"type"`
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	URL       string            `json:"url"`
	ServerURL string            `json:"serverUrl"`
	Env       map[string]string `json:"env"`
}

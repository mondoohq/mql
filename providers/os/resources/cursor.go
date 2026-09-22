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

const defaultCursorConfigDir = ".cursor"

func initCursor(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "cursor", defaultCursorConfigDir)
}

func (r *mqlCursor) id() (string, error) {
	return "cursor/" + r.ConfigPath.Data, nil
}

func (r *mqlCursor) mcpServers() ([]interface{}, error) {
	afs := connectionAfs(r.MqlRuntime)
	configDir := r.ConfigPath.Data

	// Cursor stores MCP config in mcp.json
	data, err := afs.ReadFile(filepath.Join(configDir, "mcp.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var mcpConfig cursorMCPConfig
	if err := unmarshalJSONConfig(data, &mcpConfig); err != nil {
		return nil, fmt.Errorf("failed to parse cursor mcp.json: %w", err)
	}

	var result []interface{}
	for name, server := range mcpConfig.McpServers {
		res, err := NewResource(r.MqlRuntime, "cursor.mcpServer", map[string]*llx.RawData{
			"__id":    llx.StringData("cursor.mcpServer/" + name),
			"name":    llx.StringData(name),
			"type":    llx.StringData(deriveMcpTransport(server.Type, server.Command, server.URL)),
			"command": llx.StringData(server.Command),
			"args":    strSliceToArrayData(server.Args),
			"url":     llx.StringData(server.URL),
			"hasEnv":  llx.BoolData(len(server.Env) > 0),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlCursor) rules() ([]interface{}, error) {
	afs := connectionAfs(r.MqlRuntime)
	rulesDir := filepath.Join(r.ConfigPath.Data, "rules")

	entries, err := afs.ReadDir(rulesDir)
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
		// Only process markdown and text rule files
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".md" && ext != ".txt" && ext != ".mdc" && ext != "" {
			continue
		}

		rulePath := filepath.Join(rulesDir, name)
		data, err := afs.ReadFile(rulePath)
		if err != nil {
			continue
		}

		ruleName := strings.TrimSuffix(name, filepath.Ext(name))
		res, err := NewResource(r.MqlRuntime, "cursor.rule", map[string]*llx.RawData{
			"__id":    llx.StringData("cursor.rule/" + name),
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

func (r *mqlCursor) skills() ([]interface{}, error) {
	return agentSkills(r.MqlRuntime, "cursor.skill", r.ConfigPath.Data, defaultCursorConfigDir,
		filepath.Join(defaultCursorConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

// Child resource ID methods

func (r *mqlCursor) repos() ([]interface{}, error) {
	return gitReposFromPaths(r.MqlRuntime, "cursor.repo", vscodeWorkspaceFolders(r.MqlRuntime, "Cursor"))
}

func (r *mqlCursorRepo) id() (string, error) {
	return "cursor.repo/" + r.Path.Data, nil
}

func (r *mqlCursorMcpServer) running() (*llx.AssetValue, error) {
	return mcpServerAsset(r), nil
}

// MqlAsset implements plugin.AssetSource: the asset the `running` anchor stands
// for, with the connection needed to reach it. See mcpServerAssetFor.
func (r *mqlCursorMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

func (r *mqlCursorMcpServer) id() (string, error) {
	return "cursor.mcpServer/" + r.Name.Data, nil
}

func (r *mqlCursorRule) id() (string, error) {
	return "cursor.rule/" + r.Name.Data, nil
}

func (r *mqlCursorSkill) id() (string, error) {
	return "cursor.skill/" + r.Source.Data, nil
}

func (r *mqlCursorSkill) sha256() (string, error) {
	return contentSHA256(r.Content.Data), nil
}

func (r *mqlCursorSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// Helper types

type cursorMCPConfig struct {
	McpServers map[string]cursorMCPServer `json:"mcpServers"`
}

type cursorMCPServer struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	Env     map[string]string `json:"env"`
}

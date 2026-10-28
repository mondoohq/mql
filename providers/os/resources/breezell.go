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

// Breezell keeps its agent state (rules, memories, skills) in ~/.breezell and
// its editor data (user mcp.json, extensions) in the product's dataFolderName,
// ~/.breezell-editor.
const (
	defaultBreezellConfigDir = ".breezell"
	breezellEditorDataDir    = ".breezell-editor"
)

func initBreezell(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "breezell", defaultBreezellConfigDir)
}

func (r *mqlBreezell) id() (string, error) {
	return "breezell/" + r.ConfigPath.Data, nil
}

func (r *mqlBreezell) rules() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	memoriesDir := filepath.Join(r.ConfigPath.Data, "memories")

	entries, err := afs.ReadDir(memoriesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []any
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Breezell only reads markdown here (global_rules.md, global_memories.md,
		// global_skills.md, global_commit_prompt.md), unlike Windsurf's .txt rules.
		if strings.ToLower(filepath.Ext(name)) != ".md" {
			continue
		}

		rulePath := filepath.Join(memoriesDir, name)
		data, err := afs.ReadFile(rulePath)
		if err != nil {
			continue
		}

		res, err := NewResource(r.MqlRuntime, "breezell.rule", map[string]*llx.RawData{
			"__id":    llx.StringData("breezell.rule/" + rulePath),
			"name":    llx.StringData(strings.TrimSuffix(name, filepath.Ext(name))),
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

// breezellMCPConfigPath returns the user mcp.json, which lives in the editor
// data dir next to the configuration directory rather than inside it.
func breezellMCPConfigPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), breezellEditorDataDir, "mcp.json")
}

func (r *mqlBreezell) mcpServers() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	configFile := breezellMCPConfigPath(r.ConfigPath.Data)

	data, err := afs.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var config breezellMCPConfig
	if err := unmarshalJSONConfig(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse breezell mcp.json: %w", err)
	}

	var result []any
	for name, server := range config.McpServers {
		res, err := NewResource(r.MqlRuntime, "breezell.mcpServer", map[string]*llx.RawData{
			"__id":    llx.StringData("breezell.mcpServer/" + name),
			"name":    llx.StringData(name),
			"type":    llx.StringData(deriveMcpTransport(server.Type, server.Command, server.URL)),
			"command": llx.StringData(server.Command),
			"args":    mcpArgsData(server.Args),
			"url":     llx.StringData(redactURL(server.URL)),
			"hasEnv":  llx.BoolData(len(server.Env) > 0),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlBreezell) skills() ([]any, error) {
	return agentSkills(r.MqlRuntime, "breezell.skill", r.ConfigPath.Data, defaultBreezellConfigDir,
		filepath.Join(defaultBreezellConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
}

func (r *mqlBreezell) repos() ([]any, error) {
	folders, err := vscodeWorkspaceFolders(r.MqlRuntime, "Breezell")
	if err != nil {
		return nil, err
	}
	return gitReposFromPaths(r.MqlRuntime, "breezell.repo", folders)
}

// Child resource ID methods

func (r *mqlBreezellRule) id() (string, error) {
	return "breezell.rule/" + r.Source.Data, nil
}

func (r *mqlBreezellRepo) id() (string, error) {
	return "breezell.repo/" + r.Path.Data, nil
}

func (r *mqlBreezellMcpServer) running() (*llx.AssetValue, error) {
	return mcpServerAsset(r), nil
}

// MqlAsset implements plugin.AssetSource: the asset the `running` anchor stands
// for, with the connection needed to reach it. See mcpServerAssetFor.
func (r *mqlBreezellMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

func (r *mqlBreezellMcpServer) id() (string, error) {
	return "breezell.mcpServer/" + r.Name.Data, nil
}

func (r *mqlBreezellSkill) id() (string, error) {
	return "breezell.skill/" + r.Source.Data, nil
}

func (r *mqlBreezellSkill) sha256() (string, error) {
	return contentSHA256(r.Content.Data), nil
}

func (r *mqlBreezellSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

// Helper types

type breezellMCPConfig struct {
	McpServers map[string]breezellMCPServer `json:"mcpServers"`
}

type breezellMCPServer struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	Env     map[string]string `json:"env"`
}

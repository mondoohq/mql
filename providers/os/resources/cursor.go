// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/afero"
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

func (r *mqlCursor) mcpServers() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)

	// The user's own mcp.json comes first, so it wins a name clash with a plugin.
	seen := map[string]struct{}{}
	var result []any
	for _, configFile := range cursorMCPConfigFiles(afs, r.ConfigPath.Data) {
		data, err := afs.ReadFile(configFile)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}

		var mcpConfig cursorMCPConfig
		if err := unmarshalJSONConfig(data, &mcpConfig); err != nil {
			return nil, fmt.Errorf("failed to parse cursor %s: %w", configFile, err)
		}

		for name, server := range mcpConfig.McpServers {
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			fields := map[string]*llx.RawData{
				"__id":    llx.StringData("cursor.mcpServer/" + name),
				"name":    llx.StringData(name),
				"type":    llx.StringData(deriveMcpTransport(server.Type, server.Command, server.URL)),
				"command": llx.StringData(server.Command),
				"args":    mcpArgsData(server.Args),
				"url":     llx.StringData(redactURL(server.URL)),
				"hasEnv":  llx.BoolData(len(server.Env) > 0),

				"hasHeaders":  llx.BoolData(len(server.Headers) > 0),
				"headerNames": mcpHeaderNamesData(mapKeys(server.Headers)),
				"source":      llx.StringData(configFile),
			}
			setMcpServerShape(fields, server.Command, server.Args, server.URL, mapKeys(server.Env))
			res, err := NewResource(r.MqlRuntime, "cursor.mcpServer", fields)
			if err != nil {
				return nil, err
			}
			result = append(result, res)
		}
	}
	return result, nil
}

// cursorMCPConfigFiles lists the MCP config files Cursor loads: the user's
// mcp.json, then one per installed plugin. Plugins installed from the
// Customize page or the marketplace keep their servers in their own mcp.json.
func cursorMCPConfigFiles(afs *afero.Afero, configDir string) []string {
	files := []string{filepath.Join(configDir, "mcp.json")}
	for _, root := range cursorPluginRoots(afs, configDir) {
		if f := cursorPluginMCPFile(afs, root); f != "" {
			files = append(files, f)
		}
	}
	return files
}

// cursorPluginRoots returns the root directory of each installed Cursor
// plugin: plugins/local/<plugin> and plugins/cache/<marketplace>/<plugin>/<ref>,
// where <ref> is a git commit. When an update leaves several refs behind, only
// the most recently modified one is returned.
//
// ponytail: a disabled plugin keeps its cache dir, so it is still reported.
// Cursor keeps the enabled list in its SQLite state.vscdb, which we don't read.
func cursorPluginRoots(afs *afero.Afero, configDir string) []string {
	pluginsDir := filepath.Join(configDir, "plugins")
	var roots []string
	locals, _ := listSubdirsAfero(afs, filepath.Join(pluginsDir, "local"))
	for _, d := range locals {
		roots = append(roots, d.path)
	}

	markets, _ := listSubdirsAfero(afs, filepath.Join(pluginsDir, "cache"))
	for _, market := range markets {
		plugins, _ := listSubdirsAfero(afs, market.path)
		for _, p := range plugins {
			refs, _ := listSubdirsAfero(afs, p.path)
			newest, newestTime := "", time.Time{}
			for _, ref := range refs {
				info, err := afs.Stat(ref.path)
				if err != nil {
					continue
				}
				if newest == "" || info.ModTime().After(newestTime) {
					newest, newestTime = ref.path, info.ModTime()
				}
			}
			if newest != "" {
				roots = append(roots, newest)
			}
		}
	}
	return roots
}

// cursorPluginMCPFile returns the plugin's MCP config file, or "" when it has
// none. The manifest's mcpServers may name a file inside the plugin; otherwise
// Cursor discovers mcp.json at the plugin root.
//
// ponytail: an inline or array mcpServers in plugin.json is skipped; every
// official plugin points to a file.
func cursorPluginMCPFile(afs *afero.Afero, root string) string {
	rel := "mcp.json"
	var manifest struct {
		McpServers json.RawMessage `json:"mcpServers"`
	}
	if err := readJSONFileAfero(afs, root, filepath.Join(".cursor-plugin", "plugin.json"), &manifest); err == nil {
		var path string
		if json.Unmarshal(manifest.McpServers, &path) == nil && path != "" {
			rel = path
		}
	}
	file := filepath.Join(root, filepath.FromSlash(rel))
	if r, err := filepath.Rel(root, file); err != nil || strings.HasPrefix(r, "..") {
		return ""
	}
	if ok, _ := afs.Exists(file); !ok {
		return ""
	}
	return file
}

func (r *mqlCursor) rules() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	rulesDir := filepath.Join(r.ConfigPath.Data, "rules")

	entries, err := afs.ReadDir(rulesDir)
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

func (r *mqlCursor) skills() ([]any, error) {
	dirs, err := resolvePerUserDirs(r.MqlRuntime, r.ConfigPath.Data, defaultCursorConfigDir,
		filepath.Join(defaultCursorConfigDir, "skills"), filepath.Join(r.ConfigPath.Data, "skills"))
	if err != nil {
		return nil, err
	}
	// Each skills dir sits in a .cursor dir whose installed plugins can carry
	// skills too.
	afs := connectionAfs(r.MqlRuntime)
	all := slices.Clone(dirs)
	for _, d := range dirs {
		for _, root := range cursorPluginRoots(afs, filepath.Dir(d)) {
			all = append(all, filepath.Join(root, "skills"))
		}
	}
	return readSkillsFromDirs(r.MqlRuntime, all, "cursor.skill")
}

// Child resource ID methods

func (r *mqlCursor) repos() ([]any, error) {
	folders, err := vscodeWorkspaceFolders(r.MqlRuntime, "Cursor")
	if err != nil {
		return nil, err
	}
	return gitReposFromPaths(r.MqlRuntime, "cursor.repo", folders)
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
	Headers map[string]string `json:"headers"`
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

const defaultCodexConfigDir = ".codex"

func initOpenaiCodex(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "openai.codex", defaultCodexConfigDir)
}

func (r *mqlOpenaiCodex) id() (string, error) {
	return "openai.codex/" + r.ConfigPath.Data, nil
}

func (r *mqlOpenaiCodex) codexDir() string {
	return r.ConfigPath.Data
}

// afs returns an afero.Afero wrapping the connection's filesystem.
func (r *mqlOpenaiCodex) afs() *afero.Afero {
	return connectionAfs(r.MqlRuntime)
}

func (r *mqlOpenaiCodex) authMode() (string, error) {
	auth, err := r.loadAuth()
	if err != nil {
		return "", err
	}
	return auth.AuthMode, nil
}

func (r *mqlOpenaiCodex) accountId() (string, error) {
	auth, err := r.loadAuth()
	if err != nil {
		return "", err
	}
	if auth.Tokens == nil {
		return "", nil
	}
	return auth.Tokens.AccountID, nil
}

func (r *mqlOpenaiCodex) lastRefresh() (string, error) {
	auth, err := r.loadAuth()
	if err != nil {
		return "", err
	}
	return auth.LastRefresh, nil
}

// codexConfig captures the top-level model settings from config.toml.
type codexConfig struct {
	Model         string `toml:"model"`
	ModelProvider string `toml:"model_provider"`
}

// mqlOpenaiCodexInternal caches the parsed config.toml so that model() and
// modelProvider() do not each re-read and re-parse it.
type mqlOpenaiCodexInternal struct {
	configOnce      sync.Once
	cachedConfig    *codexConfig
	cachedConfigErr error
}

func (r *mqlOpenaiCodex) loadConfig() (*codexConfig, error) {
	r.configOnce.Do(func() {
		r.cachedConfig, r.cachedConfigErr = r.readConfig()
	})
	return r.cachedConfig, r.cachedConfigErr
}

func (r *mqlOpenaiCodex) readConfig() (*codexConfig, error) {
	data, err := r.afs().ReadFile(filepath.Join(r.codexDir(), "config.toml"))
	if err != nil {
		if os.IsNotExist(err) {
			return &codexConfig{}, nil
		}
		return nil, err
	}
	var cfg codexConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse codex config.toml: %w", err)
	}
	return &cfg, nil
}

func (r *mqlOpenaiCodex) model() (string, error) {
	cfg, err := r.loadConfig()
	if err != nil {
		return "", err
	}
	return cfg.Model, nil
}

func (r *mqlOpenaiCodex) modelProvider() (string, error) {
	cfg, err := r.loadConfig()
	if err != nil {
		return "", err
	}
	return cfg.ModelProvider, nil
}

func (r *mqlOpenaiCodex) plugins() ([]interface{}, error) {
	afs := r.afs()
	pluginsDir := filepath.Join(r.codexDir(), ".tmp", "plugins", "plugins")

	subdirs, err := listSubdirsAfero(afs, pluginsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []interface{}
	for _, dir := range subdirs {
		p := codexPluginInfo{name: dir.name}

		// Read plugin.json
		var pj codexPluginJSON
		if err := readJSONFileAfero(afs, dir.path, ".codex-plugin/plugin.json", &pj); err == nil {
			p.version = pj.Version
			p.description = pj.Description
			if pj.Author != nil {
				p.author = pj.Author.Name
			}
			if pj.Interface != nil {
				p.category = pj.Interface.Category
				p.capabilities = pj.Interface.Capabilities
			}
		}

		// Collect skill names from skills directory
		skillsDir := filepath.Join(dir.path, "skills")
		if skillSubdirs, err := listSubdirsAfero(afs, skillsDir); err == nil {
			for _, sd := range skillSubdirs {
				p.skillNames = append(p.skillNames, sd.name)
			}
		}

		// Check for MCP config
		mcpExists, _ := afs.Exists(filepath.Join(dir.path, ".mcp.json"))
		p.hasMcp = mcpExists

		// Check for hooks
		hooksExists, _ := afs.Exists(filepath.Join(dir.path, "hooks.json"))
		p.hasHooks = hooksExists

		capAny := make([]interface{}, len(p.capabilities))
		for i, c := range p.capabilities {
			capAny[i] = c
		}
		skillAny := make([]interface{}, len(p.skillNames))
		for i, s := range p.skillNames {
			skillAny[i] = s
		}

		res, err := NewResource(r.MqlRuntime, "openai.codex.plugin", map[string]*llx.RawData{
			"__id":         llx.StringData("openai.codex.plugin/" + dir.name),
			"name":         llx.StringData(dir.name),
			"version":      llx.StringData(p.version),
			"description":  llx.StringData(p.description),
			"author":       llx.StringData(p.author),
			"category":     llx.StringData(p.category),
			"capabilities": llx.ArrayData(capAny, types.String),
			"skillNames":   llx.ArrayData(skillAny, types.String),
			"hasMcp":       llx.BoolData(p.hasMcp),
			"hasHooks":     llx.BoolData(p.hasHooks),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlOpenaiCodex) skills() ([]interface{}, error) {
	afs := r.afs()
	var result []interface{}
	seen := map[string]struct{}{}

	for _, codexDir := range r.codexDirs() {
		// system skills
		systemSkillsDir := filepath.Join(codexDir, "skills", ".system")
		if subdirs, err := listSubdirsAfero(afs, systemSkillsDir); err == nil {
			for _, dir := range subdirs {
				res, err := r.readCodexSkill(afs, dir.name, dir.path, "system", seen)
				if err != nil {
					return nil, err
				}
				if res != nil {
					result = append(result, res)
				}
			}
		}

		// plugin skills
		pluginsDir := filepath.Join(codexDir, ".tmp", "plugins", "plugins")
		if pluginDirs, err := listSubdirsAfero(afs, pluginsDir); err == nil {
			for _, pluginDir := range pluginDirs {
				skillDirs, err := listSubdirsAfero(afs, filepath.Join(pluginDir.path, "skills"))
				if err != nil {
					continue
				}
				for _, skillDir := range skillDirs {
					res, err := r.readCodexSkill(afs, skillDir.name, skillDir.path, pluginDir.name, seen)
					if err != nil {
						return nil, err
					}
					if res != nil {
						result = append(result, res)
					}
				}
			}
		}
	}

	return result, nil
}

// codexDirs returns the codex config dirs to scan: every user's ~/.codex, or
// the explicit configPath override when it is not a per-user default.
func (r *mqlOpenaiCodex) codexDirs() []string {
	return resolvePerUserDirs(r.MqlRuntime, r.codexDir(), defaultCodexConfigDir, defaultCodexConfigDir, r.codexDir())
}

// readCodexSkill reads a single SKILL.md, deduping by source path. Returns nil
// when the file is unreadable or already seen.
func (r *mqlOpenaiCodex) readCodexSkill(afs *afero.Afero, name, dirPath, plugin string, seen map[string]struct{}) (*mqlOpenaiCodexSkill, error) {
	skillPath := filepath.Join(dirPath, "SKILL.md")
	if _, ok := seen[skillPath]; ok {
		return nil, nil
	}
	// Mark seen before reading so an unreadable file isn't retried when the same
	// path appears under more than one codex dir (matches collectSkillFiles).
	seen[skillPath] = struct{}{}
	data, err := afs.ReadFile(skillPath)
	if err != nil {
		return nil, nil
	}
	return newCodexSkillResource(r.MqlRuntime, parseSkillMd(name, skillPath, string(data)), plugin)
}

func (r *mqlOpenaiCodex) mcpServers() ([]interface{}, error) {
	afs := r.afs()
	pluginsDir := filepath.Join(r.codexDir(), ".tmp", "plugins", "plugins")

	subdirs, err := listSubdirsAfero(afs, pluginsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []interface{}
	for _, dir := range subdirs {
		mcpPath := filepath.Join(dir.path, ".mcp.json")

		var mcpConfig struct {
			McpServers map[string]codexMcpServerEntry `json:"mcpServers"`
		}
		data, err := afs.ReadFile(mcpPath)
		if err != nil {
			continue
		}
		if err := unmarshalJSONConfig(data, &mcpConfig); err != nil {
			continue
		}

		for name, srv := range mcpConfig.McpServers {
			res, err := NewResource(r.MqlRuntime, "openai.codex.mcpServer", map[string]*llx.RawData{
				"__id":    llx.StringData("openai.codex.mcpServer/" + dir.name + "/" + name),
				"name":    llx.StringData(name),
				"type":    llx.StringData(deriveMcpTransport(srv.Type, srv.Command, srv.URL)),
				"command": llx.StringData(srv.Command),
				"args":    strSliceToArrayData(srv.Args),
				"url":     llx.StringData(srv.URL),
				"hasEnv":  llx.BoolData(len(srv.Env) > 0),
				"note":    llx.StringData(srv.Note),
				"plugin":  llx.StringData(dir.name),
			})
			if err != nil {
				return nil, err
			}
			result = append(result, res)
		}
	}
	return result, nil
}

func (r *mqlOpenaiCodex) connectors() ([]interface{}, error) {
	afs := r.afs()
	pluginsDir := filepath.Join(r.codexDir(), ".tmp", "plugins", "plugins")

	subdirs, err := listSubdirsAfero(afs, pluginsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []interface{}
	for _, dir := range subdirs {
		var appConfig struct {
			Apps map[string]struct {
				ID string `json:"id"`
			} `json:"apps"`
		}
		if err := readJSONFileAfero(afs, dir.path, ".app.json", &appConfig); err != nil {
			continue
		}

		for connName, app := range appConfig.Apps {
			res, err := NewResource(r.MqlRuntime, "openai.codex.connector", map[string]*llx.RawData{
				"__id":   llx.StringData("openai.codex.connector/" + dir.name + "/" + connName),
				"name":   llx.StringData(connName),
				"id":     llx.StringData(app.ID),
				"plugin": llx.StringData(dir.name),
			})
			if err != nil {
				return nil, err
			}
			result = append(result, res)
		}
	}
	return result, nil
}

// Helper types

type codexAuthJSON struct {
	AuthMode    string           `json:"auth_mode"`
	Tokens      *codexTokensJSON `json:"tokens"`
	LastRefresh string           `json:"last_refresh"`
}

type codexTokensJSON struct {
	AccountID string `json:"account_id"`
}

type codexPluginJSON struct {
	Version     string              `json:"version"`
	Description string              `json:"description"`
	Author      *codexAuthorJSON    `json:"author"`
	Interface   *codexInterfaceJSON `json:"interface"`
}

type codexAuthorJSON struct {
	Name string `json:"name"`
}

type codexInterfaceJSON struct {
	Category     string   `json:"category"`
	Capabilities []string `json:"capabilities"`
}

type codexMcpServerEntry struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	Env     map[string]string `json:"env"`
	Note    string            `json:"note"`
}

type codexPluginInfo struct {
	name         string
	version      string
	description  string
	author       string
	category     string
	capabilities []string
	skillNames   []string
	hasMcp       bool
	hasHooks     bool
}

func (r *mqlOpenaiCodex) loadAuth() (*codexAuthJSON, error) {
	var auth codexAuthJSON
	err := readJSONFileAfero(r.afs(), r.codexDir(), "auth.json", &auth)
	if err != nil {
		if os.IsNotExist(err) {
			return &codexAuthJSON{}, nil
		}
		return nil, err
	}
	return &auth, nil
}

func newCodexSkillResource(runtime *plugin.Runtime, skill skillInfo, pluginName string) (*mqlOpenaiCodexSkill, error) {
	res, err := NewResource(runtime, "openai.codex.skill", map[string]*llx.RawData{
		"__id":        llx.StringData("openai.codex.skill/" + skill.source),
		"name":        llx.StringData(skill.name),
		"description": llx.StringData(skill.description),
		"source":      llx.StringData(skill.source),
		"plugin":      llx.StringData(pluginName),
		"content":     llx.StringData(skill.content),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenaiCodexSkill), nil
}

// Stub ID methods for child resources

func (r *mqlOpenaiCodexPlugin) id() (string, error) {
	return "openai.codex.plugin/" + r.Name.Data, nil
}

func (r *mqlOpenaiCodexSkill) id() (string, error) {
	return "openai.codex.skill/" + r.Source.Data, nil
}

func (r *mqlOpenaiCodexSkill) sha256() (string, error) {
	return contentSHA256(r.Content.Data), nil
}

func (r *mqlOpenaiCodexSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

func (r *mqlOpenaiCodexMcpServer) running() (*llx.AssetValue, error) {
	return mcpServerAsset(r), nil
}

// MqlAsset implements plugin.AssetSource: the asset the `running` anchor stands
// for, with the connection needed to reach it. See mcpServerAssetFor.
func (r *mqlOpenaiCodexMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

func (r *mqlOpenaiCodexMcpServer) id() (string, error) {
	return "openai.codex.mcpServer/" + r.Plugin.Data + "/" + r.Name.Data, nil
}

func (r *mqlOpenaiCodexConnector) id() (string, error) {
	return "openai.codex.connector/" + r.Plugin.Data + "/" + r.Name.Data, nil
}

func (r *mqlOpenaiCodexRepo) id() (string, error) {
	return "openai.codex.repo/" + r.Path.Data, nil
}

func (r *mqlOpenaiCodex) repos() ([]interface{}, error) {
	return gitReposFromPaths(r.MqlRuntime, "openai.codex.repo", r.sessionWorkingDirs())
}

// sessionWorkingDirs collects the deduplicated working directories recorded in
// Codex session rollout files under <configDir>/sessions. Each rollout-*.jsonl
// begins with a session_meta record carrying the cwd; only that first line is
// read (the remainder of the file is the full conversation). A missing or
// unreadable sessions tree yields no directories.
func (r *mqlOpenaiCodex) sessionWorkingDirs() []string {
	afs := r.afs()
	sessionsDir := filepath.Join(r.codexDir(), "sessions")

	seen := map[string]struct{}{}
	var dirs []string
	_ = afs.Walk(sessionsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		name := info.Name()
		if !strings.HasPrefix(name, "rollout-") || !strings.HasSuffix(name, ".jsonl") {
			return nil
		}
		cwd := codexSessionCwd(afs, path)
		if cwd == "" {
			return nil
		}
		if _, ok := seen[cwd]; ok {
			return nil
		}
		seen[cwd] = struct{}{}
		dirs = append(dirs, cwd)
		return nil
	})
	return dirs
}

// codexSessionCwd reads only the first line of a rollout file and extracts
// payload.cwd from its session_meta record. Returns "" on any read or parse
// failure, or when the first record is not a session_meta.
func codexSessionCwd(afs *afero.Afero, path string) string {
	f, err := afs.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	line, err := bufio.NewReader(f).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return ""
	}

	var meta struct {
		Type    string `json:"type"`
		Payload struct {
			Cwd string `json:"cwd"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(line), &meta); err != nil {
		return ""
	}
	if meta.Type != "session_meta" {
		return ""
	}
	return meta.Payload.Cwd
}

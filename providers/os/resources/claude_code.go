// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const defaultClaudeCodeConfigDir = ".claude"

func initClaudeCode(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initConfigPath(runtime, args, "claude.code", defaultClaudeCodeConfigDir)
}

// mqlClaudeCodeInternal caches the backup state for the lifetime of
// this resource instance, avoiding the global map that leaked across assets.
type mqlClaudeCodeInternal struct {
	backupOnce  sync.Once
	backupState *claudeBackupState
	backupErr   error
}

// mqlClaudeCodeProjectInternal caches the per-project model usage read from
// the parent's backup state at creation time, so project.models() need not
// reload it.
type mqlClaudeCodeProjectInternal struct {
	modelUsage map[string]claudeModelUsage
}

func (r *mqlClaudeCode) id() (string, error) {
	return "claude.code/" + r.ConfigPath.Data, nil
}

// configDir returns the configPath for this resource instance.
func (r *mqlClaudeCode) configDir() string {
	return r.ConfigPath.Data
}

// afs returns an afero.Afero wrapping the connection's filesystem.
func (r *mqlClaudeCode) afs() *afero.Afero {
	return connectionAfs(r.MqlRuntime)
}

func (r *mqlClaudeCode) email() (string, error) {
	acct, err := r.loadOAuthAccount()
	if err != nil {
		return "", err
	}
	return acct.EmailAddress, nil
}

func (r *mqlClaudeCode) organization() (string, error) {
	acct, err := r.loadOAuthAccount()
	if err != nil {
		return "", err
	}
	return acct.OrganizationName, nil
}

func (r *mqlClaudeCode) role() (string, error) {
	acct, err := r.loadOAuthAccount()
	if err != nil {
		return "", err
	}
	return acct.OrganizationRole, nil
}

func (r *mqlClaudeCode) subscription() (string, error) {
	acct, err := r.loadOAuthAccount()
	if err != nil {
		return "", err
	}
	return acct.BillingType, nil
}

func (r *mqlClaudeCode) userId() (string, error) {
	acct, err := r.loadOAuthAccount()
	if err != nil {
		return "", err
	}
	return acct.AccountUuid, nil
}

func (r *mqlClaudeCode) organizationId() (string, error) {
	acct, err := r.loadOAuthAccount()
	if err != nil {
		return "", err
	}
	return acct.OrganizationUuid, nil
}

func (r *mqlClaudeCode) settings() (interface{}, error) {
	var settings map[string]interface{}
	err := readJSONFileAfero(r.afs(), r.configDir(), "settings.json", &settings)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]interface{}{}, nil
		}
		return nil, err
	}
	return settings, nil
}

func (r *mqlClaudeCode) enabledPlugins() ([]interface{}, error) {
	var settings struct {
		EnabledPlugins map[string]bool `json:"enabledPlugins"`
	}
	err := readJSONFileAfero(r.afs(), r.configDir(), "settings.json", &settings)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var result []interface{}
	for name, enabled := range settings.EnabledPlugins {
		if enabled {
			result = append(result, name)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].(string) < result[j].(string)
	})
	return result, nil
}

func (r *mqlClaudeCode) plugins() ([]interface{}, error) {
	afs := r.afs()

	var installedPlugins struct {
		Version int                               `json:"version"`
		Plugins map[string][]installedPluginEntry `json:"plugins"`
	}
	err := readJSONFileAfero(afs, r.configDir(), "plugins/installed_plugins.json", &installedPlugins)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var settings struct {
		EnabledPlugins map[string]bool `json:"enabledPlugins"`
	}
	_ = readJSONFileAfero(afs, r.configDir(), "settings.json", &settings)

	var result []interface{}
	for name, entries := range installedPlugins.Plugins {
		for _, entry := range entries {
			enabled := false
			if settings.EnabledPlugins != nil {
				enabled = settings.EnabledPlugins[name]
			}

			pluginID := "claude.code.plugin/" + name + "/" + entry.Scope
			res, err := NewResource(r.MqlRuntime, "claude.code.plugin", map[string]*llx.RawData{
				"__id":         llx.StringData(pluginID),
				"name":         llx.StringData(name),
				"version":      llx.StringData(entry.Version),
				"scope":        llx.StringData(entry.Scope),
				"installPath":  llx.StringData(entry.InstallPath),
				"installedAt":  llx.StringData(entry.InstalledAt),
				"lastUpdated":  llx.StringData(entry.LastUpdated),
				"gitCommitSha": llx.StringData(entry.GitCommitSha),
				"enabled":      llx.BoolData(enabled),
			})
			if err != nil {
				return nil, err
			}
			result = append(result, res)
		}
	}
	return result, nil
}

func (r *mqlClaudeCode) skills() ([]interface{}, error) {
	return agentSkills(r.MqlRuntime, "claude.code.skill", r.configDir(), defaultClaudeCodeConfigDir,
		filepath.Join(defaultClaudeCodeConfigDir, "skills"), filepath.Join(r.configDir(), "skills"))
}

func (r *mqlClaudeCode) projects() ([]interface{}, error) {
	afs := r.afs()
	state, err := r.loadBackupState()
	if err != nil {
		// A missing backup is expected on hosts without Claude Code history;
		// report no projects rather than failing the query. Real read failures
		// (permission denied, corrupt JSON, I/O) still surface.
		if errors.Is(err, os.ErrNotExist) {
			log.Debug().Err(err).Msg("no claude backup state for projects")
			return nil, nil
		}
		return nil, err
	}

	projectsDir := filepath.Join(r.configDir(), "projects")
	var result []interface{}
	for projectPath, dirName := range state.projectDirMap() {
		memoryDir := filepath.Join(projectsDir, dirName, "memory")
		hasMemory := dirHasFilesAfero(afs, memoryDir)

		res, err := NewResource(r.MqlRuntime, "claude.code.project", map[string]*llx.RawData{
			"__id":      llx.StringData("claude.code.project/" + projectPath),
			"path":      llx.StringData(projectPath),
			"hasMemory": llx.BoolData(hasMemory),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlClaudeCodeProject).modelUsage = state.Projects[projectPath].LastModelUsage
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlClaudeCode) repos() ([]interface{}, error) {
	state, err := r.loadBackupState()
	if err != nil {
		// A missing backup is expected on hosts without Claude Code history;
		// report no repos rather than failing the query. Real read failures
		// (permission denied, corrupt JSON, I/O) still surface.
		if errors.Is(err, os.ErrNotExist) {
			log.Debug().Err(err).Msg("no claude backup state for repos")
			return nil, nil
		}
		return nil, err
	}

	paths := make([]string, 0, len(state.Projects))
	for projectPath := range state.Projects {
		paths = append(paths, projectPath)
	}
	return gitReposFromPaths(r.MqlRuntime, "claude.code.repo", paths)
}

func (r *mqlClaudeCode) mcpServers() ([]interface{}, error) {
	// The needs-auth cache records which servers require authentication and
	// when that was last verified. Presence in this file means needsAuth.
	var authCache map[string]struct {
		Timestamp int64 `json:"timestamp"`
	}
	if err := readJSONFileAfero(r.afs(), r.configDir(), "mcp-needs-auth-cache.json", &authCache); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	// The full server definitions (command/args/url/env) live in
	// .claude.json, captured in the backup state we already load, and in each
	// project's .mcp.json. A missing or unreadable backup is not fatal: we
	// still surface whatever the needs-auth cache knows about, just without
	// the connection details.
	var servers []claudeScopedMcpServer
	if state, err := r.loadBackupState(); err != nil {
		// A missing backup is expected on hosts without Claude Code history;
		// log at debug so a real failure (corrupt JSON, permission denied)
		// is still discoverable without warning-spamming every scan.
		log.Debug().Err(err).Msg("could not load claude backup state for MCP server details")
	} else if state != nil {
		servers = claudeMcpServers(r.afs(), state)
	}
	authNames := make([]string, 0, len(authCache))
	for name := range authCache {
		authNames = append(authNames, name)
	}
	servers = withAuthCacheOnlyServers(servers, authNames)

	var result []interface{}
	for _, scoped := range servers {
		name, srv := scoped.name, scoped.entry
		needsAuth := false
		lastChecked := ""
		if entry, ok := authCache[name]; ok {
			needsAuth = true
			if entry.Timestamp > 0 {
				lastChecked = time.UnixMilli(entry.Timestamp).UTC().Format(time.RFC3339)
			}
		}

		res, err := NewResource(r.MqlRuntime, "claude.code.mcpServer", map[string]*llx.RawData{
			"__id":        llx.StringData(claudeMcpServerID(scoped.project, name)),
			"name":        llx.StringData(name),
			"project":     llx.StringData(scoped.project),
			"type":        llx.StringData(deriveMcpTransport(srv.Type, srv.Command, srv.URL)),
			"command":     llx.StringData(srv.Command),
			"args":        strSliceToArrayData(srv.Args),
			"url":         llx.StringData(srv.URL),
			"hasEnv":      llx.BoolData(len(srv.Env) > 0),
			"needsAuth":   llx.BoolData(needsAuth),
			"lastChecked": llx.StringData(lastChecked),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlClaudeCode) model() (string, error) {
	var settings struct {
		Model string `json:"model"`
	}
	err := readJSONFileAfero(r.afs(), r.configDir(), "settings.json", &settings)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return settings.Model, nil
}

func (r *mqlClaudeCode) models() ([]interface{}, error) {
	state, err := r.loadBackupState()
	if err != nil {
		// A missing backup is expected on hosts without Claude Code history;
		// report no usage rather than failing the query. Real read failures
		// (permission denied, corrupt JSON, I/O) still surface.
		if errors.Is(err, os.ErrNotExist) {
			log.Debug().Err(err).Msg("no claude backup state for model usage")
			return nil, nil
		}
		return nil, err
	}

	// Sum each model's usage across every recorded project.
	totals := map[string]claudeModelUsage{}
	for _, project := range state.Projects {
		for name, usage := range project.LastModelUsage {
			agg := totals[name]
			agg.add(usage)
			totals[name] = agg
		}
	}
	return claudeModelUsageResources(r.MqlRuntime, "", totals)
}

func (p *mqlClaudeCodeProject) models() ([]interface{}, error) {
	return claudeModelUsageResources(p.MqlRuntime, p.Path.Data+"/", p.modelUsage)
}

// Helper types and functions

type oauthAccount struct {
	AccountUuid      string `json:"accountUuid"`
	EmailAddress     string `json:"emailAddress"`
	OrganizationUuid string `json:"organizationUuid"`
	BillingType      string `json:"billingType"`
	OrganizationRole string `json:"organizationRole"`
	OrganizationName string `json:"organizationName"`
}

type installedPluginEntry struct {
	Scope        string `json:"scope"`
	InstallPath  string `json:"installPath"`
	Version      string `json:"version"`
	InstalledAt  string `json:"installedAt"`
	LastUpdated  string `json:"lastUpdated"`
	GitCommitSha string `json:"gitCommitSha"`
}

type claudeBackupState struct {
	OAuthAccount *oauthAccount                   `json:"oauthAccount"`
	Projects     map[string]claudeProjectEntry   `json:"projects"`
	McpServers   map[string]claudeMcpServerEntry `json:"mcpServers"`
}

// claudeProjectEntry is the per-project record inside .claude.json. We only
// read the model usage history; the rest of the (large) project object is
// ignored.
type claudeProjectEntry struct {
	LastModelUsage map[string]claudeModelUsage `json:"lastModelUsage"`
	// McpServers are the servers configured for this project only (Claude
	// Code's "local" scope), kept in .claude.json rather than the repository.
	McpServers map[string]claudeMcpServerEntry `json:"mcpServers"`
}

// claudeModelUsage is the cumulative usage of a single model, as recorded
// per project in .claude.json under lastModelUsage.
type claudeModelUsage struct {
	InputTokens              int64   `json:"inputTokens"`
	OutputTokens             int64   `json:"outputTokens"`
	CacheReadInputTokens     int64   `json:"cacheReadInputTokens"`
	CacheCreationInputTokens int64   `json:"cacheCreationInputTokens"`
	WebSearchRequests        int64   `json:"webSearchRequests"`
	CostUSD                  float64 `json:"costUSD"`
}

func (u *claudeModelUsage) add(o claudeModelUsage) {
	u.InputTokens += o.InputTokens
	u.OutputTokens += o.OutputTokens
	u.CacheReadInputTokens += o.CacheReadInputTokens
	u.CacheCreationInputTokens += o.CacheCreationInputTokens
	u.WebSearchRequests += o.WebSearchRequests
	u.CostUSD += o.CostUSD
}

// claudeModelUsageResources turns a per-model usage map into claude.code.modelUsage
// resources, sorted by model name. idPrefix disambiguates the cache key between
// the host-wide aggregate ("") and a per-project breakdown ("<projectPath>/").
func claudeModelUsageResources(runtime *plugin.Runtime, idPrefix string, usage map[string]claudeModelUsage) ([]interface{}, error) {
	names := make([]string, 0, len(usage))
	for name := range usage {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]interface{}, 0, len(names))
	for _, name := range names {
		u := usage[name]
		res, err := CreateResource(runtime, "claude.code.modelUsage", map[string]*llx.RawData{
			"__id":                     llx.StringData("claude.code.modelUsage/" + idPrefix + name),
			"name":                     llx.StringData(name),
			"inputTokens":              llx.IntData(u.InputTokens),
			"outputTokens":             llx.IntData(u.OutputTokens),
			"cacheReadInputTokens":     llx.IntData(u.CacheReadInputTokens),
			"cacheCreationInputTokens": llx.IntData(u.CacheCreationInputTokens),
			"webSearchRequests":        llx.IntData(u.WebSearchRequests),
			"cost":                     llx.FloatData(u.CostUSD),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

// claudeMcpServerEntry is a single MCP server definition as stored in
// .claude.json. Stdio servers carry command/args/env; http and sse servers
// carry a url. `type` is optional and inferred from the shape when absent.
type claudeMcpServerEntry struct {
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	Env     map[string]string `json:"env"`
}

// claudeScopedMcpServer is one MCP server together with the project it is
// scoped to; project is empty for a user-scope server.
type claudeScopedMcpServer struct {
	project string
	name    string
	entry   claudeMcpServerEntry
}

// claudeMcpServers returns every MCP server Claude Code is configured with,
// across its three scopes:
//   - user: the top-level `mcpServers` in .claude.json, project empty;
//   - local: `projects[<path>].mcpServers` in .claude.json;
//   - project: the `.mcp.json` checked into each project's root.
//
// A local and a project server with the same name in the same project are one
// server as far as Claude Code is concerned (local takes precedence), so it is
// reported once, with the local definition. A project whose .mcp.json is
// missing or does not parse contributes nothing from that file. The result is
// sorted by project, then name, so ids and output are stable.
func claudeMcpServers(afs *afero.Afero, state *claudeBackupState) []claudeScopedMcpServer {
	var out []claudeScopedMcpServer
	for name, srv := range state.McpServers {
		out = append(out, claudeScopedMcpServer{name: name, entry: srv})
	}
	for projectPath, project := range state.Projects {
		scoped := map[string]claudeMcpServerEntry{}
		var repo struct {
			McpServers map[string]claudeMcpServerEntry `json:"mcpServers"`
		}
		if data, err := afs.ReadFile(filepath.Join(projectPath, ".mcp.json")); err == nil {
			if err := unmarshalJSONConfig(data, &repo); err != nil {
				log.Debug().Err(err).Str("project", projectPath).Msg("could not parse claude project .mcp.json")
			}
		}
		for name, srv := range repo.McpServers {
			scoped[name] = srv
		}
		for name, srv := range project.McpServers {
			scoped[name] = srv
		}
		for name, srv := range scoped {
			out = append(out, claudeScopedMcpServer{project: projectPath, name: name, entry: srv})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].project != out[j].project {
			return out[i].project < out[j].project
		}
		return out[i].name < out[j].name
	})
	return out
}

// withAuthCacheOnlyServers appends a user-scope entry, without connection
// details, for every needs-auth cache name that no scope defines, so a server
// Claude Code only remembers from its auth cache is still reported. The cache is
// keyed by server name alone, so a name any scope already defines (user, local
// or project) is that server, not another one: adding it again would report a
// project-scoped server twice, once under a phantom user scope. Added names are
// sorted, so output and ids stay stable across runs.
func withAuthCacheOnlyServers(servers []claudeScopedMcpServer, authNames []string) []claudeScopedMcpServer {
	known := make(map[string]struct{}, len(servers))
	for _, srv := range servers {
		known[srv.name] = struct{}{}
	}
	var added []string
	for _, name := range authNames {
		if _, ok := known[name]; !ok {
			known[name] = struct{}{}
			added = append(added, name)
		}
	}
	sort.Strings(added)
	for _, name := range added {
		servers = append(servers, claudeScopedMcpServer{name: name})
	}
	return servers
}

// claudeMcpServerID is the resource id of a Claude Code MCP server. A user-scope
// server keeps the historical "claude.code.mcpServer/<name>" id; a project-scoped
// one includes the project path, so the same name in two projects stays distinct.
func claudeMcpServerID(project, name string) string {
	if project == "" {
		return "claude.code.mcpServer/" + name
	}
	return "claude.code.mcpServer/" + project + "/" + name
}

// projectDirMap returns a map from original project path to encoded directory name.
func (s *claudeBackupState) projectDirMap() map[string]string {
	result := make(map[string]string)
	for path := range s.Projects {
		encoded := pathToProjectDir(path)
		result[path] = encoded
	}
	return result
}

// pathToProjectDir encodes a filesystem path the same way Claude Code does:
// replace all "/" and "." with "-" and prepend "-".
func pathToProjectDir(path string) string {
	s := strings.TrimPrefix(path, "/")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ".", "-")
	return "-" + s
}

func (r *mqlClaudeCode) loadBackupState() (*claudeBackupState, error) {
	r.backupOnce.Do(func() {
		afs := r.afs()
		dir := r.configDir()

		backupFile, err := findLatestBackupAfero(afs, dir)
		if err != nil {
			r.backupErr = err
			return
		}
		var state claudeBackupState
		if err := readJSONFileAfero(afs, dir, filepath.Join("backups", backupFile), &state); err != nil {
			r.backupErr = err
			return
		}
		r.backupState = &state
	})

	return r.backupState, r.backupErr
}

func (r *mqlClaudeCode) loadOAuthAccount() (*oauthAccount, error) {
	state, err := r.loadBackupState()
	if err != nil {
		// A missing backup is expected on hosts without Claude Code history;
		// surface empty account fields rather than failing the query. Real read
		// failures (permission denied, corrupt JSON, I/O) still surface.
		if errors.Is(err, os.ErrNotExist) {
			log.Debug().Err(err).Msg("no claude backup state for account details")
			return &oauthAccount{}, nil
		}
		return nil, err
	}
	if state.OAuthAccount == nil {
		return &oauthAccount{}, nil
	}
	return state.OAuthAccount, nil
}

func findLatestBackupAfero(afs *afero.Afero, configDir string) (string, error) {
	backupsDir := filepath.Join(configDir, "backups")
	entries, err := afs.ReadDir(backupsDir)
	if err != nil {
		return "", fmt.Errorf("cannot read backups directory: %w", err)
	}

	const prefix = ".claude.json.backup."
	var latestBackup string
	var latestTimestamp int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		tsStr := strings.TrimPrefix(entry.Name(), prefix)
		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			continue
		}
		if ts > latestTimestamp {
			latestTimestamp = ts
			latestBackup = entry.Name()
		}
	}

	if latestBackup == "" {
		// A backups dir with no backup files is the same benign "no history"
		// case as a missing dir; wrap os.ErrNotExist so callers can suppress it
		// while still surfacing real read failures (permission denied, I/O).
		return "", fmt.Errorf("no backup files found in %s: %w", backupsDir, os.ErrNotExist)
	}
	return latestBackup, nil
}

// Stub ID methods for child resources (they use __id set during creation)

func (r *mqlClaudeCodePlugin) id() (string, error) {
	return "claude.code.plugin/" + r.Name.Data + "/" + r.Scope.Data, nil
}

func (r *mqlClaudeCodeSkill) id() (string, error) {
	return "claude.code.skill/" + r.Source.Data, nil
}

func (r *mqlClaudeCodeSkill) sha256() (string, error) {
	return contentSHA256(r.Content.Data), nil
}

func (r *mqlClaudeCodeSkill) purl() (string, error) {
	return skillPURL(connectionAfs(r.MqlRuntime), r.Source.Data), nil
}

func (r *mqlClaudeCodeProject) id() (string, error) {
	return "claude.code.project/" + r.Path.Data, nil
}

func (r *mqlClaudeCodeMcpServer) id() (string, error) {
	return claudeMcpServerID(r.Project.Data, r.Name.Data), nil
}

func (r *mqlClaudeCodeRepo) id() (string, error) {
	return "claude.code.repo/" + r.Path.Data, nil
}

func (r *mqlClaudeCodeMcpServer) running() (*llx.AssetValue, error) {
	return mcpServerAsset(r), nil
}

// MqlAsset implements plugin.AssetSource: the asset the `running` anchor stands
// for, with the connection needed to reach it. See mcpServerAssetFor.
func (r *mqlClaudeCodeMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

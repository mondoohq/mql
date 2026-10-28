// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/afero"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// claudeDesktopConfigFile is the file the Claude desktop app keeps its MCP
// server definitions in, inside its configuration directory.
const claudeDesktopConfigFile = "claude_desktop_config.json"

func initClaudeDesktop(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["configPath"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, fmt.Errorf("wrong type for 'configPath' in claude.desktop initialization, it must be a string")
		}
		if path != "" {
			return args, nil, nil
		}
		delete(args, "configPath")
	}

	home, err := targetHomeDir(runtime)
	if err != nil {
		return nil, nil, err
	}
	osFamily := ""
	if conn, ok := runtime.Connection.(shared.Connection); ok {
		osFamily = targetOSFamily(conn)
	}
	args["configPath"] = llx.StringData(claudeDesktopConfigDir(home, osFamily))
	return args, nil, nil
}

// claudeDesktopConfigDir returns the Claude desktop app's configuration
// directory under a user home: the per-user application-data directory of the
// platform, named "Claude".
func claudeDesktopConfigDir(home, osFamily string) string {
	switch osFamily {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude")
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Claude")
	default: // linux and other unix-likes
		return filepath.Join(home, ".config", "Claude")
	}
}

func (r *mqlClaudeDesktop) id() (string, error) {
	return "claude.desktop/" + r.ConfigPath.Data, nil
}

func (r *mqlClaudeDesktop) mcpServers() ([]any, error) {
	servers, err := claudeDesktopMCPServers(connectionAfs(r.MqlRuntime), r.ConfigPath.Data)
	if err != nil {
		return nil, err
	}
	extensions := r.GetExtensions()
	if extensions.Error != nil {
		return nil, extensions.Error
	}

	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	source := filepath.Join(r.ConfigPath.Data, claudeDesktopConfigFile)
	result := make([]any, 0, len(names))
	for _, name := range names {
		srv := servers[name]
		fields := map[string]*llx.RawData{
			"__id":    llx.StringData("claude.desktop.mcpServer/" + name),
			"name":    llx.StringData(name),
			"type":    llx.StringData(deriveMcpTransport(srv.Type, srv.Command, srv.URL)),
			"command": llx.StringData(srv.Command),
			"args":    strSliceToArrayData(srv.Args),
			"url":     llx.StringData(srv.URL),
			"hasEnv":  llx.BoolData(len(srv.Env) > 0),
			"enabled": llx.BoolData(true),

			"hasHeaders":  llx.BoolData(len(srv.Headers) > 0),
			"headerNames": mcpHeaderNamesData(mapKeys(srv.Headers)),
			"source":      llx.StringData(source),
		}
		setMcpServerShape(fields, srv.Command, srv.Args, srv.URL, mapKeys(srv.Env))
		res, err := NewResource(r.MqlRuntime, "claude.desktop.mcpServer", fields)
		if err != nil {
			return nil, err
		}
		res.(*mqlClaudeDesktopMcpServer).Extension.State = plugin.StateIsSet | plugin.StateIsNull
		result = append(result, res)
	}

	for _, e := range extensions.Data {
		srv := e.(*mqlClaudeDesktopExtension).GetMcpServer()
		if srv.Error != nil {
			return nil, srv.Error
		}
		if srv.Data != nil {
			result = append(result, srv.Data)
		}
	}
	return result, nil
}

// claudeDesktopExtensionsFile lists the installed desktop extensions with the
// manifest of each, inside the configuration directory.
const claudeDesktopExtensionsFile = "extensions-installations.json"

// claudeDesktopExtension is one installed extension in
// extensions-installations.json.
type claudeDesktopExtension struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	InstalledAt string `json:"installedAt"`
	Source      string `json:"source"`
	Manifest    struct {
		Name        string          `json:"name"`
		DisplayName string          `json:"display_name"`
		Version     string          `json:"version"`
		Description string          `json:"description"`
		Author      json.RawMessage `json:"author"`
		Repository  json.RawMessage `json:"repository"`
		Server      struct {
			Type      string               `json:"type"`
			McpConfig claudeMcpServerEntry `json:"mcp_config"`
		} `json:"server"`
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	} `json:"manifest"`
	SignatureInfo struct {
		Status string `json:"status"`
	} `json:"signatureInfo"`
}

// readClaudeDesktopExtensions reads extensions-installations.json in
// configDir, sorted by extension id, together with each extension's enabled
// state from "Claude Extensions Settings/<id>.json". An extension without a
// settings file is enabled, which is the state the app installs it in.
func readClaudeDesktopExtensions(afs *afero.Afero, configDir string) ([]claudeDesktopExtension, map[string]bool, error) {
	data, err := readBoundedRegularFile(afs, filepath.Join(configDir, claudeDesktopExtensionsFile), maxConfigFileSize)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var installs struct {
		Extensions map[string]claudeDesktopExtension `json:"extensions"`
	}
	if err := unmarshalJSONConfig(data, &installs); err != nil {
		return nil, nil, fmt.Errorf("failed to parse claude desktop %s: %w", claudeDesktopExtensionsFile, err)
	}

	exts := make([]claudeDesktopExtension, 0, len(installs.Extensions))
	enabled := make(map[string]bool, len(installs.Extensions))
	for id, ext := range installs.Extensions {
		if ext.ID == "" {
			ext.ID = id
		}
		exts = append(exts, ext)

		enabled[ext.ID] = true
		var settings struct {
			IsEnabled *bool `json:"isEnabled"`
		}
		if err := readJSONFileAfero(afs, filepath.Join(configDir, "Claude Extensions Settings"), ext.ID+".json", &settings); err == nil && settings.IsEnabled != nil {
			enabled[ext.ID] = *settings.IsEnabled
		}
	}
	sort.Slice(exts, func(i, j int) bool { return exts[i].ID < exts[j].ID })
	return exts, enabled, nil
}

// mcpServer returns the server an extension runs. The manifest writes
// ${__dirname} for the extension's directory, which is substituted as the app
// does; ${user_config.*} placeholders stand for values the user entered and
// are left as written.
func (e claudeDesktopExtension) mcpServer(dir string) mcpServerSpec {
	cfg := e.Manifest.Server.McpConfig
	spec := mcpServerSpec{
		name:      e.ID,
		transport: deriveMcpTransport(cfg.Type, cfg.Command, cfg.URL),
		command:   cfg.Command,
		args:      cfg.Args,
		url:       cfg.URL,
		hasEnv:    len(cfg.Env) > 0,

		hasHeaders:  len(cfg.Headers) > 0,
		envNames:    mcpNames(mapKeys(cfg.Env)),
		headerNames: mcpNames(mapKeys(cfg.Headers)),
	}
	return spec.expandPlaceholder("__dirname", dir)
}

func (r *mqlClaudeDesktop) extensions() ([]any, error) {
	exts, enabled, err := readClaudeDesktopExtensions(connectionAfs(r.MqlRuntime), r.ConfigPath.Data)
	if err != nil {
		return nil, err
	}

	result := make([]any, 0, len(exts))
	for _, ext := range exts {
		version := ext.Manifest.Version
		if version == "" {
			version = ext.Version
		}
		tools := make([]string, 0, len(ext.Manifest.Tools))
		for _, t := range ext.Manifest.Tools {
			tools = append(tools, t.Name)
		}
		dir := filepath.Join(r.ConfigPath.Data, "Claude Extensions", ext.ID)
		res, err := NewResource(r.MqlRuntime, "claude.desktop.extension", map[string]*llx.RawData{
			"__id":            llx.StringData("claude.desktop.extension/" + dir),
			"id":              llx.StringData(ext.ID),
			"name":            llx.StringData(ext.Manifest.Name),
			"displayName":     llx.StringData(ext.Manifest.DisplayName),
			"version":         llx.StringData(version),
			"description":     llx.StringData(ext.Manifest.Description),
			"author":          llx.StringData(pluginAuthorName(ext.Manifest.Author)),
			"repository":      llx.StringData(pluginRepositoryURL(ext.Manifest.Repository)),
			"source":          llx.StringData(ext.Source),
			"path":            llx.StringData(dir),
			"installedAt":     llx.TimeDataPtr(parseRFC3339Ptr(ext.InstalledAt)),
			"signatureStatus": llx.StringData(ext.SignatureInfo.Status),
			"enabled":         llx.BoolData(enabled[ext.ID]),
			"tools":           llx.ArrayData(llx.TArr2Raw(tools), types.String),
		})
		if err != nil {
			return nil, err
		}
		server := ext.mcpServer(dir)
		server.source = filepath.Join(r.ConfigPath.Data, claudeDesktopExtensionsFile)
		res.(*mqlClaudeDesktopExtension).server = server
		result = append(result, res)
	}
	return result, nil
}

type mqlClaudeDesktopExtensionInternal struct {
	server mcpServerSpec
}

func (r *mqlClaudeDesktopExtension) id() (string, error) {
	return "claude.desktop.extension/" + r.Path.Data, nil
}

func (r *mqlClaudeDesktopExtension) mcpServer() (*mqlClaudeDesktopMcpServer, error) {
	s := r.server
	if s.command == "" && s.url == "" {
		r.McpServer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	fields := map[string]*llx.RawData{
		"__id":    llx.StringData("claude.desktop.mcpServer/" + s.name),
		"name":    llx.StringData(s.name),
		"type":    llx.StringData(s.transport),
		"command": llx.StringData(s.command),
		"args":    strSliceToArrayData(s.args),
		"url":     llx.StringData(s.url),
		"hasEnv":  llx.BoolData(s.hasEnv),
		"enabled": llx.BoolData(r.Enabled.Data),

		"hasHeaders":  llx.BoolData(s.hasHeaders),
		"headerNames": mcpHeaderNamesData(s.headerNames),
		"source":      llx.StringData(s.source),
	}
	setMcpServerShape(fields, s.command, s.args, s.url, s.envNames)
	res, err := NewResource(r.MqlRuntime, "claude.desktop.mcpServer", fields)
	if err != nil {
		return nil, err
	}
	srv := res.(*mqlClaudeDesktopMcpServer)
	srv.Extension = plugin.TValue[*mqlClaudeDesktopExtension]{Data: r, State: plugin.StateIsSet}
	return srv, nil
}

func (r *mqlClaudeDesktopMcpServer) extension() (*mqlClaudeDesktopExtension, error) {
	r.Extension.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// claudeDesktopMCPServers reads the `mcpServers` of claude_desktop_config.json
// in configDir, keyed by name. A missing file means no servers; a file that
// exists but does not parse is an error.
func claudeDesktopMCPServers(afs *afero.Afero, configDir string) (map[string]claudeMcpServerEntry, error) {
	data, err := afs.ReadFile(filepath.Join(configDir, claudeDesktopConfigFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var config struct {
		McpServers map[string]claudeMcpServerEntry `json:"mcpServers"`
	}
	if err := unmarshalJSONConfig(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse claude desktop %s: %w", claudeDesktopConfigFile, err)
	}
	return config.McpServers, nil
}

func (r *mqlClaudeDesktopMcpServer) id() (string, error) {
	return "claude.desktop.mcpServer/" + r.Name.Data, nil
}

func (r *mqlClaudeDesktopMcpServer) running() (*llx.AssetValue, error) {
	return mcpServerAsset(r), nil
}

// MqlAsset implements plugin.AssetSource: the asset the `running` anchor stands
// for, with the connection needed to reach it. See mcpServerAssetFor.
func (r *mqlClaudeDesktopMcpServer) MqlAsset() (*inventory.Asset, error) {
	return mcpServerAssetFor(r.MqlRuntime, r)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/afero"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
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

func (r *mqlClaudeDesktop) mcpServers() ([]interface{}, error) {
	servers, err := claudeDesktopMCPServers(connectionAfs(r.MqlRuntime), r.ConfigPath.Data)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]interface{}, 0, len(names))
	for _, name := range names {
		srv := servers[name]
		res, err := NewResource(r.MqlRuntime, "claude.desktop.mcpServer", map[string]*llx.RawData{
			"__id":    llx.StringData("claude.desktop.mcpServer/" + name),
			"name":    llx.StringData(name),
			"type":    llx.StringData(deriveMcpTransport(srv.Type, srv.Command, srv.URL)),
			"command": llx.StringData(srv.Command),
			"args":    strSliceToArrayData(srv.Args),
			"url":     llx.StringData(srv.URL),
			"hasEnv":  llx.BoolData(len(srv.Env) > 0),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
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

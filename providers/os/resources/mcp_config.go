// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strings"

	"github.com/spf13/afero"
	"github.com/tailscale/hujson"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// mcpServerSpec is one MCP server definition read from an AI tool's
// configuration, normalized across the tools' file formats. Secrets (env and
// header values) are never kept, only whether any are set.
type mcpServerSpec struct {
	name       string
	transport  string
	command    string
	args       []string
	url        string
	hasEnv     bool
	hasHeaders bool
	enabled    bool
	// source is the configuration file the server was read from.
	source string
}

// mcpJSONServer is the union of the JSON shapes AI tools write for one MCP
// server. Each field below was observed in a file written by the tool's own
// `mcp add` command:
//   - the common shape (Claude, Gemini, Augment, Copilot CLI): type, command,
//     args, env, url, headers
//   - Gemini and Qwen: httpUrl for a streamable HTTP server
//   - Antigravity CLI: serverUrl for an http server
//   - Copilot CLI: type "local" for a stdio server
//   - OpenHands: transport as a string, plus enabled
//   - Cline CLI: transport as an object that carries the whole definition
//   - OpenCode and Kilo: command as an array, environment instead of env,
//     type "local" or "remote", plus enabled
type mcpJSONServer struct {
	Type        string          `json:"type"`
	Transport   json.RawMessage `json:"transport"`
	Command     json.RawMessage `json:"command"`
	Args        []string        `json:"args"`
	URL         string          `json:"url"`
	HTTPURL     string          `json:"httpUrl"`
	ServerURL   string          `json:"serverUrl"`
	Env         map[string]any  `json:"env"`
	Environment map[string]any  `json:"environment"`
	Headers     map[string]any  `json:"headers"`
	Enabled     *bool           `json:"enabled"`
	Disabled    *bool           `json:"disabled"`
}

// spec normalizes the server definition. A server is enabled unless the file
// says otherwise through `enabled: false` or `disabled: true`.
func (s mcpJSONServer) spec(name, source string) mcpServerSpec {
	transport := s.Type
	if len(s.Transport) > 0 {
		var str string
		if err := json.Unmarshal(s.Transport, &str); err == nil {
			if str != "" {
				transport = str
			}
		} else {
			var nested mcpJSONServer
			if err := json.Unmarshal(s.Transport, &nested); err == nil {
				out := nested.spec(name, source)
				out.enabled = out.enabled && s.isEnabled()
				return out
			}
		}
	}

	var command string
	var args []string
	if len(s.Command) > 0 {
		var str string
		if err := json.Unmarshal(s.Command, &str); err == nil {
			command = str
		} else {
			var parts []string
			if err := json.Unmarshal(s.Command, &parts); err == nil && len(parts) > 0 {
				command = parts[0]
				args = append(args, parts[1:]...)
			}
		}
	}
	args = append(args, s.Args...)

	url := s.URL
	if url == "" {
		url = s.HTTPURL
	}
	if url == "" {
		url = s.ServerURL
	}

	return mcpServerSpec{
		name:       name,
		transport:  deriveMcpTransport(transport, command, url),
		command:    command,
		args:       args,
		url:        url,
		hasEnv:     len(s.Env) > 0 || len(s.Environment) > 0,
		hasHeaders: len(s.Headers) > 0,
		enabled:    s.isEnabled(),
		source:     source,
	}
}

func (s mcpJSONServer) isEnabled() bool {
	if s.Enabled != nil && !*s.Enabled {
		return false
	}
	if s.Disabled != nil && *s.Disabled {
		return false
	}
	return true
}

// decodeJSONC parses a JSON file that may carry comments and trailing commas,
// as VS Code, OpenCode and Copilot CLI files do. An empty file is an empty
// object.
func decodeJSONC(data []byte, v any) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	clean, err := hujson.Standardize(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(clean, v)
}

// parseMcpServersJSON returns the MCP servers of a JSON config, sorted by
// name. key names the object holding them ("mcpServers", "servers", "mcp").
// With an empty key the file is a plugin's .mcp.json, which comes in two
// shapes: wrapped in `mcpServers`, or the server map itself at the top level.
func parseMcpServersJSON(data []byte, key, source string) ([]mcpServerSpec, error) {
	var top map[string]json.RawMessage
	if err := decodeJSONC(data, &top); err != nil {
		return nil, err
	}

	raw := json.RawMessage(nil)
	switch {
	case key != "":
		raw = top[key]
	case top["mcpServers"] != nil:
		raw = top["mcpServers"]
	default:
		servers := map[string]mcpJSONServer{}
		for name, v := range top {
			var srv mcpJSONServer
			if err := json.Unmarshal(v, &srv); err != nil {
				continue
			}
			servers[name] = srv
		}
		return mcpSpecsFromMap(servers, source), nil
	}
	if len(raw) == 0 {
		return nil, nil
	}

	var servers map[string]mcpJSONServer
	if err := json.Unmarshal(raw, &servers); err != nil {
		return nil, err
	}
	return mcpSpecsFromMap(servers, source), nil
}

func mcpSpecsFromMap(servers map[string]mcpJSONServer, source string) []mcpServerSpec {
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	specs := make([]mcpServerSpec, 0, len(names))
	for _, name := range names {
		specs = append(specs, servers[name].spec(name, source))
	}
	return specs
}

// readMcpServersFile reads the MCP servers from one JSON config file. A
// missing file means no servers; a file that exists but does not parse is an
// error.
func readMcpServersFile(afs *afero.Afero, path, key string) ([]mcpServerSpec, error) {
	data, err := readBoundedRegularFile(afs, path, maxConfigFileSize)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return parseMcpServersJSON(data, key, path)
}

// expandPlaceholder replaces a ${name} placeholder in a server's command and
// args, which plugin and extension manifests use to point at their install
// directory (${CLAUDE_PLUGIN_ROOT}, ${extensionPath}, ${__dirname}). Other
// placeholders, such as user-supplied configuration values, are left as written.
func (s mcpServerSpec) expandPlaceholder(name, value string) mcpServerSpec {
	token := "${" + name + "}"
	s.command = strings.ReplaceAll(s.command, token, value)
	args := make([]string, len(s.args))
	for i, a := range s.args {
		args[i] = strings.ReplaceAll(a, token, value)
	}
	s.args = args
	return s
}

// mcpServerResourceID is the id of an MCP server resource that is keyed by the
// file declaring it, so the same name in two files stays two servers.
func mcpServerResourceID(resourceType, source, name string) string {
	return resourceType + "/" + source + "/" + name
}

// mcpServerResourceArgs are the resource arguments shared by the MCP server
// resources keyed by their source file.
func mcpServerResourceArgs(resourceType string, s mcpServerSpec) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":       llx.StringData(mcpServerResourceID(resourceType, s.source, s.name)),
		"name":       llx.StringData(s.name),
		"type":       llx.StringData(s.transport),
		"command":    llx.StringData(s.command),
		"args":       strSliceToArrayData(s.args),
		"url":        llx.StringData(s.url),
		"hasEnv":     llx.BoolData(s.hasEnv),
		"hasHeaders": llx.BoolData(s.hasHeaders),
		"enabled":    llx.BoolData(s.enabled),
		"source":     llx.StringData(s.source),
	}
}

// newMcpServerResources creates one resource of resourceType per server, for
// the MCP server resources keyed by their source file.
func newMcpServerResources(runtime *plugin.Runtime, resourceType string, specs []mcpServerSpec) ([]any, error) {
	result := make([]any, 0, len(specs))
	for _, s := range specs {
		res, err := NewResource(runtime, resourceType, mcpServerResourceArgs(resourceType, s))
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

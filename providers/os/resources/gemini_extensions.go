// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// geminiExtensionPathVar is the placeholder Gemini CLI and Qwen Code
// substitute with an extension's directory in its MCP server commands.
const geminiExtensionPathVar = "extensionPath"

// geminiExtension is an extension installed under <configDir>/extensions, in
// the layout Gemini CLI uses and Qwen Code inherited from it.
type geminiExtension struct {
	name            string
	version         string
	dir             string
	source          string
	installType     string
	releaseTag      string
	contextFileName string
	commands        []string
	mcpServers      []mcpServerSpec
	skillsDir       string
	enabled         bool
}

// geminiExtensionFlavor names the files one tool uses for its extensions.
type geminiExtensionFlavor struct {
	// manifests are the manifest file names tried in order.
	manifests []string
	// installFile records where the extension was installed from.
	installFile string
}

var (
	geminiFlavor = geminiExtensionFlavor{
		manifests:   []string{"gemini-extension.json"},
		installFile: ".gemini-extension-install.json",
	}
	qwenFlavor = geminiExtensionFlavor{
		manifests:   []string{"qwen-extension.json", "gemini-extension.json"},
		installFile: ".qwen-extension-install.json",
	}
)

type geminiExtensionManifest struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	ContextFileName json.RawMessage `json:"contextFileName"`
}

// readGeminiExtensions reads the extensions installed under
// <configDir>/extensions, sorted by directory. enabled decides each
// extension's state from its name. A directory without a readable manifest
// is not an extension and is skipped.
func readGeminiExtensions(afs *afero.Afero, configDir string, flavor geminiExtensionFlavor, enabled func(name string) bool) ([]geminiExtension, error) {
	subdirs, err := listSubdirsAfero(afs, filepath.Join(configDir, "extensions"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	sort.Slice(subdirs, func(i, j int) bool { return subdirs[i].path < subdirs[j].path })

	var exts []geminiExtension
	for _, d := range subdirs {
		var manifestPath string
		var data []byte
		for _, name := range flavor.manifests {
			path := filepath.Join(d.path, name)
			if b, err := readBoundedRegularFile(afs, path, maxConfigFileSize); err == nil {
				manifestPath, data = path, b
				break
			}
		}
		if manifestPath == "" {
			continue
		}
		var m geminiExtensionManifest
		if err := decodeJSONC(data, &m); err != nil {
			log.Debug().Err(err).Str("path", manifestPath).Msg("could not parse extension manifest")
			continue
		}
		name := m.Name
		if name == "" {
			name = d.name
		}

		specs, err := parseMcpServersJSON(data, "mcpServers", manifestPath)
		if err != nil {
			log.Debug().Err(err).Str("path", manifestPath).Msg("could not parse extension MCP servers")
		}
		for i := range specs {
			specs[i] = specs[i].expandPlaceholder(geminiExtensionPathVar, d.path)
		}

		var install struct {
			Source     string `json:"source"`
			Type       string `json:"type"`
			ReleaseTag string `json:"releaseTag"`
		}
		_ = readJSONFileAfero(afs, d.path, flavor.installFile, &install)

		exts = append(exts, geminiExtension{
			name:            name,
			version:         m.Version,
			dir:             d.path,
			source:          install.Source,
			installType:     install.Type,
			releaseTag:      install.ReleaseTag,
			contextFileName: geminiContextFileName(m.ContextFileName),
			commands:        geminiExtensionCommands(afs, filepath.Join(d.path, "commands")),
			mcpServers:      specs,
			skillsDir:       filepath.Join(d.path, "skills"),
			enabled:         enabled(name),
		})
	}
	return exts, nil
}

// geminiContextFileName reads contextFileName, a file name or a list of them
// (joined with a comma). Without one the extension's GEMINI.md is used.
func geminiContextFileName(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return strings.Join(list, ",")
	}
	return ""
}

// geminiExtensionCommands lists the custom commands under an extension's
// commands directory. Each .toml file is a command; subdirectories namespace
// it, so commands/security/analyze.toml is "security:analyze".
func geminiExtensionCommands(afs *afero.Afero, dir string) []string {
	var names []string
	_ = afs.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(path) != ".toml" {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		rel = strings.TrimSuffix(filepath.ToSlash(rel), ".toml")
		names = append(names, strings.ReplaceAll(rel, "/", ":"))
		return nil
	})
	sort.Strings(names)
	return names
}

// geminiEnablementRules reads extensions/extension-enablement.json: per
// extension name, the path rules that enable it ("/home/alice/*") or disable
// it ("!/home/alice/*"). A missing file has no rules.
func geminiEnablementRules(afs *afero.Afero, configDir string) map[string][]string {
	var config map[string]struct {
		Overrides []string `json:"overrides"`
	}
	if err := readJSONFileAfero(afs, filepath.Join(configDir, "extensions"), "extension-enablement.json", &config); err != nil {
		return nil
	}
	rules := make(map[string][]string, len(config))
	for name, c := range config {
		rules[name] = c.Overrides
	}
	return rules
}

// extensionEnabledFor evaluates enablement rules for a directory the way
// Gemini CLI does: the last rule matching the directory wins, a leading "!"
// disables, and a trailing "*" also matches every subdirectory. Without a
// matching rule the extension keeps its default state.
func extensionEnabledFor(rules []string, dir string, def bool) bool {
	dir = strings.TrimSuffix(filepath.ToSlash(dir), "/") + "/"
	enabled := def
	for _, rule := range rules {
		pattern := strings.TrimPrefix(rule, "!")
		var match bool
		if before, ok := strings.CutSuffix(pattern, "*"); ok {
			match = strings.HasPrefix(dir, before)
		} else {
			match = strings.TrimSuffix(pattern, "/")+"/" == dir
		}
		if match {
			enabled = !strings.HasPrefix(rule, "!")
		}
	}
	return enabled
}

// geminiExtensionEnabled returns Gemini CLI's enablement for the home
// directory owning configDir.
func geminiExtensionEnabled(afs *afero.Afero, configDir string) func(string) bool {
	rules := geminiEnablementRules(afs, configDir)
	home := filepath.Dir(configDir)
	return func(name string) bool {
		return extensionEnabledFor(rules[name], home, true)
	}
}

// qwenExtensionEnabled returns Qwen Code's enablement for the home directory
// owning configDir. Qwen keeps a default activation and its path rules per
// extension in extension-store/state.json, and still honors the rules of
// extensions/extension-enablement.json after them.
func qwenExtensionEnabled(afs *afero.Afero, configDir string) func(string) bool {
	var state struct {
		Extensions map[string]struct {
			Name              string   `json:"name"`
			DefaultActivation string   `json:"defaultActivation"`
			LegacyPathRules   []string `json:"legacyPathRules"`
		} `json:"extensions"`
	}
	_ = readJSONFileAfero(afs, filepath.Join(configDir, "extension-store"), "state.json", &state)
	legacy := geminiEnablementRules(afs, configDir)
	home := filepath.Dir(configDir)

	// The store is keyed by an id per installed artifact. Entries are visited in
	// key order so that two entries sharing a name give a stable answer.
	keys := make([]string, 0, len(state.Extensions))
	for k := range state.Extensions {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return func(name string) bool {
		enabled := true
		var rules []string
		for _, k := range keys {
			if e := state.Extensions[k]; e.Name == name {
				enabled = e.DefaultActivation != "disabled"
				rules = append(rules, e.LegacyPathRules...)
			}
		}
		rules = append(rules, legacy[name]...)
		return extensionEnabledFor(rules, home, enabled)
	}
}

// geminiExtensionArgs are the arguments of a gemini.extension or
// qwen.code.extension resource.
func geminiExtensionArgs(resourceType string, e geminiExtension) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":            llx.StringData(resourceType + "/" + e.dir),
		"name":            llx.StringData(e.name),
		"version":         llx.StringData(e.version),
		"path":            llx.StringData(e.dir),
		"source":          llx.StringData(e.source),
		"installType":     llx.StringData(e.installType),
		"releaseTag":      llx.StringData(e.releaseTag),
		"enabled":         llx.BoolData(e.enabled),
		"contextFileName": llx.StringData(e.contextFileName),
		"commands":        llx.ArrayData(llx.TArr2Raw(e.commands), types.String),
	}
}

// --- gemini.extension

type mqlGeminiExtensionInternal struct {
	ext geminiExtension
}

func (r *mqlGemini) extensions() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	exts, err := readGeminiExtensions(afs, r.ConfigPath.Data, geminiFlavor, geminiExtensionEnabled(afs, r.ConfigPath.Data))
	if err != nil {
		return nil, err
	}
	result := make([]any, 0, len(exts))
	for _, e := range exts {
		res, err := NewResource(r.MqlRuntime, "gemini.extension", geminiExtensionArgs("gemini.extension", e))
		if err != nil {
			return nil, err
		}
		res.(*mqlGeminiExtension).ext = e
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlGeminiExtension) id() (string, error) {
	return "gemini.extension/" + r.Path.Data, nil
}

func (r *mqlGeminiExtension) mcpServers() ([]any, error) {
	result := make([]any, 0, len(r.ext.mcpServers))
	for _, s := range r.ext.mcpServers {
		res, err := NewResource(r.MqlRuntime, "gemini.mcpServer", geminiMcpServerArgs(s))
		if err != nil {
			return nil, err
		}
		srv := res.(*mqlGeminiMcpServer)
		srv.Extension = plugin.TValue[*mqlGeminiExtension]{Data: r, State: plugin.StateIsSet}
		result = append(result, srv)
	}
	return result, nil
}

func (r *mqlGeminiExtension) skills() ([]any, error) {
	return readSkillsFromDirs(r.MqlRuntime, []string{r.ext.skillsDir}, "gemini.skill")
}

func (r *mqlGeminiMcpServer) extension() (*mqlGeminiExtension, error) {
	r.Extension.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// geminiMcpServerID keeps the historical name-only id for servers from
// settings.json and antigravity/mcp_config.json, and keys an extension's
// servers by its manifest, so two extensions may declare the same name.
func geminiMcpServerID(source, name string) string {
	if strings.HasSuffix(source, "-extension.json") {
		return mcpServerResourceID("gemini.mcpServer", source, name)
	}
	return "gemini.mcpServer/" + name
}

func geminiMcpServerArgs(s mcpServerSpec) map[string]*llx.RawData {
	fields := map[string]*llx.RawData{
		"__id":       llx.StringData(geminiMcpServerID(s.source, s.name)),
		"name":       llx.StringData(s.name),
		"type":       llx.StringData(s.transport),
		"command":    llx.StringData(s.command),
		"args":       mcpArgsData(s.args),
		"url":        llx.StringData(redactURL(s.url)),
		"hasEnv":     llx.BoolData(s.hasEnv),
		"hasHeaders": llx.BoolData(s.hasHeaders),
		"source":     llx.StringData(s.source),

		"headerNames": mcpHeaderNamesData(s.headerNames),
	}
	setMcpServerShape(fields, s.command, s.args, s.url, s.envNames)
	return fields
}

// enabledExtensionServers returns the MCP servers of the enabled extensions
// in a list of extension resources.
func enabledExtensionServers[T interface {
	plugin.Resource
	GetEnabled() *plugin.TValue[bool]
	GetMcpServers() *plugin.TValue[[]any]
}](exts []any) ([]any, error) {
	var out []any
	for _, e := range exts {
		ext := e.(T)
		if !ext.GetEnabled().Data {
			continue
		}
		servers := ext.GetMcpServers()
		if servers.Error != nil {
			return nil, servers.Error
		}
		out = append(out, servers.Data...)
	}
	return out, nil
}

// --- qwen.code.extension

type mqlQwenCodeExtensionInternal struct {
	ext geminiExtension
}

func (r *mqlQwenCode) extensions() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	exts, err := readGeminiExtensions(afs, r.ConfigPath.Data, qwenFlavor, qwenExtensionEnabled(afs, r.ConfigPath.Data))
	if err != nil {
		return nil, err
	}
	result := make([]any, 0, len(exts))
	for _, e := range exts {
		res, err := NewResource(r.MqlRuntime, "qwen.code.extension", geminiExtensionArgs("qwen.code.extension", e))
		if err != nil {
			return nil, err
		}
		res.(*mqlQwenCodeExtension).ext = e
		result = append(result, res)
	}
	return result, nil
}

func (r *mqlQwenCodeExtension) id() (string, error) {
	return "qwen.code.extension/" + r.Path.Data, nil
}

func (r *mqlQwenCodeExtension) mcpServers() ([]any, error) {
	result := make([]any, 0, len(r.ext.mcpServers))
	for _, s := range r.ext.mcpServers {
		s.enabled = r.Enabled.Data
		res, err := NewResource(r.MqlRuntime, "qwen.code.mcpServer", mcpServerResourceArgs("qwen.code.mcpServer", s))
		if err != nil {
			return nil, err
		}
		srv := res.(*mqlQwenCodeMcpServer)
		srv.Extension = plugin.TValue[*mqlQwenCodeExtension]{Data: r, State: plugin.StateIsSet}
		result = append(result, srv)
	}
	return result, nil
}

func (r *mqlQwenCodeExtension) skills() ([]any, error) {
	return readSkillsFromDirs(r.MqlRuntime, []string{r.ext.skillsDir}, "qwen.code.skill")
}

func (r *mqlQwenCodeMcpServer) extension() (*mqlQwenCodeExtension, error) {
	r.Extension.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

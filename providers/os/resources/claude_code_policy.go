// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/plist"
	"go.mondoo.com/mql/types"
)

// Locations of Claude Code's managed policy outside the managed settings
// files (code.claude.com/docs/en/managed-settings, "Where each mechanism
// stores the policy").
const (
	claudeMdmDomain           = "com.anthropic.claudecode"
	claudeManagedPrefsDir     = "/Library/Managed Preferences"
	claudePolicyHKLM          = `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\ClaudeCode`
	claudePolicyHKCU          = `HKEY_CURRENT_USER\SOFTWARE\Policies\ClaudeCode`
	claudePolicyRegistryValue = "Settings"
	claudeRemoteSettingsFile  = "remote-settings.json"
	claudeManagedMcpFile      = "managed-mcp.json"
)

// claudeControlKeys are the settings keys that decide how managed sources
// combine. A source that sets only these does not count as a policy.
var claudeControlKeys = map[string]bool{
	"wslInheritsWindowsSettings": true,
	"managedSourcesBehavior":     true,
}

// claudeSettingsSource is one managed source of Claude Code settings.
type claudeSettingsSource struct {
	// locations are the file paths or registry key the settings come from:
	// several files for the merged managed settings files.
	locations []string
	settings  map[string]any
	// parts are the settings of each of several locations, in merge order.
	parts []map[string]any
	// admin is false for the user-writable HKCU registry value.
	admin bool
}

// hasPolicyKey reports whether the source sets any key other than the
// control keys to a non-null value.
func (s claudeSettingsSource) hasPolicyKey() bool {
	for k, v := range s.settings {
		if v != nil && !claudeControlKeys[k] {
			return true
		}
	}
	return false
}

// locationOf returns the location that sets a key, the last one for merged
// files since a later file wins. Empty when the source does not set it.
func (s claudeSettingsSource) locationOf(keys ...string) string {
	for i := len(s.parts) - 1; i >= 0; i-- {
		if claudeSettingAt(s.parts[i], keys...) != nil {
			return s.locations[i]
		}
	}
	if len(s.parts) == 0 && claudeSettingAt(s.settings, keys...) != nil {
		return s.locations[0]
	}
	return ""
}

// claudePolicy is Claude Code's settings resolved across the managed sources
// and the user's settings.json.
type claudePolicy struct {
	// sources are the managed sources that set a policy key, highest
	// priority first.
	sources []claudeSettingsSource
	// policy are the sources whose cross-source keys apply: every admin
	// source, or the HKCU value when it is the only one.
	policy []claudeSettingsSource
	// merge is true when managedSourcesBehavior is "merge".
	merge bool
	// managed is the managed tier Claude Code applies, nil without one.
	managed map[string]any
	// user is the user's settings.json, nil when absent.
	user map[string]any
	// mcp is the parsed managed-mcp.json, nil when absent or unparsable.
	mcp *claudeManagedMcp
}

// claudeManagedMcp is the system's managed-mcp.json.
type claudeManagedMcp struct {
	path    string
	servers map[string]claudeMcpServerEntry
}

// claudeRegistryReader reads the string value name of a registry key. ok is
// false when the key or value does not exist.
type claudeRegistryReader func(key, name string) (value string, ok bool, err error)

// loadClaudePolicy reads every managed source on the target, in Claude Code's
// priority order, plus the user's settings.json and managed-mcp.json.
func loadClaudePolicy(afs *afero.Afero, osFamily, configDir string, readRegistry claudeRegistryReader) (*claudePolicy, error) {
	var all []claudeSettingsSource

	// 1. Server-managed settings, applied from the local cache.
	remotePath := filepath.Join(configDir, claudeRemoteSettingsFile)
	remote, err := readClaudeSettingsFile(afs, remotePath)
	if err != nil {
		return nil, err
	}
	if remote != nil {
		all = append(all, claudeSettingsSource{locations: []string{remotePath}, settings: remote, admin: true})
	}

	// 2. MDM: the macOS configuration profile or the HKLM registry value.
	switch osFamily {
	case "darwin":
		for _, p := range claudeMdmPlists(configDir) {
			settings, err := readClaudePlist(afs, p)
			if err != nil {
				return nil, err
			}
			if settings != nil {
				all = append(all, claudeSettingsSource{locations: []string{p}, settings: settings, admin: true})
				break
			}
		}
	case "windows":
		src, err := readClaudeRegistrySettings(readRegistry, claudePolicyHKLM, true)
		if err != nil {
			return nil, err
		}
		if src != nil {
			all = append(all, *src)
		}
	}

	// 3. managed-settings.json and managed-settings.d, merged in order.
	files, err := claudeManagedSettingsFiles(afs, osFamily)
	if err != nil {
		return nil, err
	}
	var fileSettings map[string]any
	var fileLocations []string
	var fileParts []map[string]any
	for _, f := range files {
		settings, err := readClaudeSettingsFile(afs, f)
		if err != nil {
			return nil, err
		}
		if settings == nil {
			continue
		}
		fileSettings = mergeClaudeSettings(fileSettings, settings)
		fileLocations = append(fileLocations, f)
		fileParts = append(fileParts, settings)
	}
	if fileSettings != nil {
		all = append(all, claudeSettingsSource{locations: fileLocations, settings: fileSettings, parts: fileParts, admin: true})
	}

	// 4. The user-writable HKCU registry value.
	if osFamily == "windows" {
		src, err := readClaudeRegistrySettings(readRegistry, claudePolicyHKCU, false)
		if err != nil {
			return nil, err
		}
		if src != nil {
			all = append(all, *src)
		}
	}

	user, err := readClaudeSettingsFile(afs, filepath.Join(configDir, "settings.json"))
	if err != nil {
		return nil, err
	}

	p := resolveClaudePolicy(all)
	p.user = user
	p.mcp = readClaudeManagedMcp(afs, osFamily)
	return p, nil
}

// resolveClaudePolicy decides which managed sources apply. By default the
// highest-priority admin source with a policy key supplies the policy;
// with managedSourcesBehavior "merge" every admin source contributes, higher
// sources winning single values and lists combining. The HKCU value applies
// only when no admin source is present.
func resolveClaudePolicy(all []claudeSettingsSource) *claudePolicy {
	p := &claudePolicy{}
	var admin []claudeSettingsSource
	var hkcu *claudeSettingsSource
	behaviorSet := false
	for i, s := range all {
		if s.admin && !behaviorSet {
			if b, ok := s.settings["managedSourcesBehavior"].(string); ok {
				p.merge = b == "merge"
				behaviorSet = true
			} else if s.hasPolicyKey() {
				behaviorSet = true
			}
		}
		if !s.hasPolicyKey() {
			continue
		}
		p.sources = append(p.sources, s)
		if s.admin {
			admin = append(admin, s)
		} else {
			hkcu = &all[i]
		}
	}

	switch {
	case len(admin) > 0:
		// An HKCU value is listed in sources but never applies beneath an
		// admin source.
		p.policy = admin
		if p.merge {
			for i := len(admin) - 1; i >= 0; i-- {
				p.managed = mergeClaudeSettings(p.managed, admin[i].settings)
			}
		} else {
			p.managed = mergeClaudeSettings(nil, admin[0].settings)
		}
	case hkcu != nil:
		p.policy = []claudeSettingsSource{*hkcu}
		p.managed = mergeClaudeSettings(nil, hkcu.settings)
	}
	return p
}

// claudeMdmPlists returns the macOS managed preferences files for Claude
// Code in the order Claude Code reads them: the per-user profile of the user
// who owns configDir, then the device-level one.
func claudeMdmPlists(configDir string) []string {
	var out []string
	// configDir is built with the scanner's separator, which is a backslash
	// when mql runs on Windows against a Mac.
	home := path.Dir(filepath.ToSlash(configDir))
	if path.Base(filepath.ToSlash(configDir)) == defaultClaudeCodeConfigDir && path.Dir(home) == "/Users" {
		out = append(out, path.Join(claudeManagedPrefsDir, path.Base(home), claudeMdmDomain+".plist"))
	}
	return append(out, path.Join(claudeManagedPrefsDir, claudeMdmDomain+".plist"))
}

// readClaudeSettingsFile reads a JSON settings file. A missing file has no
// settings (nil); one that cannot be read or is not a JSON object is an
// error, as Claude Code refuses to start on a malformed managed file.
func readClaudeSettingsFile(afs *afero.Afero, file string) (map[string]any, error) {
	data, err := readBoundedRegularFile(afs, file, maxConfigFileSize)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return parseClaudeSettings(data, file)
}

// parseClaudeSettings decodes a settings document. An empty document is an
// empty object.
func parseClaudeSettings(data []byte, location string) (map[string]any, error) {
	settings := map[string]any{}
	if len(bytes.TrimSpace(data)) == 0 {
		return settings, nil
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse claude code settings %s: %w", location, err))
	}
	return settings, nil
}

// readClaudePlist reads a managed preferences plist. A missing file has no
// settings.
func readClaudePlist(afs *afero.Afero, file string) (map[string]any, error) {
	f, err := afs.Open(file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, classifyFsError(err)
	}
	defer f.Close()
	data, err := plist.Decode(f)
	if err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse %s: %w", file, err))
	}
	if data == nil {
		return map[string]any{}, nil
	}
	return data, nil
}

// readClaudeRegistrySettings reads the JSON policy in the Settings value of
// a registry key. A missing key or value is no source.
func readClaudeRegistrySettings(read claudeRegistryReader, key string, admin bool) (*claudeSettingsSource, error) {
	if read == nil {
		return nil, nil
	}
	value, ok, err := read(key, claudePolicyRegistryValue)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	settings, err := parseClaudeSettings([]byte(value), key)
	if err != nil {
		return nil, err
	}
	return &claudeSettingsSource{locations: []string{claudeRegistryLabel(key)}, settings: settings, admin: admin}, nil
}

// claudeRegistryLabel shortens a registry key the way Claude Code's docs name
// it, for example HKLM\SOFTWARE\Policies\ClaudeCode.
func claudeRegistryLabel(key string) string {
	switch key {
	case claudePolicyHKLM:
		return `HKLM\SOFTWARE\Policies\ClaudeCode`
	case claudePolicyHKCU:
		return `HKCU\SOFTWARE\Policies\ClaudeCode`
	}
	return key
}

// readClaudeManagedMcp reads the system's managed-mcp.json. A missing file
// or one Claude Code cannot parse has no effect, so both are nil.
func readClaudeManagedMcp(afs *afero.Afero, osFamily string) *claudeManagedMcp {
	file := joinTargetPath(osFamily, claudeManagedSettingsDir(osFamily), claudeManagedMcpFile)
	data, err := readBoundedRegularFile(afs, file, maxConfigFileSize)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Debug().Err(err).Str("path", file).Msg("could not read claude managed-mcp.json")
		}
		return nil
	}
	var doc struct {
		McpServers map[string]claudeMcpServerEntry `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		log.Debug().Err(err).Str("path", file).Msg("could not parse claude managed-mcp.json")
		return nil
	}
	return &claudeManagedMcp{path: file, servers: doc.McpServers}
}

// claudeWholeKeys are taken whole from the later document instead of
// merging, and claudeEntryKeys replace each named entry whole
// (code.claude.com/docs/en/managed-settings, "Split a file-based policy").
var (
	claudeWholeKeys = map[string]bool{"fallbackModel": true, "modelPicker": true}
	claudeEntryKeys = map[string]bool{"managedMcpServers": true, "extraKnownMarketplaces": true}
)

// mergeClaudeSettings merges over into base and returns the result, leaving
// both unchanged: single values from over replace base's, lists combine
// without duplicates, and nested objects merge key by key.
func mergeClaudeSettings(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		switch {
		case claudeWholeKeys[k]:
			out[k] = v
		case claudeEntryKeys[k]:
			b, _ := out[k].(map[string]any)
			o, ok := v.(map[string]any)
			if !ok {
				out[k] = v
				continue
			}
			m := make(map[string]any, len(b)+len(o))
			for n, e := range b {
				m[n] = e
			}
			for n, e := range o {
				m[n] = e
			}
			out[k] = m
		default:
			out[k] = mergeClaudeValue(out[k], v)
		}
	}
	return out
}

func mergeClaudeValue(base, over any) any {
	switch o := over.(type) {
	case map[string]any:
		if b, ok := base.(map[string]any); ok {
			out := make(map[string]any, len(b)+len(o))
			for k, v := range b {
				out[k] = v
			}
			for k, v := range o {
				out[k] = mergeClaudeValue(out[k], v)
			}
			return out
		}
	case []any:
		if b, ok := base.([]any); ok {
			return unionClaudeLists(b, o)
		}
	}
	return over
}

// unionClaudeLists combines lists in order, dropping duplicates.
func unionClaudeLists(lists ...[]any) []any {
	out := []any{}
	seen := map[string]bool{}
	for _, l := range lists {
		for _, v := range l {
			key, err := json.Marshal(v)
			if err != nil {
				continue
			}
			if seen[string(key)] {
				continue
			}
			seen[string(key)] = true
			out = append(out, v)
		}
	}
	return out
}

// claudeSettingAt returns the value at a dotted path of keys, nil when unset.
func claudeSettingAt(settings map[string]any, keys ...string) any {
	var cur any = settings
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

// effective returns the managed value of a key, or the user's when the
// managed tier does not set it.
func (p *claudePolicy) effective(keys ...string) any {
	if v := claudeSettingAt(p.managed, keys...); v != nil {
		return v
	}
	return claudeSettingAt(p.user, keys...)
}

// effectiveBool returns the effective value of a boolean key, nil when no
// file sets it to a boolean.
func (p *claudePolicy) effectiveBool(keys ...string) *bool {
	if v, ok := claudeSettingAt(p.managed, keys...).(bool); ok {
		return &v
	}
	if v, ok := claudeSettingAt(p.user, keys...).(bool); ok {
		return &v
	}
	return nil
}

// effectiveString returns the effective value of a string key, nil when no
// file sets it to a string.
func (p *claudePolicy) effectiveString(keys ...string) *string {
	if v, ok := claudeSettingAt(p.managed, keys...).(string); ok {
		return &v
	}
	if v, ok := claudeSettingAt(p.user, keys...).(string); ok {
		return &v
	}
	return nil
}

// managedLock returns a managed-only boolean lock. Under "merge" the
// strictest value any admin source sets applies; otherwise the selected
// source's. Nil when no applied source sets it.
func (p *claudePolicy) managedLock(keys ...string) *bool {
	if p.merge {
		return p.anyPolicyTrue(keys...)
	}
	if v, ok := claudeSettingAt(p.managed, keys...).(bool); ok {
		return &v
	}
	return nil
}

// anyPolicyTrue reads a cross-source lock: true when any policy source sets
// it to true, false when one sets it to false and none to true, nil when
// none sets it.
func (p *claudePolicy) anyPolicyTrue(keys ...string) *bool {
	var res *bool
	for _, s := range p.policy {
		if v, ok := claudeSettingAt(s.settings, keys...).(bool); ok {
			if v {
				t := true
				return &t
			}
			f := false
			res = &f
		}
	}
	return res
}

// disableSwitch reads a key whose only valid value is "disable", which any
// file may set: true when the managed tier or the user sets "disable",
// false when one of them sets another value, nil when neither sets it.
func (p *claudePolicy) disableSwitch(paths ...[]string) *bool {
	set := false
	// A nil map reads as unset. Under "merge" every policy source counts,
	// since a "disable" in any of them is the strictest value.
	sources := []map[string]any{p.managed, p.user}
	if p.merge {
		for _, s := range p.policy {
			sources = append(sources, s.settings)
		}
	}
	for _, s := range sources {
		for _, keys := range paths {
			v := claudeSettingAt(s, keys...)
			if v == nil {
				continue
			}
			set = true
			if v == "disable" {
				t := true
				return &t
			}
		}
	}
	if !set {
		return nil
	}
	f := false
	return &f
}

// claudeStringList returns the strings of a list setting.
func claudeStringList(v any) []string {
	l, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(l))
	for _, e := range l {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// combinedList combines a list setting of the managed tier and, unless
// managedOnly, the user's settings.json.
func (p *claudePolicy) combinedList(managedOnly bool, keys ...string) []string {
	lists := [][]any{}
	if l, ok := claudeSettingAt(p.managed, keys...).([]any); ok {
		lists = append(lists, l)
	}
	if !managedOnly {
		if l, ok := claudeSettingAt(p.user, keys...).([]any); ok {
			lists = append(lists, l)
		}
	}
	return claudeStringList(unionClaudeLists(lists...))
}

// policyList unions a list setting across every policy source.
func (p *claudePolicy) policyList(keys ...string) []any {
	lists := [][]any{}
	for _, s := range p.policy {
		if l, ok := claudeSettingAt(s.settings, keys...).([]any); ok {
			lists = append(lists, l)
		}
	}
	return unionClaudeLists(lists...)
}

// claudeMcpRule is one allowedMcpServers or deniedMcpServers entry.
type claudeMcpRule struct {
	ServerName    string   `json:"serverName"`
	ServerCommand []string `json:"serverCommand"`
	ServerURL     string   `json:"serverUrl"`
	managed       bool
}

func claudeMcpRules(l []any, managed bool) []claudeMcpRule {
	var out []claudeMcpRule
	for _, e := range l {
		raw, err := json.Marshal(e)
		if err != nil {
			continue
		}
		var r claudeMcpRule
		if err := json.Unmarshal(raw, &r); err != nil {
			continue
		}
		if r.ServerName == "" && len(r.ServerCommand) == 0 && r.ServerURL == "" {
			continue
		}
		r.managed = managed
		out = append(out, r)
	}
	return out
}

// allowedMcpRules returns the effective MCP allowlist, nil when no file sets
// one. With allowManagedMcpServersOnly the list comes from the highest
// policy source that sets one.
func (p *claudePolicy) allowedMcpRules() []claudeMcpRule {
	if lock := p.anyPolicyTrue("allowManagedMcpServersOnly"); lock != nil && *lock {
		for _, s := range p.policy {
			if l, ok := s.settings["allowedMcpServers"].([]any); ok {
				return append([]claudeMcpRule{}, claudeMcpRules(l, true)...)
			}
		}
		return nil
	}
	managed, mok := p.managed["allowedMcpServers"].([]any)
	user, uok := p.user["allowedMcpServers"].([]any)
	if !mok && !uok {
		return nil
	}
	out := append([]claudeMcpRule{}, claudeMcpRules(managed, true)...)
	return append(out, claudeMcpRules(user, false)...)
}

// deniedMcpRules returns the MCP denylist of every policy source and the
// user's settings.json.
func (p *claudePolicy) deniedMcpRules() []claudeMcpRule {
	out := claudeMcpRules(p.policyList("deniedMcpServers"), true)
	if l, ok := p.user["deniedMcpServers"].([]any); ok {
		out = append(out, claudeMcpRules(l, false)...)
	}
	return out
}

// loadPolicy reads and resolves Claude Code's settings once per resource.
func (r *mqlClaudeCode) loadPolicy() (*claudePolicy, error) {
	r.policyOnce.Do(func() {
		osFamily := runtimeOSFamily(r.MqlRuntime)
		var reader claudeRegistryReader
		if osFamily == "windows" {
			reader = r.readRegistryString
		}
		r.policy, r.policyErr = loadClaudePolicy(r.afs(), osFamily, r.configDir(), reader)
	})
	return r.policy, r.policyErr
}

// readRegistryString reads a string registry value through the registrykey
// resource, which reads natively on a local Windows host and over PowerShell
// otherwise.
func (r *mqlClaudeCode) readRegistryString(key, name string) (string, bool, error) {
	raw, err := CreateResource(r.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(key),
	})
	if err != nil {
		return "", false, err
	}
	items := raw.(*mqlRegistrykey).GetItems()
	if items.Error != nil {
		if isRegistryKeyAbsent(items.Error) {
			return "", false, nil
		}
		return "", false, items.Error
	}
	for _, it := range items.Data {
		prop, ok := it.(*mqlRegistrykeyProperty)
		if !ok || prop.GetName().Data != name {
			continue
		}
		data := prop.GetData()
		if data.Error != nil {
			return "", false, data.Error
		}
		s, ok := data.Data.(string)
		if !ok {
			return "", false, llx.MalformedData(fmt.Errorf("registry value %s of %s is not a string", name, key))
		}
		return s, true, nil
	}
	return "", false, nil
}

// setNullBool marks a bool field resolved to null when v is nil.
func setNullBool(field *plugin.TValue[bool], v *bool) (bool, error) {
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *v, nil
}

func setNullString(field *plugin.TValue[string], v *string) (string, error) {
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *v, nil
}

func strsToAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func (r *mqlClaudeCode) managedSettingsPresent() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	return len(p.sources) > 0, nil
}

func (r *mqlClaudeCode) managedSources() ([]any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, s := range p.sources {
		out = append(out, strsToAny(s.locations)...)
	}
	return out, nil
}

func (r *mqlClaudeCode) managedSettings() (any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	if p.managed == nil {
		r.ManagedSettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return redactSettings(p.managed), nil
}

func (r *mqlClaudeCode) defaultPermissionMode() (string, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return "", err
	}
	return setNullString(&r.DefaultPermissionMode, p.effectiveString("permissions", "defaultMode"))
}

func (r *mqlClaudeCode) bypassPermissionsDisabled() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	return setNullBool(&r.BypassPermissionsDisabled, p.disableSwitch([]string{"permissions", "disableBypassPermissionsMode"}))
}

func (r *mqlClaudeCode) autoModeDisabled() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	return setNullBool(&r.AutoModeDisabled, p.disableSwitch([]string{"disableAutoMode"}, []string{"permissions", "disableAutoMode"}))
}

func (r *mqlClaudeCode) allowManagedPermissionRulesOnly() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	return setNullBool(&r.AllowManagedPermissionRulesOnly, p.managedLock("allowManagedPermissionRulesOnly"))
}

// permissionList returns a permission rule list, managed rules only when the
// policy sets allowManagedPermissionRulesOnly.
func (r *mqlClaudeCode) permissionList(key string) ([]any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	lock := p.managedLock("allowManagedPermissionRulesOnly")
	return strsToAny(p.combinedList(lock != nil && *lock, "permissions", key)), nil
}

func (r *mqlClaudeCode) allowedPermissions() ([]any, error) {
	return r.permissionList("allow")
}

func (r *mqlClaudeCode) askPermissions() ([]any, error) {
	return r.permissionList("ask")
}

func (r *mqlClaudeCode) deniedPermissions() ([]any, error) {
	return r.permissionList("deny")
}

func (r *mqlClaudeCode) sandboxEnabled() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	return setNullBool(&r.SandboxEnabled, p.effectiveBool("sandbox", "enabled"))
}

func (r *mqlClaudeCode) sandboxAllowUnsandboxedCommands() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	return setNullBool(&r.SandboxAllowUnsandboxedCommands, p.effectiveBool("sandbox", "allowUnsandboxedCommands"))
}

func (r *mqlClaudeCode) sandboxAllowedDomains() ([]any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	keys := []string{"sandbox", "network", "allowedDomains"}
	if lock := p.anyPolicyTrue("sandbox", "network", "allowManagedDomainsOnly"); lock != nil && *lock {
		// While the lock is on, the allowlist unions every admin source.
		return strsToAny(claudeStringList(p.policyList(keys...))), nil
	}
	return strsToAny(p.combinedList(false, keys...)), nil
}

func (r *mqlClaudeCode) sandboxAllowManagedDomainsOnly() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	return setNullBool(&r.SandboxAllowManagedDomainsOnly, p.anyPolicyTrue("sandbox", "network", "allowManagedDomainsOnly"))
}

func (r *mqlClaudeCode) allowManagedHooksOnly() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	return setNullBool(&r.AllowManagedHooksOnly, p.managedLock("allowManagedHooksOnly"))
}

func (r *mqlClaudeCode) disableAllHooks() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	return setNullBool(&r.DisableAllHooks, p.effectiveBool("disableAllHooks"))
}

func (r *mqlClaudeCode) hasApiKeyHelper() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	v := p.effectiveString("apiKeyHelper")
	return v != nil && *v != "", nil
}

func (r *mqlClaudeCode) enableAllProjectMcpServers() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	return setNullBool(&r.EnableAllProjectMcpServers, p.effectiveBool("enableAllProjectMcpServers"))
}

func (r *mqlClaudeCode) allowManagedMcpServersOnly() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	return setNullBool(&r.AllowManagedMcpServersOnly, p.anyPolicyTrue("allowManagedMcpServersOnly"))
}

func (r *mqlClaudeCode) allowedMcpServers() ([]any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	rules := p.allowedMcpRules()
	if rules == nil {
		r.AllowedMcpServers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return claudeMcpRuleResources(r.MqlRuntime, "allowed", rules)
}

func (r *mqlClaudeCode) deniedMcpServers() ([]any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	return claudeMcpRuleResources(r.MqlRuntime, "denied", p.deniedMcpRules())
}

// claudeMcpRuleID is the resource id of an allowlist or denylist entry. It
// hashes the raw entry, so a token in a server URL or command never appears
// in the id, while two entries that differ only in a redacted part stay
// distinct.
func claudeMcpRuleID(list string, rule claudeMcpRule) string {
	key, _ := json.Marshal([]any{rule.ServerName, rule.ServerCommand, rule.ServerURL, rule.managed})
	return "claude.code.mcpServerRule/" + list + "/" + contentSHA256(string(key))
}

func claudeMcpRuleResources(runtime *plugin.Runtime, list string, rules []claudeMcpRule) ([]any, error) {
	out := []any{}
	for _, rule := range rules {
		cmd := redactArgs(rule.ServerCommand)
		res, err := CreateResource(runtime, "claude.code.mcpServerRule", map[string]*llx.RawData{
			"__id":          llx.StringData(claudeMcpRuleID(list, rule)),
			"serverName":    llx.StringData(rule.ServerName),
			"serverCommand": llx.ArrayData(llx.TArr2Raw(cmd), types.String),
			"serverUrl":     llx.StringData(redactURL(rule.ServerURL)),
			"managed":       llx.BoolData(rule.managed),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlClaudeCode) managedMcpExclusive() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	return p.mcp != nil, nil
}

// managedMcpServers lists the servers of managed-mcp.json and of the
// managed managedMcpServers key, sorted by source and name.
func (p *claudePolicy) managedMcpServers() []claudeScopedMcpServer {
	var out []claudeScopedMcpServer
	if p.mcp != nil {
		for name, srv := range p.mcp.servers {
			out = append(out, claudeScopedMcpServer{name: name, entry: srv, source: p.mcp.path})
		}
	}
	if m, ok := p.managed["managedMcpServers"].(map[string]any); ok {
		for name, v := range m {
			var source string
			for _, src := range p.policy {
				if source = src.locationOf("managedMcpServers", name); source != "" {
					break
				}
			}
			raw, err := json.Marshal(v)
			if err != nil {
				continue
			}
			var srv claudeMcpServerEntry
			if err := json.Unmarshal(raw, &srv); err != nil {
				continue
			}
			out = append(out, claudeScopedMcpServer{name: name, entry: srv, source: source})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].source != out[j].source {
			return out[i].source < out[j].source
		}
		return out[i].name < out[j].name
	})
	return out
}

func (r *mqlClaudeCode) managedMcpServers() ([]any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, s := range p.managedMcpServers() {
		srv := s.entry
		fields := map[string]*llx.RawData{
			"__id":        llx.StringData("claude.code.mcpServer/managed:" + s.source + "/" + s.name),
			"name":        llx.StringData(s.name),
			"project":     llx.StringData(""),
			"type":        llx.StringData(deriveMcpTransport(srv.Type, srv.Command, srv.URL)),
			"command":     llx.StringData(srv.Command),
			"args":        mcpArgsData(srv.Args),
			"url":         llx.StringData(redactURL(srv.URL)),
			"hasEnv":      llx.BoolData(len(srv.Env) > 0),
			"hasHeaders":  llx.BoolData(len(srv.Headers) > 0),
			"needsAuth":   llx.BoolData(false),
			"lastChecked": llx.StringData(""),
			"plugin":      llx.StringData(""),
			"headerNames": mcpHeaderNamesData(mapKeys(srv.Headers)),
			"source":      llx.StringData(s.source),
		}
		setMcpServerShape(fields, srv.Command, srv.Args, srv.URL, mapKeys(srv.Env))
		res, err := CreateResource(r.MqlRuntime, "claude.code.mcpServer", fields)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlClaudeCode) forceLoginMethod() (string, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return "", err
	}
	return setNullString(&r.ForceLoginMethod, p.effectiveString("forceLoginMethod"))
}

func (r *mqlClaudeCode) forceLoginOrgUuids() ([]any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	switch v := p.effective("forceLoginOrgUUID").(type) {
	case string:
		return []any{v}, nil
	case []any:
		return strsToAny(claudeStringList(v)), nil
	}
	r.ForceLoginOrgUuids.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

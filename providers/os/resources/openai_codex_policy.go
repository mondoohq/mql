// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// Codex's admin-managed configuration (codex-rs/config/src/loader):
// requirements.toml and config.toml live in /etc/codex on Unix and in
// %ProgramData%\OpenAI\Codex on Windows. The legacy managed_config.toml is
// read from /etc/codex on Unix only. On macOS, MDM delivers base64-encoded
// TOML in the com.openai.codex preference domain.
const (
	codexSystemDirUnix          = "/etc/codex"
	codexSystemDirWindows       = `C:\ProgramData\OpenAI\Codex`
	codexManagedPrefsDomain     = "com.openai.codex"
	codexMdmConfigKey           = "config_toml_base64"
	codexMdmRequirementsKey     = "requirements_toml_base64"
	codexManagedConfigFile      = "managed_config.toml"
	codexRequirementsFile       = "requirements.toml"
	codexConfigFile             = "config.toml"
	codexApprovalPolicyGranular = "granular"
)

// codexPolicyInputs are the raw layers Codex builds its approval and sandbox
// posture from. A nil map is an absent layer.
type codexPolicyInputs struct {
	systemConfig       codexTomlLayer
	userConfig         codexTomlLayer
	managedConfig      codexTomlLayer
	mdmConfig          codexTomlLayer
	systemRequirements codexTomlLayer
	mdmRequirements    codexTomlLayer
}

// codexTomlLayer is one parsed TOML file or managed preference value and
// where it came from.
type codexTomlLayer struct {
	source string
	values map[string]any
}

func (l codexTomlLayer) present() bool { return l.values != nil }

// codexPolicy is the posture computed from the layers. Nil pointers and nil
// slices are settings no layer sets.
type codexPolicy struct {
	approvalPolicy          *string
	sandboxMode             *string
	defaultPermissions      *string
	sandboxNetworkAccess    *bool
	writableRoots           []string
	trustedProjects         []string
	managedConfigSources    []string
	requirementsSources     []string
	allowedApprovalPolicies []string
	allowedSandboxModes     []string
}

// codexSystemDir returns Codex's system configuration directory on the
// target's OS.
func codexSystemDir(osFamily string) string {
	if osFamily == "windows" {
		return codexSystemDirWindows
	}
	return codexSystemDirUnix
}

// readCodexTomlLayer reads and parses one TOML file. A missing file is an
// absent layer; a file that cannot be read or parsed is an error, as it is
// for Codex.
func readCodexTomlLayer(afs *afero.Afero, path string) (codexTomlLayer, error) {
	data, err := afs.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return codexTomlLayer{}, nil
		}
		return codexTomlLayer{}, fmt.Errorf("cannot read %s: %w", path, err)
	}
	values := map[string]any{}
	if err := toml.Unmarshal(data, &values); err != nil {
		return codexTomlLayer{}, fmt.Errorf("cannot parse %s: %w", path, err)
	}
	return codexTomlLayer{source: path, values: values}, nil
}

// codexMdmLayer decodes one base64 TOML value of the com.openai.codex managed
// preferences. A missing or blank key is an absent layer.
func codexMdmLayer(prefs map[string]any, key string) (codexTomlLayer, error) {
	raw, ok := prefs[key]
	if !ok {
		return codexTomlLayer{}, nil
	}
	encoded, ok := raw.(string)
	if !ok {
		return codexTomlLayer{}, fmt.Errorf("managed preference %s.%s is not a string", codexManagedPrefsDomain, key)
	}
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return codexTomlLayer{}, nil
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return codexTomlLayer{}, fmt.Errorf("managed preference %s.%s is not valid base64: %w", codexManagedPrefsDomain, key, err)
	}
	values := map[string]any{}
	if err := toml.Unmarshal(data, &values); err != nil {
		return codexTomlLayer{}, fmt.Errorf("managed preference %s.%s is not valid TOML: %w", codexManagedPrefsDomain, key, err)
	}
	return codexTomlLayer{
		source: managedPreferencesDir + "/" + codexManagedPrefsDomain + ".plist#" + key,
		values: values,
	}, nil
}

// readCodexPolicyInputs reads every layer for the Codex configuration
// directory codexDir. mdmPrefs are the enforced values of the
// com.openai.codex managed preferences domain, nil when there are none.
func readCodexPolicyInputs(afs *afero.Afero, codexDir, osFamily string, mdmPrefs map[string]any) (*codexPolicyInputs, error) {
	systemDir := codexSystemDir(osFamily)
	var in codexPolicyInputs
	var err error
	if in.systemConfig, err = readCodexTomlLayer(afs, joinTargetPath(osFamily, systemDir, codexConfigFile)); err != nil {
		return nil, err
	}
	if in.userConfig, err = readCodexTomlLayer(afs, filepath.Join(codexDir, codexConfigFile)); err != nil {
		return nil, err
	}
	// Codex no longer reads managed_config.toml on Windows.
	if osFamily != "windows" {
		if in.managedConfig, err = readCodexTomlLayer(afs, joinTargetPath(osFamily, systemDir, codexManagedConfigFile)); err != nil {
			return nil, err
		}
	}
	if in.systemRequirements, err = readCodexTomlLayer(afs, joinTargetPath(osFamily, systemDir, codexRequirementsFile)); err != nil {
		return nil, err
	}
	if in.mdmConfig, err = codexMdmLayer(mdmPrefs, codexMdmConfigKey); err != nil {
		return nil, err
	}
	if in.mdmRequirements, err = codexMdmLayer(mdmPrefs, codexMdmRequirementsKey); err != nil {
		return nil, err
	}
	return &in, nil
}

// mergeCodexToml merges overlay into base the way Codex merges config layers:
// tables merge key by key, any other value (arrays included) replaces the
// lower layer's value.
func mergeCodexToml(base, overlay map[string]any) {
	for k, v := range overlay {
		if ov, ok := v.(map[string]any); ok {
			if bv, ok := base[k].(map[string]any); ok {
				mergeCodexToml(bv, ov)
				continue
			}
			cp := map[string]any{}
			mergeCodexToml(cp, ov)
			base[k] = cp
			continue
		}
		base[k] = v
	}
}

// codexApprovalPolicyName names an approval_policy value: the string as
// written, or "granular" for a `{ granular = { ... } }` table.
func codexApprovalPolicyName(v any) (string, bool) {
	switch p := v.(type) {
	case string:
		return p, true
	case map[string]any:
		if _, ok := p[codexApprovalPolicyGranular]; ok {
			return codexApprovalPolicyGranular, true
		}
	}
	return "", false
}

// codexLegacyRequirements maps a managed configuration layer to the
// requirements Codex derives from it: its approval_policy becomes the only
// allowed policy, and its sandbox_mode is allowed together with read-only.
func codexLegacyRequirements(values map[string]any) map[string]any {
	req := map[string]any{}
	if p, ok := codexApprovalPolicyName(values["approval_policy"]); ok {
		req["allowed_approval_policies"] = []any{p}
	}
	if m, ok := values["sandbox_mode"].(string); ok {
		modes := []any{"read-only"}
		if m != "read-only" {
			modes = append(modes, m)
		}
		req["allowed_sandbox_modes"] = modes
	}
	return req
}

func codexStringPtr(v any) *string {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

// codexStringList returns the strings of a TOML array, nil when v is not an
// array.
func codexStringList(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	res := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			res = append(res, s)
		}
	}
	return res
}

// computeCodexPolicy applies Codex's layering to the inputs. Config layers
// rise from the system config.toml through the user's config.toml to
// managed_config.toml and MDM config. Requirement layers rise from
// requirements.toml through the managed configuration layers to MDM
// requirements; a higher layer's list replaces a lower one's.
func computeCodexPolicy(in *codexPolicyInputs) *codexPolicy {
	cfg := map[string]any{}
	for _, l := range []codexTomlLayer{in.systemConfig, in.userConfig, in.managedConfig, in.mdmConfig} {
		if l.present() {
			mergeCodexToml(cfg, l.values)
		}
	}

	p := &codexPolicy{
		managedConfigSources: []string{},
		requirementsSources:  []string{},
	}
	if name, ok := codexApprovalPolicyName(cfg["approval_policy"]); ok {
		p.approvalPolicy = &name
	}
	p.sandboxMode = codexStringPtr(cfg["sandbox_mode"])
	p.defaultPermissions = codexStringPtr(cfg["default_permissions"])
	if sww, ok := cfg["sandbox_workspace_write"].(map[string]any); ok {
		if b, ok := sww["network_access"].(bool); ok {
			p.sandboxNetworkAccess = &b
		}
		p.writableRoots = codexStringList(sww["writable_roots"])
	}

	p.trustedProjects = []string{}
	if projects, ok := cfg["projects"].(map[string]any); ok {
		for path, raw := range projects {
			if proj, ok := raw.(map[string]any); ok && proj["trust_level"] == "trusted" {
				p.trustedProjects = append(p.trustedProjects, path)
			}
		}
		sort.Strings(p.trustedProjects)
	}

	for _, l := range []codexTomlLayer{in.managedConfig, in.mdmConfig} {
		if l.present() {
			p.managedConfigSources = append(p.managedConfigSources, l.source)
		}
	}

	req := map[string]any{}
	reqLayers := []codexTomlLayer{in.systemRequirements}
	for _, l := range []codexTomlLayer{in.managedConfig, in.mdmConfig} {
		if !l.present() {
			continue
		}
		// A managed configuration layer that sets neither approval_policy nor
		// sandbox_mode contributes no requirements.
		if legacy := codexLegacyRequirements(l.values); len(legacy) > 0 {
			reqLayers = append(reqLayers, codexTomlLayer{source: l.source, values: legacy})
		}
	}
	reqLayers = append(reqLayers, in.mdmRequirements)
	for _, l := range reqLayers {
		if !l.present() {
			continue
		}
		p.requirementsSources = append(p.requirementsSources, l.source)
		mergeCodexToml(req, l.values)
	}
	p.allowedApprovalPolicies = codexStringList(req["allowed_approval_policies"])
	p.allowedSandboxModes = codexStringList(req["allowed_sandbox_modes"])
	return p
}

// codexManagedPrefs returns the enforced values of the com.openai.codex
// managed preferences domain on a macOS target, nil elsewhere.
func codexManagedPrefs(runtime *plugin.Runtime, osFamily string) (map[string]any, error) {
	if osFamily != "darwin" {
		return nil, nil
	}
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return nil, nil
	}
	return newMacosPrefReader(conn).managedFor(managedPreferencesDir, codexManagedPrefsDomain)
}

func (r *mqlOpenaiCodex) loadPolicy() (*codexPolicy, error) {
	r.policyOnce.Do(func() {
		osFamily := runtimeOSFamily(r.MqlRuntime)
		prefs, err := codexManagedPrefs(r.MqlRuntime, osFamily)
		if err != nil {
			r.policyErr = err
			return
		}
		in, err := readCodexPolicyInputs(r.afs(), r.codexDir(), osFamily, prefs)
		if err != nil {
			r.policyErr = err
			return
		}
		r.policy = computeCodexPolicy(in)
	})
	return r.policy, r.policyErr
}

// codexPolicyString returns a string setting, marking the field null when no
// layer sets it.
func codexPolicyString(field *plugin.TValue[string], v *string) (string, error) {
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *v, nil
}

// codexPolicyList returns a list setting, marking the field null when no
// layer sets it.
func codexPolicyList(field *plugin.TValue[[]any], v []string) ([]any, error) {
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return llx.TArr2Raw(v), nil
}

func (r *mqlOpenaiCodex) approvalPolicy() (string, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return "", err
	}
	return codexPolicyString(&r.ApprovalPolicy, p.approvalPolicy)
}

func (r *mqlOpenaiCodex) sandboxMode() (string, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return "", err
	}
	return codexPolicyString(&r.SandboxMode, p.sandboxMode)
}

func (r *mqlOpenaiCodex) defaultPermissions() (string, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return "", err
	}
	return codexPolicyString(&r.DefaultPermissions, p.defaultPermissions)
}

func (r *mqlOpenaiCodex) sandboxNetworkAccess() (bool, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return false, err
	}
	if p.sandboxNetworkAccess == nil {
		r.SandboxNetworkAccess.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *p.sandboxNetworkAccess, nil
}

func (r *mqlOpenaiCodex) writableRoots() ([]any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	return codexPolicyList(&r.WritableRoots, p.writableRoots)
}

func (r *mqlOpenaiCodex) trustedProjects() ([]any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	return llx.TArr2Raw(p.trustedProjects), nil
}

func (r *mqlOpenaiCodex) managedConfigSources() ([]any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	return llx.TArr2Raw(p.managedConfigSources), nil
}

func (r *mqlOpenaiCodex) requirementsSources() ([]any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	return llx.TArr2Raw(p.requirementsSources), nil
}

func (r *mqlOpenaiCodex) allowedApprovalPolicies() ([]any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	return codexPolicyList(&r.AllowedApprovalPolicies, p.allowedApprovalPolicies)
}

func (r *mqlOpenaiCodex) allowedSandboxModes() ([]any, error) {
	p, err := r.loadPolicy()
	if err != nil {
		return nil, err
	}
	return codexPolicyList(&r.AllowedSandboxModes, p.allowedSandboxModes)
}

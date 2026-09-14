// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// toStringMap converts an API string map into the shape a map[string]string
// schema field takes. A map the API left out stays nil so the field reads as
// null rather than as a map that was read and found empty.
func toStringMap(in map[string]string) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// stringMapData wraps an API string map for a map[string]string field, keeping
// an absent map null.
func stringMapData(in map[string]string) *llx.RawData {
	m := toStringMap(in)
	if m == nil {
		return llx.NilData
	}
	return llx.MapData(m, types.String)
}

// sortedKeys returns the keys of a string map in a stable order. Go randomizes
// map iteration, so a list built straight out of a map changes order between
// scans and the values read differently every time.
func sortedKeys(in map[string]string) []string {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// parseRFC3339 reads an RFC 3339 timestamp the API reports as a string. An
// empty or unreadable value becomes nil so the field is null instead of a
// year-1 timestamp that would read as "expired long ago".
func parseRFC3339(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

// nonZeroInt maps a zero count to nil. The Agents API sends null for a count
// that does not apply, which decodes to 0, and 0 is a meaningful number of
// concurrent subagents to claim when the real answer is "subagents are off".
func nonZeroInt(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}

// openai.agent

// agentArgs builds the scalar resource args for an openai.agent. The tools
// collection is attached by newAgent, which needs a runtime to build it.
func agentArgs(a openai.Agent) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                   llx.StringData(a.ID),
		"id":                     llx.StringData(a.ID),
		"name":                   llx.StringDataPtr(emptyToNil(a.Name)),
		"model":                  llx.StringData(a.Model),
		"instructions":           llx.StringData(a.Instructions),
		"serviceTier":            llx.StringDataPtr(emptyToNil(string(a.ServiceTier))),
		"metadata":               stringMapData(a.Metadata),
		"multiAgentEnabled":      llx.BoolData(a.MultiAgent.Enabled),
		"maxConcurrentSubagents": llx.IntDataPtr(nonZeroInt(a.MultiAgent.MaxConcurrentSubagents)),
		"reasoningEffort":        llx.StringDataPtr(emptyToNil(string(a.Reasoning.Effort))),
		"reasoningSummary":       llx.StringDataPtr(emptyToNil(string(a.Reasoning.Summary))),
		"textVerbosity":          llx.StringDataPtr(emptyToNil(string(a.Text.Verbosity))),
		"createdAt":              llx.TimeDataPtr(unixToNullableTime(a.CreatedAt)),
		"updatedAt":              llx.TimeDataPtr(unixToNullableTime(a.UpdatedAt)),
	}
}

// agentToolArgs builds the resource args for one entry of an agent's tool
// list, together with the vault credential id the entry names. The list is a
// discriminated union, so every field that belongs to another variant is set
// to null: reporting "" or an empty list would claim a setting the tool does
// not carry.
//
// The mcp variant's request_metadata is deliberately left out. It is
// free-form, it travels with every request the agent makes to the server, and
// a token put there would be copied into scan results verbatim.
func agentToolArgs(agentID string, index int, t openai.PersistedAgentToolUnion) (map[string]*llx.RawData, string) {
	args := map[string]*llx.RawData{
		"__id":                 llx.StringData(agentID + "/tool/" + strconv.Itoa(index)),
		"type":                 llx.StringDataPtr(emptyToNil(t.Type)),
		"name":                 llx.NilData,
		"description":          llx.NilData,
		"parameters":           llx.NilData,
		"deferLoading":         llx.NilData,
		"enabled":              llx.NilData,
		"serverLabel":          llx.NilData,
		"connectionOrigin":     llx.NilData,
		"allowedTools":         llx.NilData,
		"required":             llx.NilData,
		"transportType":        llx.NilData,
		"transportServerUrl":   llx.NilData,
		"transportHeaderNames": llx.NilData,
		"transportCommand":     llx.NilData,
		"transportArgs":        llx.NilData,
		"transportCwd":         llx.NilData,
		"transportEnvVars":     llx.NilData,
		"allowedDomains":       llx.NilData,
		"mode":                 llx.NilData,
		"contextSize":          llx.NilData,
	}

	credentialID := ""

	switch t.Type {
	case "function":
		fn := t.AsFunction()
		args["name"] = llx.StringData(fn.Name)
		args["description"] = llx.StringData(fn.Description)
		args["parameters"] = llx.DictData(fn.Parameters)
		args["deferLoading"] = llx.BoolData(fn.DeferLoading)

	case "programmatic_tool_calling":
		ptc := t.AsProgrammaticToolCalling()
		args["enabled"] = llx.BoolData(ptc.Enabled)

	case "mcp":
		mcp := t.AsMcp()
		credentialID = mcp.CredentialID
		args["serverLabel"] = llx.StringData(mcp.ServerLabel)
		args["connectionOrigin"] = llx.StringDataPtr(emptyToNil(mcp.ConnectionOrigin))
		// an empty allowlist means every tool the server publishes is callable,
		// which is the finding, so it stays an empty list rather than null: a
		// check that counts the entries then fails instead of reading as
		// "nothing was measured"
		args["allowedTools"] = llx.ArrayData(convertStringSlice(mcp.AllowedTools), types.String)
		args["required"] = llx.BoolData(mcp.Required)
		args["transportType"] = llx.StringDataPtr(emptyToNil(mcp.Transport.Type))
		switch mcp.Transport.Type {
		case "http":
			http := mcp.Transport.AsHTTP()
			args["transportServerUrl"] = llx.StringData(http.ServerURL)
			// only the header names: a header value is the usual hiding place
			// for an API key, and the schema must not carry one
			args["transportHeaderNames"] = llx.ArrayData(convertStringSlice(sortedKeys(http.Headers)), types.String)
		case "stdio":
			stdio := mcp.Transport.AsStdio()
			args["transportCommand"] = llx.StringData(stdio.Command)
			args["transportArgs"] = llx.ArrayData(convertStringSlice(stdio.Args), types.String)
			args["transportCwd"] = llx.StringDataPtr(emptyToNil(stdio.Cwd))
			args["transportEnvVars"] = llx.ArrayData(convertStringSlice(stdio.EnvVars), types.String)
		}

	case "web_search":
		ws := t.AsWebSearch()
		// same reasoning as allowedTools: an unrestricted search is an empty
		// list, not an absence of measurement
		args["allowedDomains"] = llx.ArrayData(convertStringSlice(ws.AllowedDomains), types.String)
		args["mode"] = llx.StringDataPtr(emptyToNil(ws.Mode))
		args["contextSize"] = llx.StringDataPtr(emptyToNil(ws.ContextSize))
	}

	return args, credentialID
}

// newAgent builds an openai.agent along with the tools hanging off it.
func newAgent(runtime *plugin.Runtime, a openai.Agent) (plugin.Resource, error) {
	tools := make([]any, 0, len(a.Tools))
	for i := range a.Tools {
		toolArgs, credentialID := agentToolArgs(a.ID, i, a.Tools[i])
		mqlTool, err := CreateResource(runtime, "openai.agent.tool", toolArgs)
		if err != nil {
			return nil, err
		}
		mqlTool.(*mqlOpenaiAgentTool).cacheCredentialID = credentialID
		tools = append(tools, mqlTool)
	}

	args := agentArgs(a)
	args["tools"] = llx.ArrayData(tools, types.Resource("openai.agent.tool"))
	return CreateResource(runtime, "openai.agent", args)
}

func (r *mqlOpenai) agents() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.agents")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	var res []any
	err = walkPages(
		client.Beta.Agents.ListAutoPaging(ctx, openai.BetaAgentListParams{}),
		func(a openai.Agent) string { return a.ID },
		func(a openai.Agent) error {
			mqlAgent, err := newAgent(r.MqlRuntime, a)
			if err != nil {
				return err
			}
			res = append(res, mqlAgent)
			return nil
		})
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list agents: %w", err)
	}
	return res, nil
}

func initOpenaiAgent(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	agentID, ok := stringArg(args, "id")
	if !ok {
		return args, nil, nil
	}

	conn := openaiConn(runtime)
	client, err := dataPlaneClient(conn, "openai.agent")
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, fmt.Errorf("cannot fetch agent %s: no project API key configured", agentID)
	}
	a, err := client.Beta.Agents.Get(context.Background(), agentID)
	if err != nil {
		// returning (args, nil, nil) here would build a husk carrying nothing
		// but the id, and every field on it would read as a primitive with no
		// type information rather than naming the failure
		return nil, nil, fmt.Errorf("failed to get agent %s: %w", agentID, err)
	}

	mqlAgent, err := newAgent(runtime, *a)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlAgent, nil
}

// openai.vault

// mapVault builds the resource args for an openai.vault. Both the collection
// path and the single-object init share it so the two paths cannot diverge.
func mapVault(v openai.Vault) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":      llx.StringData(v.ID),
		"id":        llx.StringData(v.ID),
		"name":      llx.StringDataPtr(emptyToNil(v.Name)),
		"metadata":  stringMapData(v.Metadata),
		"createdAt": llx.TimeDataPtr(unixToNullableTime(v.CreatedAt)),
	}
}

func (r *mqlOpenai) vaults() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.vaults")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	var res []any
	err = walkPages(
		client.Beta.Agents.Vaults.ListAutoPaging(ctx, openai.BetaAgentVaultListParams{}),
		func(v openai.Vault) string { return v.ID },
		func(v openai.Vault) error {
			mqlVault, err := CreateResource(r.MqlRuntime, "openai.vault", mapVault(v))
			if err != nil {
				return err
			}
			res = append(res, mqlVault)
			return nil
		})
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list vaults: %w", err)
	}
	return res, nil
}

func initOpenaiVault(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	vaultID, ok := stringArg(args, "id")
	if !ok {
		return args, nil, nil
	}

	conn := openaiConn(runtime)
	client, err := dataPlaneClient(conn, "openai.vault")
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, fmt.Errorf("cannot fetch vault %s: no project API key configured", vaultID)
	}
	v, err := client.Beta.Agents.Vaults.Get(context.Background(), vaultID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get vault %s: %w", vaultID, err)
	}
	return mapVault(*v), nil, nil
}

// openai.vault.credential

type mqlOpenaiVaultCredentialInternal struct {
	cacheVaultID string
}

// mapCredential builds the resource args for an openai.vault.credential.
//
// The auth block is a discriminated union over mcp_oauth and static_bearer.
// Only its non-secret half is carried across: the API documents that tokens
// and client secrets are never returned in a response, and nothing here copies
// a raw response body into a dict, so no key the API may add later can reach a
// scan result without someone naming it first.
func mapCredential(c openai.Credential) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		// a credential id is unique to its vault, and the credential is only
		// reachable through one, so the vault is part of the key
		"__id":                         llx.StringData(c.VaultID + "/" + c.ID),
		"id":                           llx.StringData(c.ID),
		"name":                         llx.StringData(c.Name),
		"authType":                     llx.StringDataPtr(emptyToNil(c.Auth.Type)),
		"mcpServerUrl":                 llx.StringDataPtr(emptyToNil(c.Auth.McpServerURL)),
		"expiresAt":                    llx.TimeDataPtr(parseRFC3339(c.Auth.ExpiresAt)),
		"refreshClientId":              llx.StringDataPtr(emptyToNil(c.Auth.Refresh.ClientID)),
		"refreshTokenEndpoint":         llx.StringDataPtr(emptyToNil(c.Auth.Refresh.TokenEndpoint)),
		"refreshScope":                 llx.StringDataPtr(emptyToNil(c.Auth.Refresh.Scope)),
		"refreshResource":              llx.StringDataPtr(emptyToNil(c.Auth.Refresh.Resource)),
		"refreshTokenEndpointAuthType": llx.StringDataPtr(emptyToNil(c.Auth.Refresh.TokenEndpointAuth.Type)),
		"createdAt":                    llx.TimeDataPtr(unixToNullableTime(c.CreatedAt)),
		"updatedAt":                    llx.TimeDataPtr(unixToNullableTime(c.UpdatedAt)),
	}
}

func (r *mqlOpenaiVault) credentials() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.vault.credentials")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	vaultID := r.Id.Data
	var res []any
	err = walkPages(
		client.Beta.Agents.Vaults.Credentials.ListAutoPaging(ctx, vaultID, openai.BetaAgentVaultCredentialListParams{}),
		func(c openai.Credential) string { return c.ID },
		func(c openai.Credential) error {
			mqlCred, err := CreateResource(r.MqlRuntime, "openai.vault.credential", mapCredential(c))
			if err != nil {
				return err
			}
			// the response carries the owning vault, but an entry that leaves
			// it out still belongs to the vault it was listed from
			owner := c.VaultID
			if owner == "" {
				owner = vaultID
			}
			mqlCred.(*mqlOpenaiVaultCredential).cacheVaultID = owner
			res = append(res, mqlCred)
			return nil
		})
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list credentials in vault %s: %w", vaultID, err)
	}
	return res, nil
}

func (r *mqlOpenaiVaultCredential) vault() (*mqlOpenaiVault, error) {
	v, err := resolveVault(r.MqlRuntime, r.cacheVaultID)
	if err != nil {
		return nil, err
	}
	if v == nil {
		r.Vault.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return v, nil
}

// openaiVaultList returns the project vault collection through the openai
// resource so the underlying list call is made once per scan.
func openaiVaultList(runtime *plugin.Runtime) ([]any, error) {
	obj, err := CreateResource(runtime, "openai", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	vaults := obj.(*mqlOpenai).GetVaults()
	if vaults.Error != nil {
		return nil, vaults.Error
	}
	return vaults.Data, nil
}

// resolveVault finds the vault with the given id in the project vault list.
// A miss is (nil, nil) for the caller to null, because a credential can name a
// vault the key reading it is not allowed to list.
func resolveVault(runtime *plugin.Runtime, vaultID string) (*mqlOpenaiVault, error) {
	if vaultID == "" {
		return nil, nil
	}
	vaults, err := openaiVaultList(runtime)
	if err != nil {
		return nil, err
	}
	for i := range vaults {
		v, ok := vaults[i].(*mqlOpenaiVault)
		if ok && v.Id.Data == vaultID {
			return v, nil
		}
	}
	return nil, nil
}

// resolveVaultCredential finds the credential with the given id by scanning the
// credentials of every vault in the project. Resolving through the cached
// collections keeps a reference from costing a get per referring tool: the
// vault list is read once and each vault's credential list once, no matter how
// many agents point at them.
func resolveVaultCredential(runtime *plugin.Runtime, credentialID string) (*mqlOpenaiVaultCredential, error) {
	if credentialID == "" {
		return nil, nil
	}
	vaults, err := openaiVaultList(runtime)
	if err != nil {
		return nil, err
	}
	for i := range vaults {
		v, ok := vaults[i].(*mqlOpenaiVault)
		if !ok {
			continue
		}
		creds := v.GetCredentials()
		if creds.Error != nil {
			return nil, creds.Error
		}
		for j := range creds.Data {
			c, ok := creds.Data[j].(*mqlOpenaiVaultCredential)
			if ok && c.Id.Data == credentialID {
				return c, nil
			}
		}
	}
	return nil, nil
}

// openai.agent.tool

type mqlOpenaiAgentToolInternal struct {
	cacheCredentialID string
}

func (r *mqlOpenaiAgentTool) credential() (*mqlOpenaiVaultCredential, error) {
	c, err := resolveVaultCredential(r.MqlRuntime, r.cacheCredentialID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		r.Credential.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return c, nil
}

// openai.environmentTemplate

// environmentTemplateArgs builds the scalar resource args for an
// openai.environmentTemplate. The skill and file collections are attached by
// newEnvironmentTemplate, which needs a runtime to build them.
func environmentTemplateArgs(t openai.EnvironmentTemplate) map[string]*llx.RawData {
	// a template with no network block at all has no policy to report, and an
	// empty allowlist there would read as "restricted to nothing"
	networkPolicyType := llx.NilData
	allowedDomains := llx.NilData
	if t.JSON.Network.Valid() {
		networkPolicyType = llx.StringDataPtr(emptyToNil(t.Network.Access))
		allowedDomains = llx.ArrayData(convertStringSlice(t.Network.AllowedDomains), types.String)
	}

	plugins := make(map[string]string, len(t.Plugins))
	for _, p := range t.Plugins {
		plugins[p.Name] = p.Description
	}

	return map[string]*llx.RawData{
		"__id":                        llx.StringData(t.ID),
		"id":                          llx.StringData(t.ID),
		"name":                        llx.StringDataPtr(emptyToNil(t.Name)),
		"networkPolicyType":           networkPolicyType,
		"networkPolicyAllowedDomains": allowedDomains,
		"capabilityDirectories":       llx.ArrayData(convertStringSlice(t.CapabilityDirectories), types.String),
		"npmPackages":                 llx.ArrayData(convertStringSlice(t.Packages.Npm), types.String),
		"pythonPackages":              llx.ArrayData(convertStringSlice(t.Packages.Python), types.String),
		"systemPackages":              llx.ArrayData(convertStringSlice(t.Packages.System), types.String),
		"plugins":                     llx.MapData(toStringMap(plugins), types.String),
		"createdAt":                   llx.TimeDataPtr(unixToNullableTime(t.CreatedAt)),
		"updatedAt":                   llx.TimeDataPtr(unixToNullableTime(t.UpdatedAt)),
	}
}

// environmentTemplateSkillArgs builds the resource args for one entry of a
// template's skill list, together with the skill id a skill_reference entry
// names. An inline skill carries a name and description of its own and names
// no project skill.
func environmentTemplateSkillArgs(templateID string, index int, s openai.EnvironmentTemplateSkillUnion) (map[string]*llx.RawData, string) {
	args := map[string]*llx.RawData{
		"__id":        llx.StringData(templateID + "/skill/" + strconv.Itoa(index)),
		"type":        llx.StringDataPtr(emptyToNil(s.Type)),
		"version":     llx.NilData,
		"name":        llx.NilData,
		"description": llx.NilData,
	}

	skillID := ""
	switch s.Type {
	case "skill_reference":
		ref := s.AsSkillReference()
		skillID = ref.SkillID
		args["version"] = llx.StringDataPtr(emptyToNil(ref.Version))
	case "inline":
		inline := s.AsInline()
		args["name"] = llx.StringData(inline.Name)
		args["description"] = llx.StringData(inline.Description)
	}
	return args, skillID
}

// environmentTemplateFileArgs builds the resource args for one entry of a
// template's file list, together with the uploaded file id a file_id entry
// names. An inline file carries its contents with the template and reports
// only a size.
func environmentTemplateFileArgs(templateID string, index int, f openai.EnvironmentTemplateFileUnion) (map[string]*llx.RawData, string) {
	args := map[string]*llx.RawData{
		"__id":      llx.StringData(templateID + "/file/" + strconv.Itoa(index)),
		"path":      llx.StringData(f.Path),
		"type":      llx.StringDataPtr(emptyToNil(f.Type)),
		"sizeBytes": llx.NilData,
	}

	fileID := ""
	switch f.Type {
	case "file_id":
		fileID = f.AsFileID().FileID
	case "inline":
		inline := f.AsInline()
		args["sizeBytes"] = llx.IntData(inline.SizeBytes)
	}
	return args, fileID
}

// newEnvironmentTemplate builds an openai.environmentTemplate along with the
// skills and files placed in the sandbox it provisions.
func newEnvironmentTemplate(runtime *plugin.Runtime, t openai.EnvironmentTemplate) (plugin.Resource, error) {
	skills := make([]any, 0, len(t.Skills))
	for i := range t.Skills {
		skillArgs, skillID := environmentTemplateSkillArgs(t.ID, i, t.Skills[i])
		mqlSkill, err := CreateResource(runtime, "openai.environmentTemplate.skill", skillArgs)
		if err != nil {
			return nil, err
		}
		mqlSkill.(*mqlOpenaiEnvironmentTemplateSkill).cacheSkillID = skillID
		skills = append(skills, mqlSkill)
	}

	files := make([]any, 0, len(t.Files))
	for i := range t.Files {
		fileArgs, fileID := environmentTemplateFileArgs(t.ID, i, t.Files[i])
		mqlFile, err := CreateResource(runtime, "openai.environmentTemplate.file", fileArgs)
		if err != nil {
			return nil, err
		}
		mqlFile.(*mqlOpenaiEnvironmentTemplateFile).cacheFileID = fileID
		files = append(files, mqlFile)
	}

	args := environmentTemplateArgs(t)
	args["skills"] = llx.ArrayData(skills, types.Resource("openai.environmentTemplate.skill"))
	args["files"] = llx.ArrayData(files, types.Resource("openai.environmentTemplate.file"))
	return CreateResource(runtime, "openai.environmentTemplate", args)
}

func (r *mqlOpenai) environmentTemplates() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.environmentTemplates")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	var res []any
	err = walkPages(
		client.Beta.Agents.Environments.Templates.ListAutoPaging(ctx, openai.BetaAgentEnvironmentTemplateListParams{}),
		func(t openai.EnvironmentTemplate) string { return t.ID },
		func(t openai.EnvironmentTemplate) error {
			mqlTemplate, err := newEnvironmentTemplate(r.MqlRuntime, t)
			if err != nil {
				return err
			}
			res = append(res, mqlTemplate)
			return nil
		})
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list environment templates: %w", err)
	}
	return res, nil
}

func initOpenaiEnvironmentTemplate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	templateID, ok := stringArg(args, "id")
	if !ok {
		return args, nil, nil
	}

	conn := openaiConn(runtime)
	client, err := dataPlaneClient(conn, "openai.environmentTemplate")
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, fmt.Errorf("cannot fetch environment template %s: no project API key configured", templateID)
	}
	t, err := client.Beta.Agents.Environments.Templates.Get(context.Background(), templateID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get environment template %s: %w", templateID, err)
	}

	mqlTemplate, err := newEnvironmentTemplate(runtime, *t)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlTemplate, nil
}

// openai.environmentTemplate.skill

type mqlOpenaiEnvironmentTemplateSkillInternal struct {
	cacheSkillID string
}

func (r *mqlOpenaiEnvironmentTemplateSkill) skill() (*mqlOpenaiSkill, error) {
	s, err := resolveSkill(r.MqlRuntime, r.cacheSkillID)
	if err != nil {
		return nil, err
	}
	if s == nil {
		r.Skill.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return s, nil
}

// openaiSkillList returns the project skill collection through the openai
// resource so the underlying list call is made once per scan.
func openaiSkillList(runtime *plugin.Runtime) ([]any, error) {
	obj, err := CreateResource(runtime, "openai", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	skills := obj.(*mqlOpenai).GetSkills()
	if skills.Error != nil {
		return nil, skills.Error
	}
	return skills.Data, nil
}

// resolveSkill finds the registered skill with the given id in the project
// skill list. A template outlives the skill it names, so a miss is (nil, nil)
// for the caller to null rather than an error that would take the whole
// template collection down with it.
func resolveSkill(runtime *plugin.Runtime, skillID string) (*mqlOpenaiSkill, error) {
	if skillID == "" {
		return nil, nil
	}
	skills, err := openaiSkillList(runtime)
	if err != nil {
		return nil, err
	}
	for i := range skills {
		s, ok := skills[i].(*mqlOpenaiSkill)
		if ok && s.Id.Data == skillID {
			return s, nil
		}
	}
	return nil, nil
}

// openai.environmentTemplate.file

type mqlOpenaiEnvironmentTemplateFileInternal struct {
	cacheFileID string
}

func (r *mqlOpenaiEnvironmentTemplateFile) file() (*mqlOpenaiFile, error) {
	if r.cacheFileID == "" {
		r.File.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	f, err := resolveFile(r.MqlRuntime, r.cacheFileID)
	if err != nil {
		return nil, err
	}
	if f == nil {
		r.File.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return f, nil
}

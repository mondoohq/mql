// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strconv"

	"github.com/anthropics/anthropic-sdk-go"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// claude.agent

type mqlClaudeAgentInternal struct {
	cacheSubagentIDs []string
}

func (r *mqlClaude) agents() ([]interface{}, error) {
	c := conn(r.MqlRuntime)
	client := c.Client()

	pager := client.Beta.Agents.ListAutoPaging(context.Background(), anthropic.BetaAgentListParams{})

	var res []interface{}
	for pager.Next() {
		a := pager.Current()

		skills, err := agentSkills(r.MqlRuntime, a.ID, a.Skills)
		if err != nil {
			return nil, err
		}
		toolsets, customTools, err := agentTools(r.MqlRuntime, a.ID, a.Tools)
		if err != nil {
			return nil, err
		}

		mcpServers := make(map[string]interface{}, len(a.MCPServers))
		for _, server := range a.MCPServers {
			mcpServers[server.Name] = server.URL
		}

		// The roster mixes agent references, which name another managed
		// agent, with advisors, which only name a model.
		var subagentIDs []string
		advisorModels := []interface{}{}
		for _, entry := range a.Multiagent.Agents {
			switch entry.Type {
			case "agent":
				subagentIDs = append(subagentIDs, entry.ID)
			case "advisor":
				advisorModels = append(advisorModels, entry.Model)
			}
		}

		mqlAgent, err := CreateResource(r.MqlRuntime, "claude.agent", map[string]*llx.RawData{
			"__id":              llx.StringData(a.ID),
			"id":                llx.StringData(a.ID),
			"name":              llx.StringData(a.Name),
			"description":       llx.StringData(a.Description),
			"system":            llx.StringData(a.System),
			"model":             llx.StringData(string(a.Model.ID)),
			"modelEffort":       llx.StringData(a.Model.Effort.Type),
			"modelInferenceGeo": llx.StringData(a.Model.InferenceGeo),
			"modelSpeed":        llx.StringData(string(a.Model.Speed)),
			"metadata":          llx.MapData(toInterfaceMap(a.Metadata), types.String),
			"mcpServers":        llx.MapData(mcpServers, types.String),
			"skills":            llx.ArrayData(skills, types.Resource("claude.agent.skill")),
			"toolsets":          llx.ArrayData(toolsets, types.Resource("claude.agent.toolset")),
			"customTools":       llx.ArrayData(customTools, types.Resource("claude.agent.customTool")),
			"multiagentType":    llx.StringData(string(a.Multiagent.Type)),
			"advisorModels":     llx.ArrayData(advisorModels, types.String),
			"version":           llx.IntData(a.Version),
			"createdAt":         llx.TimeData(a.CreatedAt),
			"updatedAt":         llx.TimeData(a.UpdatedAt),
			"archivedAt":        llx.TimeData(a.ArchivedAt),
			"type":              llx.StringData(string(a.Type)),
		})
		if err != nil {
			return nil, err
		}

		mqlAgent.(*mqlClaudeAgent).cacheSubagentIDs = subagentIDs

		res = append(res, mqlAgent)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing agents: %w", err)
	}

	return res, nil
}

func (r *mqlClaudeAgent) subagents() ([]interface{}, error) {
	res := []interface{}{}
	if len(r.cacheSubagentIDs) == 0 {
		return res, nil
	}

	agents, err := claudeChildren(r.MqlRuntime, (*mqlClaude).GetAgents)
	if err != nil {
		return nil, err
	}

	for _, id := range r.cacheSubagentIDs {
		if agent, ok := findByID[*mqlClaudeAgent](agents, id); ok {
			res = append(res, agent)
		}
	}

	return res, nil
}

type mqlClaudeAgentSkillInternal struct {
	cacheSkillID string
}

func agentSkills(runtime *plugin.Runtime, agentID string, skills []anthropic.BetaManagedAgentsAgentSkillUnion) ([]interface{}, error) {
	res := make([]interface{}, 0, len(skills))
	for _, s := range skills {
		mqlSkill, err := CreateResource(runtime, "claude.agent.skill", map[string]*llx.RawData{
			"__id":    llx.StringData(agentID + "/skill/" + s.SkillID + "/" + s.Version),
			"source":  llx.StringData(s.Type),
			"version": llx.StringData(s.Version),
		})
		if err != nil {
			return nil, err
		}

		mqlSkill.(*mqlClaudeAgentSkill).cacheSkillID = s.SkillID

		res = append(res, mqlSkill)
	}
	return res, nil
}

func (r *mqlClaudeAgentSkill) skill() (*mqlClaudeSkill, error) {
	skill, ok, err := lookupClaudeChild[*mqlClaudeSkill](r.MqlRuntime, r.cacheSkillID, (*mqlClaude).GetSkills)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Skill.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return skill, nil
}

// agentTools splits the agent's tool entries into toolsets, which carry a
// permission policy and the tools configured under it, and custom tools, which
// are declared inline on the agent and have no policy of their own.
func agentTools(runtime *plugin.Runtime, agentID string, entries []anthropic.BetaManagedAgentsAgentToolUnion) ([]interface{}, []interface{}, error) {
	toolsets := []interface{}{}
	customTools := []interface{}{}

	for i, entry := range entries {
		switch entry.Type {
		case "agent_toolset_20260401":
			toolset := entry.AsAgentToolset20260401()

			spec := toolsetSpec{
				toolsetType:    string(toolset.Type),
				defaultEnabled: toolset.DefaultConfig.Enabled,
				defaultPolicy:  toolset.DefaultConfig.PermissionPolicy.Type,
				tools:          make([]toolSpec, 0, len(toolset.Configs)),
			}
			for _, cfg := range toolset.Configs {
				spec.tools = append(spec.tools, toolSpec{name: string(cfg.Name), enabled: cfg.Enabled, permissionPolicy: cfg.PermissionPolicy.Type})
			}

			mqlToolset, err := newToolset(runtime, agentID, i, spec)
			if err != nil {
				return nil, nil, err
			}
			toolsets = append(toolsets, mqlToolset)

		case "mcp_toolset":
			toolset := entry.AsMCPToolset()

			spec := toolsetSpec{
				toolsetType:    string(toolset.Type),
				mcpServerName:  toolset.MCPServerName,
				defaultEnabled: toolset.DefaultConfig.Enabled,
				defaultPolicy:  toolset.DefaultConfig.PermissionPolicy.Type,
				tools:          make([]toolSpec, 0, len(toolset.Configs)),
			}
			for _, cfg := range toolset.Configs {
				spec.tools = append(spec.tools, toolSpec{name: cfg.Name, enabled: cfg.Enabled, permissionPolicy: cfg.PermissionPolicy.Type})
			}

			mqlToolset, err := newToolset(runtime, agentID, i, spec)
			if err != nil {
				return nil, nil, err
			}
			toolsets = append(toolsets, mqlToolset)

		case "custom":
			tool := entry.AsCustom()

			inputSchema, err := rawJSONToDict(tool.InputSchema.RawJSON())
			if err != nil {
				return nil, nil, fmt.Errorf("parsing input schema of custom tool %q: %w", tool.Name, err)
			}

			mqlTool, err := CreateResource(runtime, "claude.agent.customTool", map[string]*llx.RawData{
				"__id":        llx.StringData(agentID + "/customTool/" + tool.Name),
				"name":        llx.StringData(tool.Name),
				"description": llx.StringData(tool.Description),
				"inputSchema": llx.DictData(inputSchema),
			})
			if err != nil {
				return nil, nil, err
			}
			customTools = append(customTools, mqlTool)
		}
	}

	return toolsets, customTools, nil
}

// toolSpec is one tool's configuration, normalized across the built-in and MCP
// toolset variants, which carry the same three values under different types.
type toolSpec struct {
	name             string
	enabled          bool
	permissionPolicy string
}

// toolsetSpec is a toolset's configuration, likewise normalized. mcpServerName
// stays empty for a built-in toolset, which has no server behind it.
type toolsetSpec struct {
	toolsetType    string
	mcpServerName  string
	defaultEnabled bool
	defaultPolicy  string
	tools          []toolSpec
}

func newToolset(runtime *plugin.Runtime, agentID string, toolsetIndex int, spec toolsetSpec) (plugin.Resource, error) {
	toolsetID := agentID + "/toolset/" + strconv.Itoa(toolsetIndex)

	tools := make([]interface{}, 0, len(spec.tools))
	for _, tool := range spec.tools {
		mqlTool, err := CreateResource(runtime, "claude.agent.toolset.tool", map[string]*llx.RawData{
			"__id":             llx.StringData(toolsetID + "/" + tool.name),
			"name":             llx.StringData(tool.name),
			"enabled":          llx.BoolData(tool.enabled),
			"permissionPolicy": llx.StringData(tool.permissionPolicy),
		})
		if err != nil {
			return nil, err
		}
		tools = append(tools, mqlTool)
	}

	return CreateResource(runtime, "claude.agent.toolset", map[string]*llx.RawData{
		"__id":                    llx.StringData(toolsetID),
		"type":                    llx.StringData(spec.toolsetType),
		"mcpServerName":           llx.StringData(spec.mcpServerName),
		"defaultEnabled":          llx.BoolData(spec.defaultEnabled),
		"defaultPermissionPolicy": llx.StringData(spec.defaultPolicy),
		"tools":                   llx.ArrayData(tools, types.Resource("claude.agent.toolset.tool")),
	})
}

// claude.environment

func (r *mqlClaude) environments() ([]interface{}, error) {
	c := conn(r.MqlRuntime)
	client := c.Client()

	pager := client.Beta.Environments.ListAutoPaging(context.Background(), anthropic.BetaEnvironmentListParams{})

	var res []interface{}
	for pager.Next() {
		e := pager.Current()

		createdAt, err := parseTime(e.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing environment createdAt: %w", err)
		}
		updatedAt, err := parseTime(e.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing environment updatedAt: %w", err)
		}
		archivedAt, err := parseTime(e.ArchivedAt)
		if err != nil {
			return nil, fmt.Errorf("parsing environment archivedAt: %w", err)
		}

		args := map[string]*llx.RawData{
			"__id":                 llx.StringData(e.ID),
			"id":                   llx.StringData(e.ID),
			"name":                 llx.StringData(e.Name),
			"description":          llx.StringData(e.Description),
			"scope":                llx.StringData(string(e.Scope)),
			"metadata":             llx.MapData(toInterfaceMap(e.Metadata), types.String),
			"configType":           llx.StringData(e.Config.Type),
			"networkingType":       llx.StringData(e.Config.Networking.Type),
			"allowedHosts":         llx.ArrayData(toInterfaceSlice(e.Config.Networking.AllowedHosts), types.String),
			"aptPackages":          llx.ArrayData(toInterfaceSlice(e.Config.Packages.Apt), types.String),
			"cargoPackages":        llx.ArrayData(toInterfaceSlice(e.Config.Packages.Cargo), types.String),
			"gemPackages":          llx.ArrayData(toInterfaceSlice(e.Config.Packages.Gem), types.String),
			"goPackages":           llx.ArrayData(toInterfaceSlice(e.Config.Packages.Go), types.String),
			"npmPackages":          llx.ArrayData(toInterfaceSlice(e.Config.Packages.Npm), types.String),
			"pipPackages":          llx.ArrayData(toInterfaceSlice(e.Config.Packages.Pip), types.String),
			"allowMcpServers":      {Type: types.Bool},
			"allowPackageManagers": {Type: types.Bool},
			"createdAt":            llx.TimeData(createdAt),
			"updatedAt":            llx.TimeData(updatedAt),
			"archivedAt":           llx.TimeData(archivedAt),
			"type":                 llx.StringData(string(e.Type)),
		}

		// The two allow flags only exist on a limited network policy. An
		// unrestricted environment reports neither, so they stay null rather
		// than claiming the traffic is blocked.
		if e.Config.Networking.Type == "limited" {
			args["allowMcpServers"] = llx.BoolData(e.Config.Networking.AllowMCPServers)
			args["allowPackageManagers"] = llx.BoolData(e.Config.Networking.AllowPackageManagers)
		}

		mqlEnv, err := CreateResource(r.MqlRuntime, "claude.environment", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEnv)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing environments: %w", err)
	}

	return res, nil
}

// claude.session

type mqlClaudeSessionInternal struct {
	cacheEnvironmentID string
}

func (r *mqlClaudeSession) environment() (*mqlClaudeEnvironment, error) {
	env, ok, err := lookupClaudeChild[*mqlClaudeEnvironment](r.MqlRuntime, r.cacheEnvironmentID, (*mqlClaude).GetEnvironments)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Environment.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return env, nil
}

func (r *mqlClaude) sessions() ([]interface{}, error) {
	c := conn(r.MqlRuntime)
	client := c.Client()

	pager := client.Beta.Sessions.ListAutoPaging(context.Background(), anthropic.BetaSessionListParams{})

	var res []interface{}
	for pager.Next() {
		s := pager.Current()

		mqlSession, err := CreateResource(r.MqlRuntime, "claude.session", map[string]*llx.RawData{
			"__id":       llx.StringData(s.ID),
			"id":         llx.StringData(s.ID),
			"title":      llx.StringData(s.Title),
			"status":     llx.StringData(string(s.Status)),
			"createdAt":  llx.TimeData(s.CreatedAt),
			"updatedAt":  llx.TimeData(s.UpdatedAt),
			"archivedAt": llx.TimeData(s.ArchivedAt),
			"type":       llx.StringData(string(s.Type)),
		})
		if err != nil {
			return nil, err
		}

		mqlSession.(*mqlClaudeSession).cacheEnvironmentID = s.EnvironmentID

		res = append(res, mqlSession)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}

	return res, nil
}

// claude.file

func (r *mqlClaude) files() ([]interface{}, error) {
	c := conn(r.MqlRuntime)
	client := c.Client()

	pager := client.Beta.Files.ListAutoPaging(context.Background(), anthropic.BetaFileListParams{})

	var res []interface{}
	for pager.Next() {
		f := pager.Current()

		mqlFile, err := CreateResource(r.MqlRuntime, "claude.file", map[string]*llx.RawData{
			"__id":         llx.StringData(f.ID),
			"id":           llx.StringData(f.ID),
			"filename":     llx.StringData(f.Filename),
			"mimeType":     llx.StringData(f.MimeType),
			"sizeBytes":    llx.IntData(f.SizeBytes),
			"downloadable": llx.BoolData(f.Downloadable),
			"createdAt":    llx.TimeData(f.CreatedAt),
			"type":         llx.StringData(string(f.Type)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFile)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing files: %w", err)
	}

	return res, nil
}

// claude.skill

func (r *mqlClaude) skills() ([]interface{}, error) {
	c := conn(r.MqlRuntime)
	client := c.Client()

	pager := client.Beta.Skills.ListAutoPaging(context.Background(), anthropic.BetaSkillListParams{})

	var res []interface{}
	for pager.Next() {
		s := pager.Current()

		mqlSkill, err := CreateResource(r.MqlRuntime, "claude.skill", map[string]*llx.RawData{
			"__id":          llx.StringData(s.ID),
			"id":            llx.StringData(s.ID),
			"displayTitle":  llx.StringData(s.DisplayName),
			"source":        llx.StringData(string(s.Source.Type)),
			"latestVersion": llx.StringData(s.LatestVersionID),
			"createdAt":     llx.TimeData(s.CreatedAt),
			"updatedAt":     llx.TimeData(s.UpdatedAt),
			"type":          llx.StringData(string(s.Type)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSkill)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing skills: %w", err)
	}

	return res, nil
}

// claude.vault

func (r *mqlClaude) vaults() ([]interface{}, error) {
	c := conn(r.MqlRuntime)
	client := c.Client()

	pager := client.Beta.Vaults.ListAutoPaging(context.Background(), anthropic.BetaVaultListParams{})

	var res []interface{}
	for pager.Next() {
		v := pager.Current()

		mqlVault, err := CreateResource(r.MqlRuntime, "claude.vault", map[string]*llx.RawData{
			"__id":        llx.StringData(v.ID),
			"id":          llx.StringData(v.ID),
			"displayName": llx.StringData(v.DisplayName),
			"createdAt":   llx.TimeData(v.CreatedAt),
			"updatedAt":   llx.TimeData(v.UpdatedAt),
			"archivedAt":  llx.TimeData(v.ArchivedAt),
			"type":        llx.StringData(string(v.Type)),
		})
		if err != nil {
			return nil, err
		}

		res = append(res, mqlVault)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}

	return res, nil
}

type mqlClaudeVaultCredentialInternal struct {
	cacheVaultID string
}

func (r *mqlClaudeVaultCredential) vault() (*mqlClaudeVault, error) {
	vault, ok, err := lookupClaudeChild[*mqlClaudeVault](r.MqlRuntime, r.cacheVaultID, (*mqlClaude).GetVaults)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Vault.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return vault, nil
}

func (r *mqlClaudeVault) credentials() ([]interface{}, error) {
	c := conn(r.MqlRuntime)
	client := c.Client()

	pager := client.Beta.Vaults.Credentials.ListAutoPaging(context.Background(), r.GetId().Data, anthropic.BetaVaultCredentialListParams{})

	var res []interface{}
	for pager.Next() {
		cred := pager.Current()

		mqlCred, err := CreateResource(r.MqlRuntime, "claude.vault.credential", map[string]*llx.RawData{
			"__id":        llx.StringData(cred.ID),
			"id":          llx.StringData(cred.ID),
			"displayName": llx.StringData(cred.DisplayName),
			"createdAt":   llx.TimeData(cred.CreatedAt),
			"updatedAt":   llx.TimeData(cred.UpdatedAt),
			"archivedAt":  llx.TimeData(cred.ArchivedAt),
			"type":        llx.StringData(string(cred.Type)),
		})
		if err != nil {
			return nil, err
		}

		mqlCred.(*mqlClaudeVaultCredential).cacheVaultID = cred.VaultID

		res = append(res, mqlCred)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing vault credentials: %w", err)
	}

	return res, nil
}

// claude.memoryStore

func (r *mqlClaude) memoryStores() ([]interface{}, error) {
	c := conn(r.MqlRuntime)
	client := c.Client()

	pager := client.Beta.MemoryStores.ListAutoPaging(context.Background(), anthropic.BetaMemoryStoreListParams{})

	var res []interface{}
	for pager.Next() {
		ms := pager.Current()

		mqlMS, err := CreateResource(r.MqlRuntime, "claude.memoryStore", map[string]*llx.RawData{
			"__id":        llx.StringData(ms.ID),
			"id":          llx.StringData(ms.ID),
			"name":        llx.StringData(ms.Name),
			"description": llx.StringData(ms.Description),
			"createdAt":   llx.TimeData(ms.CreatedAt),
			"updatedAt":   llx.TimeData(ms.UpdatedAt),
			"archivedAt":  llx.TimeData(ms.ArchivedAt),
			"type":        llx.StringData(string(ms.Type)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlMS)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing memory stores: %w", err)
	}

	return res, nil
}

// claude.messageBatch

func (r *mqlClaude) messageBatches() ([]interface{}, error) {
	c := conn(r.MqlRuntime)
	client := c.Client()

	pager := client.Beta.Messages.Batches.ListAutoPaging(context.Background(), anthropic.BetaMessageBatchListParams{})

	var res []interface{}
	for pager.Next() {
		b := pager.Current()

		mqlBatch, err := CreateResource(r.MqlRuntime, "claude.messageBatch", map[string]*llx.RawData{
			"__id":              llx.StringData(b.ID),
			"id":                llx.StringData(b.ID),
			"processingStatus":  llx.StringData(string(b.ProcessingStatus)),
			"createdAt":         llx.TimeData(b.CreatedAt),
			"endedAt":           llx.TimeData(b.EndedAt),
			"expiresAt":         llx.TimeData(b.ExpiresAt),
			"archivedAt":        llx.TimeData(b.ArchivedAt),
			"cancelInitiatedAt": llx.TimeData(b.CancelInitiatedAt),
			"type":              llx.StringData(string(b.Type)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBatch)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing message batches: %w", err)
	}

	return res, nil
}

// claude.userProfile

func (r *mqlClaude) userProfiles() ([]interface{}, error) {
	c := conn(r.MqlRuntime)
	client := c.Client()

	pager := client.Beta.UserProfiles.ListAutoPaging(context.Background(), anthropic.BetaUserProfileListParams{})

	var res []interface{}
	for pager.Next() {
		p := pager.Current()

		mqlProfile, err := CreateResource(r.MqlRuntime, "claude.userProfile", map[string]*llx.RawData{
			"__id":                    llx.StringData(p.ID),
			"id":                      llx.StringData(p.ID),
			"name":                    llx.StringData(p.Name),
			"externalId":              llx.StringData(p.ExternalID),
			"relationship":            llx.NilData,
			"accessType":              claudeAccessType(p.AccessType),
			"externalUserOnboardedAt": llx.TimeDataPtr(nullableTime(p.ExternalUserOnboardedAt)),
			"createdAt":               llx.TimeData(p.CreatedAt),
			"updatedAt":               llx.TimeData(p.UpdatedAt),
			"type":                    llx.StringData(string(p.Type)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlProfile)
	}
	if err := pager.Err(); err != nil {
		return nil, fmt.Errorf("listing user profiles: %w", err)
	}

	return res, nil
}

// claudeAccessType maps a profile's access type into MQL data, reporting null
// when the API omits it. The field is optional on the profile payload, and an
// empty string would read as a real access type that is neither `application`
// nor `passthrough`.
func claudeAccessType(t anthropic.BetaUserProfileAccessType) *llx.RawData {
	if t == "" {
		return llx.NilData
	}
	return llx.StringData(string(t))
}

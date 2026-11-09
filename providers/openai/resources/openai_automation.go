// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// automationRefs carries the ids an automation names, which the typed
// accessors resolve against the project's cached collections.
type automationRefs struct {
	agentID    string
	vaultIDs   []string
	templateID string
}

// automationArgs builds the scalar resource args for an openai.automation and
// returns the ids its accessors resolve. The automation is a union of a
// periodic and a once schedule, its target a union of a new and an existing
// session, and the target's environment a union of none, openai_hosted and
// self_hosted. Every field that belongs to a variant the record does not carry
// is null: reporting "" or an empty list there would claim a setting the
// automation does not have.
func automationArgs(a openai.AutomationUnion) (map[string]*llx.RawData, automationRefs) {
	refs := automationRefs{}
	args := map[string]*llx.RawData{
		"__id":                llx.StringData(a.ID),
		"id":                  llx.StringData(a.ID),
		"name":                llx.StringDataPtr(emptyToNil(a.Name)),
		"type":                llx.StringDataPtr(emptyToNil(a.Type)),
		"status":              llx.StringDataPtr(emptyToNil(a.Status)),
		"expression":          llx.NilData,
		"timezone":            llx.NilData,
		"runAt":               llx.NilData,
		"metadata":            stringMapData(a.Metadata),
		"createdAt":           llx.TimeDataPtr(unixToNullableTime(a.CreatedAt)),
		"createdByType":       llx.StringDataPtr(emptyToNil(a.CreatedBy.Type)),
		"createdBySessionId":  llx.NilData,
		"createdByToolCallId": llx.NilData,
		"targetType":          llx.StringDataPtr(emptyToNil(a.Target.Type)),
		"targetSessionId":     llx.NilData,
		"targetInstructions":  llx.NilData,
	}

	switch a.Type {
	case "periodic":
		args["expression"] = llx.StringDataPtr(emptyToNil(a.Expression))
		args["timezone"] = llx.StringDataPtr(emptyToNil(a.Timezone))
	case "once":
		args["runAt"] = llx.TimeDataPtr(unixToNullableTime(a.RunAt))
	}

	if a.CreatedBy.Type == "agent" {
		args["createdBySessionId"] = llx.StringDataPtr(emptyToNil(a.CreatedBy.SessionID))
		args["createdByToolCallId"] = llx.StringDataPtr(emptyToNil(a.CreatedBy.ToolCallID))
	}

	// inline agent fields; the tool list is attached by newAutomation
	args["inlineAgentModel"] = llx.NilData
	args["inlineAgentInstructions"] = llx.NilData

	envNulls(args)

	switch a.Target.Type {
	case "existing_session":
		args["targetSessionId"] = llx.StringDataPtr(emptyToNil(a.Target.SessionID))
		args["targetInstructions"] = llx.StringDataPtr(emptyToNil(a.Target.Instructions))

	case "new_session":
		target := a.Target
		refs.agentID = target.AgentID
		refs.vaultIDs = target.VaultIDs
		// agent and agent_id are exclusive: the inline config is null when a
		// saved agent is referenced
		if target.AgentID == "" && target.JSON.Agent.Valid() {
			args["inlineAgentModel"] = llx.StringDataPtr(emptyToNil(target.Agent.Model))
			args["inlineAgentInstructions"] = llx.StringDataPtr(emptyToNil(target.Agent.Instructions))
		}
		automationEnvironmentArgs(args, &refs, target.Environment)
	}

	return args, refs
}

// envNulls sets every environment field to null, the starting point for each
// environment variant.
func envNulls(args map[string]*llx.RawData) {
	for _, name := range []string{
		"environmentType", "environmentId", "networkPolicyType",
		"networkPolicyAllowedDomains", "desktopEnabled", "containerSize",
		"capabilityDirectories", "npmPackages", "pythonPackages",
		"systemPackages", "plugins", "workspaceDirectory",
	} {
		args[name] = llx.NilData
	}
}

// automationEnvironmentArgs fills the environment fields of a new_session
// automation. On an openai_hosted environment every block is an override: the
// API sends null for a block the automation leaves to its environment template,
// so each field is set only when its block is present. An empty list there is
// a real override (no packages, no allowed domains) and is kept as one.
func automationEnvironmentArgs(args map[string]*llx.RawData, refs *automationRefs, env openai.AutomationEnvironmentUnion) {
	args["environmentType"] = llx.StringDataPtr(emptyToNil(env.Type))

	switch env.Type {
	case "self_hosted":
		args["environmentId"] = llx.StringDataPtr(emptyToNil(env.EnvironmentID))
		args["capabilityDirectories"] = llx.ArrayData(convertStringSlice(env.CapabilityDirectories), types.String)
		args["workspaceDirectory"] = llx.StringDataPtr(emptyToNil(env.WorkspaceDirectory))

	case "openai_hosted":
		refs.templateID = env.EnvironmentTemplateID
		args["environmentId"] = llx.StringDataPtr(emptyToNil(env.EnvironmentID))
		args["containerSize"] = llx.StringDataPtr(emptyToNil(env.ContainerSize))
		if env.JSON.Network.Valid() {
			args["networkPolicyType"] = llx.StringDataPtr(emptyToNil(env.Network.Access))
			args["networkPolicyAllowedDomains"] = llx.ArrayData(convertStringSlice(env.Network.AllowedDomains), types.String)
		}
		if env.JSON.Desktop.Valid() {
			args["desktopEnabled"] = llx.BoolData(env.Desktop.Enabled)
		}
		if env.JSON.CapabilityDirectories.Valid() {
			args["capabilityDirectories"] = llx.ArrayData(convertStringSlice(env.CapabilityDirectories), types.String)
		}
		if env.JSON.Packages.Valid() {
			args["npmPackages"] = llx.ArrayData(convertStringSlice(env.Packages.Npm), types.String)
			args["pythonPackages"] = llx.ArrayData(convertStringSlice(env.Packages.Python), types.String)
			args["systemPackages"] = llx.ArrayData(convertStringSlice(env.Packages.System), types.String)
		}
		if env.JSON.Plugins.Valid() {
			plugins := make(map[string]string, len(env.Plugins))
			for _, p := range env.Plugins {
				plugins[p.Name] = p.Description
			}
			args["plugins"] = llx.MapData(toStringMap(plugins), types.String)
		}
	}
}

// persistedAgentTool re-reads an inline agent's tool as the type a saved
// agent's tool list uses. The two SDK types decode the same wire shape, so
// reading the raw JSON again lets one mapper, and the secret handling in it,
// serve both. A tool with no raw JSON keeps only its type.
func persistedAgentTool(t openai.AgentToolUnion) openai.PersistedAgentToolUnion {
	raw := t.RawJSON()
	if raw == "" {
		return openai.PersistedAgentToolUnion{Type: t.Type}
	}
	var p openai.PersistedAgentToolUnion
	if err := p.UnmarshalJSON([]byte(raw)); err != nil {
		return openai.PersistedAgentToolUnion{Type: t.Type}
	}
	return p
}

// newAutomation builds an openai.automation along with the inline agent tools,
// skills and files it carries.
func newAutomation(runtime *plugin.Runtime, a openai.AutomationUnion) (plugin.Resource, error) {
	args, refs := automationArgs(a)

	args["inlineAgentTools"] = llx.NilData
	args["skills"] = llx.NilData
	args["files"] = llx.NilData

	if a.Target.Type == "new_session" {
		target := a.Target
		if target.AgentID == "" && target.JSON.Agent.Valid() {
			tools := make([]any, 0, len(target.Agent.Tools))
			for i := range target.Agent.Tools {
				toolArgs, credentialID := agentToolArgs(a.ID, i, persistedAgentTool(target.Agent.Tools[i]))
				mqlTool, err := CreateResource(runtime, "openai.agent.tool", toolArgs)
				if err != nil {
					return nil, err
				}
				mqlTool.(*mqlOpenaiAgentTool).cacheCredentialID = credentialID
				tools = append(tools, mqlTool)
			}
			args["inlineAgentTools"] = llx.ArrayData(tools, types.Resource("openai.agent.tool"))
		}

		env := target.Environment
		if env.Type == "openai_hosted" && env.JSON.Skills.Valid() {
			skills := make([]any, 0, len(env.Skills))
			for i, s := range env.Skills {
				skillArgs, skillID := sandboxSkillArgs(a.ID, i, s.Type, s.SkillID, s.Version, s.Name, s.Description)
				mqlSkill, err := newSandboxSkill(runtime, skillArgs, skillID)
				if err != nil {
					return nil, err
				}
				skills = append(skills, mqlSkill)
			}
			args["skills"] = llx.ArrayData(skills, types.Resource("openai.environmentTemplate.skill"))
		}
		if env.Type == "openai_hosted" && env.JSON.Files.Valid() {
			files := make([]any, 0, len(env.Files))
			for i, f := range env.Files {
				fileArgs, fileID := sandboxFileArgs(a.ID, i, f.Type, f.Path, f.FileID, f.SizeBytes)
				mqlFile, err := newSandboxFile(runtime, fileArgs, fileID)
				if err != nil {
					return nil, err
				}
				files = append(files, mqlFile)
			}
			args["files"] = llx.ArrayData(files, types.Resource("openai.environmentTemplate.file"))
		}
	}

	res, err := CreateResource(runtime, "openai.automation", args)
	if err != nil {
		return nil, err
	}
	mqlAutomation := res.(*mqlOpenaiAutomation)
	mqlAutomation.cacheAgentID = refs.agentID
	mqlAutomation.cacheVaultIDs = refs.vaultIDs
	mqlAutomation.cacheTemplateID = refs.templateID
	return mqlAutomation, nil
}

type mqlOpenaiAutomationInternal struct {
	cacheAgentID    string
	cacheVaultIDs   []string
	cacheTemplateID string
}

func (r *mqlOpenai) automations() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.automations")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	res := []any{}
	err = walkPages(
		client.Beta.Agents.Automations.ListAutoPaging(ctx, openai.BetaAgentAutomationListParams{}),
		func(a openai.AutomationUnion) string { return a.ID },
		func(a openai.AutomationUnion) error {
			mqlAutomation, err := newAutomation(r.MqlRuntime, a)
			if err != nil {
				return err
			}
			res = append(res, mqlAutomation)
			return nil
		})
	if err != nil {
		return nil, classifyReportError(err, "agent automation list")
	}
	return res, nil
}

func initOpenaiAutomation(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	automationID, ok := stringArg(args, "id")
	if !ok {
		return args, nil, nil
	}

	conn := openaiConn(runtime)
	client, err := dataPlaneClient(conn, "openai.automation")
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, fmt.Errorf("cannot fetch automation %s: no project API key configured", automationID)
	}
	a, err := client.Beta.Agents.Automations.Get(context.Background(), automationID)
	if err != nil {
		return nil, nil, classifyReportError(err, "agent automation "+automationID)
	}

	mqlAutomation, err := newAutomation(runtime, *a)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlAutomation, nil
}

func (r *mqlOpenaiAutomation) agent() (*mqlOpenaiAgent, error) {
	a, err := resolveAgent(r.MqlRuntime, r.cacheAgentID)
	if err != nil {
		return nil, err
	}
	if a == nil {
		r.Agent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return a, nil
}

func (r *mqlOpenaiAutomation) vaults() ([]any, error) {
	res := []any{}
	for _, id := range r.cacheVaultIDs {
		v, err := resolveVault(r.MqlRuntime, id)
		if err != nil {
			return nil, err
		}
		if v != nil {
			res = append(res, v)
		}
	}
	return res, nil
}

func (r *mqlOpenaiAutomation) environmentTemplate() (*mqlOpenaiEnvironmentTemplate, error) {
	t, err := resolveEnvironmentTemplate(r.MqlRuntime, r.cacheTemplateID)
	if err != nil {
		return nil, err
	}
	if t == nil {
		r.EnvironmentTemplate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return t, nil
}

// openai.agent.automations

func (r *mqlOpenaiAgent) automations() ([]any, error) {
	all, err := openaiAutomationList(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	res := []any{}
	for i := range all {
		a, ok := all[i].(*mqlOpenaiAutomation)
		if ok && a.cacheAgentID == r.Id.Data {
			res = append(res, a)
		}
	}
	return res, nil
}

// openaiRoot returns the cached openai root resource, through which each
// collection is listed once per scan.
func openaiRoot(runtime *plugin.Runtime) (*mqlOpenai, error) {
	obj, err := CreateResource(runtime, "openai", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlOpenai), nil
}

func openaiAutomationList(runtime *plugin.Runtime) ([]any, error) {
	root, err := openaiRoot(runtime)
	if err != nil {
		return nil, err
	}
	list := root.GetAutomations()
	if list.Error != nil {
		return nil, list.Error
	}
	return list.Data, nil
}

// resolveAgent finds the saved agent with the given id in the project agent
// list. An automation outlives the agent it names, so a miss is (nil, nil) for
// the caller to null.
func resolveAgent(runtime *plugin.Runtime, agentID string) (*mqlOpenaiAgent, error) {
	if agentID == "" {
		return nil, nil
	}
	root, err := openaiRoot(runtime)
	if err != nil {
		return nil, err
	}
	agents := root.GetAgents()
	if agents.Error != nil {
		return nil, agents.Error
	}
	for i := range agents.Data {
		a, ok := agents.Data[i].(*mqlOpenaiAgent)
		if ok && a.Id.Data == agentID {
			return a, nil
		}
	}
	return nil, nil
}

// resolveEnvironmentTemplate finds the template with the given id in the
// project template list. A miss is (nil, nil) for the caller to null.
func resolveEnvironmentTemplate(runtime *plugin.Runtime, templateID string) (*mqlOpenaiEnvironmentTemplate, error) {
	if templateID == "" {
		return nil, nil
	}
	root, err := openaiRoot(runtime)
	if err != nil {
		return nil, err
	}
	templates := root.GetEnvironmentTemplates()
	if templates.Error != nil {
		return nil, templates.Error
	}
	for i := range templates.Data {
		t, ok := templates.Data[i].(*mqlOpenaiEnvironmentTemplate)
		if ok && t.Id.Data == templateID {
			return t, nil
		}
	}
	return nil, nil
}

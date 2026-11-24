// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mistral/internal/mistralai"
	"go.mondoo.com/mql/types"
)

// mqlMistralAgentInternal carries the raw ids an agent's configuration names,
// so the accessors can hand them back as the resources they identify.
type mqlMistralAgentInternal struct {
	libraryIDs   []string
	connectorIDs []string
	handoffIDs   []string
}

// mqlMistralAgentToolInternal carries the id of the connector a connector tool
// calls.
type mqlMistralAgentToolInternal struct {
	connectorID string
}

func (r *mqlMistral) agents() ([]any, error) {
	conn := mistralConn(r.MqlRuntime)
	client := conn.Client()

	agents, err := client.ListAgents(context.Background())
	if mistralai.IsAccessDenied(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(agents))
	for _, a := range agents {
		tools := make([]any, 0, len(a.Tools))
		for i, t := range a.Tools {
			tool, err := newMqlAgentTool(r.MqlRuntime, a.ID, i, t)
			if err != nil {
				return nil, err
			}
			tools = append(tools, tool)
		}

		mqlAgent, err := CreateResource(r.MqlRuntime, "mistral.agent", map[string]*llx.RawData{
			"__id":                   llx.StringData(a.ID),
			"id":                     llx.StringData(a.ID),
			"name":                   llx.StringData(a.Name),
			"description":            llx.StringDataPtr(a.Description),
			"version":                llx.IntData(a.Version),
			"modelName":              llx.StringData(a.Model),
			"instructions":           llx.StringDataPtr(a.Instructions),
			"tools":                  llx.ArrayData(tools, types.Resource("mistral.agent.tool")),
			"guardrailsBlockOnError": llx.BoolDataPtr(a.GuardrailsBlockOnError()),
			"createdAt":              llx.TimeDataPtr(a.CreatedAt),
			"updatedAt":              llx.TimeDataPtr(a.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		agent := mqlAgent.(*mqlMistralAgent)
		agent.libraryIDs = a.LibraryIDs()
		agent.connectorIDs = a.ConnectorIDs()
		agent.handoffIDs = a.Handoffs
		res = append(res, agent)
	}

	return res, nil
}

// agentToolID keys a tool inside its agent. Tools carry no id of their own and
// an agent may list two tools of the same type, so the position in the agent's
// tool list is the key.
func agentToolID(agentID string, index int) string {
	return agentID + "/tools/" + strconv.Itoa(index)
}

func newMqlAgentTool(runtime *plugin.Runtime, agentID string, index int, t mistralai.AgentTool) (*mqlMistralAgentTool, error) {
	var name *string
	if t.Function != nil && t.Function.Name != "" {
		name = &t.Function.Name
	}

	var include, exclude, confirm []string
	if t.ToolConfiguration != nil {
		include = t.ToolConfiguration.Include
		exclude = t.ToolConfiguration.Exclude
		confirm = t.ToolConfiguration.RequiresConfirmation
	}

	res, err := CreateResource(runtime, "mistral.agent.tool", map[string]*llx.RawData{
		"__id":                 llx.StringData(agentToolID(agentID, index)),
		"type":                 llx.StringData(t.Type),
		"name":                 llx.StringDataPtr(name),
		"requiresConfirmation": llx.ArrayData(stringsToAny(confirm), types.String),
		"include":              llx.ArrayData(stringsToAny(include), types.String),
		"exclude":              llx.ArrayData(stringsToAny(exclude), types.String),
	})
	if err != nil {
		return nil, err
	}
	tool := res.(*mqlMistralAgentTool)
	if t.ConnectorID != nil {
		tool.connectorID = *t.ConnectorID
	}
	return tool, nil
}

func (r *mqlMistralAgent) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlMistralAgent) model() (*mqlMistralModel, error) {
	m, err := listedModel(r.MqlRuntime, r.ModelName.Data)
	if err != nil {
		return nil, err
	}
	if m == nil {
		r.Model.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return m, nil
}

func (r *mqlMistralAgent) libraries() ([]any, error) {
	if len(r.libraryIDs) == 0 {
		return []any{}, nil
	}
	root, err := rootResource(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := root.GetLibraries()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, r.libraryIDs, func(l *mqlMistralLibrary) string { return l.Id.Data }), nil
}

func (r *mqlMistralAgent) connectors() ([]any, error) {
	if len(r.connectorIDs) == 0 {
		return []any{}, nil
	}
	root, err := rootResource(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := root.GetConnectors()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, r.connectorIDs, func(c *mqlMistralConnector) string { return c.Id.Data }), nil
}

func (r *mqlMistralAgent) handoffs() ([]any, error) {
	if len(r.handoffIDs) == 0 {
		return []any{}, nil
	}
	root, err := rootResource(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := root.GetAgents()
	if list.Error != nil {
		return nil, list.Error
	}
	return pickByID(list.Data, r.handoffIDs, func(a *mqlMistralAgent) string { return a.Id.Data }), nil
}

func (r *mqlMistralAgentTool) connector() (*mqlMistralConnector, error) {
	if r.connectorID == "" {
		r.Connector.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	root, err := rootResource(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := root.GetConnectors()
	if list.Error != nil {
		return nil, list.Error
	}
	found := pickByID(list.Data, []string{r.connectorID}, func(c *mqlMistralConnector) string { return c.Id.Data })
	if len(found) == 0 {
		r.Connector.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return found[0].(*mqlMistralConnector), nil
}

// listedAgent resolves an agent id against the workspace agent list. It
// returns nil, nil when the id is empty or the list does not carry it.
func listedAgent(runtime *plugin.Runtime, id string) (*mqlMistralAgent, error) {
	if id == "" {
		return nil, nil
	}
	root, err := rootResource(runtime)
	if err != nil {
		return nil, err
	}
	list := root.GetAgents()
	if list.Error != nil {
		return nil, list.Error
	}
	found := pickByID(list.Data, []string{id}, func(a *mqlMistralAgent) string { return a.Id.Data })
	if len(found) == 0 {
		return nil, nil
	}
	return found[0].(*mqlMistralAgent), nil
}

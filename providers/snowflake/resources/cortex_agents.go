// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// cortexAgentSpec is the part of an agent specification the provider reads.
// DESCRIBE AGENT returns the specification as JSON (the SDK normalizes it).
type cortexAgentSpec struct {
	Models struct {
		Orchestration string `json:"orchestration"`
	} `json:"models"`
	Orchestration struct {
		Budget struct {
			Seconds *int64 `json:"seconds"`
			Tokens  *int64 `json:"tokens"`
		} `json:"budget"`
	} `json:"orchestration"`
	Tools []struct {
		ToolSpec cortexAgentToolSpec `json:"tool_spec"`
	} `json:"tools"`
	ToolResources map[string]map[string]any `json:"tool_resources"`
}

type cortexAgentToolSpec struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func parseCortexAgentSpec(spec string) (*cortexAgentSpec, error) {
	out := &cortexAgentSpec{}
	if strings.TrimSpace(spec) == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(spec), out); err != nil {
		return nil, err
	}
	return out, nil
}

// cortexAgentToolSearchService returns the search service a tool's resources
// name. Specifications write it under `search_service` or, in the form the
// CREATE AGENT reference shows, under `name` as a database.schema.service
// reference.
func cortexAgentToolSearchService(resources map[string]any) string {
	if s, ok := resources["search_service"].(string); ok && s != "" {
		return s
	}
	if s, ok := resources["name"].(string); ok && strings.Count(s, ".") == 2 {
		return s
	}
	return ""
}

// cortexAgentToolWarehouse returns the warehouse a tool's execution
// environment names.
func cortexAgentToolWarehouse(resources map[string]any) string {
	env, ok := resources["execution_environment"].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := env["warehouse"].(string)
	return s
}

type mqlSnowflakeCortexAgentInternal struct {
	cacheOwner string

	describeOnce sync.Once
	spec         *cortexAgentSpec
	specErr      error
}

type mqlSnowflakeCortexAgentToolInternal struct {
	cacheSearchService string
	cacheWarehouse     string
}

func (r *mqlSnowflakeAccount) cortexAgents() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	agents, err := conn.Client().CortexAgents.Show(context.Background(),
		sdk.NewShowCortexAgentRequest().WithIn(sdk.ExtendedIn{In: sdk.In{Account: new(true)}}))
	if err != nil {
		if isAccessDenied(err) {
			return nil, llx.Forbidden(err)
		}
		return nil, err
	}

	list := make([]any, 0, len(agents))
	for i := range agents {
		a := agents[i]
		displayName := ""
		if a.Profile.DisplayName != nil {
			displayName = *a.Profile.DisplayName
		}
		res, err := CreateResource(r.MqlRuntime, "snowflake.cortexAgent", map[string]*llx.RawData{
			"__id":         llx.StringData(snowflakeSchemaObjectID(a.DatabaseName, a.SchemaName, a.Name)),
			"name":         llx.StringData(a.Name),
			"databaseName": llx.StringData(a.DatabaseName),
			"schemaName":   llx.StringData(a.SchemaName),
			"comment":      llx.StringData(a.Comment),
			"displayName":  llx.StringData(displayName),
			"createdAt":    snowflakeTime(a.CreatedOn),
		})
		if err != nil {
			return nil, err
		}
		agent := res.(*mqlSnowflakeCortexAgent)
		agent.cacheOwner = a.Owner
		list = append(list, agent)
	}
	return list, nil
}

// describe fetches and memoizes the agent's specification, which backs the
// model, budget, and tool fields with a single DESCRIBE AGENT.
func (r *mqlSnowflakeCortexAgent) describe() (*cortexAgentSpec, error) {
	r.describeOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		id := sdk.NewSchemaObjectIdentifier(r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data)
		details, err := conn.Client().CortexAgents.Describe(context.Background(), id)
		if err != nil {
			if isAccessDenied(err) {
				err = llx.Forbidden(err)
			}
			r.specErr = err
			return
		}
		r.spec, r.specErr = parseCortexAgentSpec(details.AgentSpec)
	})
	return r.spec, r.specErr
}

func (r *mqlSnowflakeCortexAgent) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakeCortexAgent) schema() (*mqlSnowflakeSchema, error) {
	return resolveSchemaRef(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, &r.Schema)
}

func (r *mqlSnowflakeCortexAgent) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}

func (r *mqlSnowflakeCortexAgent) orchestrationModel() (string, error) {
	spec, err := r.describe()
	if err != nil {
		return "", err
	}
	return spec.Models.Orchestration, nil
}

func (r *mqlSnowflakeCortexAgent) budgetSeconds() (int64, error) {
	spec, err := r.describe()
	if err != nil {
		return 0, err
	}
	if spec.Orchestration.Budget.Seconds == nil {
		r.BudgetSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *spec.Orchestration.Budget.Seconds, nil
}

func (r *mqlSnowflakeCortexAgent) budgetTokens() (int64, error) {
	spec, err := r.describe()
	if err != nil {
		return 0, err
	}
	if spec.Orchestration.Budget.Tokens == nil {
		r.BudgetTokens.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *spec.Orchestration.Budget.Tokens, nil
}

func (r *mqlSnowflakeCortexAgent) tools() ([]any, error) {
	spec, err := r.describe()
	if err != nil {
		return nil, err
	}

	agentID := snowflakeSchemaObjectID(r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data)
	list := make([]any, 0, len(spec.Tools))
	for _, t := range spec.Tools {
		resources := spec.ToolResources[t.ToolSpec.Name]
		if resources == nil {
			resources = map[string]any{}
		}
		res, err := CreateResource(r.MqlRuntime, "snowflake.cortexAgent.tool", map[string]*llx.RawData{
			"__id":        llx.StringData(agentID + "/tool/" + t.ToolSpec.Name),
			"name":        llx.StringData(t.ToolSpec.Name),
			"type":        llx.StringData(t.ToolSpec.Type),
			"description": llx.StringData(t.ToolSpec.Description),
			"resources":   llx.DictData(resources),
		})
		if err != nil {
			return nil, err
		}
		tool := res.(*mqlSnowflakeCortexAgentTool)
		tool.cacheSearchService = cortexAgentToolSearchService(resources)
		tool.cacheWarehouse = cortexAgentToolWarehouse(resources)
		list = append(list, tool)
	}
	return list, nil
}

func (r *mqlSnowflakeCortexAgentTool) searchService() (*mqlSnowflakeCortexSearchService, error) {
	return resolveCortexSearchServiceRef(r.MqlRuntime, r.cacheSearchService, &r.SearchService)
}

func (r *mqlSnowflakeCortexAgentTool) warehouse() (*mqlSnowflakeWarehouse, error) {
	return resolveWarehouseRef(r.MqlRuntime, r.cacheWarehouse, &r.Warehouse)
}

// splitObjectFQN splits a database.schema.name reference into its parts,
// dropping the quotes a part carries. It reports false for anything that is
// not three parts.
func splitObjectFQN(fqn string) ([3]string, bool) {
	parts := splitQualifiedName(strings.TrimSpace(fqn))
	if len(parts) != 3 {
		return [3]string{}, false
	}
	var out [3]string
	for i, p := range parts {
		out[i] = identifierName(p)
		if out[i] == "" {
			return [3]string{}, false
		}
	}
	return out, true
}

// sameObjectFQN reports whether a reference written in a specification names
// the object with the given parts. Specifications usually write unquoted
// names, which Snowflake resolves case-insensitively.
func sameObjectFQN(ref [3]string, databaseName, schemaName, name string) bool {
	return strings.EqualFold(ref[0], databaseName) &&
		strings.EqualFold(ref[1], schemaName) &&
		strings.EqualFold(ref[2], name)
}

// resolveCortexSearchServiceRef resolves a fully qualified search service name
// against the account's search services, reporting the reference as null when
// the name is empty or names a service the scanning role cannot list.
func resolveCortexSearchServiceRef(runtime *plugin.Runtime, fqn string, field *plugin.TValue[*mqlSnowflakeCortexSearchService]) (*mqlSnowflakeCortexSearchService, error) {
	ref, ok := splitObjectFQN(fqn)
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	account, err := snowflakeAccount(runtime)
	if err != nil {
		return nil, err
	}
	services := account.GetCortexSearchServices()
	if services.Error != nil {
		return nil, services.Error
	}
	for _, s := range services.Data {
		svc := s.(*mqlSnowflakeCortexSearchService)
		if sameObjectFQN(ref, svc.DatabaseName.Data, svc.SchemaName.Data, svc.Name.Data) {
			return svc, nil
		}
	}
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// resolveCortexAgentRef resolves a fully qualified agent name against the
// account's agents, with the same null handling as
// resolveCortexSearchServiceRef.
func resolveCortexAgentRef(runtime *plugin.Runtime, fqn string, field *plugin.TValue[*mqlSnowflakeCortexAgent]) (*mqlSnowflakeCortexAgent, error) {
	ref, ok := splitObjectFQN(fqn)
	if !ok {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	account, err := snowflakeAccount(runtime)
	if err != nil {
		return nil, err
	}
	agents := account.GetCortexAgents()
	if agents.Error != nil {
		return nil, agents.Error
	}
	for _, a := range agents.Data {
		agent := a.(*mqlSnowflakeCortexAgent)
		if sameObjectFQN(ref, agent.DatabaseName.Data, agent.SchemaName.Data, agent.Name.Data) {
			return agent, nil
		}
	}
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// cortexUserRole returns the SNOWFLAKE.CORTEX_USER database role, whose
// grantees are the roles allowed to call Cortex AI functions.
func (r *mqlSnowflakeAccount) cortexUserRole() (*mqlSnowflakeDatabaseRole, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	roles, err := conn.Client().DatabaseRoles.Show(context.Background(),
		sdk.NewShowDatabaseRoleRequest().
			WithDatabase(sdk.NewAccountObjectIdentifier("SNOWFLAKE")).
			WithLike(sdk.Like{Pattern: new("CORTEX_USER")}))
	if err != nil {
		if isAccessDenied(err) {
			return nil, llx.Forbidden(err)
		}
		return nil, err
	}
	for i := range roles {
		if strings.EqualFold(roles[i].Name, "CORTEX_USER") {
			return newMqlSnowflakeDatabaseRole(r.MqlRuntime, "SNOWFLAKE", roles[i])
		}
	}
	r.CortexUserRole.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

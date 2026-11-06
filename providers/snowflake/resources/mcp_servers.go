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

// mcpServerSpec is an MCP server specification. DESCRIBE MCP SERVER returns it
// as JSON (the SDK normalizes it).
type mcpServerSpec struct {
	Tools []mcpServerToolSpec `json:"tools"`
}

type mcpServerToolSpec struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Type        string         `json:"type"`
	Description string         `json:"description"`
	Identifier  string         `json:"identifier"`
	Config      map[string]any `json:"config"`
}

func parseMcpServerSpec(spec string) (*mcpServerSpec, error) {
	out := &mcpServerSpec{}
	if strings.TrimSpace(spec) == "" {
		return out, nil
	}
	if err := json.Unmarshal([]byte(spec), out); err != nil {
		return nil, err
	}
	return out, nil
}

type mqlSnowflakeMcpServerInternal struct {
	cacheOwner string

	describeOnce sync.Once
	spec         *mcpServerSpec
	specErr      error
}

type mqlSnowflakeMcpServerToolInternal struct {
	cacheIdentifier string
}

func (r *mqlSnowflakeAccount) mcpServers() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	servers, err := conn.Client().McpServers.Show(context.Background(),
		sdk.NewShowMcpServerRequest().WithIn(sdk.In{Account: new(true)}))
	if err != nil {
		if isAccessDenied(err) {
			return nil, llx.Forbidden(err)
		}
		return nil, err
	}

	list := make([]any, 0, len(servers))
	for i := range servers {
		s := servers[i]
		res, err := CreateResource(r.MqlRuntime, "snowflake.mcpServer", map[string]*llx.RawData{
			"__id":         llx.StringData(snowflakeSchemaObjectID(s.DatabaseName, s.SchemaName, s.Name)),
			"name":         llx.StringData(s.Name),
			"databaseName": llx.StringData(s.DatabaseName),
			"schemaName":   llx.StringData(s.SchemaName),
			"comment":      llx.StringData(s.Comment),
			"createdAt":    snowflakeTime(s.CreatedOn),
		})
		if err != nil {
			return nil, err
		}
		server := res.(*mqlSnowflakeMcpServer)
		server.cacheOwner = s.Owner
		list = append(list, server)
	}
	return list, nil
}

func (r *mqlSnowflakeMcpServer) describe() (*mcpServerSpec, error) {
	r.describeOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		id := sdk.NewSchemaObjectIdentifier(r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data)
		details, err := conn.Client().McpServers.Describe(context.Background(), id)
		if err != nil {
			if isAccessDenied(err) {
				err = llx.Forbidden(err)
			}
			r.specErr = err
			return
		}
		r.spec, r.specErr = parseMcpServerSpec(details.ServerSpec)
	})
	return r.spec, r.specErr
}

func (r *mqlSnowflakeMcpServer) database() (*mqlSnowflakeDatabase, error) {
	return resolveDatabaseRef(r.MqlRuntime, r.DatabaseName.Data, &r.Database)
}

func (r *mqlSnowflakeMcpServer) schema() (*mqlSnowflakeSchema, error) {
	return resolveSchemaRef(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, &r.Schema)
}

func (r *mqlSnowflakeMcpServer) ownerRole() (*mqlSnowflakeRole, error) {
	return resolveOwnerRole(r.MqlRuntime, r.cacheOwner, &r.OwnerRole)
}

func (r *mqlSnowflakeMcpServer) tools() ([]any, error) {
	spec, err := r.describe()
	if err != nil {
		return nil, err
	}

	serverID := snowflakeSchemaObjectID(r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data)
	list := make([]any, 0, len(spec.Tools))
	for _, t := range spec.Tools {
		config := t.Config
		if config == nil {
			config = map[string]any{}
		}
		res, err := CreateResource(r.MqlRuntime, "snowflake.mcpServer.tool", map[string]*llx.RawData{
			"__id":        llx.StringData(serverID + "/tool/" + t.Name),
			"name":        llx.StringData(t.Name),
			"title":       llx.StringData(t.Title),
			"type":        llx.StringData(t.Type),
			"description": llx.StringData(t.Description),
			"identifier":  llx.StringData(t.Identifier),
			"config":      llx.DictData(config),
		})
		if err != nil {
			return nil, err
		}
		tool := res.(*mqlSnowflakeMcpServerTool)
		tool.cacheIdentifier = t.Identifier
		list = append(list, tool)
	}
	return list, nil
}

func (r *mqlSnowflakeMcpServerTool) searchService() (*mqlSnowflakeCortexSearchService, error) {
	if !strings.EqualFold(r.Type.Data, "CORTEX_SEARCH_SERVICE_QUERY") {
		r.SearchService.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveCortexSearchServiceRef(r.MqlRuntime, r.cacheIdentifier, &r.SearchService)
}

func (r *mqlSnowflakeMcpServerTool) cortexAgent() (*mqlSnowflakeCortexAgent, error) {
	if !strings.EqualFold(r.Type.Data, "CORTEX_AGENT_RUN") {
		r.CortexAgent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveCortexAgentRef(r.MqlRuntime, r.cacheIdentifier, &r.CortexAgent)
}

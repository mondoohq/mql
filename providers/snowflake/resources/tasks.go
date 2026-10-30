// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

type mqlSnowflakeTaskInternal struct {
	cacheOwner        string
	cacheWarehouse    string
	cachePredecessors []string
}

func (r *mqlSnowflakeAccount) tasks() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	tasks, err := client.Tasks.Show(ctx, sdk.NewShowTaskRequest())
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range tasks {
		mqlTask, err := newMqlSnowflakeTask(r.MqlRuntime, tasks[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlTask)
	}
	return list, nil
}

func newMqlSnowflakeTask(runtime *plugin.Runtime, task sdk.Task) (*mqlSnowflakeTask, error) {
	predecessors := make([]string, 0, len(task.Predecessors))
	for _, p := range task.Predecessors {
		predecessors = append(predecessors, p.FullyQualifiedName())
	}
	warehouse := ""
	if task.Warehouse != nil {
		warehouse = task.Warehouse.Name()
	}

	r, err := CreateResource(runtime, "snowflake.task", map[string]*llx.RawData{
		"__id":                      llx.StringData(task.ID().FullyQualifiedName()),
		"name":                      llx.StringData(task.Name),
		"databaseName":              llx.StringData(task.DatabaseName),
		"schemaName":                llx.StringData(task.SchemaName),
		"ownerRoleType":             llx.StringData(task.OwnerRoleType),
		"schedule":                  llx.StringData(task.Schedule),
		"state":                     llx.StringData(string(task.State)),
		"definition":                llx.StringData(task.Definition),
		"condition":                 llx.StringData(task.Condition),
		"allowOverlappingExecution": llx.BoolData(task.AllowOverlappingExecution),
		"comment":                   llx.StringData(task.Comment),
	})
	if err != nil {
		return nil, err
	}
	mqlTask := r.(*mqlSnowflakeTask)
	mqlTask.cacheOwner = task.Owner
	mqlTask.cacheWarehouse = warehouse
	mqlTask.cachePredecessors = predecessors
	return mqlTask, nil
}

func (r *mqlSnowflakeTask) owner() (*mqlSnowflakeRole, error) {
	if r.cacheOwner == "" {
		r.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	role, err := snowflakeRoleByName(r.MqlRuntime, r.cacheOwner)
	if err != nil {
		return nil, err
	}
	if role == nil {
		r.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return role, nil
}

func (r *mqlSnowflakeTask) warehouse() (*mqlSnowflakeWarehouse, error) {
	if r.cacheWarehouse == "" {
		r.Warehouse.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	wh, err := snowflakeWarehouseByName(r.MqlRuntime, r.cacheWarehouse)
	if err != nil {
		return nil, err
	}
	if wh == nil {
		r.Warehouse.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return wh, nil
}

// initSnowflakeTask resolves a task by its database, schema, and name so typed
// references (such as snowflake.task.predecessors) can hydrate a full task
// from a fully qualified name.
func initSnowflakeTask(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}
	dbRaw, ok1 := args["databaseName"]
	schemaRaw, ok2 := args["schemaName"]
	nameRaw, ok3 := args["name"]
	if !ok1 || !ok2 || !ok3 {
		return args, nil, nil
	}
	databaseName, _ := dbRaw.Value.(string)
	schemaName, _ := schemaRaw.Value.(string)
	name, _ := nameRaw.Value.(string)
	if databaseName == "" || schemaName == "" || name == "" {
		return nil, nil, fmt.Errorf("snowflake.task requires a non-empty databaseName, schemaName, and name")
	}

	conn := runtime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	tasks, err := client.Tasks.Show(ctx, sdk.NewShowTaskRequest().
		WithLike(sdk.Like{Pattern: new(name)}).
		WithIn(sdk.ExtendedIn{Schema: sdk.NewDatabaseObjectIdentifier(databaseName, schemaName)}))
	if err != nil {
		return nil, nil, err
	}
	for i := range tasks {
		if tasks[i].Name == name && tasks[i].DatabaseName == databaseName && tasks[i].SchemaName == schemaName {
			res, err := newMqlSnowflakeTask(runtime, tasks[i])
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("snowflake.task %q not found in %q.%q", name, databaseName, schemaName)
}

// snowflakeTaskByFQN resolves a fully qualified task name (database.schema.name)
// to a typed snowflake.task.
func snowflakeTaskByFQN(runtime *plugin.Runtime, fqn string) (*mqlSnowflakeTask, error) {
	id, err := sdk.ParseSchemaObjectIdentifier(fqn)
	if err != nil {
		return nil, err
	}
	res, err := NewResource(runtime, "snowflake.task", map[string]*llx.RawData{
		"databaseName": llx.StringData(id.DatabaseName()),
		"schemaName":   llx.StringData(id.SchemaName()),
		"name":         llx.StringData(id.Name()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlSnowflakeTask), nil
}

// predecessors resolves the task's predecessor tasks from their fully qualified
// names, forming the task graph.
func (r *mqlSnowflakeTask) predecessors() ([]any, error) {
	out := []any{}
	for _, fqn := range r.cachePredecessors {
		if fqn == "" {
			continue
		}
		task, err := snowflakeTaskByFQN(r.MqlRuntime, fqn)
		if err != nil {
			return nil, err
		}
		out = append(out, task)
	}
	return out, nil
}

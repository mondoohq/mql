// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	cosmos "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v4"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// cosmosAccountRef resolves the subscription/resource-group/account-name triple
// from the account's ARM id, shared by every data-plane RBAC accessor.
func (a *mqlAzureSubscriptionCosmosDbServiceAccount) cosmosAccountRef() (*ResourceID, string, error) {
	rid, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, "", err
	}
	accountName, err := rid.Component("databaseAccounts")
	if err != nil {
		return nil, "", err
	}
	return rid, accountName, nil
}

// cosmosRoleDefinition is the normalized shape of a Cosmos data-plane role
// definition. The Cassandra, Gremlin, Table, and MongoMI SDK resource types are
// structurally identical but share no Go interface, so each accessor maps its
// concrete type into this struct for the shared collector below.
type cosmosRoleDefinition struct {
	id, name, typ *string
	systemData    *cosmos.SystemData
	roleName      *string
	roleType      *cosmos.RoleDefinitionType
	scopes        []*string
	permissions   []*cosmos.Permission
}

// cosmosRoleAssignment is the normalized shape of a Cosmos data-plane role
// assignment (see cosmosRoleDefinition for why it exists).
type cosmosRoleAssignment struct {
	id, name, typ     *string
	systemData        *cosmos.SystemData
	principalID       *string
	roleDefinitionID  *string
	scope             *string
	provisioningState *string
}

// cosmosRolePermissionsToMql builds the typed permission blocks of a Cosmos
// data-plane role definition.
//
// A permission block usually carries no id of its own, so the cache key falls
// back to its position within the definition.
func cosmosRolePermissionsToMql(runtime *plugin.Runtime, definitionID string, permissions []*cosmos.Permission) ([]any, error) {
	res := []any{}
	for i, p := range permissions {
		if p == nil {
			continue
		}
		key := convert.ToValue(p.ID)
		if key == "" {
			key = strconv.Itoa(i)
		}
		dataActions := []any{}
		for _, a := range p.DataActions {
			if a != nil {
				dataActions = append(dataActions, *a)
			}
		}
		notDataActions := []any{}
		for _, a := range p.NotDataActions {
			if a != nil {
				notDataActions = append(notDataActions, *a)
			}
		}
		mqlPerm, err := CreateResource(runtime, "azure.subscription.cosmosDbService.account.roleDefinitionPermission",
			map[string]*llx.RawData{
				"__id":           llx.StringData(subResourceCacheID(nil, definitionID, "dataPermissions", key)),
				"id":             llx.StringDataPtr(p.ID),
				"dataActions":    llx.ArrayData(dataActions, types.String),
				"notDataActions": llx.ArrayData(notDataActions, types.String),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPerm)
	}
	return res, nil
}

// cosmosRoleDefinitionArgs maps a normalized role definition to MQL resource
// args: the roleType enum is coerced to its string form, nil fields default to
// empty, nil scope/permission entries are dropped, and each permission is
// converted to a dict. Kept as a pure function so it can be unit-tested without
// a live pager.
func cosmosRoleDefinitionArgs(d cosmosRoleDefinition) (map[string]*llx.RawData, error) {
	args := map[string]*llx.RawData{
		"__id":             llx.StringDataPtr(d.id),
		"id":               llx.StringDataPtr(d.id),
		"name":             llx.StringDataPtr(d.name),
		"type":             llx.StringDataPtr(d.typ),
		"roleName":         llx.StringData(""),
		"roleType":         llx.StringData(""),
		"assignableScopes": llx.ArrayData([]any{}, types.String),
		"permissions":      llx.ArrayData([]any{}, types.Dict),
	}
	if d.roleName != nil {
		args["roleName"] = llx.StringDataPtr(d.roleName)
	}
	if d.roleType != nil {
		args["roleType"] = llx.StringData(string(*d.roleType))
	}
	scopes := []any{}
	for _, s := range d.scopes {
		if s != nil {
			scopes = append(scopes, *s)
		}
	}
	args["assignableScopes"] = llx.ArrayData(scopes, types.String)
	perms := []any{}
	for _, p := range d.permissions {
		if p == nil {
			continue
		}
		m, err := convert.JsonToDict(p)
		if err != nil {
			return nil, err
		}
		perms = append(perms, m)
	}
	args["permissions"] = llx.ArrayData(perms, types.Dict)
	return args, nil
}

// cosmosRoleAssignmentArgs maps a normalized role assignment to MQL resource
// args (see cosmosRoleDefinitionArgs for the conventions).
func cosmosRoleAssignmentArgs(ra cosmosRoleAssignment) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":              llx.StringDataPtr(ra.id),
		"id":                llx.StringDataPtr(ra.id),
		"name":              llx.StringDataPtr(ra.name),
		"type":              llx.StringDataPtr(ra.typ),
		"principalId":       llx.StringData(""),
		"roleDefinitionId":  llx.StringData(""),
		"scope":             llx.StringData(""),
		"provisioningState": llx.StringData(""),
	}
	if ra.principalID != nil {
		args["principalId"] = llx.StringDataPtr(ra.principalID)
	}
	if ra.roleDefinitionID != nil {
		args["roleDefinitionId"] = llx.StringDataPtr(ra.roleDefinitionID)
	}
	if ra.scope != nil {
		args["scope"] = llx.StringDataPtr(ra.scope)
	}
	if ra.provisioningState != nil {
		args["provisioningState"] = llx.StringDataPtr(ra.provisioningState)
	}
	return args
}

// collectCosmosRoleDefinitions drains a role-definition pager into MQL resources.
// values extracts the page items, extract normalizes each SDK item, and setCache
// stores the resource's SystemData on its concrete Internal struct.
func collectCosmosRoleDefinitions[P, T any](
	runtime *plugin.Runtime,
	ctx context.Context,
	resource string,
	pager *azruntime.Pager[P],
	values func(P) []*T,
	extract func(*T) cosmosRoleDefinition,
	setCache func(plugin.Resource, any),
) ([]any, error) {
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, item := range values(page) {
			if item == nil {
				continue
			}
			d := extract(item)
			args, err := cosmosRoleDefinitionArgs(d)
			if err != nil {
				return nil, err
			}
			dataPermissions, err := cosmosRolePermissionsToMql(runtime, convert.ToValue(d.id), d.permissions)
			if err != nil {
				return nil, err
			}
			args["dataPermissions"] = llx.ArrayData(dataPermissions, types.Resource("azure.subscription.cosmosDbService.account.roleDefinitionPermission"))
			mqlDef, err := CreateResource(runtime, resource, args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(d.systemData)
			if err != nil {
				return nil, err
			}
			setCache(mqlDef, sysData)
			res = append(res, mqlDef)
		}
	}
	return res, nil
}

// collectCosmosRoleAssignments drains a role-assignment pager into MQL resources.
func collectCosmosRoleAssignments[P, T any](
	runtime *plugin.Runtime,
	ctx context.Context,
	resource string,
	pager *azruntime.Pager[P],
	values func(P) []*T,
	extract func(*T) cosmosRoleAssignment,
	setCache func(plugin.Resource, any),
) ([]any, error) {
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, item := range values(page) {
			if item == nil {
				continue
			}
			ra := extract(item)
			mqlRA, err := CreateResource(runtime, resource, cosmosRoleAssignmentArgs(ra))
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(ra.systemData)
			if err != nil {
				return nil, err
			}
			setCache(mqlRA, sysData)
			res = append(res, mqlRA)
		}
	}
	return res, nil
}

// Cassandra data-plane RBAC

type mqlAzureSubscriptionCosmosDbServiceAccountCassandraRoleDefinitionInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountCassandraRoleDefinition) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) cassandraRoleDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	rid, accountName, err := a.cosmosAccountRef()
	if err != nil {
		return nil, err
	}
	client, err := cosmos.NewCassandraResourcesClient(rid.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	return collectCosmosRoleDefinitions(a.MqlRuntime, context.Background(),
		"azure.subscription.cosmosDbService.account.cassandraRoleDefinition",
		client.NewListCassandraRoleDefinitionsPager(rid.ResourceGroup, accountName, nil),
		func(p cosmos.CassandraResourcesClientListCassandraRoleDefinitionsResponse) []*cosmos.CassandraRoleDefinitionResource {
			return p.Value
		},
		func(d *cosmos.CassandraRoleDefinitionResource) cosmosRoleDefinition {
			r := cosmosRoleDefinition{id: d.ID, name: d.Name, typ: d.Type, systemData: d.SystemData}
			if d.Properties != nil {
				r.roleName = d.Properties.RoleName
				r.roleType = d.Properties.Type
				r.scopes = d.Properties.AssignableScopes
				r.permissions = d.Properties.Permissions
			}
			return r
		},
		func(res plugin.Resource, raw any) {
			res.(*mqlAzureSubscriptionCosmosDbServiceAccountCassandraRoleDefinition).cacheSystemData = raw
		},
	)
}

type mqlAzureSubscriptionCosmosDbServiceAccountCassandraRoleAssignmentInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountCassandraRoleAssignment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) cassandraRoleAssignments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	rid, accountName, err := a.cosmosAccountRef()
	if err != nil {
		return nil, err
	}
	client, err := cosmos.NewCassandraResourcesClient(rid.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	return collectCosmosRoleAssignments(a.MqlRuntime, context.Background(),
		"azure.subscription.cosmosDbService.account.cassandraRoleAssignment",
		client.NewListCassandraRoleAssignmentsPager(rid.ResourceGroup, accountName, nil),
		func(p cosmos.CassandraResourcesClientListCassandraRoleAssignmentsResponse) []*cosmos.CassandraRoleAssignmentResource {
			return p.Value
		},
		func(ra *cosmos.CassandraRoleAssignmentResource) cosmosRoleAssignment {
			r := cosmosRoleAssignment{id: ra.ID, name: ra.Name, typ: ra.Type, systemData: ra.SystemData}
			if ra.Properties != nil {
				r.principalID = ra.Properties.PrincipalID
				r.roleDefinitionID = ra.Properties.RoleDefinitionID
				r.scope = ra.Properties.Scope
				r.provisioningState = ra.Properties.ProvisioningState
			}
			return r
		},
		func(res plugin.Resource, raw any) {
			res.(*mqlAzureSubscriptionCosmosDbServiceAccountCassandraRoleAssignment).cacheSystemData = raw
		},
	)
}

// Gremlin data-plane RBAC

type mqlAzureSubscriptionCosmosDbServiceAccountGremlinRoleDefinitionInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountGremlinRoleDefinition) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) gremlinRoleDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	rid, accountName, err := a.cosmosAccountRef()
	if err != nil {
		return nil, err
	}
	client, err := cosmos.NewGremlinResourcesClient(rid.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	return collectCosmosRoleDefinitions(a.MqlRuntime, context.Background(),
		"azure.subscription.cosmosDbService.account.gremlinRoleDefinition",
		client.NewListGremlinRoleDefinitionsPager(rid.ResourceGroup, accountName, nil),
		func(p cosmos.GremlinResourcesClientListGremlinRoleDefinitionsResponse) []*cosmos.GremlinRoleDefinitionResource {
			return p.Value
		},
		func(d *cosmos.GremlinRoleDefinitionResource) cosmosRoleDefinition {
			r := cosmosRoleDefinition{id: d.ID, name: d.Name, typ: d.Type, systemData: d.SystemData}
			if d.Properties != nil {
				r.roleName = d.Properties.RoleName
				r.roleType = d.Properties.Type
				r.scopes = d.Properties.AssignableScopes
				r.permissions = d.Properties.Permissions
			}
			return r
		},
		func(res plugin.Resource, raw any) {
			res.(*mqlAzureSubscriptionCosmosDbServiceAccountGremlinRoleDefinition).cacheSystemData = raw
		},
	)
}

type mqlAzureSubscriptionCosmosDbServiceAccountGremlinRoleAssignmentInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountGremlinRoleAssignment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) gremlinRoleAssignments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	rid, accountName, err := a.cosmosAccountRef()
	if err != nil {
		return nil, err
	}
	client, err := cosmos.NewGremlinResourcesClient(rid.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	return collectCosmosRoleAssignments(a.MqlRuntime, context.Background(),
		"azure.subscription.cosmosDbService.account.gremlinRoleAssignment",
		client.NewListGremlinRoleAssignmentsPager(rid.ResourceGroup, accountName, nil),
		func(p cosmos.GremlinResourcesClientListGremlinRoleAssignmentsResponse) []*cosmos.GremlinRoleAssignmentResource {
			return p.Value
		},
		func(ra *cosmos.GremlinRoleAssignmentResource) cosmosRoleAssignment {
			r := cosmosRoleAssignment{id: ra.ID, name: ra.Name, typ: ra.Type, systemData: ra.SystemData}
			if ra.Properties != nil {
				r.principalID = ra.Properties.PrincipalID
				r.roleDefinitionID = ra.Properties.RoleDefinitionID
				r.scope = ra.Properties.Scope
				r.provisioningState = ra.Properties.ProvisioningState
			}
			return r
		},
		func(res plugin.Resource, raw any) {
			res.(*mqlAzureSubscriptionCosmosDbServiceAccountGremlinRoleAssignment).cacheSystemData = raw
		},
	)
}

// Table data-plane RBAC

type mqlAzureSubscriptionCosmosDbServiceAccountTableRoleDefinitionInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountTableRoleDefinition) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) tableRoleDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	rid, accountName, err := a.cosmosAccountRef()
	if err != nil {
		return nil, err
	}
	client, err := cosmos.NewTableResourcesClient(rid.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	return collectCosmosRoleDefinitions(a.MqlRuntime, context.Background(),
		"azure.subscription.cosmosDbService.account.tableRoleDefinition",
		client.NewListTableRoleDefinitionsPager(rid.ResourceGroup, accountName, nil),
		func(p cosmos.TableResourcesClientListTableRoleDefinitionsResponse) []*cosmos.TableRoleDefinitionResource {
			return p.Value
		},
		func(d *cosmos.TableRoleDefinitionResource) cosmosRoleDefinition {
			r := cosmosRoleDefinition{id: d.ID, name: d.Name, typ: d.Type, systemData: d.SystemData}
			if d.Properties != nil {
				r.roleName = d.Properties.RoleName
				r.roleType = d.Properties.Type
				r.scopes = d.Properties.AssignableScopes
				r.permissions = d.Properties.Permissions
			}
			return r
		},
		func(res plugin.Resource, raw any) {
			res.(*mqlAzureSubscriptionCosmosDbServiceAccountTableRoleDefinition).cacheSystemData = raw
		},
	)
}

type mqlAzureSubscriptionCosmosDbServiceAccountTableRoleAssignmentInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountTableRoleAssignment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) tableRoleAssignments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	rid, accountName, err := a.cosmosAccountRef()
	if err != nil {
		return nil, err
	}
	client, err := cosmos.NewTableResourcesClient(rid.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	return collectCosmosRoleAssignments(a.MqlRuntime, context.Background(),
		"azure.subscription.cosmosDbService.account.tableRoleAssignment",
		client.NewListTableRoleAssignmentsPager(rid.ResourceGroup, accountName, nil),
		func(p cosmos.TableResourcesClientListTableRoleAssignmentsResponse) []*cosmos.TableRoleAssignmentResource {
			return p.Value
		},
		func(ra *cosmos.TableRoleAssignmentResource) cosmosRoleAssignment {
			r := cosmosRoleAssignment{id: ra.ID, name: ra.Name, typ: ra.Type, systemData: ra.SystemData}
			if ra.Properties != nil {
				r.principalID = ra.Properties.PrincipalID
				r.roleDefinitionID = ra.Properties.RoleDefinitionID
				r.scope = ra.Properties.Scope
				r.provisioningState = ra.Properties.ProvisioningState
			}
			return r
		},
		func(res plugin.Resource, raw any) {
			res.(*mqlAzureSubscriptionCosmosDbServiceAccountTableRoleAssignment).cacheSystemData = raw
		},
	)
}

// MongoDB managed-instance data-plane RBAC

type mqlAzureSubscriptionCosmosDbServiceAccountMongoMIRoleDefinitionInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountMongoMIRoleDefinition) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) mongoMIRoleDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	rid, accountName, err := a.cosmosAccountRef()
	if err != nil {
		return nil, err
	}
	client, err := cosmos.NewMongoMIResourcesClient(rid.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	return collectCosmosRoleDefinitions(a.MqlRuntime, context.Background(),
		"azure.subscription.cosmosDbService.account.mongoMIRoleDefinition",
		client.NewListMongoMIRoleDefinitionsPager(rid.ResourceGroup, accountName, nil),
		func(p cosmos.MongoMIResourcesClientListMongoMIRoleDefinitionsResponse) []*cosmos.MongoMIRoleDefinitionResource {
			return p.Value
		},
		func(d *cosmos.MongoMIRoleDefinitionResource) cosmosRoleDefinition {
			r := cosmosRoleDefinition{id: d.ID, name: d.Name, typ: d.Type, systemData: d.SystemData}
			if d.Properties != nil {
				r.roleName = d.Properties.RoleName
				r.roleType = d.Properties.Type
				r.scopes = d.Properties.AssignableScopes
				r.permissions = d.Properties.Permissions
			}
			return r
		},
		func(res plugin.Resource, raw any) {
			res.(*mqlAzureSubscriptionCosmosDbServiceAccountMongoMIRoleDefinition).cacheSystemData = raw
		},
	)
}

type mqlAzureSubscriptionCosmosDbServiceAccountMongoMIRoleAssignmentInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountMongoMIRoleAssignment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) mongoMIRoleAssignments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	rid, accountName, err := a.cosmosAccountRef()
	if err != nil {
		return nil, err
	}
	client, err := cosmos.NewMongoMIResourcesClient(rid.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	return collectCosmosRoleAssignments(a.MqlRuntime, context.Background(),
		"azure.subscription.cosmosDbService.account.mongoMIRoleAssignment",
		client.NewListMongoMIRoleAssignmentsPager(rid.ResourceGroup, accountName, nil),
		func(p cosmos.MongoMIResourcesClientListMongoMIRoleAssignmentsResponse) []*cosmos.MongoMIRoleAssignmentResource {
			return p.Value
		},
		func(ra *cosmos.MongoMIRoleAssignmentResource) cosmosRoleAssignment {
			r := cosmosRoleAssignment{id: ra.ID, name: ra.Name, typ: ra.Type, systemData: ra.SystemData}
			if ra.Properties != nil {
				r.principalID = ra.Properties.PrincipalID
				r.roleDefinitionID = ra.Properties.RoleDefinitionID
				r.scope = ra.Properties.Scope
				r.provisioningState = ra.Properties.ProvisioningState
			}
			return r
		},
		func(res plugin.Resource, raw any) {
			res.(*mqlAzureSubscriptionCosmosDbServiceAccountMongoMIRoleAssignment).cacheSystemData = raw
		},
	)
}

// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	backupdr "cloud.google.com/go/backupdr/apiv1"
	"cloud.google.com/go/backupdr/apiv1/backupdrpb"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/gcp/connection"
	"go.mondoo.com/mql/v13/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpProject) backupdr() (*mqlGcpProjectBackupdrService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectBackupdrService), nil
}

func initGcpProjectBackupdrService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	args["projectId"] = llx.StringData(conn.ResourceID())
	return args, nil, nil
}

func (g *mqlGcpProjectBackupdrService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/backupdrService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectBackupdrService) managementServers() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(backupdr.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := backupdr.NewClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListManagementServers(ctx, &backupdrpb.ListManagementServersRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		server, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		networks := make([]any, 0, len(server.Networks))
		for _, n := range server.Networks {
			d, err := protoToDict(n)
			if err != nil {
				return nil, err
			}
			networks = append(networks, d)
		}

		managementUri, err := protoToDict(server.ManagementUri)
		if err != nil {
			return nil, err
		}

		mqlServer, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService.managementServer", map[string]*llx.RawData{
			"name":           llx.StringData(server.Name),
			"description":    llx.StringData(server.Description),
			"state":          llx.StringData(server.State.String()),
			"type":           llx.StringData(server.Type.String()),
			"networks":       llx.ArrayData(networks, types.Dict),
			"managementUri":  llx.DictData(managementUri),
			"oauth2ClientId": llx.StringData(server.Oauth2ClientId),
			"satisfiesPzs":   llx.BoolData(server.GetSatisfiesPzs().GetValue()),
			"etag":           llx.StringData(server.Etag),
			"labels":         llx.MapData(convert.MapToInterfaceMap(server.Labels), types.String),
			"createdAt":      llx.TimeDataPtr(timestampAsTimePtr(server.CreateTime)),
			"updatedAt":      llx.TimeDataPtr(timestampAsTimePtr(server.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlServer)
	}
	return res, nil
}

func (g *mqlGcpProjectBackupdrServiceManagementServer) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectBackupdrService) backupVaults() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(backupdr.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := backupdr.NewClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListBackupVaults(ctx, &backupdrpb.ListBackupVaultsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		vault, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		mqlVault, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService.backupVault", map[string]*llx.RawData{
			"name":                                  llx.StringData(vault.Name),
			"description":                           llx.StringData(vault.GetDescription()),
			"state":                                  llx.StringData(vault.State.String()),
			"backupMinimumEnforcedRetentionDuration": llx.StringData(vault.BackupMinimumEnforcedRetentionDuration.String()),
			"deletable":                              llx.BoolData(vault.GetDeletable()),
			"etag":                                   llx.StringData(vault.GetEtag()),
			"effectiveTime":                          llx.TimeDataPtr(timestampAsTimePtr(vault.EffectiveTime)),
			"backupCount":                            llx.IntData(vault.GetBackupCount()),
			"serviceAccount":                         llx.StringData(vault.ServiceAccount),
			"totalStoredBytes":                       llx.IntData(vault.GetTotalStoredBytes()),
			"accessRestriction":                      llx.StringData(vault.AccessRestriction.String()),
			"annotations":                            llx.MapData(convert.MapToInterfaceMap(vault.Annotations), types.String),
			"labels":                                 llx.MapData(convert.MapToInterfaceMap(vault.Labels), types.String),
			"createdAt":                              llx.TimeDataPtr(timestampAsTimePtr(vault.CreateTime)),
			"updatedAt":                              llx.TimeDataPtr(timestampAsTimePtr(vault.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlVault)
	}
	return res, nil
}

func (g *mqlGcpProjectBackupdrServiceBackupVault) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectBackupdrServiceBackupVault) dataSources() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	vaultName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(backupdr.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := backupdr.NewClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListDataSources(ctx, &backupdrpb.ListDataSourcesRequest{
		Parent: vaultName,
	})

	var res []any
	for {
		ds, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		gcpResource, err := protoToDict(ds.GetDataSourceGcpResource())
		if err != nil {
			return nil, err
		}
		backupApplianceApp, err := protoToDict(ds.GetDataSourceBackupApplianceApplication())
		if err != nil {
			return nil, err
		}

		mqlDs, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService.dataSource", map[string]*llx.RawData{
			"name":                                  llx.StringData(ds.Name),
			"state":                                 llx.StringData(ds.State.String()),
			"labels":                                llx.MapData(convert.MapToInterfaceMap(ds.Labels), types.String),
			"dataSourceGcpResource":                 llx.DictData(gcpResource),
			"dataSourceBackupApplianceApplication":  llx.DictData(backupApplianceApp),
			"totalStoredBytes":                      llx.IntData(ds.GetTotalStoredBytes()),
			"backupCount":                           llx.IntData(ds.GetBackupCount()),
			"etag":                                  llx.StringData(ds.GetEtag()),
			"configState":                           llx.StringData(ds.ConfigState.String()),
			"createdAt":                             llx.TimeDataPtr(timestampAsTimePtr(ds.CreateTime)),
			"updatedAt":                             llx.TimeDataPtr(timestampAsTimePtr(ds.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDs)
	}
	return res, nil
}

func (g *mqlGcpProjectBackupdrServiceDataSource) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectBackupdrService) backupPlans() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(backupdr.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := backupdr.NewClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListBackupPlans(ctx, &backupdrpb.ListBackupPlansRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		plan, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		backupRules := make([]any, 0, len(plan.BackupRules))
		for _, rule := range plan.BackupRules {
			d, err := protoToDict(rule)
			if err != nil {
				return nil, err
			}
			backupRules = append(backupRules, d)
		}

		mqlPlan, err := CreateResource(g.MqlRuntime, "gcp.project.backupdrService.backupPlan", map[string]*llx.RawData{
			"name":                    llx.StringData(plan.Name),
			"description":             llx.StringData(plan.Description),
			"state":                   llx.StringData(plan.State.String()),
			"resourceType":            llx.StringData(plan.ResourceType),
			"backupVault":             llx.StringData(plan.BackupVault),
			"backupVaultServiceAccount": llx.StringData(plan.BackupVaultServiceAccount),
			"labels":                  llx.MapData(convert.MapToInterfaceMap(plan.Labels), types.String),
			"backupRules":             llx.ArrayData(backupRules, types.Dict),
			"etag":                    llx.StringData(plan.Etag),
			"createdAt":               llx.TimeDataPtr(timestampAsTimePtr(plan.CreateTime)),
			"updatedAt":               llx.TimeDataPtr(timestampAsTimePtr(plan.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPlan)
	}
	return res, nil
}

func (g *mqlGcpProjectBackupdrServiceBackupPlan) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

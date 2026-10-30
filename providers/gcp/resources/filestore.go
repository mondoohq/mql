// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	filestore "cloud.google.com/go/filestore/apiv1"
	"cloud.google.com/go/filestore/apiv1/filestorepb"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type mqlGcpProjectFilestoreServiceInstanceInternal struct {
	cacheKmsKeyName string
}

func (g *mqlGcpProject) filestore() (*mqlGcpProjectFilestoreService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.filestoreService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectFilestoreService), nil
}

// Direct construction (e.g. `gcp.project.filestoreService.instances`) bypasses
// gcp.project.filestore(), leaving projectId empty so instances() raises a
// malformed RESOURCE_PROJECT_INVALID instead of returning the proper
// SERVICE_DISABLED message. Delegate to the parent project accessor.
func initGcpProjectFilestoreService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["projectId"]; ok {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	proj, err := NewResource(runtime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(conn.ResourceID()),
	})
	if err != nil {
		return nil, nil, err
	}
	svc, err := proj.(*mqlGcpProject).filestore()
	if err != nil {
		return nil, nil, err
	}
	return nil, svc, nil
}

func (g *mqlGcpProjectFilestoreService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/filestoreService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectFilestoreService) instances() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(filestore.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := filestore.NewCloudFilestoreManagerClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListInstances(ctx, &filestorepb.ListInstancesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		instance, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		fileShares := make([]any, 0, len(instance.FileShares))
		for _, fs := range instance.FileShares {
			nfsExportOptions := make([]any, 0, len(fs.NfsExportOptions))
			for _, opt := range fs.NfsExportOptions {
				nfsExportOptions = append(nfsExportOptions, map[string]any{
					"ipRanges":   convert.SliceAnyToInterface(opt.IpRanges),
					"accessMode": opt.AccessMode.String(),
					"squashMode": opt.SquashMode.String(),
					"anonUid":    opt.AnonUid,
					"anonGid":    opt.AnonGid,
				})
			}

			mqlFs, err := CreateResource(g.MqlRuntime, "gcp.project.filestoreService.instance.fileShare", map[string]*llx.RawData{
				"id":               llx.StringData(fmt.Sprintf("%s/fileShares/%s", instance.Name, fs.Name)),
				"name":             llx.StringData(fs.Name),
				"capacityGb":       llx.IntData(fs.CapacityGb),
				"nfsExportOptions": llx.ArrayData(nfsExportOptions, types.Dict),
			})
			if err != nil {
				return nil, err
			}
			fileShares = append(fileShares, mqlFs)
		}

		networks := make([]any, 0, len(instance.Networks))
		for _, net := range instance.Networks {
			modes := make([]any, 0, len(net.Modes))
			for _, m := range net.Modes {
				modes = append(modes, m.String())
			}
			mqlNet, err := CreateResource(g.MqlRuntime, "gcp.project.filestoreService.instance.network", map[string]*llx.RawData{
				"id":              llx.StringData(fmt.Sprintf("%s/networks/%s", instance.Name, net.Network)),
				"network":         llx.StringData(net.Network),
				"modes":           llx.ArrayData(modes, types.String),
				"ipAddresses":     llx.ArrayData(convert.SliceAnyToInterface(net.IpAddresses), types.String),
				"reservedIpRange": llx.StringData(net.ReservedIpRange),
				"connectMode":     llx.StringData(net.ConnectMode.String()),
			})
			if err != nil {
				return nil, err
			}
			networks = append(networks, mqlNet)
		}

		var satisfiesPzs *bool
		if instance.SatisfiesPzs != nil {
			v := instance.SatisfiesPzs.GetValue()
			satisfiesPzs = &v
		}

		mqlInstance, err := CreateResource(g.MqlRuntime, "gcp.project.filestoreService.instance", map[string]*llx.RawData{
			"projectId":                 llx.StringData(projectId),
			"name":                      llx.StringData(instance.Name),
			"description":               llx.StringData(instance.Description),
			"tier":                      llx.StringData(instance.Tier.String()),
			"state":                     llx.StringData(instance.State.String()),
			"createTime":                llx.TimeDataPtr(timestampAsTimePtr(instance.CreateTime)),
			"labels":                    llx.MapData(convert.MapToInterfaceMap(instance.Labels), types.String),
			"fileShares":                llx.ArrayData(fileShares, types.Resource("gcp.project.filestoreService.instance.fileShare")),
			"networks":                  llx.ArrayData(networks, types.Resource("gcp.project.filestoreService.instance.network")),
			"satisfiesPzi":              llx.BoolData(instance.SatisfiesPzi),
			"satisfiesPzs":              llx.BoolDataPtr(satisfiesPzs),
			"deletionProtectionEnabled": llx.BoolData(instance.DeletionProtectionEnabled),
			"protocol":                  llx.StringData(instance.Protocol.String()),
		})
		if err != nil {
			return nil, err
		}
		mqlRef := mqlInstance.(*mqlGcpProjectFilestoreServiceInstance)
		mqlRef.cacheKmsKeyName = instance.KmsKeyName
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (g *mqlGcpProjectFilestoreServiceInstance) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/filestoreService.instance/%s", g.ProjectId.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectFilestoreServiceInstance) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(g.MqlRuntime, &g.KmsKey, g.cacheKmsKeyName)
}

func (g *mqlGcpProjectFilestoreServiceInstanceFileShare) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectFilestoreServiceInstanceNetwork) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	filestore "cloud.google.com/go/filestore/apiv1"
	"cloud.google.com/go/filestore/apiv1/filestorepb"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/gcp/connection"
	"go.mondoo.com/mql/v13/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

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
	client, err := filestore.NewCloudFilestoreManagerClient(ctx, option.WithCredentials(creds))
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
		for i, fs := range instance.FileShares {
			mqlFs, err := CreateResource(g.MqlRuntime, "gcp.project.filestoreService.instance.fileShare", map[string]*llx.RawData{
				"id":         llx.StringData(fmt.Sprintf("%s/fileShares/%d", instance.Name, i)),
				"name":       llx.StringData(fs.Name),
				"capacityGb": llx.IntData(fs.CapacityGb),
			})
			if err != nil {
				return nil, err
			}
			fileShares = append(fileShares, mqlFs)
		}

		networks := make([]any, 0, len(instance.Networks))
		for i, net := range instance.Networks {
			modes := make([]any, 0, len(net.Modes))
			for _, m := range net.Modes {
				modes = append(modes, m.String())
			}
			mqlNet, err := CreateResource(g.MqlRuntime, "gcp.project.filestoreService.instance.network", map[string]*llx.RawData{
				"id":              llx.StringData(fmt.Sprintf("%s/networks/%d", instance.Name, i)),
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
			"createTime":                llx.TimeData(instance.CreateTime.AsTime()),
			"labels":                    llx.MapData(convert.MapToInterfaceMap(instance.Labels), types.String),
			"fileShares":                llx.ArrayData(fileShares, types.Resource("gcp.project.filestoreService.instance.fileShare")),
			"networks":                  llx.ArrayData(networks, types.Resource("gcp.project.filestoreService.instance.network")),
			"kmsKeyName":                llx.StringData(instance.KmsKeyName),
			"satisfiesPzi":              llx.BoolData(instance.SatisfiesPzi),
			"satisfiesPzs":              llx.BoolDataPtr(satisfiesPzs),
			"deletionProtectionEnabled": llx.BoolData(instance.DeletionProtectionEnabled),
			"protocol":                  llx.StringData(instance.Protocol.String()),
		})
		if err != nil {
			return nil, err
		}
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

func (g *mqlGcpProjectFilestoreServiceInstanceFileShare) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectFilestoreServiceInstanceNetwork) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

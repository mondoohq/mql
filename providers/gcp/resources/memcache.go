// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	memcache "cloud.google.com/go/memcache/apiv1"
	"cloud.google.com/go/memcache/apiv1/memcachepb"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpProject) memcache() (*mqlGcpProjectMemcacheService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.memcacheService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectMemcacheService), nil
}

func initGcpProjectMemcacheService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (g *mqlGcpProjectMemcacheService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/memcacheService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectMemcacheServiceInstance) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/memcacheService/instance/%s", g.ProjectId.Data, g.Name.Data), nil
}

func initGcpProjectMemcacheServiceInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		args = make(map[string]*llx.RawData)
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
			args["location"] = llx.StringData(ids.region)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New(`gcp.project.memcacheService.instance requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.memcacheService.instance requires a non-empty "name" argument`)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	// Accept either the full resource path or a short name + location from
	// the asset-identifier-driven discovery path.
	var fullName, projectId string
	if strings.HasPrefix(name, "projects/") {
		fullName = name
		projectId = parseProjectFromPath(name)
	} else {
		locRaw := args["location"]
		projRaw := args["projectId"]
		if locRaw == nil || projRaw == nil {
			return nil, nil, errors.New("memcache instance init: projectId and location required when name is not a full resource path")
		}
		projectId, _ = projRaw.Value.(string)
		location, _ := locRaw.Value.(string)
		fullName = fmt.Sprintf("projects/%s/locations/%s/instances/%s", projectId, location, name)
	}

	// Ask whether the API is on before paying for a Get that cannot succeed
	// without it. The answer is memoized per project, so this is free after the
	// first caller.
	if enabled, err := serviceEnabledForInit(runtime, projectId, service_memcache); err != nil {
		return nil, nil, err
	} else if !enabled {
		return nil, nil, errors.New("Cloud Memorystore for Memcached API is not enabled on project " + projectId)
	}

	creds, err := conn.Credentials(memcache.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	client, err := memcache.NewCloudMemcacheClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	inst, err := client.GetInstance(ctx, &memcachepb.GetInstanceRequest{Name: fullName})
	if err != nil {
		return nil, nil, err
	}

	res, err := mqlMemcacheInstanceFromProto(runtime, projectId, inst)
	if err != nil {
		return nil, nil, err
	}
	delete(args, "location")
	return args, res, nil
}

func (g *mqlGcpProjectMemcacheServiceInstanceNode) id() (string, error) {
	if g.InstanceName.Error != nil {
		return "", g.InstanceName.Error
	}
	if g.NodeId.Error != nil {
		return "", g.NodeId.Error
	}
	return fmt.Sprintf("%s/node/%s", g.InstanceName.Data, g.NodeId.Data), nil
}

func (g *mqlGcpProjectMemcacheServiceInstanceParameters) id() (string, error) {
	if g.InstanceName.Error != nil {
		return "", g.InstanceName.Error
	}
	return fmt.Sprintf("%s/parameters", g.InstanceName.Data), nil
}

func (g *mqlGcpProjectMemcacheServiceInstanceNodeParameters) id() (string, error) {
	if g.InstanceName.Error != nil {
		return "", g.InstanceName.Error
	}
	if g.NodeId.Error != nil {
		return "", g.NodeId.Error
	}
	return fmt.Sprintf("%s/node/%s/parameters", g.InstanceName.Data, g.NodeId.Data), nil
}

type mqlGcpProjectMemcacheServiceInstanceInternal struct {
	cacheAuthorizedNetwork string
}

func (g *mqlGcpProjectMemcacheServiceInstance) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.cacheAuthorizedNetwork == "" {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return getNetworkByUrl(g.cacheAuthorizedNetwork, g.MqlRuntime)
}

func (g *mqlGcpProjectMemcacheServiceInstance) managedBy() (string, error) {
	return managedByFromLabels(&g.Labels)
}

func (g *mqlGcpProjectMemcacheService) instances() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(memcache.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := memcache.NewCloudMemcacheClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListInstances(ctx, &memcachepb.ListInstancesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		inst, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		mqlInst, err := mqlMemcacheInstanceFromProto(g.MqlRuntime, projectId, inst)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInst)
	}

	return res, nil
}

func mqlMemcacheInstanceFromProto(runtime *plugin.Runtime, projectId string, inst *memcachepb.Instance) (*mqlGcpProjectMemcacheServiceInstance, error) {
	var nodeCpu, nodeMem int64
	if inst.NodeConfig != nil {
		nodeCpu = int64(inst.NodeConfig.CpuCount)
		nodeMem = int64(inst.NodeConfig.MemorySizeMb)
	}

	params, err := newMqlMemcacheParameters(runtime, projectId, inst.Name, inst.Parameters)
	if err != nil {
		return nil, err
	}

	maintenancePolicy, err := protoToDict(inst.MaintenancePolicy)
	if err != nil {
		return nil, err
	}
	maintenanceSchedule, err := protoToDict(inst.MaintenanceSchedule)
	if err != nil {
		return nil, err
	}

	var createTime, updateTime *llx.RawData
	if inst.CreateTime != nil {
		createTime = llx.TimeData(inst.CreateTime.AsTime())
	} else {
		createTime = llx.NilData
	}
	if inst.UpdateTime != nil {
		updateTime = llx.TimeData(inst.UpdateTime.AsTime())
	} else {
		updateTime = llx.NilData
	}

	instanceMessages := make([]any, 0, len(inst.InstanceMessages))
	for _, msg := range inst.InstanceMessages {
		if msg == nil {
			continue
		}
		instanceMessages = append(instanceMessages, map[string]any{
			"code":    msg.Code.String(),
			"message": msg.Message,
		})
	}

	nodes, err := buildMemcacheNodes(runtime, projectId, inst.Name, inst.MemcacheNodes)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "gcp.project.memcacheService.instance", map[string]*llx.RawData{
		"projectId":           llx.StringData(projectId),
		"name":                llx.StringData(inst.Name),
		"displayName":         llx.StringData(inst.DisplayName),
		"labels":              llx.MapData(convert.MapToInterfaceMap(inst.Labels), types.String),
		"zones":               llx.ArrayData(convert.SliceAnyToInterface(inst.Zones), types.String),
		"nodeCount":           llx.IntData(int64(inst.NodeCount)),
		"nodeCpuCount":        llx.IntData(nodeCpu),
		"nodeMemorySizeMb":    llx.IntData(nodeMem),
		"memcacheVersion":     llx.StringData(inst.MemcacheVersion.String()),
		"memcacheFullVersion": llx.StringData(inst.MemcacheFullVersion),
		"parameters":          llx.ResourceData(params, "gcp.project.memcacheService.instance.parameters"),
		"state":               llx.StringData(inst.State.String()),
		"discoveryEndpoint":   llx.StringData(inst.DiscoveryEndpoint),
		"instanceMessages":    llx.ArrayData(instanceMessages, types.Dict),
		"maintenancePolicy":   llx.DictData(maintenancePolicy),
		"maintenanceSchedule": llx.DictData(maintenanceSchedule),
		"createTime":          createTime,
		"updateTime":          updateTime,
		"nodes":               llx.ArrayData(nodes, types.Resource("gcp.project.memcacheService.instance.node")),
	})
	if err != nil {
		return nil, err
	}
	mqlInstance := res.(*mqlGcpProjectMemcacheServiceInstance)
	mqlInstance.cacheAuthorizedNetwork = inst.AuthorizedNetwork
	return mqlInstance, nil
}

func newMqlMemcacheParameters(runtime *plugin.Runtime, projectId, instanceName string, p *memcachepb.MemcacheParameters) (*mqlGcpProjectMemcacheServiceInstanceParameters, error) {
	id := ""
	var params map[string]any
	if p != nil {
		id = p.Id
		params = convert.MapToInterfaceMap(p.Params)
	}
	res, err := CreateResource(runtime, "gcp.project.memcacheService.instance.parameters", map[string]*llx.RawData{
		"projectId":    llx.StringData(projectId),
		"instanceName": llx.StringData(instanceName),
		"id":           llx.StringData(id),
		"params":       llx.MapData(params, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectMemcacheServiceInstanceParameters), nil
}

func newMqlMemcacheNodeParameters(runtime *plugin.Runtime, projectId, instanceName, nodeId string, p *memcachepb.MemcacheParameters) (*mqlGcpProjectMemcacheServiceInstanceNodeParameters, error) {
	id := ""
	var params map[string]any
	if p != nil {
		id = p.Id
		params = convert.MapToInterfaceMap(p.Params)
	}
	res, err := CreateResource(runtime, "gcp.project.memcacheService.instance.node.parameters", map[string]*llx.RawData{
		"projectId":    llx.StringData(projectId),
		"instanceName": llx.StringData(instanceName),
		"nodeId":       llx.StringData(nodeId),
		"id":           llx.StringData(id),
		"params":       llx.MapData(params, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectMemcacheServiceInstanceNodeParameters), nil
}

func buildMemcacheNodes(runtime *plugin.Runtime, projectId, instanceName string, nodes []*memcachepb.Instance_Node) ([]any, error) {
	res := make([]any, 0, len(nodes))
	for _, n := range nodes {
		if n == nil {
			continue
		}
		params, err := newMqlMemcacheNodeParameters(runtime, projectId, instanceName, n.NodeId, n.Parameters)
		if err != nil {
			return nil, err
		}
		mqlNode, err := CreateResource(runtime, "gcp.project.memcacheService.instance.node", map[string]*llx.RawData{
			"projectId":    llx.StringData(projectId),
			"instanceName": llx.StringData(instanceName),
			"nodeId":       llx.StringData(n.NodeId),
			"zone":         llx.StringData(n.Zone),
			"host":         llx.StringData(n.Host),
			"port":         llx.IntData(int64(n.Port)),
			"state":        llx.StringData(n.State.String()),
			"parameters":   llx.ResourceData(params, "gcp.project.memcacheService.instance.node.parameters"),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlNode)
	}
	return res, nil
}

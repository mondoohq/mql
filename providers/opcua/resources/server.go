// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/opcua/connection"
)

func initOpcuaServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.OpcuaConnection)
	client := conn.Client()

	ctx := context.Background()
	n := client.Node(ua.NewNumericNodeID(0, id.Server))
	ndef, err := fetchNodeInfo(ctx, n)
	if err != nil {
		return nil, nil, err
	}

	// create server resource
	serverNode, err := newMqlOpcuaNodeResource(runtime, ndef)
	if err != nil {
		return nil, nil, err
	}
	args["node"] = llx.ResourceData(serverNode, "opcua.node")

	// server status variable of server
	nodeID := ua.NewNumericNodeID(0, id.Server_ServerStatus)
	v, err := client.Node(nodeID).Value(ctx)
	switch {
	case err != nil:
		return nil, nil, err
	case v == nil:
		args["buildInfo"] = llx.NilData
		args["currentTime"] = llx.NilData
		args["startTime"] = llx.NilData
		args["state"] = llx.StringData("")
	default:
		res := v.Value()
		extensionObject := res.(*ua.ExtensionObject)
		serverStatus := extensionObject.Value.(*ua.ServerStatusDataType)

		buildInfo, _ := convert.JsonToDict(serverStatus.BuildInfo)
		args["buildInfo"] = llx.DictData(buildInfo)
		args["currentTime"] = llx.TimeData(serverStatus.CurrentTime)
		args["startTime"] = llx.TimeData(serverStatus.StartTime)
		args["state"] = llx.StringData(serverStatus.State.String())
	}

	return args, nil, nil
}

func (o *mqlOpcuaServer) id() (string, error) {
	if o.Node.Error != nil {
		return "", o.Node.Error
	}
	node := o.Node.Data
	return "opcua.server/" + node.Id.Data, nil
}

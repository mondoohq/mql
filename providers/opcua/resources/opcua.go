// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"go.mondoo.com/mql/providers/opcua/connection"
)

func (o *mqlOpcua) id() (string, error) {
	return "opcua", nil
}

func (o *mqlOpcua) root() (*mqlOpcuaNode, error) {
	conn := o.MqlRuntime.Connection.(*connection.OpcuaConnection)
	client := conn.Client()

	ctx := context.Background()
	n := client.Node(ua.NewNumericNodeID(0, id.RootFolder))
	ndef, err := fetchNodeInfo(ctx, n)
	if err != nil {
		return nil, err
	}
	return newMqlOpcuaNodeResource(o.MqlRuntime, ndef)
}

func resolve(ctx context.Context, meta *nodeMeta) ([]*nodeMeta, error) {
	nodeList := []*nodeMeta{}

	for i := range meta.Organizes {
		child := meta.Organizes[i]
		nInfoChild, err := fetchNodeInfo(ctx, child)
		if err != nil {
			return nil, err
		}
		nodeList = append(nodeList, nInfoChild)
		resolved, err := resolve(ctx, nInfoChild)
		if err != nil {
			return nil, err
		}
		nodeList = append(nodeList, resolved...)
	}

	for i := range meta.Properties {
		child := meta.Properties[i]
		nInfoChild, err := fetchNodeInfo(ctx, child)
		if err != nil {
			return nil, err
		}
		nodeList = append(nodeList, nInfoChild)
		resolved, err := resolve(ctx, nInfoChild)
		if err != nil {
			return nil, err
		}
		nodeList = append(nodeList, resolved...)
	}

	for i := range meta.Components {
		child := meta.Components[i]
		nInfoChild, err := fetchNodeInfo(ctx, child)
		if err != nil {
			return nil, err
		}
		nodeList = append(nodeList, nInfoChild)
		resolved, err := resolve(ctx, nInfoChild)
		if err != nil {
			return nil, err
		}
		nodeList = append(nodeList, resolved...)
	}

	return nodeList, nil
}

func (o *mqlOpcua) nodes() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OpcuaConnection)
	client := conn.Client()

	ctx := context.Background()
	n := client.Node(ua.NewNumericNodeID(0, id.RootFolder))

	nodeList := []*nodeMeta{}
	nInfo, err := fetchNodeInfo(ctx, n)
	if err != nil {
		return nil, err
	}
	nodeList = append(nodeList, nInfo)
	resolved, err := resolve(ctx, nInfo)
	if err != nil {
		return nil, err
	}
	nodeList = append(nodeList, resolved...)

	// convert list to interface
	res := []any{}
	for i := range nodeList {
		entry, err := newMqlOpcuaNodeResource(o.MqlRuntime, nodeList[i])
		if err != nil {
			return nil, err
		}
		res = append(res, entry)
	}
	return res, nil
}

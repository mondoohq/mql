// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/errors"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type nodeMeta struct {
	NodeID      *ua.NodeID
	NodeClass   ua.NodeClass
	BrowseName  string
	Description string
	AccessLevel ua.AccessLevelType
	Path        string
	DataType    string
	Writable    bool
	Unit        string
	Scale       string
	Min         string
	Max         string
	Components  []*opcua.Node
	Organizes   []*opcua.Node
	Properties  []*opcua.Node
}

func fetchNodeInfo(ctx context.Context, n *opcua.Node) (*nodeMeta, error) {
	attrs, err := n.Attributes(ctx, ua.AttributeIDNodeClass, ua.AttributeIDBrowseName, ua.AttributeIDDescription, ua.AttributeIDAccessLevel, ua.AttributeIDDataType)
	if err != nil {
		return nil, err
	}

	def := nodeMeta{
		NodeID: n.ID,
	}

	switch err := attrs[0].Status; err {
	case ua.StatusOK:
		def.NodeClass = ua.NodeClass(attrs[0].Value.Int())
	default:
		return nil, err
	}

	switch err := attrs[0].Status; err {
	case ua.StatusOK:
		def.NodeClass = ua.NodeClass(attrs[0].Value.Int())
	default:
		return nil, err
	}

	switch err := attrs[1].Status; err {
	case ua.StatusOK:
		def.BrowseName = attrs[1].Value.String()
	default:
		return nil, err
	}

	switch err := attrs[2].Status; err {
	case ua.StatusOK:
		def.Description = attrs[2].Value.String()
	case ua.StatusBadAttributeIDInvalid:
		// ignore
	default:
		return nil, err
	}

	switch err := attrs[3].Status; err {
	case ua.StatusOK:
		def.AccessLevel = ua.AccessLevelType(attrs[3].Value.Int())
		def.Writable = def.AccessLevel&ua.AccessLevelTypeCurrentWrite == ua.AccessLevelTypeCurrentWrite
	case ua.StatusBadAttributeIDInvalid:
		// ignore
	default:
		return nil, err
	}

	switch err := attrs[4].Status; err {
	case ua.StatusOK:
		switch v := attrs[4].Value.NodeID().IntID(); v {
		case id.DateTime:
			def.DataType = "time.Time"
		case id.Boolean:
			def.DataType = "bool"
		case id.SByte:
			def.DataType = "int8"
		case id.Int16:
			def.DataType = "int16"
		case id.Int32:
			def.DataType = "int32"
		case id.Byte:
			def.DataType = "byte"
		case id.UInt16:
			def.DataType = "uint16"
		case id.UInt32:
			def.DataType = "uint32"
		case id.UtcTime:
			def.DataType = "time.Time"
		case id.String:
			def.DataType = "string"
		case id.Float:
			def.DataType = "float32"
		case id.Double:
			def.DataType = "float64"
		default:
			def.DataType = attrs[4].Value.NodeID().String()
		}
	case ua.StatusBadAttributeIDInvalid:
		// ignore
	default:
		return nil, err
	}

	// TODO: set path
	fetchReference := func(refType uint32) ([]*opcua.Node, error) {
		return n.ReferencedNodes(ctx, refType, ua.BrowseDirectionForward, ua.NodeClassAll, true)
	}

	if componentRefs, err := fetchReference(id.HasComponent); err != nil {
		return nil, err
	} else {
		def.Components = append(def.Components, componentRefs...)
	}

	if componentRefs, err := fetchReference(id.Organizes); err != nil {
		return nil, err
	} else {
		def.Organizes = append(def.Organizes, componentRefs...)
	}

	if componentRefs, err := fetchReference(id.HasProperty); err != nil {
		return nil, err
	} else {
		def.Properties = append(def.Properties, componentRefs...)
	}

	return &def, nil
}

func newMqlOpcuaNodeResource(runtime *plugin.Runtime, ndef *nodeMeta) (*mqlOpcuaNode, error) {
	res, err := CreateResource(runtime, "opcua.node", map[string]*llx.RawData{
		"id":          llx.StringData(ndef.NodeID.String()),
		"name":        llx.StringData(ndef.BrowseName),
		"class":       llx.StringData(ndef.NodeClass.String()),
		"description": llx.StringData(ndef.Description),
		"writeable":   llx.BoolData(ndef.Writable),
		"dataType":    llx.StringData(ndef.DataType),
		"min":         llx.StringData(ndef.Min),
		"max":         llx.StringData(ndef.Max),
		"unit":        llx.StringData(ndef.Unit),
		"accessLevel": llx.StringData(ndef.AccessLevel.String()),
	})
	if err != nil {
		return nil, err
	}

	r := res.(*mqlOpcuaNode)
	r.object = ndef
	return r, nil
}

type mqlOpcuaNodeInternal struct {
	object *nodeMeta
}

func (o *mqlOpcuaNode) id() (string, error) {
	return "opcua.node/" + o.Id.Data, o.Id.Error
}

func (o *mqlOpcuaNode) namespace() (*mqlOpcuaNamespace, error) {
	nodeDef := o.object
	if nodeDef == nil {
		return nil, errors.New("could not fetch properties")
	}

	obj, err := CreateResource(o.MqlRuntime, "opcua", nil)
	if err != nil {
		return nil, err
	}
	mqlOpcua := obj.(*mqlOpcua)

	namespaces := mqlOpcua.GetNamespaces()
	if namespaces.Error != nil {
		return nil, namespaces.Error
	}

	entry := namespaces.Data[nodeDef.NodeID.Namespace()]
	return entry.(*mqlOpcuaNamespace), nil
}

func (o *mqlOpcuaNode) properties() ([]any, error) {
	nodeDef := o.object
	if nodeDef == nil {
		return nil, errors.New("could not fetch properties")
	}

	ctx := context.Background()
	results := []any{}
	for i := range nodeDef.Properties {
		def := nodeDef.Properties[i]
		n, err := fetchNodeInfo(ctx, def)
		if err != nil {
			return nil, err
		}
		r, err := newMqlOpcuaNodeResource(o.MqlRuntime, n)
		if err != nil {
			return nil, err
		}
		results = append(results, r)
	}

	return results, nil
}

func (o *mqlOpcuaNode) components() ([]any, error) {
	nodeDef := o.object
	if nodeDef == nil {
		return nil, errors.New("could not fetch properties")
	}

	ctx := context.Background()
	results := []any{}
	for i := range nodeDef.Components {
		def := nodeDef.Components[i]
		n, err := fetchNodeInfo(ctx, def)
		if err != nil {
			return nil, err
		}
		r, err := newMqlOpcuaNodeResource(o.MqlRuntime, n)
		if err != nil {
			return nil, err
		}
		results = append(results, r)
	}

	return results, nil
}

func (o *mqlOpcuaNode) organizes() ([]any, error) {
	nodeDef := o.object
	if nodeDef == nil {
		return nil, errors.New("could not fetch properties")
	}

	ctx := context.Background()
	results := []any{}
	for i := range nodeDef.Organizes {
		def := nodeDef.Organizes[i]
		n, err := fetchNodeInfo(ctx, def)
		if err != nil {
			return nil, err
		}
		r, err := newMqlOpcuaNodeResource(o.MqlRuntime, n)
		if err != nil {
			return nil, err
		}
		results = append(results, r)
	}

	return results, nil
}

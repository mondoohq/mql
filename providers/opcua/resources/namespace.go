// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/opcua/connection"
)

func (o *mqlOpcuaNamespace) id() (string, error) {
	if o.Id.Error != nil {
		return "", o.Id.Error
	}
	s := strconv.FormatInt(o.Id.Data, 10)
	return "opcua.namespace/" + s, nil
}

// https://reference.opcfoundation.org/specs/OPC-10000-100/11
func (o *mqlOpcua) namespaces() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OpcuaConnection)
	client := conn.Client()

	namespaces := client.Namespaces()
	resList := []any{}
	for i := range namespaces {
		res, err := newMqlOpcuaNamespaceResource(o.MqlRuntime, int64(i), namespaces[i])
		if err != nil {
			return nil, err
		}
		resList = append(resList, res)
	}
	return resList, nil
}

func newMqlOpcuaNamespaceResource(runtime *plugin.Runtime, id int64, name string) (any, error) {
	return CreateResource(runtime, "opcua.namespace", map[string]*llx.RawData{
		"id":   llx.IntData(id),
		"name": llx.StringData(name),
	})
}

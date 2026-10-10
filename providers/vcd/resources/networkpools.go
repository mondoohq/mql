// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/vmware/go-vcloud-director/v3/types/v56"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vcd/connection"
)

// https://developer.broadcom.com/xapis/vmware-cloud-director-api/latest/doc/types/QueryResultNetworkPoolRecordType.html
func (v *mqlVcd) networkPools() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VcdConnection)
	client := conn.Client()

	networkPoolList, err := client.QueryNetworkPools()
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range networkPoolList {
		entry, err := newMqlVcdNetworkPool(v.MqlRuntime, networkPoolList[i])
		if err != nil {
			return nil, err
		}
		list = append(list, entry)
	}

	return list, nil
}

func newMqlVcdNetworkPool(runtime *plugin.Runtime, networkPool *types.QueryResultNetworkPoolRecordType) (any, error) {
	return CreateResource(runtime, "vcd.networkPool", map[string]*llx.RawData{
		"name":            llx.StringData(networkPool.Name),
		"isBusy":          llx.BoolData(networkPool.IsBusy),
		"networkPoolType": llx.IntData(int64(networkPool.NetworkPoolType)),
	})
}

func (o *mqlVcdNetworkPool) id() (string, error) {
	return "vcd.networkPool/" + o.Name.Data, o.Name.Error
}

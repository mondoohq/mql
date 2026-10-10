// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/vmware/go-vcloud-director/v3/govcd"
	"github.com/vmware/go-vcloud-director/v3/types/v56"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vcd/connection"
)

// https://developer.broadcom.com/xapis/vmware-cloud-director-api/latest/doc/types/VimServerType.html
func (v *mqlVcd) serverInstances() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VcdConnection)
	client := conn.Client()

	vdcList, err := govcd.QueryVirtualCenters(client, "")
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range vdcList {
		entry, err := newMqlVcdServerInstance(v.MqlRuntime, vdcList[i])
		if err != nil {
			return nil, err
		}
		list = append(list, entry)
	}

	return list, nil
}

func newMqlVcdServerInstance(runtime *plugin.Runtime, vcdProvider *types.QueryResultVirtualCenterRecordType) (any, error) {
	return CreateResource(runtime, "vcd.serverInstance", map[string]*llx.RawData{
		"name":          llx.StringData(vcdProvider.Name),
		"isBusy":        llx.BoolData(vcdProvider.IsBusy),
		"isEnabled":     llx.BoolData(vcdProvider.IsEnabled),
		"isSupported":   llx.BoolData(vcdProvider.IsEnabled),
		"listenerState": llx.StringData(vcdProvider.ListenerState),
		"status":        llx.StringData(vcdProvider.Status),
		"userName":      llx.StringData(vcdProvider.UserName),
		"vcVersion":     llx.StringData(vcdProvider.VcVersion),
		"uuid":          llx.StringData(vcdProvider.UUID),
		"vsmIP":         llx.StringData(vcdProvider.VsmIP),
	})
}

func (o *mqlVcdServerInstance) id() (string, error) {
	return "vcd.serverInstance/" + o.Name.Data, o.Name.Error
}

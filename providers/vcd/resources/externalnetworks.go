// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/vmware/go-vcloud-director/v3/govcd"
	"github.com/vmware/go-vcloud-director/v3/types/v56"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/vcd/connection"
)

func (v *mqlVcd) externalNetworks() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VcdConnection)
	client := conn.Client()

	externalNetworkList, err := client.GetExternalNetworks()
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range externalNetworkList.ExternalNetworkReference {
		entry, err := newMqlVcdExternalNetwork(v.MqlRuntime, externalNetworkList.ExternalNetworkReference[i])
		if err != nil {
			return nil, err
		}
		list = append(list, entry)
	}

	return list, nil
}

func newMqlVcdExternalNetwork(runtime *plugin.Runtime, networkPool *types.ExternalNetworkReference) (any, error) {
	return CreateResource(runtime, "vcd.externalNetwork", map[string]*llx.RawData{
		"__id": llx.StringData("vcd.externalNetwork/" + networkPool.Name),
		"name": llx.StringData(networkPool.Name),
	})
}

type mqlVcdExternalNetworkInternal struct {
	externalNetwork *govcd.ExternalNetwork
}

func (v *mqlVcdExternalNetwork) getData() (*types.ExternalNetwork, error) {
	// check if the data is cached
	// TODO: probably we need locking here to make sure concurrent access is covered
	if v.externalNetwork != nil {
		return v.externalNetwork.ExternalNetwork, nil
	}

	conn := v.MqlRuntime.Connection.(*connection.VcdConnection)
	client := conn.Client()

	if v.Name.Error != nil {
		return nil, v.Name.Error
	}
	name := v.Name.Data

	externalNetwork, err := client.GetExternalNetworkByName(name)
	if err != nil {
		return nil, err
	}
	v.externalNetwork = externalNetwork

	return externalNetwork.ExternalNetwork, nil
}

func (v *mqlVcdExternalNetwork) urn() (string, error) {
	externalNetwork, err := v.getData()
	if err != nil {
		return "", err
	}
	return externalNetwork.ID, nil
}

func (v *mqlVcdExternalNetwork) description() (string, error) {
	externalNetwork, err := v.getData()
	if err != nil {
		return "", err
	}
	return externalNetwork.Description, nil
}

func (v *mqlVcdExternalNetwork) configuration() (any, error) {
	externalNetwork, err := v.getData()
	if err != nil {
		return "", err
	}

	// TODO: json has inconsistent naming
	return convert.JsonToDict(externalNetwork.Configuration)
}

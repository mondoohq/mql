// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/facebookincubator/nvdtools/wfn"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/vsphere/connection"
)

func (a *mqlAsset) cpes() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.VsphereConnection)
	if ok && conn.Asset() != nil && conn.Asset().Platform != nil {
		switch conn.Asset().Platform.Name {
		case connection.VspherePlatform:
			// follow the following format cpe:2.3:a:vmware:vcenter_server:7.0:update1d:*:*:*:*:*:*
			attr := wfn.Attributes{
				Part:    "a",
				Vendor:  "vmware",
				Product: "vcenter_server",
				Version: conn.Asset().Platform.Version,
				Update:  conn.Asset().Platform.Build,
			}
			cpe, err := a.MqlRuntime.CreateSharedResource("cpe", map[string]*llx.RawData{
				"uri": llx.StringData(attr.BindToFmtString()),
			})
			if err != nil {
				return nil, err
			}
			return []any{cpe}, nil

		case connection.EsxiPlatform:
			// follow the following format // cpe:2.3:o:vmware:esxi:7.0:update_3c:*:*:*:*:*:*
			attr := wfn.Attributes{
				Part:    "o",
				Vendor:  "vmware",
				Product: "esxi",
				Version: conn.Asset().Platform.Version,
				Update:  conn.Asset().Platform.Build,
			}
			cpe, err := a.MqlRuntime.CreateSharedResource("cpe", map[string]*llx.RawData{
				"uri": llx.StringData(attr.BindToFmtString()),
			})
			if err != nil {
				return nil, err
			}
			return []any{cpe}, nil
		}
	}
	return nil, nil
}

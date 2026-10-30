// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/jamf/connection"
)

func (r *mqlJamf) computerGroups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.JamfConnection)
	client := conn.Client

	groups, err := client.GetComputerGroups()
	if err != nil {
		return nil, err
	}

	var res []any
	for _, g := range groups.Results {
		item, err := CreateResource(r.MqlRuntime, "jamf.computerGroup", map[string]*llx.RawData{
			"id":         llx.IntData(g.ID),
			"name":       llx.StringData(g.Name),
			"smartGroup": llx.BoolData(g.IsSmart),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, item)
	}

	return res, nil
}

func (u *mqlJamfComputerGroup) id() (string, error) {
	return "jamf.computerGroup/" + strconv.FormatInt(u.Id.Data, 10), nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/ipmi/connection"
	"go.mondoo.com/mql/providers/ipmi/connection/client"
)

func (r *mqlIpmi) users() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.IpmiConnection)

	users, err := conn.Client().Users(client.ChannelSelf)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(users))
	for _, user := range users {
		// An account slot repeats along two dimensions: the slot number and
		// the channel the access settings apply to. Both are in the key so a
		// second channel's slot 2 cannot collide with the first channel's.
		id := "ipmi.user/" + strconv.FormatInt(user.ChannelID, 10) + "/" + strconv.FormatInt(user.ID, 10)

		mqlUser, err := CreateResource(r.MqlRuntime, "ipmi.user", map[string]*llx.RawData{
			"__id":                      llx.StringData(id),
			"id":                        llx.IntData(user.ID),
			"name":                      llx.StringDataPtr(user.Name),
			"enabled":                   llx.BoolDataPtr(user.Enabled),
			"privilegeLimit":            llx.StringData(user.PrivilegeLimit),
			"linkAuthenticationEnabled": llx.BoolData(user.LinkAuthenticationEnabled),
			"ipmiMessagingEnabled":      llx.BoolData(user.IpmiMessagingEnabled),
			"callbackOnly":              llx.BoolData(user.CallbackOnly),
			"fixedName":                 llx.BoolData(user.FixedName),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}

	return res, nil
}

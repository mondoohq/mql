// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/jamf/connection"
)

func (r *mqlJamf) users() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.JamfConnection)
	client := conn.Client

	users, err := client.GetUsers()
	if err != nil {
		return nil, err
	}

	var res []any
	for _, u := range users.Users {
		item, err := CreateResource(r.MqlRuntime, "jamf.user", map[string]*llx.RawData{
			"id":   llx.IntData(u.ID),
			"name": llx.StringData(u.Name),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, item)
	}
	return res, nil
}

func (u *mqlJamfUser) id() (string, error) {
	return "jamf.user/" + strconv.FormatInt(u.Id.Data, 10), nil
}

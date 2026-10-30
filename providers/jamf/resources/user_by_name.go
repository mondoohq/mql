// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jamf/connection"
)

func (u *mqlJamfUserByName) id() (string, error) {
	return "jamf.userByName/" + u.Name.Data, nil
}

func initJamfUserByName(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Already hydrated (e.g., from a recording or a previous fetch) — skip the API call.
	if _, ok := args["id"]; ok {
		return args, nil, nil
	}

	nameArg, ok := args["name"]
	if !ok || nameArg.Value == nil {
		// Bare resource access is a valid empty state, not an error.
		return args, nil, nil
	}
	name, ok := nameArg.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New("jamf.userByName requires a non-empty name")
	}

	conn := runtime.Connection.(*connection.JamfConnection)
	user, err := conn.Client.GetUserByName(name)
	if err != nil {
		return nil, nil, err
	}

	args["__id"] = llx.StringData("jamf.userByName/" + user.Name)
	args["id"] = llx.IntData(user.ID)
	args["name"] = llx.StringData(user.Name)
	args["fullName"] = llx.StringData(user.FullName)
	args["email"] = llx.StringData(user.Email)
	args["phone"] = llx.StringData(user.PhoneNumber)
	args["position"] = llx.StringData(user.Position)
	args["enableCustomPhoto"] = llx.BoolData(user.EnableCustomPhoto)

	return args, nil, nil
}

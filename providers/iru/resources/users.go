// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/iru/connection"
	"go.mondoo.com/mql/providers/iru/connection/client"
)

func (r *mqlIru) users() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.IruConnection)
	users, err := conn.ListUsers()
	if err != nil {
		if client.IsAccessDenied(err) {
			log.Warn().Err(err).Msg("iru> access denied to users; returning empty list")
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(users))
	for i := range users {
		item, err := CreateResource(r.MqlRuntime, "iru.user", userArgs(&users[i]))
		if err != nil {
			return nil, err
		}
		res = append(res, item)
	}
	return res, nil
}

func (u *mqlIruUser) id() (string, error) {
	return "iru.user/" + u.Id.Data, nil
}

// initIruUser hydrates an iru.user created by id (via `iru.user(id: "...")`
// or as a cross-reference from iru.device.user) using the tenant-wide user
// listing memoized on the connection.
func initIruUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	idArg, ok := args["id"]
	if !ok || idArg == nil || idArg.Value == nil {
		return args, nil, nil
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.IruConnection)
	users, err := conn.ListUsers()
	if err != nil {
		return args, nil, err
	}
	for i := range users {
		if users[i].ID != id {
			continue
		}
		return userArgs(&users[i]), nil, nil
	}
	return nil, nil, fmt.Errorf("iru.user with id %q not found", id)
}

func userArgs(u *client.User) map[string]*llx.RawData {
	// The top-level /users listing uses `archived`; the device-embedded user
	// object uses `is_archived`. Fold both so the field is correct regardless
	// of which shape hydrated the record.
	archived := u.Archived || u.IsArchived
	integrationName := ""
	integrationType := ""
	if u.Integration != nil {
		integrationName = u.Integration.Name
		integrationType = u.Integration.Type
	}
	return map[string]*llx.RawData{
		"id":              llx.StringData(u.ID),
		"name":            llx.StringData(u.Name),
		"email":           llx.StringData(u.Email),
		"active":          llx.BoolData(u.Active),
		"archived":        llx.BoolData(archived),
		"department":      llx.StringData(u.Department),
		"jobTitle":        llx.StringData(u.JobTitle),
		"deviceCount":     llx.IntData(int64(u.DeviceCount)),
		"created":         llx.TimeDataPtr(client.ParseTime(u.CreatedAt)),
		"updatedAt":       llx.TimeDataPtr(client.ParseTime(u.UpdatedAt)),
		"integrationName": llx.StringData(integrationName),
		"integrationType": llx.StringData(integrationType),
	}
}

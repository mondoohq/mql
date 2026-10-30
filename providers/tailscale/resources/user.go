// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/tailscale/connection"
	tsclient "tailscale.com/client/tailscale/v2"
)

func (r *mqlTailscaleUser) id() (string, error) {
	return "tailscale/user/" + r.Id.Data, nil
}

func initTailscaleUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.TailscaleConnection)

	// On a discovered user asset the user is implied by the asset itself, so a
	// bare `tailscale.user` resolves without an explicit id argument.
	args = withDefaultArg(args, "id", connection.UserIdFromAsset(conn.Asset()))

	id, err := requiredStringArg(args, "id")
	if err != nil {
		return nil, nil, err
	}

	user, err := conn.Client().Users().Get(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}

	resource, err := createTailscaleUserResource(runtime, user)
	if err != nil {
		return nil, nil, err
	}

	return args, resource.(*mqlTailscaleUser), nil
}

func createTailscaleUserResource(runtime *plugin.Runtime, user *tsclient.User) (plugin.Resource, error) {
	return CreateResource(runtime, "tailscale.user", map[string]*llx.RawData{
		"id":                 llx.StringData(user.ID),
		"displayName":        llx.StringData(user.DisplayName),
		"loginName":          llx.StringData(user.LoginName),
		"profilePicUrl":      llx.StringData(user.ProfilePicURL),
		"tailnetId":          llx.StringData(user.TailnetID),
		"type":               llx.StringData(string(user.Type)),
		"role":               llx.StringData(string(user.Role)),
		"status":             llx.StringData(string(user.Status)),
		"deviceCount":        llx.IntData(user.DeviceCount),
		"createdAt":          llx.TimeDataPtr(optionalTimeValue(user.Created)),
		"lastSeenAt":         llx.TimeDataPtr(optionalTimeValue(user.LastSeen)),
		"currentlyConnected": llx.BoolData(user.CurrentlyConnected),
	})
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/slack/connection"
)

func (x *mqlSlackTeam) id() (string, error) {
	return "slack.team/" + x.Id.Data, nil
}

// init method for slack team
func initSlackTeam(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.SlackConnection)
	client := conn.Client()
	if client == nil {
		return nil, nil, errors.New("cannot retrieve new data while using a mock connection")
	}

	teamInfo := conn.TeamInfo()
	args["id"] = llx.StringData(teamInfo.ID)
	args["name"] = llx.StringData(teamInfo.Name)
	args["domain"] = llx.StringData(teamInfo.Domain)
	args["emailDomain"] = llx.StringData(teamInfo.EmailDomain)

	return args, nil, nil
}

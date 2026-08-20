// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/notion/connection"
)

// initNotionBot populates the integration's own bot identity, captured once
// during the connection's Verify() step so this never needs a second round
// trip. notion.bot is a connection-level singleton, queried directly as
// notion.bot.
func initNotionBot(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.NotionConnection)
	u := conn.BotUser()

	var ownerType, workspaceName string
	if u.Bot != nil {
		ownerType = u.Bot.Owner.Type
		workspaceName = u.Bot.WorkspaceName
	}

	args["__id"] = llx.StringData(string(u.ID))
	args["id"] = llx.StringData(string(u.ID))
	args["name"] = llx.StringData(u.Name)
	args["avatarUrl"] = llx.StringData(u.AvatarURL)
	args["ownerType"] = llx.StringData(ownerType)
	args["workspaceName"] = llx.StringData(workspaceName)

	return args, nil, nil
}

// owner resolves the individual owner of the integration when ownerType is
// 'user'. The Notion API returns the owning user object inline on the bot's
// owner field, but the community SDK's Owner struct only decodes the
// discriminator (type/workspace) and does not capture the nested user
// object, so the owning user's id is not available through this client and
// the field stays null even for a user-owned integration. Reviewing a
// user-owned integration's actual owner requires the integration's settings
// page in the Notion admin console.
func (b *mqlNotionBot) owner() (*mqlNotionUser, error) {
	b.Owner.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/jomei/notionapi"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

// bot returns the integration's own bot identity, captured once during the
// connection's Verify() step so this never needs a second round trip.
func (r *mqlNotion) bot() (*mqlNotionBot, error) {
	conn := r.conn()
	return mqlNotionBotFromAPI(r.MqlRuntime, conn.BotUser())
}

// mqlNotionBotFromAPI maps a *notionapi.User (of type "bot") to its MQL
// resource.
func mqlNotionBotFromAPI(runtime *plugin.Runtime, u *notionapi.User) (*mqlNotionBot, error) {
	var ownerType, workspaceName string
	if u.Bot != nil {
		ownerType = u.Bot.Owner.Type
		workspaceName = u.Bot.WorkspaceName
	}

	res, err := CreateResource(runtime, "notion.bot", map[string]*llx.RawData{
		"__id":          llx.StringData(string(u.ID)),
		"id":            llx.StringData(string(u.ID)),
		"name":          llx.StringData(u.Name),
		"avatarUrl":     llx.StringData(u.AvatarURL),
		"ownerType":     llx.StringData(ownerType),
		"workspaceName": llx.StringData(workspaceName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNotionBot), nil
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

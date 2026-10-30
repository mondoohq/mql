// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/notion/connection"
)

// initNotionBot populates the integration's own bot identity, captured once
// during the connection's Verify() step so this never needs a second round
// trip. notion.bot is a connection-level singleton, queried directly as
// notion.bot.
func initNotionBot(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// A caller that already carries the bot's identity has nothing to look
	// up. Anything short of that, `__id` alone included, is filled from the
	// identity Verify() captured on the connection, which costs no round
	// trip, so the guard keys on a populated field rather than an arg count.
	if _, ok := args["id"]; ok {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.NotionConnection)
	u := conn.BotUser()
	if u == nil {
		// Verify() populates this before the runtime is built and aborts the
		// connection when it cannot, so there is no path here today. Guarded
		// anyway: a panic in an accessor takes down the whole scan, and
		// notion.workspace already guards the same call.
		return nil, nil, errors.New("notion.bot is unavailable: the connection did not report a bot identity")
	}

	// Null rather than empty when Notion did not report the value. ownerType
	// is the signal an audit turns on, so an empty string would assert "this
	// integration has no owner type" and let a denylist check on 'user' pass
	// on a value that was never read.
	var ownerType, workspaceName *string
	if u.Bot != nil {
		if u.Bot.Owner.Type != "" {
			ownerType = &u.Bot.Owner.Type
		}
		if u.Bot.WorkspaceName != "" {
			workspaceName = &u.Bot.WorkspaceName
		}
	}

	args["__id"] = llx.StringData(string(u.ID))
	args["id"] = llx.StringData(string(u.ID))
	args["name"] = llx.StringData(u.Name)
	args["avatarUrl"] = llx.StringData(u.AvatarURL)
	args["ownerType"] = llx.StringDataPtr(ownerType)
	args["workspaceName"] = llx.StringDataPtr(workspaceName)

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

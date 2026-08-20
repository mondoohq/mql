// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/notion/connection"
)

// initNotionWorkspace populates the workspace-level view of this
// integration's connected content. Notion has no dedicated workspace
// endpoint: the name comes from the integration's own bot identity.
// notion.workspace is a connection-level singleton, queried directly as
// notion.workspace.
func initNotionWorkspace(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.NotionConnection)

	var name string
	if bot := conn.BotUser(); bot != nil && bot.Bot != nil {
		name = bot.Bot.WorkspaceName
	}

	// Fall back to a stable constant when the bot identity carries no
	// workspace name, so the cache key stays "notion.workspace" instead of
	// an odd-looking trailing-slash "notion.workspace/".
	id := "notion.workspace"
	if name != "" {
		id += "/" + name
	}

	args["__id"] = llx.StringData(id)
	args["name"] = llx.StringData(name)

	return args, nil, nil
}

// notionRoot resolves the singleton notion resource so the count methods can
// reuse its per-field cached users/databases/pages instead of re-paginating
// the API. The __id is deterministic ("notion"), so this returns the same
// instance a `notion { users databases pages }` query populates.
func (w *mqlNotionWorkspace) notionRoot() (*mqlNotion, error) {
	res, err := CreateResource(w.MqlRuntime, "notion", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNotion), nil
}

// userCount reports the number of workspace members and bots visible to
// this integration.
//
// When the token may not list users at all, users is null rather than
// empty, and the count is null too. Reporting 0 there would state as fact
// that the workspace has no members, which is a different claim from "this
// token cannot see them".
func (w *mqlNotionWorkspace) userCount() (int64, error) {
	notion, err := w.notionRoot()
	if err != nil {
		return 0, err
	}
	users := notion.GetUsers()
	if users.Error != nil {
		return 0, users.Error
	}
	if users.State&plugin.StateIsNull != 0 {
		w.UserCount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(len(users.Data)), nil
}

// databaseCount reports the number of databases visible to this
// integration.
func (w *mqlNotionWorkspace) databaseCount() (int64, error) {
	notion, err := w.notionRoot()
	if err != nil {
		return 0, err
	}
	databases := notion.GetDatabases()
	if databases.Error != nil {
		return 0, databases.Error
	}
	return int64(len(databases.Data)), nil
}

// pageCount reports the number of pages visible to this integration.
func (w *mqlNotionWorkspace) pageCount() (int64, error) {
	notion, err := w.notionRoot()
	if err != nil {
		return 0, err
	}
	pages := notion.GetPages()
	if pages.Error != nil {
		return 0, pages.Error
	}
	return int64(len(pages.Data)), nil
}

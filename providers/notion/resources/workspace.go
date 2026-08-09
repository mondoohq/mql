// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers/notion/connection"
)

// workspace returns the workspace-level view of this integration's
// connected content. Notion has no dedicated workspace endpoint: the name
// comes from the integration's own bot identity.
func (r *mqlNotion) workspace() (*mqlNotionWorkspace, error) {
	conn := r.conn()

	var name string
	if bot := conn.BotUser(); bot != nil && bot.Bot != nil {
		name = bot.Bot.WorkspaceName
	}

	res, err := CreateResource(r.MqlRuntime, "notion.workspace", map[string]*llx.RawData{
		"__id": llx.StringData("notion.workspace/" + name),
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNotionWorkspace), nil
}

// userCount reports the number of workspace members and bots visible to
// this integration.
func (w *mqlNotionWorkspace) userCount() (int64, error) {
	conn := w.MqlRuntime.Connection.(*connection.NotionConnection)
	list, err := listNotionUsers(conn)
	if err != nil {
		return 0, err
	}
	return int64(len(list)), nil
}

// databaseCount reports the number of databases visible to this
// integration.
func (w *mqlNotionWorkspace) databaseCount() (int64, error) {
	conn := w.MqlRuntime.Connection.(*connection.NotionConnection)
	list, err := searchNotionDatabases(conn)
	if err != nil {
		return 0, err
	}
	return int64(len(list)), nil
}

// pageCount reports the number of pages visible to this integration.
func (w *mqlNotionWorkspace) pageCount() (int64, error) {
	conn := w.MqlRuntime.Connection.(*connection.NotionConnection)
	list, err := searchNotionPages(conn)
	if err != nil {
		return 0, err
	}
	return int64(len(list)), nil
}

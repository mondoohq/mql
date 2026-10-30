// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/jomei/notionapi"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/notion/connection"
)

type mqlNotionDatabaseInternal struct {
	cacheParentPageId string
}

// id provides a defense-in-depth cache key fallback: mqlNotionDatabaseFromAPI
// already sets "__id" explicitly on every CreateResource call, but should a
// future call site create a notion.database without it, this keeps distinct
// databases from collapsing onto a single cache entry instead of silently
// colliding. It returns the bare database UUID to match the "__id" set by
// mqlNotionDatabaseFromAPI, so both paths resolve to the same cache entry.
func (r *mqlNotionDatabase) id() (string, error) {
	return r.Id.Data, nil
}

// databases lists the databases visible to this integration through
// Notion's search endpoint.
func (r *mqlNotion) databases() ([]any, error) {
	conn := r.conn()
	list, err := searchNotionDatabases(conn)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(list))
	for _, db := range list {
		mqlDb, err := mqlNotionDatabaseFromAPI(r.MqlRuntime, db)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDb)
	}
	return res, nil
}

// searchNotionDatabases paginates POST /v1/search filtered to databases,
// following start_cursor/has_more/next_cursor to completion. Notion has no
// "list all databases" endpoint; search is the only way to enumerate what
// this integration was given access to.
func searchNotionDatabases(conn *connection.NotionConnection) ([]*notionapi.Database, error) {
	client := conn.Client()

	return walkCursor(func(cursor notionapi.Cursor) ([]*notionapi.Database, notionapi.Cursor, bool, error) {
		resp, err := client.Search.Do(context.Background(), &notionapi.SearchRequest{
			Filter:      notionapi.SearchFilter{Property: "object", Value: "database"},
			StartCursor: cursor,
			PageSize:    100,
		})
		if err != nil {
			return nil, "", false, err
		}
		page := make([]*notionapi.Database, 0, len(resp.Results))
		for _, result := range resp.Results {
			db, ok := result.(*notionapi.Database)
			if !ok {
				continue
			}
			page = append(page, db)
		}
		return page, resp.NextCursor, resp.HasMore, nil
	})
}

// mqlNotionDatabaseFromAPI maps a single *notionapi.Database to its MQL
// resource. Used both by the databases() lister and initNotionDatabase's
// lazy lookup.
func mqlNotionDatabaseFromAPI(runtime *plugin.Runtime, db *notionapi.Database) (*mqlNotionDatabase, error) {
	res, err := CreateResource(runtime, "notion.database", map[string]*llx.RawData{
		"__id":           llx.StringData(string(db.ID)),
		"id":             llx.StringData(string(db.ID)),
		"title":          llx.StringData(richTextToString(db.Title)),
		"url":            llx.StringData(db.URL),
		"publicUrl":      llx.StringData(db.PublicURL),
		"createdTime":    llx.TimeData(db.CreatedTime),
		"lastEditedTime": llx.TimeData(db.LastEditedTime),
		"archived":       llx.BoolData(db.Archived),
	})
	if err != nil {
		return nil, err
	}

	mqlDb := res.(*mqlNotionDatabase)
	if db.Parent.Type == notionapi.ParentTypePageID {
		mqlDb.cacheParentPageId = string(db.Parent.PageID)
	}
	return mqlDb, nil
}

// initNotionDatabase resolves a database by id on demand.
func initNotionDatabase(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// fast path: the caller already provided a fully populated resource
	if len(args) > 2 {
		return args, nil, nil
	}

	idRaw, ok := args["id"]
	if !ok {
		return nil, nil, errors.New("notion.database requires an id")
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return nil, nil, errors.New("notion.database requires a valid id")
	}

	conn := runtime.Connection.(*connection.NotionConnection)
	db, err := conn.Client().Database.Get(context.Background(), notionapi.DatabaseID(id))
	if err != nil {
		return nil, nil, errors.Wrapf(err, "notion.database with id %q not found", id)
	}

	res, err := mqlNotionDatabaseFromAPI(runtime, db)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// isPubliclyShared reports whether the database has been published to the
// web through Notion Sites and is reachable without a Notion account.
func (d *mqlNotionDatabase) isPubliclyShared() (bool, error) {
	return d.PublicUrl.Data != "", nil
}

// parentPage resolves the page this database is nested under, when there is
// one. A database can otherwise sit directly under the workspace or a block,
// in which case this stays null.
func (d *mqlNotionDatabase) parentPage() (*mqlNotionPage, error) {
	if d.cacheParentPageId == "" {
		d.ParentPage.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	parent, err := pageByID(d.MqlRuntime, d.cacheParentPageId)
	if err != nil {
		return nil, err
	}
	if parent == nil {
		// Not among the pages shared with this integration; see
		// notion.page's parentDatabase for why this is null, not an error.
		d.ParentPage.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return parent, nil
}

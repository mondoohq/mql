// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/cockroachdb/errors"
	"github.com/jomei/notionapi"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/notion/connection"
)

type mqlNotionPageInternal struct {
	cacheParentDatabaseId string
	cacheParentPageId     string
}

// id provides a defense-in-depth cache key fallback: mqlNotionPageFromAPI
// already sets "__id" explicitly on every CreateResource call, but should a
// future call site create a notion.page without it, this keeps distinct
// pages from collapsing onto a single cache entry instead of silently
// colliding. It returns the bare page UUID to match the "__id" set by
// mqlNotionPageFromAPI, so both paths resolve to the same cache entry.
func (r *mqlNotionPage) id() (string, error) {
	return r.Id.Data, nil
}

// pages lists the pages visible to this integration through Notion's
// search endpoint.
func (r *mqlNotion) pages() ([]any, error) {
	conn := r.conn()
	list, err := searchNotionPages(conn)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(list))
	for _, p := range list {
		mqlPage, err := mqlNotionPageFromAPI(r.MqlRuntime, p)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPage)
	}
	return res, nil
}

// searchNotionPages paginates POST /v1/search filtered to pages, following
// start_cursor/has_more/next_cursor to completion. Notion has no "list all
// pages" endpoint; search is the only way to enumerate what this
// integration was given access to.
func searchNotionPages(conn *connection.NotionConnection) ([]*notionapi.Page, error) {
	client := conn.Client()

	var all []*notionapi.Page
	cursor := notionapi.Cursor("")
	for {
		resp, err := client.Search.Do(context.Background(), &notionapi.SearchRequest{
			Filter:      notionapi.SearchFilter{Property: "object", Value: "page"},
			StartCursor: cursor,
			PageSize:    100,
		})
		if err != nil {
			return nil, err
		}
		for _, result := range resp.Results {
			p, ok := result.(*notionapi.Page)
			if !ok {
				continue
			}
			all = append(all, p)
		}
		if !resp.HasMore || resp.NextCursor == "" {
			break
		}
		cursor = resp.NextCursor
	}
	return all, nil
}

// mqlNotionPageFromAPI maps a single *notionapi.Page to its MQL resource.
// Used both by the pages() lister and initNotionPage's lazy lookup.
func mqlNotionPageFromAPI(runtime *plugin.Runtime, p *notionapi.Page) (*mqlNotionPage, error) {
	properties, err := convert.JsonToDict(p.Properties)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "notion.page", map[string]*llx.RawData{
		"__id":           llx.StringData(string(p.ID)),
		"id":             llx.StringData(string(p.ID)),
		"title":          llx.StringData(pageTitle(p.Properties)),
		"url":            llx.StringData(p.URL),
		"publicUrl":      llx.StringData(p.PublicURL),
		"createdTime":    llx.TimeData(p.CreatedTime),
		"lastEditedTime": llx.TimeData(p.LastEditedTime),
		"archived":       llx.BoolData(p.Archived),
		"properties":     llx.DictData(properties),
	})
	if err != nil {
		return nil, err
	}

	mqlPage := res.(*mqlNotionPage)
	switch p.Parent.Type {
	case notionapi.ParentTypeDatabaseID:
		mqlPage.cacheParentDatabaseId = string(p.Parent.DatabaseID)
	case notionapi.ParentTypePageID:
		mqlPage.cacheParentPageId = string(p.Parent.PageID)
	}
	return mqlPage, nil
}

// pageTitle extracts the plain text of a page's title-type property. Every
// page has exactly one title property, but its key varies (it's the
// database's title column name for database rows, or literally "title" for
// pages under a page or the workspace), so this scans by property type
// instead of a fixed key.
func pageTitle(props notionapi.Properties) string {
	for _, prop := range props {
		if prop.GetType() != notionapi.PropertyTypeTitle {
			continue
		}
		if tp, ok := prop.(*notionapi.TitleProperty); ok {
			return richTextToString(tp.Title)
		}
	}
	return ""
}

// initNotionPage resolves a page by id on demand. This calls GET
// /v1/pages/{id} directly rather than falling through to search, since a
// page can be visible by id even when properties filtering makes it hard to
// search for by title.
func initNotionPage(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// fast path: the caller already provided a fully populated resource
	if len(args) > 2 {
		return args, nil, nil
	}

	idRaw, ok := args["id"]
	if !ok {
		return nil, nil, errors.New("notion.page requires an id")
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return nil, nil, errors.New("notion.page requires a valid id")
	}

	conn := runtime.Connection.(*connection.NotionConnection)
	p, err := conn.Client().Page.Get(context.Background(), notionapi.PageID(id))
	if err != nil {
		return nil, nil, errors.Wrapf(err, "notion.page with id %q not found", id)
	}

	res, err := mqlNotionPageFromAPI(runtime, p)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// isPubliclyShared reports whether the page has been published to the web
// through Notion Sites and is reachable without a Notion account.
func (p *mqlNotionPage) isPubliclyShared() (bool, error) {
	return p.PublicUrl.Data != "", nil
}

// parentDatabase resolves the database this page is a row of, when it is
// one.
func (p *mqlNotionPage) parentDatabase() (*mqlNotionDatabase, error) {
	if p.cacheParentDatabaseId == "" {
		p.ParentDatabase.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(p.MqlRuntime, "notion.database",
		map[string]*llx.RawData{"id": llx.StringData(p.cacheParentDatabaseId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNotionDatabase), nil
}

// parentPage resolves the page this page is nested under, when it is
// nested under another page rather than a database, the workspace, or a
// block.
func (p *mqlNotionPage) parentPage() (*mqlNotionPage, error) {
	if p.cacheParentPageId == "" {
		p.ParentPage.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(p.MqlRuntime, "notion.page",
		map[string]*llx.RawData{"id": llx.StringData(p.cacheParentPageId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNotionPage), nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	"github.com/jomei/notionapi"
	"go.mondoo.com/mql/providers/notion/connection"
)

// mqlNotionInternal memoizes the id lookups that page and database parent
// resolution needs. Both collections are scanned by id once per parent
// reference, so on a workspace of ~12k pages a linear scan makes the walk
// quadratic. The maps are built once from the same collections the
// accessors return.
type mqlNotionInternal struct {
	indexLock   sync.Mutex
	databaseIdx map[string]*mqlNotionDatabase
	pageIdx     map[string]*mqlNotionPage
}

// databaseIndex returns the id to database map for notion.databases,
// building it on first use.
func (r *mqlNotion) databaseIndex() (map[string]*mqlNotionDatabase, error) {
	// Resolved before the lock is taken: GetDatabases is memoized by the
	// runtime, and holding the lock across it would make a nested parent
	// lookup deadlock against itself.
	databases := r.GetDatabases()
	if databases.Error != nil {
		return nil, databases.Error
	}

	r.indexLock.Lock()
	defer r.indexLock.Unlock()
	if r.databaseIdx != nil {
		return r.databaseIdx, nil
	}

	idx := make(map[string]*mqlNotionDatabase, len(databases.Data))
	for _, entry := range databases.Data {
		db, ok := entry.(*mqlNotionDatabase)
		if !ok {
			continue
		}
		idx[db.Id.Data] = db
	}
	r.databaseIdx = idx
	return idx, nil
}

// pageIndex returns the id to page map for notion.pages, building it on
// first use.
func (r *mqlNotion) pageIndex() (map[string]*mqlNotionPage, error) {
	pages := r.GetPages()
	if pages.Error != nil {
		return nil, pages.Error
	}

	r.indexLock.Lock()
	defer r.indexLock.Unlock()
	if r.pageIdx != nil {
		return r.pageIdx, nil
	}

	idx := make(map[string]*mqlNotionPage, len(pages.Data))
	for _, entry := range pages.Data {
		page, ok := entry.(*mqlNotionPage)
		if !ok {
			continue
		}
		idx[page.Id.Data] = page
	}
	r.pageIdx = idx
	return idx, nil
}

func (r *mqlNotion) id() (string, error) {
	return "notion", nil
}

// conn returns the Notion connection backing this runtime.
func (r *mqlNotion) conn() *connection.NotionConnection {
	return r.MqlRuntime.Connection.(*connection.NotionConnection)
}

// richTextToString concatenates the plain-text content of a rich-text array,
// as returned for a title or rich_text property.
func richTextToString(rt []notionapi.RichText) string {
	if len(rt) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, r := range rt {
		sb.WriteString(r.PlainText)
	}
	return sb.String()
}

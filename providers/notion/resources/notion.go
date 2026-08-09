// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/jomei/notionapi"
	"go.mondoo.com/mql/v13/providers/notion/connection"
)

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

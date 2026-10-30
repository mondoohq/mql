// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"maps"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/iru/connection"
	"go.mondoo.com/mql/providers/iru/connection/client"
)

func (r *mqlIru) libraryItems() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.IruConnection)
	items, err := conn.ListLibraryItems()
	if err != nil {
		if client.IsAccessDenied(err) {
			log.Warn().Err(err).Msg("iru> access denied to library items; returning empty list")
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		item, err := CreateResource(r.MqlRuntime, "iru.libraryItem", libraryItemArgs(&items[i]))
		if err != nil {
			return nil, err
		}
		res = append(res, item)
	}
	return res, nil
}

func (l *mqlIruLibraryItem) id() (string, error) {
	// The catalog is aggregated from three separate /library/<type> endpoints,
	// each with its own id space, so the kind is part of the cache key to keep
	// an id shared across kinds from collapsing two items into one.
	return "iru.libraryItem/" + l.Kind.Data + "/" + l.Id.Data, nil
}

func libraryItemArgs(li *client.LibraryItem) map[string]*llx.RawData {
	payload := make(map[string]any, len(li.Payload))
	maps.Copy(payload, li.Payload)
	return map[string]*llx.RawData{
		"id":        llx.StringData(li.ID),
		"name":      llx.StringData(li.Name),
		"kind":      llx.StringData(li.Kind),
		"active":    llx.BoolData(li.Active),
		"payload":   llx.DictData(payload),
		"created":   llx.TimeDataPtr(client.ParseTime(li.CreatedAt)),
		"updatedAt": llx.TimeDataPtr(client.ParseTime(li.UpdatedAt)),
	}
}

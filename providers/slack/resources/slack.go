// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (k *mqlSlack) id() (string, error) {
	return "slack", nil
}

// walkCursor calls fetch with an empty cursor, then with each next cursor it
// returns, until it returns an empty one. Slack may return empty pages that
// still carry a cursor, so the page contents never end the walk. A cursor
// seen before stops it with an error instead of looping forever.
func walkCursor(fetch func(cursor string) (string, error)) error {
	seen := map[string]struct{}{}
	cursor := ""
	for {
		next, err := fetch(cursor)
		if err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		if _, ok := seen[next]; ok {
			return fmt.Errorf("slack returned the pagination cursor %q twice", next)
		}
		seen[next] = struct{}{}
		cursor = next
	}
}

// slackUserRef resolves a slack.user reference for the given ID, or sets the
// field to null when the ID is empty, so an absent user never triggers a
// users.info lookup for "".
func slackUserRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlSlackUser]) (*mqlSlackUser, error) {
	if id == "" {
		*field = plugin.TValue[*mqlSlackUser]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	r, err := NewResource(runtime, "slack.user", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSlackUser), nil
}

// unixTimeData converts a Unix timestamp in seconds to time data, reading 0
// (the value Slack's JSON decodes to when the timestamp is absent) as null.
func unixTimeData(ts int64) *llx.RawData {
	if ts == 0 {
		return llx.NilData
	}
	return llx.TimeData(time.Unix(ts, 0))
}

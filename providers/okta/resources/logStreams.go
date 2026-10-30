// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
)

// oktaLogStreamRaw flattens the polymorphic log stream response (AWS
// EventBridge or Splunk) into the shared fields plus a type-discriminated
// settings map. The SDK models the list as a union, so re-marshaling each
// entry to JSON gives one code path over both variants.
type oktaLogStreamRaw struct {
	Id          string         `json:"id"`
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	Status      string         `json:"status"`
	Created     *time.Time     `json:"created"`
	LastUpdated *time.Time     `json:"lastUpdated"`
	Settings    map[string]any `json:"settings"`
}

func (o *mqlOkta) logStreams() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.LogStreamAPI.ListLogStreams(ctx).Limit(queryLimit).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.ListLogStreams200ResponseInner) error {
		for i := range datalist {
			r, err := newMqlOktaLogStream(o.MqlRuntime, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(slice); err != nil {
		return nil, err
	}
	for resp != nil && resp.HasNextPage() {
		var page []okta.ListLogStreams200ResponseInner
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

// decodeOktaLogStream flattens one entry of the polymorphic listing into the
// shared fields plus its type-specific settings, dropping the Splunk token.
// Kept separate from resource construction so the redaction is testable.
func decodeOktaLogStream(entry *okta.ListLogStreams200ResponseInner) (*oktaLogStreamRaw, error) {
	raw, err := json.Marshal(entry.GetActualInstance())
	if err != nil {
		return nil, err
	}
	stream := &oktaLogStreamRaw{}
	if err := json.Unmarshal(raw, stream); err != nil {
		return nil, err
	}

	// The Splunk token is a secret; never expose it.
	delete(stream.Settings, "token")
	return stream, nil
}

func newMqlOktaLogStream(runtime *plugin.Runtime, entry *okta.ListLogStreams200ResponseInner) (any, error) {
	stream, err := decodeOktaLogStream(entry)
	if err != nil {
		return nil, err
	}

	settings, err := convert.JsonToDict(stream.Settings)
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "okta.logStream", map[string]*llx.RawData{
		"id":          llx.StringData(stream.Id),
		"name":        llx.StringData(stream.Name),
		"type":        llx.StringData(stream.Type),
		"status":      llx.StringData(stream.Status),
		"settings":    llx.DictData(settings),
		"created":     llx.TimeDataPtr(stream.Created),
		"lastUpdated": llx.TimeDataPtr(stream.LastUpdated),
	})
}

func (o *mqlOktaLogStream) id() (string, error) {
	return "okta.logStream/" + o.Id.Data, o.Id.Error
}

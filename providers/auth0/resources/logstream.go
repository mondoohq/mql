// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/auth0/go-auth0/management"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// logStreams lists the connections that export tenant events to external
// destinations. The log-streams endpoint is not paginated.
func (a *mqlAuth0) logStreams() ([]any, error) {
	conn := a.conn()
	client := conn.Client()

	streams, err := client.LogStream.List(context.Background())
	if err != nil {
		return nil, err
	}

	var all []any
	for _, ls := range streams {
		r, err := newMqlAuth0LogStream(a.MqlRuntime, ls)
		if err != nil {
			return nil, err
		}
		all = append(all, r)
	}
	return all, nil
}

// newMqlAuth0LogStream maps a single SDK log stream to its MQL resource.
func newMqlAuth0LogStream(runtime *plugin.Runtime, ls *management.LogStream) (plugin.Resource, error) {
	sink, err := convert.JsonToDict(ls.Sink)
	if err != nil {
		return nil, err
	}

	var filters []any
	if ls.Filters != nil {
		filters, err = convert.JsonToDictSlice(*ls.Filters)
		if err != nil {
			return nil, err
		}
	}

	r, err := CreateResource(runtime, "auth0.logStream", map[string]*llx.RawData{
		"id":      llx.StringDataPtr(ls.ID),
		"name":    llx.StringDataPtr(ls.Name),
		"type":    llx.StringDataPtr(ls.Type),
		"status":  llx.StringDataPtr(ls.Status),
		"sink":    llx.DictData(sink),
		"filters": llx.ArrayData(filters, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *mqlAuth0LogStream) id() (string, error) {
	return "auth0.logStream/" + r.Id.Data, nil
}

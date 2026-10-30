// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOkta) trustedOrigins() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.TrustedOriginAPI.ListTrustedOrigins(ctx).Limit(queryLimit).Execute()
	if err != nil {
		return nil, err
	}

	if len(slice) == 0 {
		return nil, nil
	}

	list := []any{}
	appendEntry := func(datalist []okta.TrustedOrigin) error {
		for i := range datalist {
			r, err := newMqlOktaTrustedOrigin(o.MqlRuntime, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	err = appendEntry(slice)
	if err != nil {
		return nil, err
	}

	for resp != nil && resp.HasNextPage() {
		var slice []okta.TrustedOrigin
		resp, err = resp.Next(&slice)
		if err != nil {
			return nil, err
		}
		err = appendEntry(slice)
		if err != nil {
			return nil, err
		}
	}
	return list, nil
}

func newMqlOktaTrustedOrigin(runtime *plugin.Runtime, entry *okta.TrustedOrigin) (any, error) {
	scopes, err := convert.JsonToDictSlice(entry.Scopes)
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "okta.trustedOrigin", map[string]*llx.RawData{
		"id":            llx.StringData(oktaStr(entry.Id)),
		"name":          llx.StringData(oktaStr(entry.Name)),
		"origin":        llx.StringData(oktaStr(entry.Origin)),
		"created":       llx.TimeDataPtr(entry.Created),
		"createdBy":     llx.StringData(oktaStr(entry.CreatedBy)),
		"lastUpdated":   llx.TimeDataPtr(entry.LastUpdated),
		"lastUpdatedBy": llx.StringData(oktaStr(entry.LastUpdatedBy)),
		"scopes":        llx.ArrayData(scopes, types.Dict),
		"status":        llx.StringData(oktaStr(entry.Status)),
	})
}

func (o *mqlOktaTrustedOrigin) id() (string, error) {
	return "okta.trustedOrigin/" + o.Id.Data, o.Id.Error
}

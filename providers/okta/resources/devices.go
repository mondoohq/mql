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
)

func (o *mqlOkta) devices() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.DeviceAPI.ListDevices(ctx).Limit(queryLimit).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.DeviceList) error {
		for i := range datalist {
			r, err := newMqlOktaDevice(o.MqlRuntime, &datalist[i])
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
		var page []okta.DeviceList
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

func newMqlOktaDevice(runtime *plugin.Runtime, entry *okta.DeviceList) (any, error) {
	profile, err := convert.JsonToDict(entry.Profile)
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "okta.device", map[string]*llx.RawData{
		"id":           llx.StringData(oktaStr(entry.Id)),
		"status":       llx.StringData(oktaStr(entry.Status)),
		"resourceType": llx.StringData(oktaStr(entry.ResourceType)),
		"profile":      llx.DictData(profile),
		"created":      llx.TimeDataPtr(entry.Created),
		"lastUpdated":  llx.TimeDataPtr(entry.LastUpdated),
	})
}

func (o *mqlOktaDevice) id() (string, error) {
	return "okta.device/" + o.Id.Data, o.Id.Error
}

func (o *mqlOktaDevice) users() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.DeviceAPI.ListDeviceUsers(ctx, o.Id.Data).Execute()
	if err != nil {
		return nil, err
	}

	userIDs := []string{}
	collect := func(datalist []okta.DeviceUser) {
		for i := range datalist {
			if datalist[i].User != nil {
				userIDs = append(userIDs, oktaStr(datalist[i].User.Id))
			}
		}
	}

	collect(slice)
	for resp != nil && resp.HasNextPage() {
		var page []okta.DeviceUser
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		collect(page)
	}

	return resolveOktaUserRefs(o.MqlRuntime, userIDs)
}

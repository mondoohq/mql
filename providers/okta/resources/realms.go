// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"maps"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
)

func (o *mqlOkta) realms() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.RealmAPI.ListRealms(ctx).Limit(queryLimit).Execute()
	if err != nil {
		// Realms are a licensed feature; orgs without it have no endpoint.
		if isOktaFeatureUnavailable(resp, err) {
			return nil, nil
		}
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.Realm) error {
		for i := range datalist {
			r, err := newMqlOktaRealm(o.MqlRuntime, &datalist[i])
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
		var page []okta.Realm
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

// initOktaRealm allows callers to construct an okta.realm via NewResource by
// id, which is how a user resolves the realm it resides in.
func initOktaRealm(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// If we already have the full set of fields, no fetch needed.
	if len(args) > 1 {
		return args, nil, nil
	}

	idArg, ok := args["id"]
	if !ok || idArg == nil || idArg.Value == nil {
		// Bare resource construction (no id) is a valid empty state.
		return args, nil, nil
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()
	item, resp, err := client.RealmAPI.GetRealm(ctx, id).Execute()
	if err != nil {
		// Realms are a licensed feature, so an org that stamped a realm id on a
		// user can still refuse to serve the realm itself. Both that and a
		// deleted realm resolve to a null reference rather than failing the
		// user the reference was read from.
		if isOktaFeatureUnavailable(resp, err) {
			return nil, nil, fmt.Errorf("%w: okta.realm %q", errOktaResourceNotFound, id)
		}
		return nil, nil, err
	}
	if item == nil {
		return nil, nil, fmt.Errorf("%w: okta.realm %q", errOktaResourceNotFound, id)
	}

	maps.Copy(args, oktaRealmArgs(item))
	return args, nil, nil
}

func oktaRealmArgs(entry *okta.Realm) map[string]*llx.RawData {
	var name, realmType string
	if profile := entry.Profile; profile != nil {
		name = profile.Name
		realmType = oktaStr(profile.RealmType)
	}

	return map[string]*llx.RawData{
		"id":          llx.StringData(oktaStr(entry.Id)),
		"name":        llx.StringData(name),
		"realmType":   llx.StringData(realmType),
		"isDefault":   llx.BoolDataPtr(entry.IsDefault),
		"created":     llx.TimeDataPtr(entry.Created),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
	}
}

func newMqlOktaRealm(runtime *plugin.Runtime, entry *okta.Realm) (any, error) {
	return CreateResource(runtime, "okta.realm", oktaRealmArgs(entry))
}

func (o *mqlOktaRealm) id() (string, error) {
	return "okta.realm/" + o.Id.Data, o.Id.Error
}

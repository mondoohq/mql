// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
)

// oktaProfileMappingAppType is the source/target type Okta uses for the
// application side of a mapping. The other side is "user", an Okta user type.
const oktaProfileMappingAppType = "appuser"

// mqlOktaProfileMappingInternal caches the ids behind the application and
// userType accessors. A mapping always has one application side and one user
// side, so which of source/target holds each is resolved once at build time.
type mqlOktaProfileMappingInternal struct {
	cacheApplicationID string
	cacheUserTypeID    string
}

func (o *mqlOkta) profileMappings() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.ProfileMappingAPI.ListProfileMappings(ctx).Limit(queryLimit).Execute()
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			return nil, nil
		}
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.ListProfileMappings) error {
		for i := range datalist {
			r, err := newMqlOktaProfileMapping(o.MqlRuntime, &datalist[i])
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
		var page []okta.ListProfileMappings
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

func newMqlOktaProfileMapping(runtime *plugin.Runtime, entry *okta.ListProfileMappings) (*mqlOktaProfileMapping, error) {
	var sourceID, sourceName, sourceType string
	if src := entry.Source; src != nil {
		sourceID, sourceName, sourceType = oktaStr(src.Id), oktaStr(src.Name), oktaStr(src.Type)
	}
	var targetID, targetName, targetType string
	if tgt := entry.Target; tgt != nil {
		targetID, targetName, targetType = oktaStr(tgt.Id), oktaStr(tgt.Name), oktaStr(tgt.Type)
	}

	r, err := CreateResource(runtime, "okta.profileMapping", map[string]*llx.RawData{
		"id":         llx.StringData(oktaStr(entry.Id)),
		"sourceId":   llx.StringData(sourceID),
		"sourceName": llx.StringData(sourceName),
		"sourceType": llx.StringData(sourceType),
		"targetId":   llx.StringData(targetID),
		"targetName": llx.StringData(targetName),
		"targetType": llx.StringData(targetType),
	})
	if err != nil {
		return nil, err
	}

	mqlMapping := r.(*mqlOktaProfileMapping)
	mqlMapping.cacheApplicationID, mqlMapping.cacheUserTypeID = oktaProfileMappingSides(
		sourceType, sourceID, targetType, targetID)
	return mqlMapping, nil
}

// oktaProfileMappingSides sorts a mapping's two endpoints into the application
// id and the user type id. Either may come back empty when the mapping does not
// carry that side.
func oktaProfileMappingSides(sourceType, sourceID, targetType, targetID string) (applicationID, userTypeID string) {
	for _, side := range []struct{ typ, id string }{
		{sourceType, sourceID},
		{targetType, targetID},
	} {
		if side.id == "" {
			continue
		}
		if side.typ == oktaProfileMappingAppType {
			applicationID = side.id
		} else {
			userTypeID = side.id
		}
	}
	return applicationID, userTypeID
}

func (o *mqlOktaProfileMapping) id() (string, error) {
	return "okta.profileMapping/" + o.Id.Data, o.Id.Error
}

// Mappings also cover applications Okta manages internally, which it does not
// serve from `/api/v1/apps`; those resolve to null rather than failing every
// other mapping in the same query.
func (o *mqlOktaProfileMapping) application() (*mqlOktaApplication, error) {
	return resolveOktaApplicationRef(o.MqlRuntime, o.cacheApplicationID, &o.Application)
}

func (o *mqlOktaProfileMapping) userType() (*mqlOktaUserType, error) {
	if o.cacheUserTypeID == "" {
		o.UserType.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	r, err := NewResource(o.MqlRuntime, "okta.userType", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheUserTypeID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOktaUserType), nil
}

// properties resolves the mapping's per-attribute expressions. Okta returns
// them only from the single-mapping endpoint, never in the listing, so both the
// collection path and a directly constructed mapping fetch them here and agree.
func (o *mqlOktaProfileMapping) properties() (any, error) {
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	if o.Id.Data == "" {
		return map[string]any{}, nil
	}

	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	mapping, _, err := client.ProfileMappingAPI.GetProfileMapping(ctx, o.Id.Data).Execute()
	if err != nil {
		return nil, err
	}

	properties := map[string]any{}
	if mapping == nil {
		return properties, nil
	}

	// The endpoint answers with a map of target property name to that
	// property's mapping, but the generated model types the whole map as a
	// single mapping object. Only `expression` and `pushStatus` are declared on
	// it, so every named entry the org actually configured arrives in
	// AdditionalProperties instead, keyed by property name.
	for name, raw := range mapping.Properties.AdditionalProperties {
		prop, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		properties[name] = map[string]any{
			"expression": oktaStrFrom(prop["expression"]),
			"pushStatus": oktaStrFrom(prop["pushStatus"]),
		}
	}
	return properties, nil
}

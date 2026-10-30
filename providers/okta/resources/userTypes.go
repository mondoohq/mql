// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
)

// oktaUserTypeRaw is the user type wire shape. The SDK's UserType struct
// declares only `id`; every other attribute the API returns lands in its
// untyped AdditionalProperties map. Its MarshalJSON writes those back out, so
// re-marshaling an SDK UserType and decoding it here recovers the full object.
type oktaUserTypeRaw struct {
	Id            string     `json:"id,omitempty"`
	Name          string     `json:"name,omitempty"`
	DisplayName   string     `json:"displayName,omitempty"`
	Description   string     `json:"description,omitempty"`
	Default       bool       `json:"default,omitempty"`
	CreatedBy     string     `json:"createdBy,omitempty"`
	LastUpdatedBy string     `json:"lastUpdatedBy,omitempty"`
	Created       *time.Time `json:"created,omitempty"`
	LastUpdated   *time.Time `json:"lastUpdated,omitempty"`
}

// mqlOktaUserTypeInternal caches the administrator ids behind the createdBy and
// lastUpdatedBy accessors so they resolve without public raw-id fields.
type mqlOktaUserTypeInternal struct {
	cacheCreatedBy     string
	cacheLastUpdatedBy string
}

func (o *mqlOkta) userTypes() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, _, err := client.UserTypeAPI.ListUserTypes(ctx).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range slice {
		entry, err := decodeOktaUserType(&slice[i])
		if err != nil {
			return nil, err
		}
		r, err := newMqlOktaUserType(o.MqlRuntime, entry)
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

// decodeOktaUserType normalizes an SDK UserType through JSON into the full
// wire shape. See oktaUserTypeRaw for why the SDK type is not enough.
func decodeOktaUserType(src *okta.UserType) (*oktaUserTypeRaw, error) {
	raw, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	entry := &oktaUserTypeRaw{}
	if err := json.Unmarshal(raw, entry); err != nil {
		return nil, err
	}
	return entry, nil
}

func initOktaUserType(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// If we already have the full set of fields, no fetch needed.
	if len(args) > 1 {
		return args, nil, nil
	}

	idArg, ok := args["id"]
	if !ok || idArg == nil || idArg.Value == nil {
		// Bare resource construction (no id) is a valid empty state.
		return args, nil, nil
	}

	// Supplying an id but supplying a bad one is different from not supplying
	// one. okta.userType is private, so the only callers are this provider's own
	// accessors, which guard for an empty cached id before resolving. Reaching
	// here with a non-string or empty id means one of them regressed, and
	// falling through would hide that as a husk resource whose fields surface
	// much later as "primitive with no type information".
	id, ok := idArg.Value.(string)
	if !ok {
		return nil, nil, fmt.Errorf("okta.userType id must be a string, got %T", idArg.Value)
	}
	if id == "" {
		return nil, nil, errors.New("okta.userType id must not be empty")
	}

	conn := runtime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	item, resp, err := client.UserTypeAPI.GetUserType(ctx, id).Execute()
	if err != nil {
		// A user can outlive the type it was created under. Report that as a
		// missing reference so the accessor reading it resolves to null,
		// rather than failing every user in the collection.
		if isOktaNotFound(resp) {
			return nil, nil, fmt.Errorf("%w: okta.userType %q", errOktaResourceNotFound, id)
		}
		return nil, nil, err
	}
	if item == nil {
		return nil, nil, fmt.Errorf("okta.userType with id %q not found", id)
	}

	entry, err := decodeOktaUserType(item)
	if err != nil {
		return nil, nil, err
	}

	// Returning the built resource is the only way to populate the Internal
	// struct the createdBy and lastUpdatedBy accessors read from.
	res, err := newMqlOktaUserType(runtime, entry)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func newMqlOktaUserType(runtime *plugin.Runtime, entry *oktaUserTypeRaw) (*mqlOktaUserType, error) {
	r, err := CreateResource(runtime, "okta.userType", map[string]*llx.RawData{
		"id":          llx.StringData(entry.Id),
		"name":        llx.StringData(entry.Name),
		"displayName": llx.StringData(entry.DisplayName),
		"description": llx.StringData(entry.Description),
		"default":     llx.BoolData(entry.Default),
		"created":     llx.TimeDataPtr(entry.Created),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
	})
	if err != nil {
		return nil, err
	}

	mqlUserType := r.(*mqlOktaUserType)
	mqlUserType.cacheCreatedBy = entry.CreatedBy
	mqlUserType.cacheLastUpdatedBy = entry.LastUpdatedBy
	return mqlUserType, nil
}

func (o *mqlOktaUserType) id() (string, error) {
	return "okta.userType/" + o.Id.Data, o.Id.Error
}

// Okta stamps the built-in user type with a system principal id rather than a
// user id, so these resolve to null on the default type instead of failing the
// collection. The shared resolver handles both that and an empty id.
func (o *mqlOktaUserType) createdBy() (*mqlOktaUser, error) {
	return resolveOktaUserRef(o.MqlRuntime, o.cacheCreatedBy, &o.CreatedBy)
}

func (o *mqlOktaUserType) lastUpdatedBy() (*mqlOktaUser, error) {
	return resolveOktaUserRef(o.MqlRuntime, o.cacheLastUpdatedBy, &o.LastUpdatedBy)
}

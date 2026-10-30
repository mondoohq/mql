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

type mqlOktaGroupOwnerInternal struct {
	// cacheOwnerID is the id of the owning principal. Which of the user or
	// group references it resolves is decided by cacheOwnerType, since Okta
	// reuses the one id field for both.
	cacheOwnerID       string
	cacheOwnerType     string
	cacheApplicationID string
}

func (o *mqlOktaGroup) owners() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	ctx := context.Background()
	groupID := o.Id.Data

	slice, resp, err := conn.Client().GroupOwnerAPI.ListGroupOwners(ctx, groupID).Limit(queryLimit).Execute()
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			return nil, nil
		}
		return nil, err
	}

	owners, err := oktaCollectPages(slice, resp)
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(owners))
	for i := range owners {
		r, err := newMqlOktaGroupOwner(o.MqlRuntime, groupID, &owners[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

// newMqlOktaGroupOwner maps one owner of a group. Okta returns the owning
// principal's id in a single `id` field and discriminates it with `type`, so
// the id is cached and read back through whichever of the user or group
// references matches that type.
func newMqlOktaGroupOwner(runtime *plugin.Runtime, groupID string, entry *okta.GroupOwner) (*mqlOktaGroupOwner, error) {
	ownerID := oktaStr(entry.Id)

	r, err := CreateResource(runtime, "okta.group.owner", map[string]*llx.RawData{
		"__id":        llx.StringData("okta.group.owner/" + groupID + "/" + ownerID),
		"type":        llx.StringData(oktaStr(entry.Type)),
		"displayName": llx.StringData(oktaStr(entry.DisplayName)),
		"originType":  llx.StringData(oktaStr(entry.OriginType)),
		"resolved":    llx.BoolData(oktaBool(entry.Resolved)),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
	})
	if err != nil {
		return nil, err
	}

	owner := r.(*mqlOktaGroupOwner)
	owner.cacheOwnerID = ownerID
	owner.cacheOwnerType = oktaStr(entry.Type)
	// originId is populated only for APPLICATION-sourced ownership, where it
	// is the id of the app instance managing it.
	owner.cacheApplicationID = oktaStr(entry.OriginId)
	return owner, nil
}

func (o *mqlOktaGroupOwner) user() (*mqlOktaUser, error) {
	if o.cacheOwnerType != "USER" {
		o.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveOktaUserRef(o.MqlRuntime, o.cacheOwnerID, &o.User)
}

func (o *mqlOktaGroupOwner) group() (*mqlOktaGroup, error) {
	if o.cacheOwnerType != "GROUP" {
		o.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveOktaGroupRef(o.MqlRuntime, o.cacheOwnerID, &o.Group)
}

func (o *mqlOktaGroupOwner) application() (*mqlOktaApplication, error) {
	return resolveOktaApplicationRef(o.MqlRuntime, o.cacheApplicationID, &o.Application)
}

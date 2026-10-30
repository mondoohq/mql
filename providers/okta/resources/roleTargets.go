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

// Administrator role assignments can be narrowed to a set of groups or
// applications. Okta serves those targets from a different endpoint per
// principal kind, and the assignment only knows which principal it was read
// from, so both accessors below dispatch on the cached principal id.
//
// An empty result is the wide case, not the narrow one: an assignment with no
// targets is not scoped at all and covers every group or application in the
// org.

// isCustomRoleAssignment reports whether the assignment grants a custom role.
// Custom roles take their scope from the resource set they are bound to rather
// than from a target list, so Okta rejects the target endpoints for them with a
// 400. Read `resourceSet` to see what such an assignment covers.
func (o *mqlOktaRole) isCustomRoleAssignment() bool {
	return o.Type.Error == nil && o.Type.Data == "CUSTOM"
}

func (o *mqlOktaRole) groupTargets() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	ctx := context.Background()
	roleID := o.Id.Data

	if o.isCustomRoleAssignment() {
		return nil, nil
	}

	var groups []okta.Group
	switch {
	case o.cacheUserID != "":
		slice, resp, err := conn.Client().RoleBTargetAdminAPI.
			ListGroupTargetsForRole(ctx, o.cacheUserID, roleID).Limit(queryLimit).Execute()
		if err != nil {
			// An unscoped assignment has no targets resource at all.
			if isOktaFeatureUnavailable(resp, err) {
				return nil, nil
			}
			return nil, err
		}
		groups, err = oktaCollectPages(slice, resp)
		if err != nil {
			return nil, err
		}

	case o.cacheGroupID != "":
		slice, resp, err := conn.Client().RoleBTargetBGroupAPI.
			ListGroupTargetsForGroupRole(ctx, o.cacheGroupID, roleID).Limit(queryLimit).Execute()
		if err != nil {
			if isOktaFeatureUnavailable(resp, err) {
				return nil, nil
			}
			return nil, err
		}
		groups, err = oktaCollectPages(slice, resp)
		if err != nil {
			return nil, err
		}

	case o.cacheClientID != "":
		apiSupplement := conn.ApiExtension()
		slice, resp, err := apiSupplement.ListClientRoleGroupTargets(ctx, o.cacheClientID, roleID)
		if err != nil {
			if isOktaRawFeatureUnavailable(resp, err) {
				return nil, nil
			}
			return nil, err
		}
		groups = slice

	default:
		// The assignment was built without a principal, so there is nothing to
		// look targets up against.
		return nil, nil
	}

	list := make([]any, 0, len(groups))
	for i := range groups {
		r, err := newMqlOktaGroup(o.MqlRuntime, &groups[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func (o *mqlOktaRole) appTargets() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	ctx := context.Background()
	roleID := o.Id.Data

	if o.isCustomRoleAssignment() {
		return nil, nil
	}

	var apps []okta.CatalogApplication
	switch {
	case o.cacheUserID != "":
		slice, resp, err := conn.Client().RoleBTargetAdminAPI.
			ListApplicationTargetsForApplicationAdministratorRoleForUser(ctx, o.cacheUserID, roleID).
			Limit(queryLimit).Execute()
		if err != nil {
			if isOktaFeatureUnavailable(resp, err) {
				return nil, nil
			}
			return nil, err
		}
		apps, err = oktaCollectPages(slice, resp)
		if err != nil {
			return nil, err
		}

	case o.cacheGroupID != "":
		slice, resp, err := conn.Client().RoleBTargetBGroupAPI.
			ListApplicationTargetsForApplicationAdministratorRoleForGroup(ctx, o.cacheGroupID, roleID).
			Limit(queryLimit).Execute()
		if err != nil {
			if isOktaFeatureUnavailable(resp, err) {
				return nil, nil
			}
			return nil, err
		}
		apps, err = oktaCollectPages(slice, resp)
		if err != nil {
			return nil, err
		}

	case o.cacheClientID != "":
		apiSupplement := conn.ApiExtension()
		slice, resp, err := apiSupplement.ListClientRoleAppTargets(ctx, o.cacheClientID, roleID)
		if err != nil {
			if isOktaRawFeatureUnavailable(resp, err) {
				return nil, nil
			}
			return nil, err
		}
		apps = slice

	default:
		return nil, nil
	}

	list := make([]any, 0, len(apps))
	for i := range apps {
		r, err := newMqlOktaRoleAppTarget(o.MqlRuntime, roleID, &apps[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

// newMqlOktaRoleAppTarget maps one application target of a role assignment.
// Okta returns two shapes from the same collection: a target naming a single
// app instance carries that instance's `id`, while a target naming a whole
// catalog app type carries only `name`. The instance id is therefore what
// decides whether `application` resolves, and it is kept internal so the
// distinction is read through the typed reference rather than a bare string.
func newMqlOktaRoleAppTarget(runtime *plugin.Runtime, roleID string, entry *okta.CatalogApplication) (*mqlOktaRoleAppTarget, error) {
	instanceID := oktaStr(entry.Id)
	name := oktaStr(entry.Name)

	// A catalog app type has no instance id, so qualify the key with the app
	// type name to keep the two shapes from colliding in the resource cache.
	targetKey := instanceID
	if targetKey == "" {
		targetKey = "catalog/" + name
	}

	r, err := CreateResource(runtime, "okta.role.appTarget", map[string]*llx.RawData{
		"__id":        llx.StringData("okta.role.appTarget/" + roleID + "/" + targetKey),
		"name":        llx.StringData(name),
		"displayName": llx.StringData(oktaStr(entry.DisplayName)),
	})
	if err != nil {
		return nil, err
	}

	target := r.(*mqlOktaRoleAppTarget)
	target.cacheApplicationID = instanceID
	return target, nil
}

func (o *mqlOktaRoleAppTarget) application() (*mqlOktaApplication, error) {
	return resolveOktaApplicationRef(o.MqlRuntime, o.cacheApplicationID, &o.Application)
}

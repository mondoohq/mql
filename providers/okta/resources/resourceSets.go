// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/types"
)

type mqlOktaResourceSetResourceInternal struct {
	cacheTargetType string
	cacheTargetID   string
}

type mqlOktaResourceSetBindingInternal struct {
	cacheUserIDs  []string
	cacheGroupIDs []string
}

// oktaSelfHref reads the `self` href from a HAL `_links` value. GetSelf/GetHref
// are pointer-receiver methods on the OpenAPI-generated types, so the value is
// bound to an addressable local first.
func oktaSelfHref(l okta.LinksSelf) string {
	s := l.GetSelf()
	return s.GetHref()
}

// oktaResourceSelfHref reads the self link of a resource-set resource, whose
// links object is typed separately from the shared self-link one.
func oktaResourceSelfHref(l okta.ResourceSetResourceLinks) string {
	s := l.GetSelf()
	return s.GetHref()
}

func (o *mqlOkta) resourceSets() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.RoleCResourceSetAPI.ListResourceSets(ctx).Execute()
	if err != nil {
		// Resource sets require custom admin roles to be enabled for the org.
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	if slice == nil {
		return nil, nil
	}

	list := []any{}
	appendEntry := func(datalist []okta.ResourceSet) error {
		for i := range datalist {
			r, err := newMqlOktaResourceSet(o.MqlRuntime, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(slice.ResourceSets); err != nil {
		return nil, err
	}
	for resp != nil && resp.HasNextPage() {
		var page okta.ResourceSets
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page.ResourceSets); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func initOktaResourceSet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
	set, resp, err := client.RoleCResourceSetAPI.GetResourceSet(ctx, id).Execute()
	if err != nil {
		if isOktaNotFound(resp) {
			return nil, nil, fmt.Errorf("%w: okta.resourceSet %q", errOktaResourceNotFound, id)
		}
		return nil, nil, err
	}
	if set == nil {
		return args, nil, nil
	}

	maps.Copy(args, oktaResourceSetArgs(set))
	return args, nil, nil
}

func oktaResourceSetArgs(entry *okta.ResourceSet) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":    llx.StringData(oktaStr(entry.Id)),
		"label": llx.StringData(oktaStr(entry.Label)),
		// The resource set types this field, unlike the resources inside it.
		"description": llx.StringData(oktaStr(entry.Description)),
		"created":     llx.TimeDataPtr(entry.Created),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
	}
}

func newMqlOktaResourceSet(runtime *plugin.Runtime, entry *okta.ResourceSet) (any, error) {
	return CreateResource(runtime, "okta.resourceSet", oktaResourceSetArgs(entry))
}

func (o *mqlOktaResourceSet) id() (string, error) {
	return "okta.resourceSet/" + o.Id.Data, o.Id.Error
}

func (o *mqlOktaResourceSet) resources() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	setID := o.Id.Data
	page, resp, err := client.RoleCResourceSetResourceAPI.ListResourceSetResources(ctx, setID).Execute()
	if err != nil {
		return nil, err
	}
	if page == nil {
		return nil, nil
	}

	list := []any{}
	appendEntry := func(datalist []okta.ResourceSetResource) error {
		for i := range datalist {
			r, err := newMqlOktaResourceSetResource(o.MqlRuntime, setID, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(page.Resources); err != nil {
		return nil, err
	}
	for resp != nil && resp.HasNextPage() {
		var next okta.ResourceSetResources
		resp, err = resp.Next(&next)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(next.Resources); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func newMqlOktaResourceSetResource(runtime *plugin.Runtime, setID string, entry *okta.ResourceSetResource) (any, error) {
	href := oktaResourceSelfHref(entry.GetLinks())
	orn := oktaStr(entry.Orn)
	targetType, targetID := resolveOktaResourceTarget(orn, href)

	// Exclusions narrow what the entry actually grants. An absent conditions
	// block means nothing is carved out, which is an empty list rather than a
	// null: the API answered, and the answer is "none".
	excluded := []any{}
	if entry.Conditions != nil && entry.Conditions.Exclude != nil {
		for _, orn := range entry.Conditions.Exclude.OktaORN {
			excluded = append(excluded, orn)
		}
	}

	resourceID := oktaStr(entry.Id)
	r, err := CreateResource(runtime, "okta.resourceSet.resource", map[string]*llx.RawData{
		"__id":         llx.StringData(fmt.Sprintf("%s/%s", setID, resourceID)),
		"id":           llx.StringData(resourceID),
		"description":  llx.StringData(oktaStrFrom(entry.AdditionalProperties["description"])),
		"href":         llx.StringData(href),
		"orn":          llx.StringData(orn),
		"excludedOrns": llx.ArrayData(excluded, types.String),
	})
	if err != nil {
		return nil, err
	}
	res := r.(*mqlOktaResourceSetResource)
	res.cacheTargetType = targetType
	res.cacheTargetID = targetID
	return res, nil
}

func (o *mqlOktaResourceSet) bindings() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	setID := o.Id.Data
	page, resp, err := client.RoleDResourceSetBindingAPI.ListBindings(ctx, setID).Execute()
	if err != nil {
		return nil, err
	}
	if page == nil {
		return nil, nil
	}

	roles := page.Roles
	for resp != nil && resp.HasNextPage() {
		var next okta.ResourceSetBindings
		resp, err = resp.Next(&next)
		if err != nil {
			return nil, err
		}
		roles = append(roles, next.Roles...)
	}

	list := []any{}
	for i := range roles {
		roleID := roles[i].GetId()
		userIDs, groupIDs, err := o.bindingMembers(ctx, client, setID, roleID)
		if err != nil {
			return nil, err
		}
		r, err := CreateResource(o.MqlRuntime, "okta.resourceSet.binding", map[string]*llx.RawData{
			"__id": llx.StringData(fmt.Sprintf("%s/%s", setID, roleID)),
			"id":   llx.StringData(roleID),
		})
		if err != nil {
			return nil, err
		}
		binding := r.(*mqlOktaResourceSetBinding)
		binding.cacheUserIDs = userIDs
		binding.cacheGroupIDs = groupIDs
		list = append(list, binding)
	}
	return list, nil
}

// bindingMembers lists the members of a single binding and partitions them into
// user and group ids by resolving each member's self-link.
func (o *mqlOktaResourceSet) bindingMembers(ctx context.Context, client *okta.APIClient, setID, roleID string) (userIDs []string, groupIDs []string, err error) {
	page, resp, err := client.RoleDResourceSetBindingMemberAPI.ListMembersOfBinding(ctx, setID, roleID).Execute()
	if err != nil {
		return nil, nil, err
	}
	if page == nil {
		return nil, nil, nil
	}

	partition := func(members []okta.ResourceSetBindingMember) {
		for i := range members {
			href := oktaSelfHref(members[i].GetLinks())
			var orn string
			if members[i].AdditionalProperties != nil {
				if v, ok := members[i].AdditionalProperties["orn"].(string); ok {
					orn = v
				}
			}
			switch t, id := resolveOktaResourceTarget(orn, href); t {
			case "user":
				userIDs = append(userIDs, id)
			case "group":
				groupIDs = append(groupIDs, id)
			}
		}
	}

	partition(page.Members)
	for resp != nil && resp.HasNextPage() {
		var next okta.ResourceSetBindingMembers
		resp, err = resp.Next(&next)
		if err != nil {
			return nil, nil, err
		}
		partition(next.Members)
	}
	return userIDs, groupIDs, nil
}

// --- okta.resourceSet.resource typed target references ---

func (o *mqlOktaResourceSetResource) group() (*mqlOktaGroup, error) {
	if o.cacheTargetType != "group" {
		o.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveOktaGroupRef(o.MqlRuntime, o.cacheTargetID, &o.Group)
}

func (o *mqlOktaResourceSetResource) application() (*mqlOktaApplication, error) {
	if o.cacheTargetType != "application" {
		o.Application.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveOktaApplicationRef(o.MqlRuntime, o.cacheTargetID, &o.Application)
}

func (o *mqlOktaResourceSetResource) user() (*mqlOktaUser, error) {
	if o.cacheTargetType != "user" {
		o.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveOktaUserRef(o.MqlRuntime, o.cacheTargetID, &o.User)
}

// --- okta.resourceSet.binding typed references ---

func (o *mqlOktaResourceSetBinding) customRole() (*mqlOktaCustomRole, error) {
	return resolveOktaCustomRoleRef(o.MqlRuntime, o.Id.Data, &o.CustomRole)
}

func (o *mqlOktaResourceSetBinding) users() ([]any, error) {
	return resolveOktaUserRefs(o.MqlRuntime, o.cacheUserIDs)
}

func (o *mqlOktaResourceSetBinding) groups() ([]any, error) {
	return resolveOktaGroupRefs(o.MqlRuntime, o.cacheGroupIDs)
}

// --- shared typed-reference resolvers ---

// Every resolver below reads the reference back through NewResource, which runs
// the target's init and therefore issues a fetch. A reference can outlive the
// object it names (a deleted user), point at something Okta does not serve from
// the collection endpoint (an internal application), or carry a principal id
// that is not the kind being resolved at all -- `createdBy` on an Okta-managed
// object holds a system principal id, not a user id. All three come back as a
// 404, and none of them is a reason to fail the collection the reference was
// read from, so they resolve to a null field instead.

func resolveOktaUserRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOktaUser]) (*mqlOktaUser, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(runtime, "okta.user", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		if errors.Is(err, errOktaResourceNotFound) {
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlOktaUser), nil
}

func resolveOktaGroupRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOktaGroup]) (*mqlOktaGroup, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(runtime, "okta.group", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		if errors.Is(err, errOktaResourceNotFound) {
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlOktaGroup), nil
}

func resolveOktaApplicationRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOktaApplication]) (*mqlOktaApplication, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(runtime, "okta.application", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		if errors.Is(err, errOktaResourceNotFound) {
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlOktaApplication), nil
}

func resolveOktaCustomRoleRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOktaCustomRole]) (*mqlOktaCustomRole, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(runtime, "okta.customRole", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		if errors.Is(err, errOktaResourceNotFound) {
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlOktaCustomRole), nil
}

func resolveOktaUserTypeRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOktaUserType]) (*mqlOktaUserType, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(runtime, "okta.userType", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		if errors.Is(err, errOktaResourceNotFound) {
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlOktaUserType), nil
}

func resolveOktaRealmRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOktaRealm]) (*mqlOktaRealm, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(runtime, "okta.realm", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		if errors.Is(err, errOktaResourceNotFound) {
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return r.(*mqlOktaRealm), nil
}

// The plural resolvers drop members the org no longer has rather than failing
// the list, so one stale member id does not hide every other member alongside
// it.

func resolveOktaUserRefs(runtime *plugin.Runtime, ids []string) ([]any, error) {
	list := make([]any, 0, len(ids))
	for _, id := range ids {
		r, err := NewResource(runtime, "okta.user", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			if errors.Is(err, errOktaResourceNotFound) {
				continue
			}
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func resolveOktaGroupRefs(runtime *plugin.Runtime, ids []string) ([]any, error) {
	list := make([]any, 0, len(ids))
	for _, id := range ids {
		r, err := NewResource(runtime, "okta.group", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			if errors.Is(err, errOktaResourceNotFound) {
				continue
			}
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

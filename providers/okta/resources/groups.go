// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"maps"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
)

func (o *mqlOkta) groups() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.GroupAPI.ListGroups(ctx).Limit(queryLimit).Execute()
	if err != nil {
		return nil, err
	}

	if len(slice) == 0 {
		return nil, nil
	}

	list := []any{}
	appendEntry := func(datalist []okta.Group) error {
		for i := range datalist {
			r, err := newMqlOktaGroup(o.MqlRuntime, &datalist[i])
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
		var slice []okta.Group
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

func initOktaGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
	group, resp, err := client.GroupAPI.GetGroup(ctx, id).Execute()
	if err != nil {
		if isOktaNotFound(resp) {
			return nil, nil, fmt.Errorf("%w: okta.group %q", errOktaResourceNotFound, id)
		}
		return nil, nil, err
	}

	groupArgs, err := oktaGroupArgs(group)
	if err != nil {
		return nil, nil, err
	}
	maps.Copy(args, groupArgs)
	return args, nil, nil
}

func oktaGroupArgs(entry *okta.Group) (map[string]*llx.RawData, error) {
	profile, err := convert.JsonToDict(entry.Profile)
	if err != nil {
		return nil, err
	}

	name, description := oktaGroupProfileNameAndDescription(entry.Profile)

	return map[string]*llx.RawData{
		"id":                    llx.StringData(oktaStr(entry.Id)),
		"name":                  llx.StringData(name),
		"description":           llx.StringData(description),
		"type":                  llx.StringData(oktaStr(entry.Type)),
		"created":               llx.TimeDataPtr(entry.Created),
		"lastMembershipUpdated": llx.TimeDataPtr(entry.LastMembershipUpdated),
		"lastUpdated":           llx.TimeDataPtr(entry.LastUpdated),
		"profile":               llx.DictData(profile),
	}, nil
}

// oktaGroupProfileNameAndDescription reads the name and description out of a
// group profile. The profile is a union of an Okta-sourced group and one
// mastered by Active Directory; both carry the two fields, so either member
// answers. A profile of neither kind yields empty values.
func oktaGroupProfileNameAndDescription(profile *okta.GroupProfile) (name, description string) {
	if profile == nil {
		return "", ""
	}
	switch {
	case profile.OktaUserGroupProfile != nil:
		return oktaStr(profile.OktaUserGroupProfile.Name),
			oktaStr(profile.OktaUserGroupProfile.Description)
	case profile.OktaActiveDirectoryGroupProfile != nil:
		return oktaStr(profile.OktaActiveDirectoryGroupProfile.Name),
			oktaStr(profile.OktaActiveDirectoryGroupProfile.Description)
	default:
		return "", ""
	}
}

func newMqlOktaGroup(runtime *plugin.Runtime, entry *okta.Group) (any, error) {
	args, err := oktaGroupArgs(entry)
	if err != nil {
		return nil, err
	}
	return CreateResource(runtime, "okta.group", args)
}

func (o *mqlOktaGroup) id() (string, error) {
	return "okta.group/" + o.Id.Data, o.Id.Error
}

func (o *mqlOktaGroup) members() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	groupID := o.Id.Data
	slice, resp, err := client.GroupAPI.ListGroupUsers(ctx, groupID).Limit(queryLimit).Execute()
	if err != nil {
		return nil, err
	}

	if len(slice) == 0 {
		return nil, nil
	}

	list := []any{}
	appendEntry := func(datalist []okta.User) error {
		for i := range datalist {
			r, err := newMqlOktaUser(o.MqlRuntime, &datalist[i])
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
		var slice []okta.User
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

func (o *mqlOktaGroup) roles() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	groupID := o.Id.Data
	slice, resp, err := client.RoleAssignmentBGroupAPI.ListGroupAssignedRoles(ctx, groupID).Execute()
	if err != nil {
		return nil, err
	}

	if len(slice) == 0 {
		return nil, nil
	}

	list := []any{}
	appendEntry := func(datalist []okta.ListGroupAssignedRoles200ResponseInner) error {
		for i := range datalist {
			r, err := newMqlOktaAssignedRole(o.MqlRuntime, &datalist[i], "group", o.Id.Data)
			if err != nil {
				return err
			}
			if r == nil {
				log.Warn().Str("group", o.Id.Data).
					Msg("skipping a role assignment of an unrecognized kind")
				continue
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
		var slice []okta.ListGroupAssignedRoles200ResponseInner
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

// applications lists every application the group grants. Okta answers with the
// full application records rather than with ids, so the reverse edge costs one
// request per group instead of one per application behind it.
func (o *mqlOktaGroup) applications() ([]any, error) {
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	if o.Id.Data == "" {
		return []any{}, nil
	}

	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	slice, resp, err := client.GroupAPI.
		ListAssignedApplicationsForGroup(ctx, o.Id.Data).
		Limit(queryLimit).
		Execute()
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			return oktaUnreadableList(&o.Applications)
		}
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.ListApplications200ResponseInner) error {
		for i := range datalist {
			app, err := oktaApplicationFromUnion(datalist[i])
			if err != nil {
				return err
			}
			r, err := newMqlOktaApplication(o.MqlRuntime, app)
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
		var page []okta.ListApplications200ResponseInner
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

func (o *mqlOkta) groupRules() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.GroupRuleAPI.ListGroupRules(ctx).Limit(queryLimit).Execute()
	if err != nil {
		return nil, err
	}

	if len(slice) == 0 {
		return nil, nil
	}

	list := []any{}
	appendEntry := func(datalist []okta.GroupRule) error {
		for i := range datalist {
			r, err := newMqlOktaGroupRule(o.MqlRuntime, &datalist[i])
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
		var slice []okta.GroupRule
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

func newMqlOktaGroupRule(runtime *plugin.Runtime, entry *okta.GroupRule) (any, error) {
	return CreateResource(runtime, "okta.groupRule", map[string]*llx.RawData{
		"id":     llx.StringData(oktaStr(entry.Id)),
		"name":   llx.StringData(oktaStr(entry.Name)),
		"status": llx.StringData(oktaStr(entry.Status)),
		"type":   llx.StringData(oktaStr(entry.Type)),
	})
}

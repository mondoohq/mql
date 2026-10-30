// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"

	"github.com/databricks/databricks-sdk-go/service/compute"
	"github.com/databricks/databricks-sdk-go/service/domains"
	"github.com/databricks/databricks-sdk-go/service/iam"
	"github.com/databricks/databricks-sdk-go/service/provisioning"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// mqlDatabricksInternal caches account- and workspace-wide listings on the root
// databricks resource so cross-references resolve them once per scan rather than
// issuing one lookup per referring resource. Each cache is a list-once map keyed
// by the referenced resource's id.
type mqlDatabricksInternal struct {
	groupsOnce sync.Once
	groupsByID map[string]iam.Group
	groupsErr  error

	policiesOnce sync.Once
	policiesByID map[string]compute.Policy
	policiesErr  error

	instanceProfilesOnce  sync.Once
	instanceProfilesByARN map[string]compute.InstanceProfile
	instanceProfilesErr   error

	instancePoolsOnce sync.Once
	instancePoolList  []compute.InstancePoolAndStats
	instancePoolsByID map[string]compute.InstancePoolAndStats
	instancePoolsErr  error

	networksOnce sync.Once
	networksByID map[string]provisioning.Network
	networksErr  error

	privateAccessOnce sync.Once
	privateAccessByID map[string]provisioning.PrivateAccessSettings
	privateAccessErr  error

	domainsOnce sync.Once
	domainList  []domains.Domain
	domainsByID map[string]domains.Domain
	domainsErr  error
}

// cachedAccountGroups lists the account groups at most once per scan, caching
// the result on the root databricks resource so repeated group-ref resolutions
// (e.g. databricks.users { groups }) share a single ListAll rather than one per
// user or service principal.
func cachedAccountGroups(runtime *plugin.Runtime) (map[string]iam.Group, error) {
	rootRes, err := NewResource(runtime, "databricks", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	root := rootRes.(*mqlDatabricks)
	root.groupsOnce.Do(func() {
		acc, err := accountClient(runtime)
		if err != nil {
			root.groupsErr = err
			return
		}
		groups, err := acc.Groups.ListAll(context.Background(), iam.ListAccountGroupsRequest{})
		if err != nil {
			root.groupsErr = err
			return
		}
		byID := make(map[string]iam.Group, len(groups))
		for i := range groups {
			byID[groups[i].Id] = groups[i]
		}
		root.groupsByID = byID
	})
	return root.groupsByID, root.groupsErr
}

type mqlDatabricksUserInternal struct {
	cacheGroupIds []string
}

type mqlDatabricksServicePrincipalInternal struct {
	cacheGroupIds []string
}

// complexValueIds extracts the referenced ids (the value field) from a SCIM
// complex-value list such as a principal's group memberships.
func complexValueIds(vals []iam.ComplexValue) []string {
	out := make([]string, 0, len(vals))
	for i := range vals {
		if vals[i].Value != "" {
			out = append(out, vals[i].Value)
		}
	}
	return out
}

// resolveGroupRefs hydrates each account group id into a databricks.group. It
// lists the account groups once and resolves each membership from that set
// (Pattern C) rather than one GetById per id (N+1). A membership whose group was
// deleted after it was recorded is simply skipped.
func resolveGroupRefs(runtime *plugin.Runtime, ids []string) ([]any, error) {
	if len(ids) == 0 {
		return []any{}, nil
	}
	byID, err := cachedAccountGroups(runtime)
	if err != nil {
		return nil, err
	}

	out := []any{}
	for _, id := range ids {
		g, ok := byID[id]
		if !ok {
			continue
		}
		res, err := newMqlDatabricksGroup(runtime, g)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDatabricks) users() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	users, err := acc.Users.ListAll(context.Background(), iam.ListAccountUsersRequest{})
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range users {
		mqlUser, err := newMqlDatabricksUser(r.MqlRuntime, users[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlUser)
	}
	return list, nil
}

func newMqlDatabricksUser(runtime *plugin.Runtime, user iam.User) (*mqlDatabricksUser, error) {
	emails := []any{}
	for i := range user.Emails {
		if user.Emails[i].Value != "" {
			emails = append(emails, user.Emails[i].Value)
		}
	}

	res, err := CreateResource(runtime, "databricks.user", map[string]*llx.RawData{
		"__id":         llx.StringData("databricks.user/" + user.Id),
		"id":           llx.StringData(user.Id),
		"userName":     llx.StringData(user.UserName),
		"displayName":  llx.StringData(user.DisplayName),
		"active":       llx.BoolData(user.Active),
		"externalId":   llx.StringData(user.ExternalId),
		"emails":       llx.ArrayData(emails, types.String),
		"entitlements": llx.ArrayData(complexValues(user.Entitlements), types.String),
		"roles":        llx.ArrayData(complexValues(user.Roles), types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlUser := res.(*mqlDatabricksUser)
	mqlUser.cacheGroupIds = complexValueIds(user.Groups)
	return mqlUser, nil
}

// groups resolves the account groups this user belongs to, hydrated by id
// through the group's init.
func (r *mqlDatabricksUser) groups() ([]any, error) {
	return resolveGroupRefs(r.MqlRuntime, r.cacheGroupIds)
}

func (r *mqlDatabricks) groups() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	groups, err := acc.Groups.ListAll(context.Background(), iam.ListAccountGroupsRequest{})
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range groups {
		res, err := newMqlDatabricksGroup(r.MqlRuntime, groups[i])
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// newMqlDatabricksGroup maps an account group to its resource. Shared by the
// list path and the init lookup so a group hydrated by id carries the same
// fields as a listed one.
func newMqlDatabricksGroup(runtime *plugin.Runtime, group iam.Group) (*mqlDatabricksGroup, error) {
	res, err := CreateResource(runtime, "databricks.group", map[string]*llx.RawData{
		"__id":         llx.StringData("databricks.group/" + group.Id),
		"id":           llx.StringData(group.Id),
		"displayName":  llx.StringData(group.DisplayName),
		"externalId":   llx.StringData(group.ExternalId),
		"members":      llx.ArrayData(complexValues(group.Members), types.String),
		"entitlements": llx.ArrayData(complexValues(group.Entitlements), types.String),
		"roles":        llx.ArrayData(complexValues(group.Roles), types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksGroup), nil
}

// initDatabricksGroup resolves a single account group by id so typed references
// (such as databricks.user.groups) can hydrate a full group from just its id.
func initDatabricksGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, _ := idRaw.Value.(string)
	if id == "" {
		return nil, nil, fmt.Errorf("databricks.group requires a non-empty id")
	}

	acc, err := accountClient(runtime)
	if err != nil {
		return nil, nil, err
	}
	group, err := acc.Groups.GetById(context.Background(), id)
	if err != nil {
		return nil, nil, err
	}
	res, err := newMqlDatabricksGroup(runtime, *group)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlDatabricks) servicePrincipals() ([]any, error) {
	acc, err := accountClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	sps, err := acc.ServicePrincipals.ListAll(context.Background(), iam.ListAccountServicePrincipalsRequest{})
	if err != nil {
		return nil, err
	}

	list := []any{}
	for i := range sps {
		sp := sps[i]
		res, err := CreateResource(r.MqlRuntime, "databricks.servicePrincipal", map[string]*llx.RawData{
			"__id":          llx.StringData("databricks.servicePrincipal/" + sp.Id),
			"id":            llx.StringData(sp.Id),
			"applicationId": llx.StringData(sp.ApplicationId),
			"displayName":   llx.StringData(sp.DisplayName),
			"active":        llx.BoolData(sp.Active),
			"externalId":    llx.StringData(sp.ExternalId),
			"entitlements":  llx.ArrayData(complexValues(sp.Entitlements), types.String),
			"roles":         llx.ArrayData(complexValues(sp.Roles), types.String),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlDatabricksServicePrincipal).cacheGroupIds = complexValueIds(sp.Groups)
		list = append(list, res)
	}
	return list, nil
}

// groups resolves the account groups this service principal belongs to,
// hydrated by id through the group's init.
func (r *mqlDatabricksServicePrincipal) groups() ([]any, error) {
	return resolveGroupRefs(r.MqlRuntime, r.cacheGroupIds)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/auth0/go-auth0/management"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/auth0/connection"
	"go.mondoo.com/mql/types"
)

// users lists the accounts held in the tenant's database connections.
func (a *mqlAuth0) users() ([]any, error) {
	conn := a.conn()
	client := conn.Client()

	var all []any
	page := 0
	for {
		list, err := client.User.List(context.Background(),
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, u := range list.Users {
			r, err := newMqlAuth0User(a.MqlRuntime, u)
			if err != nil {
				return nil, err
			}
			all = append(all, r)
		}
		if !list.HasNext() {
			break
		}
		page++
	}
	return all, nil
}

// newMqlAuth0User maps a single SDK user to its MQL resource.
func newMqlAuth0User(runtime *plugin.Runtime, u *management.User) (plugin.Resource, error) {
	identities, err := convert.JsonToDictSlice(u.Identities)
	if err != nil {
		return nil, err
	}

	var appMetadata, userMetadata any
	if u.AppMetadata != nil {
		appMetadata = *u.AppMetadata
	}
	if u.UserMetadata != nil {
		userMetadata = *u.UserMetadata
	}

	r, err := CreateResource(runtime, "auth0.user", map[string]*llx.RawData{
		"id":            llx.StringDataPtr(u.ID),
		"email":         llx.StringDataPtr(u.Email),
		"emailVerified": llx.BoolDataPtr(u.EmailVerified),
		"name":          llx.StringDataPtr(u.Name),
		"username":      llx.StringDataPtr(u.Username),
		"phoneNumber":   llx.StringDataPtr(u.PhoneNumber),
		"phoneVerified": llx.BoolDataPtr(u.PhoneVerified),
		"blocked":       llx.BoolDataPtr(u.Blocked),
		"createdAt":     llx.TimeDataPtr(u.CreatedAt),
		"updatedAt":     llx.TimeDataPtr(u.UpdatedAt),
		"lastLogin":     llx.TimeDataPtr(u.LastLogin),
		"lastIp":        llx.StringDataPtr(u.LastIP),
		"loginsCount":   llx.IntDataPtr(u.LoginsCount),
		"multifactor":   llx.ArrayData(strList(u.Multifactor), types.String),
		"identities":    llx.ArrayData(identities, types.Dict),
		"appMetadata":   llx.DictData(appMetadata),
		"userMetadata":  llx.DictData(userMetadata),
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// initAuth0User resolves a user by its user ID on demand, for typed references
// (e.g. auth0.organization.members) and direct lookups.
func initAuth0User(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// fast path: the caller already provided a fully populated resource
	if len(args) > 2 {
		return args, nil, nil
	}

	idArg, ok := args["id"]
	if !ok {
		return nil, nil, fmt.Errorf("auth0.user requires an id argument")
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return nil, nil, fmt.Errorf("auth0.user requires a valid id")
	}

	conn := runtime.Connection.(*connection.Auth0Connection)
	u, err := conn.Client().User.Read(context.Background(), id)
	if err != nil {
		return nil, nil, fmt.Errorf("auth0.user with id %q not found: %w", id, err)
	}

	res, err := newMqlAuth0User(runtime, u)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// roles resolves the administrative and application roles granted to the user.
func (u *mqlAuth0User) roles() ([]any, error) {
	conn := u.MqlRuntime.Connection.(*connection.Auth0Connection)
	client := conn.Client()

	var all []any
	page := 0
	for {
		list, err := client.User.Roles(context.Background(), u.Id.Data,
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, role := range list.Roles {
			r, err := newMqlAuth0Role(u.MqlRuntime, role)
			if err != nil {
				return nil, err
			}
			all = append(all, r)
		}
		if !list.HasNext() {
			break
		}
		page++
	}
	return all, nil
}

func (r *mqlAuth0User) id() (string, error) {
	return "auth0.user/" + r.Id.Data, nil
}

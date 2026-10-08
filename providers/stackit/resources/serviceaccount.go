// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	serviceaccount "github.com/stackitcloud/stackit-sdk-go/services/serviceaccount/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func (r *mqlStackit) serviceAccounts() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ServiceAccount()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListServiceAccounts(bgctx(), c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildServiceAccount(r.MqlRuntime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitServiceAccount) id() (string, error) {
	return "stackit.serviceAccount/" + r.Email.Data, nil
}

// memberships lists every role binding the service account holds across the
// STACKIT hierarchy, as the authorization service resolves it: bindings on
// this project and bindings inherited from the folder or organization above
// it. This is the view roleBindings cannot give, since the project's member
// list holds direct bindings only. Empty when the credential may not read
// the account's memberships.
func (r *mqlStackitServiceAccount) memberships() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.Authorization()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListUserMemberships(bgctx(), r.Email.Data).Execute()
	if err != nil {
		if isNotFound(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := CreateResource(r.MqlRuntime, "stackit.iam.membership", iamMembershipArgs(&items[i], c.ProjectID()))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// roleBindings lists the project bindings whose subject is this service
// account, read off the member list the stackit.iam singleton already holds.
// Direct project bindings only: a role granted on the folder or organization
// is inherited by the project but does not appear in its member list.
func (r *mqlStackitServiceAccount) roleBindings() ([]any, error) {
	i, err := iamResource(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	members := i.GetMembers()
	if members.Error != nil {
		return nil, members.Error
	}
	return filterIamMembers(members.Data, func(m *mqlStackitIamMember) bool {
		return m.Subject.Data == r.Email.Data
	}), nil
}

func buildServiceAccount(runtime *plugin.Runtime, sa *serviceaccount.ServiceAccount) (plugin.Resource, error) {
	return CreateResource(runtime, "stackit.serviceAccount", map[string]*llx.RawData{
		"email":     llx.StringData(sa.GetEmail()),
		"projectId": llx.StringData(sa.GetProjectId()),
		"id":        llx.StringData(sa.GetId()),
		"internal":  llx.BoolData(sa.GetInternal()),
	})
}

func initStackitServiceAccount(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	email, ok := idArg(args, "email")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.ServiceAccount()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.ListServiceAccounts(bgctx(), c.ProjectID()).Execute()
	if err != nil {
		return nil, nil, err
	}
	items, _ := resp.GetItemsOk()
	for i := range items {
		if items[i].GetEmail() != email {
			continue
		}
		res, err := buildServiceAccount(runtime, &items[i])
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	}
	return nil, nil, fmt.Errorf("stackit.serviceAccount with email %q not found", email)
}

// accessTokens reports an empty list. STACKIT retired long-lived service
// account access tokens on 17 December 2025 and removed the access-token
// endpoints from the service account API (spec commits of 2026-08-27 and
// 2026-09-04), so no service account can hold one and there is nothing left
// to list. The field is kept, deprecated, so existing queries keep compiling;
// `keys` carries the successor credentials.
func (r *mqlStackitServiceAccount) accessTokens() ([]any, error) {
	return []any{}, nil
}

func (r *mqlStackitServiceAccount) keys() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ServiceAccount()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListServiceAccountKeys(bgctx(), r.ProjectId.Data, r.Email.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	out := make([]any, 0, len(items))
	for i := range items {
		out = append(out, serviceAccountKeyEntry(&items[i]))
	}
	return out, nil
}

// mqlStackitServiceAccountFederatedIdentityProviderInternal caches the owning
// service account's email so the back-reference resolves without the schema
// repeating it as a raw field.
type mqlStackitServiceAccountFederatedIdentityProviderInternal struct {
	cacheServiceAccountEmail string
}

func (r *mqlStackitServiceAccount) federatedIdentityProviders() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ServiceAccount()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListFederatedIdentityProviders(bgctx(), r.ProjectId.Data, r.Email.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		// A service account with federation never configured answers 404
		// rather than an empty list.
		if isNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}
	items, _ := resp.GetResourcesOk()
	out := make([]any, 0, len(items))
	for i := range items {
		fip := &items[i]
		createdAt, ok1 := fip.GetCreatedAtOk()
		updatedAt, ok2 := fip.GetUpdatedAtOk()

		assertions := make([]any, 0, len(fip.GetAssertions()))
		for _, a := range fip.GetAssertions() {
			assertions = append(assertions, map[string]any{
				"item":     a.GetItem(),
				"operator": a.GetOperator(),
				"value":    a.GetValue(),
			})
		}

		// the SDK marks the id optional, so fall back to the name, which is
		// unique per service account
		key := fip.GetId()
		if key == "" {
			key = fip.GetName()
		}

		args := map[string]*llx.RawData{
			// the provider is only unique within its service account, so the
			// cache key has to carry the account it belongs to
			"__id":       llx.StringData(qualifiedId("stackit.serviceAccount.federatedIdentityProvider", r.Email.Data, key)),
			"id":         llx.StringData(fip.GetId()),
			"name":       llx.StringData(fip.GetName()),
			"issuer":     llx.StringData(fip.GetIssuer()),
			"assertions": llx.ArrayData(assertions, types.Dict),
			"createdAt":  llx.TimeDataPtr(timeOrNil(createdAt, ok1)),
			"updatedAt":  llx.TimeDataPtr(timeOrNil(updatedAt, ok2)),
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.serviceAccount.federatedIdentityProvider", args)
		if err != nil {
			return nil, err
		}
		if mfip, ok := res.(*mqlStackitServiceAccountFederatedIdentityProvider); ok {
			mfip.cacheServiceAccountEmail = r.Email.Data
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitServiceAccountFederatedIdentityProvider) serviceAccount() (*mqlStackitServiceAccount, error) {
	if r.cacheServiceAccountEmail == "" {
		return markNull[mqlStackitServiceAccount](&r.ServiceAccount)
	}
	res, err := NewResource(r.MqlRuntime, "stackit.serviceAccount", map[string]*llx.RawData{
		"email": llx.StringData(r.cacheServiceAccountEmail),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitServiceAccount), nil
}

// serviceAccountKeyEntry maps a service-account key record into a dict-native
// map. The key* fields are named string enums in the SDK, cast to plain
// strings, and the timestamps are RFC3339 strings so the entry serializes
// cleanly for the `keys []dict` field (a `dict` cannot carry a *time.Time or a
// defined string type).
func serviceAccountKeyEntry(k *serviceaccount.ServiceAccountKeyListResponse) map[string]any {
	createdAt, ok1 := k.GetCreatedAtOk()
	validUntil, ok2 := k.GetValidUntilOk()
	return map[string]any{
		"id":           k.GetId(),
		"keyType":      string(k.GetKeyType()),
		"keyAlgorithm": string(k.GetKeyAlgorithm()),
		"keyOrigin":    string(k.GetKeyOrigin()),
		"active":       k.GetActive(),
		"createdAt":    rfc3339OrNil(createdAt, ok1),
		"validUntil":   rfc3339OrNil(validUntil, ok2),
	}
}

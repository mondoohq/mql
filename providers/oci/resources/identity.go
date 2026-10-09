// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciIdentity) id() (string, error) {
	return "oci.identity", nil
}

func (o *mqlOciIdentity) users() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociRunRegionPool(o.getUsers(conn))
}

func (s *mqlOciIdentity) listUsers(ctx context.Context, identityClient identity.IdentityClient, compartmentID string) ([]identity.User, error) {
	users, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]identity.User, *string, error) {
		request := identity.ListUsersRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := identityClient.ListUsers(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (o *mqlOciIdentity) getUsers(conn *connection.OciConnection) []*jobpool.Job {
	ctx := context.Background()
	// IAM is a global service: every regional identity endpoint serves the same
	// tenancy-wide set, so fanning out over regions returned each user once per
	// subscribed region. CreateResource hands back the cached instance for a
	// repeated __id, so the slice held N copies of one pointer and the counts
	// (and anything filtering them) were inflated N-fold.
	f := func() (jobpool.JobResult, error) {
		svc, err := conn.IdentityClient()
		if err != nil {
			return nil, err
		}

		var res []any
		users, err := o.listUsers(ctx, svc, conn.TenantID())
		if err != nil {
			return nil, err
		}

		for i := range users {
			user := users[i]

			if conn.Filters.IsFilteredOutByTags(user.FreeformTags, user.DefinedTags) {
				continue
			}

			var created *time.Time
			if user.TimeCreated != nil {
				created = &user.TimeCreated.Time
			}

			var lastLogin *time.Time
			if user.LastSuccessfulLoginTime != nil {
				lastLogin = &user.LastSuccessfulLoginTime.Time
			}

			var previousLogin *time.Time
			if user.PreviousSuccessfulLoginTime != nil {
				previousLogin = &user.PreviousSuccessfulLoginTime.Time
			}

			// Every key is always present: a missing key reads as null, and
			// `capabilities["a"] && capabilities["b"]` over two nulls
			// evaluates to true in MQL, so a user whose capabilities the
			// API omitted would silently pass a credential-capability check.
			capabilities := map[string]any{
				"canUseConsolePassword":         false,
				"canUseApiKeys":                 false,
				"canUseAuthTokens":              false,
				"canUseSmtpCredentials":         false,
				"canUseCustomerSecretKeys":      false,
				"canUseOAuth2ClientCredentials": false,
			}
			if user.Capabilities != nil {
				capabilities["canUseConsolePassword"] = boolValue(user.Capabilities.CanUseConsolePassword)
				capabilities["canUseApiKeys"] = boolValue(user.Capabilities.CanUseApiKeys)
				capabilities["canUseAuthTokens"] = boolValue(user.Capabilities.CanUseAuthTokens)
				capabilities["canUseSmtpCredentials"] = boolValue(user.Capabilities.CanUseSmtpCredentials)
				capabilities["canUseCustomerSecretKeys"] = boolValue(user.Capabilities.CanUseCustomerSecretKeys)
				capabilities["canUseOAuth2ClientCredentials"] = boolValue(user.Capabilities.CanUseOAuth2ClientCredentials)
			}

			mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.identity.user", stringValue(user.CompartmentId), map[string]*llx.RawData{
				"id":                 llx.StringDataPtr(user.Id),
				"name":               llx.StringDataPtr(user.Name),
				"description":        llx.StringDataPtr(user.Description),
				"created":            llx.TimeDataPtr(created),
				"state":              llx.StringData(string(user.LifecycleState)),
				"mfaActivated":       llx.BoolData(boolValue(user.IsMfaActivated)),
				"email":              llx.StringDataPtr(user.Email),
				"emailVerified":      llx.BoolData(boolValue(user.EmailVerified)),
				"externalIdentifier": llx.StringDataPtr(user.ExternalIdentifier),
				"capabilities":       llx.MapData(capabilities, types.Bool),
				"lastLogin":          llx.TimeDataPtr(lastLogin),
				"previousLogin":      llx.TimeDataPtr(previousLogin),
				"freeformTags":       llx.MapData(strMapToAny(user.FreeformTags), types.String),
				"definedTags":        llx.MapData(definedTagsToAny(user.DefinedTags), types.Any),
			})
			if err != nil {
				return nil, err
			}
			mqlInstance.(*mqlOciIdentityUser).cacheIdentityProviderID = stringValue(user.IdentityProviderId)
			res = append(res, mqlInstance)
		}

		return jobpool.JobResult(res), nil
	}
	return []*jobpool.Job{jobpool.NewJob(f)}
}

type mqlOciIdentityUserInternal struct {
	ociCompartmentRef
	cacheIdentityProviderID string
}

func (o *mqlOciIdentityUser) id() (string, error) {
	return "oci.identity.user/" + o.Id.Data, nil
}

// initOciIdentityUser resolves a single user resource when policies reference
// `oci.identity.user` on a discovered oci-identity-user asset. If the caller
// passes an explicit `id` we use it directly; otherwise we parse the
// connection's Conf.PlatformId to extract the OCID. Matching uses the existing
// listing path so we reuse the auth/pagination work done by `users()`.
func initOciIdentityUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Fully populated — nothing to do.
	if len(args) > 2 {
		return args, nil, nil
	}

	id := ociArgString(args, "id")
	if id == "" {
		conn := runtime.Connection.(*connection.OciConnection)
		if conn.Conf == nil || conn.Conf.PlatformId == "" {
			return args, nil, nil
		}
		parsed, ok := parseOciObjectPlatformID(conn.Conf.PlatformId)
		if !ok || parsed.service != "identity" || parsed.objectType != "user" {
			return args, nil, nil
		}
		id = parsed.id
	}

	res, err := findOciIdentityUser(runtime, id)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// findOciIdentityUser locates a user by OCID by materialising the tenancy's
// user list and filtering. We accept the list cost (typically small) to avoid
// duplicating the ListUsers/pagination/region-fanout logic.
func findOciIdentityUser(runtime *plugin.Runtime, id string) (plugin.Resource, error) {
	if id == "" {
		return nil, errors.New("id required to fetch oci.identity.user")
	}
	obj, err := CreateResource(runtime, "oci.identity", nil)
	if err != nil {
		return nil, err
	}
	identity := obj.(*mqlOciIdentity)
	list := identity.GetUsers()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, raw := range list.Data {
		user := raw.(*mqlOciIdentityUser)
		if user.Id.Data == id {
			return user, nil
		}
	}
	return nil, errors.New("oci.identity.user not found: " + id)
}

func (o *mqlOciIdentityUser) apiKeys() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	userId := o.Id.Data

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := client.ListApiKeys(ctx, identity.ListApiKeysRequest{
		UserId: common.String(userId),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range resp.Items {
		apikey := resp.Items[i]

		var created *time.Time
		if apikey.TimeCreated != nil {
			created = &apikey.TimeCreated.Time
		}

		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.identity.apiKey", map[string]*llx.RawData{
			"id":          llx.StringDataPtr(apikey.KeyId),
			"value":       llx.StringDataPtr(apikey.KeyValue),
			"fingerprint": llx.StringDataPtr(apikey.Fingerprint),
			"created":     llx.TimeDataPtr(created),
			"state":       llx.StringData(string(apikey.LifecycleState)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciIdentityApiKey) id() (string, error) {
	return "oci.identity.apiKey/" + o.Id.Data, nil
}

func (o *mqlOciIdentityUser) customerSecretKeys() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	userId := o.Id.Data

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := client.ListCustomerSecretKeys(ctx, identity.ListCustomerSecretKeysRequest{
		UserId: common.String(userId),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range resp.Items {
		secretKey := resp.Items[i]

		var created *time.Time
		if secretKey.TimeCreated != nil {
			created = &secretKey.TimeCreated.Time
		}

		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.identity.customerSecretKey", map[string]*llx.RawData{
			"id":      llx.StringDataPtr(secretKey.Id),
			"name":    llx.StringDataPtr(secretKey.DisplayName),
			"created": llx.TimeDataPtr(created),
			"state":   llx.StringData(string(secretKey.LifecycleState)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciIdentityCustomerSecretKey) id() (string, error) {
	return "oci.identity.customerSecretKey/" + o.Id.Data, nil
}

func (o *mqlOciIdentityUser) authTokens() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	userId := o.Id.Data

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := client.ListAuthTokens(ctx, identity.ListAuthTokensRequest{
		UserId: common.String(userId),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range resp.Items {
		authToken := resp.Items[i]

		var created *time.Time
		if authToken.TimeCreated != nil {
			created = &authToken.TimeCreated.Time
		}
		var expires *time.Time
		if authToken.TimeExpires != nil {
			expires = &authToken.TimeExpires.Time
		}

		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.identity.authToken", map[string]*llx.RawData{
			"id":          llx.StringDataPtr(authToken.Id),
			"description": llx.StringDataPtr(authToken.Description),
			"created":     llx.TimeDataPtr(created),
			"expires":     llx.TimeDataPtr(expires),
			"state":       llx.StringData(string(authToken.LifecycleState)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciIdentityAuthToken) id() (string, error) {
	return "oci.identity.authToken/" + o.Id.Data, nil
}

func (o *mqlOciIdentityUser) groups() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	userId := o.Id.Data
	compartmentID := o.cacheCompartmentID

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	grpMember := map[string]bool{}
	memberships, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]identity.UserGroupMembership, *string, error) {
		response, err := client.ListUserGroupMemberships(ctx, identity.ListUserGroupMembershipsRequest{
			CompartmentId: common.String(compartmentID),
			UserId:        common.String(userId),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}
	for i := range memberships {
		m := memberships[i]
		if m.GroupId != nil {
			grpMember[*m.GroupId] = true
		}
	}

	// fetch all groups and filter the groups
	obj, err := NewResource(o.MqlRuntime, "oci.identity", nil)
	if err != nil {
		return nil, err
	}
	ociIdentity := obj.(*mqlOciIdentity)
	list := ociIdentity.GetGroups()
	if list.Error != nil {
		return nil, list.Error
	}

	res := []any{}
	for i := range list.Data {
		grp := list.Data[i].(*mqlOciIdentityGroup)
		id := grp.Id.Data
		_, ok := grpMember[id]
		if ok {
			res = append(res, grp)
		}
	}

	return res, nil
}

func (o *mqlOciIdentity) groups() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociRunRegionPool(o.getGroups(conn))
}

func (s *mqlOciIdentity) listGroups(ctx context.Context, identityClient identity.IdentityClient, compartmentID string) ([]identity.Group, error) {
	groups, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]identity.Group, *string, error) {
		request := identity.ListGroupsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := identityClient.ListGroups(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func (o *mqlOciIdentity) getGroups(conn *connection.OciConnection) []*jobpool.Job {
	ctx := context.Background()
	// IAM is a global service: every regional identity endpoint serves the same
	// tenancy-wide set, so fanning out over regions returned each group once per
	// subscribed region. CreateResource hands back the cached instance for a
	// repeated __id, so the slice held N copies of one pointer and the counts
	// (and anything filtering them) were inflated N-fold.
	f := func() (jobpool.JobResult, error) {
		svc, err := conn.IdentityClient()
		if err != nil {
			return nil, err
		}

		var res []any
		groups, err := o.listGroups(ctx, svc, conn.TenantID())
		if err != nil {
			return nil, err
		}

		for i := range groups {
			grp := groups[i]

			var created *time.Time
			if grp.TimeCreated != nil {
				created = &grp.TimeCreated.Time
			}

			mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.identity.group", stringValue(grp.CompartmentId), map[string]*llx.RawData{
				"id":           llx.StringDataPtr(grp.Id),
				"name":         llx.StringDataPtr(grp.Name),
				"description":  llx.StringDataPtr(grp.Description),
				"created":      llx.TimeDataPtr(created),
				"state":        llx.StringData(string(grp.LifecycleState)),
				"freeformTags": llx.MapData(strMapToAny(grp.FreeformTags), types.String),
				"definedTags":  llx.MapData(definedTagsToAny(grp.DefinedTags), types.Any),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlInstance)
		}

		return jobpool.JobResult(res), nil
	}
	return []*jobpool.Job{jobpool.NewJob(f)}
}

func (o *mqlOciIdentityGroup) id() (string, error) {
	return "oci.identity.group/" + o.Id.Data, nil
}

// policies lists the IAM policies of every compartment the filters admit. A
// policy can be attached to any compartment, and ListPolicies answers for
// one, so asking only the tenancy root missed every policy attached lower in
// the tree. IAM is global, so there is no region dimension.
func (o *mqlOciIdentity) policies() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return ociCollectGlobal(o.MqlRuntime, func(ctx context.Context, compartmentID string) ([]any, error) {
		return o.policiesIn(ctx, conn, compartmentID)
	})
}

func (s *mqlOciIdentity) listPolicies(ctx context.Context, identityClient identity.IdentityClient, compartmentID string) ([]identity.Policy, error) {
	policies, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]identity.Policy, *string, error) {
		request := identity.ListPoliciesRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		}

		response, err := identityClient.ListPolicies(ctx, request)
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	return policies, nil
}

func (o *mqlOciIdentity) policiesIn(ctx context.Context, conn *connection.OciConnection, compartmentID string) ([]any, error) {
	{
		svc, err := conn.IdentityClient()
		if err != nil {
			return nil, err
		}

		var res []any
		policies, err := o.listPolicies(ctx, svc, compartmentID)
		if err != nil {
			return nil, err
		}

		for i := range policies {
			policy := policies[i]

			if conn.Filters.IsFilteredOutByTags(policy.FreeformTags, policy.DefinedTags) {
				continue
			}

			var created *time.Time
			if policy.TimeCreated != nil {
				created = &policy.TimeCreated.Time
			}

			var versionDate *time.Time
			if policy.VersionDate != nil {
				versionDate = &policy.VersionDate.Date
			}

			mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.identity.policy", stringValue(policy.CompartmentId), map[string]*llx.RawData{
				"id":           llx.StringDataPtr(policy.Id),
				"name":         llx.StringDataPtr(policy.Name),
				"description":  llx.StringDataPtr(policy.Description),
				"created":      llx.TimeDataPtr(created),
				"state":        llx.StringData(string(policy.LifecycleState)),
				"statements":   llx.ArrayData(convert.SliceAnyToInterface(policy.Statements), types.String),
				"versionDate":  llx.TimeDataPtr(versionDate),
				"freeformTags": llx.MapData(strMapToAny(policy.FreeformTags), types.String),
				"definedTags":  llx.MapData(definedTagsToAny(policy.DefinedTags), types.Any),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlInstance)
		}

		return res, nil
	}
}

func (o *mqlOciIdentityPolicy) id() (string, error) {
	return "oci.identity.policy/" + o.Id.Data, nil
}

// initOciIdentityPolicy mirrors initOciIdentityUser: explicit id wins, else
// fall back to the discovered asset's PlatformId to resolve the specific
// policy, else leave the resource unresolved (MQL will error if fields are
// read).
func initOciIdentityPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	id := ociArgString(args, "id")
	if id == "" {
		conn := runtime.Connection.(*connection.OciConnection)
		if conn.Conf == nil || conn.Conf.PlatformId == "" {
			return args, nil, nil
		}
		parsed, ok := parseOciObjectPlatformID(conn.Conf.PlatformId)
		if !ok || parsed.service != "identity" || parsed.objectType != "policy" {
			return args, nil, nil
		}
		id = parsed.id
	}

	obj, err := CreateResource(runtime, "oci.identity", nil)
	if err != nil {
		return nil, nil, err
	}
	identity := obj.(*mqlOciIdentity)
	list := identity.GetPolicies()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		policy := raw.(*mqlOciIdentityPolicy)
		if policy.Id.Data == id {
			return args, policy, nil
		}
	}
	return nil, nil, errors.New("oci.identity.policy not found: " + id)
}

func (o *mqlOciIdentityUser) mfaDevices() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	devices, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]identity.MfaTotpDeviceSummary, *string, error) {
		response, err := client.ListMfaTotpDevices(ctx, identity.ListMfaTotpDevicesRequest{
			UserId: common.String(o.Id.Data),
			Page:   page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(devices))
	for i := range devices {
		d := devices[i]

		var created *time.Time
		if d.TimeCreated != nil {
			created = &d.TimeCreated.Time
		}
		var expires *time.Time
		if d.TimeExpires != nil {
			expires = &d.TimeExpires.Time
		}

		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.identity.mfaDevice", map[string]*llx.RawData{
			"id":          llx.StringDataPtr(d.Id),
			"userId":      llx.StringDataPtr(d.UserId),
			"isActivated": llx.BoolDataPtr(d.IsActivated),
			"state":       llx.StringData(string(d.LifecycleState)),
			"created":     llx.TimeDataPtr(created),
			"expires":     llx.TimeDataPtr(expires),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciIdentityMfaDevice) id() (string, error) {
	return "oci.identity.mfaDevice/" + o.Id.Data, nil
}

func (o *mqlOciIdentityGroup) members() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	userMember := map[string]bool{}
	memberships, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]identity.UserGroupMembership, *string, error) {
		response, err := client.ListUserGroupMemberships(ctx, identity.ListUserGroupMembershipsRequest{
			CompartmentId: common.String(o.cacheCompartmentID),
			GroupId:       common.String(o.Id.Data),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}
	for i := range memberships {
		m := memberships[i]
		if m.UserId != nil {
			userMember[*m.UserId] = true
		}
	}

	obj, err := NewResource(o.MqlRuntime, "oci.identity", nil)
	if err != nil {
		return nil, err
	}
	ociIdentity := obj.(*mqlOciIdentity)
	list := ociIdentity.GetUsers()
	if list.Error != nil {
		return nil, list.Error
	}

	res := []any{}
	for i := range list.Data {
		user := list.Data[i].(*mqlOciIdentityUser)
		if userMember[user.Id.Data] {
			res = append(res, user)
		}
	}

	return res, nil
}

func (o *mqlOciIdentityUser) dbCredentials() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	creds, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]identity.DbCredentialSummary, *string, error) {
		resp, err := client.ListDbCredentials(ctx, identity.ListDbCredentialsRequest{
			UserId: common.String(o.Id.Data),
			Page:   page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range creds {
		cred := creds[i]

		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.identity.dbCredential", map[string]*llx.RawData{
			"id":          llx.StringDataPtr(cred.Id),
			"description": llx.StringDataPtr(cred.Description),
			"created":     sdkTimeData(cred.TimeCreated),
			"expires":     sdkTimeData(cred.TimeExpires),
			"state":       llx.StringData(string(cred.LifecycleState)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciIdentityDbCredential) id() (string, error) {
	return "oci.identity.dbCredential/" + o.Id.Data, nil
}

func (o *mqlOciIdentityUser) smtpCredentials() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	// ListSmtpCredentials returns the full set in a single response.
	resp, err := client.ListSmtpCredentials(context.Background(), identity.ListSmtpCredentialsRequest{
		UserId: common.String(o.Id.Data),
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(resp.Items))
	for i := range resp.Items {
		cred := resp.Items[i]

		mqlInstance, err := CreateResource(o.MqlRuntime, "oci.identity.smtpCredential", map[string]*llx.RawData{
			"id":          llx.StringDataPtr(cred.Id),
			"username":    llx.StringDataPtr(cred.Username),
			"description": llx.StringDataPtr(cred.Description),
			"created":     sdkTimeData(cred.TimeCreated),
			"expires":     sdkTimeData(cred.TimeExpires),
			"state":       llx.StringData(string(cred.LifecycleState)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciIdentitySmtpCredential) id() (string, error) {
	return "oci.identity.smtpCredential/" + o.Id.Data, nil
}

// ociOauthScope is the dict shape for an OAuth 2.0 client credential scope.
type ociOauthScope struct {
	Audience string `json:"audience"`
	Scope    string `json:"scope"`
}

func (o *mqlOciIdentityUser) oauth2ClientCredentials() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	creds, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]identity.OAuth2ClientCredentialSummary, *string, error) {
		resp, err := client.ListOAuthClientCredentials(ctx, identity.ListOAuthClientCredentialsRequest{
			UserId: common.String(o.Id.Data),
			Page:   page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range creds {
		cred := creds[i]

		scopes := make([]ociOauthScope, 0, len(cred.Scopes))
		for j := range cred.Scopes {
			s := cred.Scopes[j]
			scopes = append(scopes, ociOauthScope{
				Audience: stringValue(s.Audience),
				Scope:    stringValue(s.Scope),
			})
		}
		scopesDict, err := convert.JsonToDictSlice(scopes)
		if err != nil {
			return nil, err
		}

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.identity.oauth2ClientCredential", stringValue(cred.CompartmentId), map[string]*llx.RawData{
			"id":          llx.StringDataPtr(cred.Id),
			"name":        llx.StringDataPtr(cred.Name),
			"description": llx.StringDataPtr(cred.Description),
			"scopes":      llx.ArrayData(scopesDict, types.Dict),
			"created":     sdkTimeData(cred.TimeCreated),
			"expires":     sdkTimeData(cred.ExpiresOn),
			"state":       llx.StringData(string(cred.LifecycleState)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

type mqlOciIdentityOauth2ClientCredentialInternal struct {
	ociCompartmentRef
}

func (o *mqlOciIdentityOauth2ClientCredential) id() (string, error) {
	return "oci.identity.oauth2ClientCredential/" + o.Id.Data, nil
}

func (o *mqlOciIdentity) dynamicGroups() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	groups, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]identity.DynamicGroup, *string, error) {
		resp, err := client.ListDynamicGroups(ctx, identity.ListDynamicGroupsRequest{
			CompartmentId: common.String(conn.TenantID()),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range groups {
		dg := groups[i]

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.identity.dynamicGroup", stringValue(dg.CompartmentId), map[string]*llx.RawData{
			"id":           llx.StringDataPtr(dg.Id),
			"name":         llx.StringDataPtr(dg.Name),
			"description":  llx.StringDataPtr(dg.Description),
			"matchingRule": llx.StringDataPtr(dg.MatchingRule),
			"created":      sdkTimeData(dg.TimeCreated),
			"state":        llx.StringData(string(dg.LifecycleState)),
			"freeformTags": llx.MapData(strMapToAny(dg.FreeformTags), types.String),
			"definedTags":  llx.MapData(definedTagsToAny(dg.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciIdentityDynamicGroup) id() (string, error) {
	return "oci.identity.dynamicGroup/" + o.Id.Data, nil
}

func (o *mqlOciIdentity) identityProviders() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	providers, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]identity.IdentityProvider, *string, error) {
		// SAML2 is the only federation protocol the ListIdentityProviders API accepts.
		resp, err := client.ListIdentityProviders(ctx, identity.ListIdentityProvidersRequest{
			Protocol:      identity.ListIdentityProvidersProtocolSaml2,
			CompartmentId: common.String(conn.TenantID()),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range providers {
		idp := providers[i]

		args := map[string]*llx.RawData{
			"id":                 llx.StringDataPtr(idp.GetId()),
			"name":               llx.StringDataPtr(idp.GetName()),
			"description":        llx.StringDataPtr(idp.GetDescription()),
			"productType":        llx.StringDataPtr(idp.GetProductType()),
			"created":            sdkTimeData(idp.GetTimeCreated()),
			"state":              llx.StringData(string(idp.GetLifecycleState())),
			"freeformTags":       llx.MapData(strMapToAny(idp.GetFreeformTags()), types.String),
			"definedTags":        llx.MapData(definedTagsToAny(idp.GetDefinedTags()), types.Any),
			"protocol":           llx.StringData(""),
			"metadataUrl":        llx.StringData(""),
			"signingCertificate": llx.StringData(""),
			"redirectUrl":        llx.StringData(""),
		}
		if saml, ok := idp.(identity.Saml2IdentityProvider); ok {
			args["protocol"] = llx.StringData("SAML2")
			args["metadataUrl"] = llx.StringDataPtr(saml.MetadataUrl)
			args["signingCertificate"] = llx.StringDataPtr(saml.SigningCertificate)
			args["redirectUrl"] = llx.StringDataPtr(saml.RedirectUrl)
		} else {
			// SAML2 is the only protocol ListIdentityProviders accepts today;
			// warn if OCI ever returns another so the gap is noticed.
			log.Warn().Str("id", stringValue(idp.GetId())).
				Msgf("oci.identity.identityProvider: unexpected provider type %T, SAML2-specific fields left empty", idp)
		}

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.identity.identityProvider", stringValue(idp.GetCompartmentId()), args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciIdentityIdentityProvider) id() (string, error) {
	return "oci.identity.identityProvider/" + o.Id.Data, nil
}

// ociNetworkVirtualSource is the dict shape for a network source's
// virtual-source allowlist entry.
type ociNetworkVirtualSource struct {
	VcnId    string   `json:"vcnId"`
	IpRanges []string `json:"ipRanges"`
}

func (o *mqlOciIdentity) networkSources() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	res := []any{}
	sources, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]identity.NetworkSourcesSummary, *string, error) {
		resp, err := client.ListNetworkSources(ctx, identity.ListNetworkSourcesRequest{
			CompartmentId: common.String(conn.TenantID()),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	for i := range sources {
		ns := sources[i]

		virtual := make([]ociNetworkVirtualSource, 0, len(ns.VirtualSourceList))
		for j := range ns.VirtualSourceList {
			v := ns.VirtualSourceList[j]
			virtual = append(virtual, ociNetworkVirtualSource{
				VcnId:    stringValue(v.VcnId),
				IpRanges: v.IpRanges,
			})
		}
		virtualDict, err := convert.JsonToDictSlice(virtual)
		if err != nil {
			return nil, err
		}

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.identity.networkSource", stringValue(ns.CompartmentId), map[string]*llx.RawData{
			"id":                llx.StringDataPtr(ns.Id),
			"name":              llx.StringDataPtr(ns.Name),
			"description":       llx.StringDataPtr(ns.Description),
			"publicSourceList":  llx.ArrayData(stringsToAny(ns.PublicSourceList), types.String),
			"virtualSourceList": llx.ArrayData(virtualDict, types.Dict),
			"services":          llx.ArrayData(stringsToAny(ns.Services), types.String),
			"created":           sdkTimeData(ns.TimeCreated),
			"state":             llx.StringData(string(ns.LifecycleState)),
			"freeformTags":      llx.MapData(strMapToAny(ns.FreeformTags), types.String),
			"definedTags":       llx.MapData(definedTagsToAny(ns.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

func (o *mqlOciIdentityNetworkSource) id() (string, error) {
	return "oci.identity.networkSource/" + o.Id.Data, nil
}

// ociAuthenticationPolicyArgs fetches the tenancy authentication policy and
// returns it as MQL resource arguments. The OCI API always returns a policy
// for a tenancy, defaulting any unset password or network rule.
func ociAuthenticationPolicyArgs(client identity.IdentityClient, tenantID string) (map[string]*llx.RawData, error) {
	resp, err := client.GetAuthenticationPolicy(context.Background(), identity.GetAuthenticationPolicyRequest{
		CompartmentId: common.String(tenantID),
	})
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"compartmentID":             llx.StringData(tenantID),
		"minimumPasswordLength":     llx.IntData(0),
		"passwordRequiresUppercase": llx.BoolData(false),
		"passwordRequiresLowercase": llx.BoolData(false),
		"passwordRequiresNumeric":   llx.BoolData(false),
		"passwordRequiresSpecial":   llx.BoolData(false),
		// Unlike the passwordRequires* flags, false is the *permissive* value
		// here, so defaulting to false would let a missing password policy pass
		// a `passwordUsernameContainmentAllowed == false` check. OCI's own
		// service default is true, so an absent policy fails the check.
		"passwordUsernameContainmentAllowed": llx.BoolData(true),
		"networkSourceIds":                   llx.ArrayData([]any{}, types.String),
	}
	if pp := resp.PasswordPolicy; pp != nil {
		args["minimumPasswordLength"] = llx.IntData(intValue(pp.MinimumPasswordLength))
		args["passwordRequiresUppercase"] = llx.BoolData(boolValue(pp.IsUppercaseCharactersRequired))
		args["passwordRequiresLowercase"] = llx.BoolData(boolValue(pp.IsLowercaseCharactersRequired))
		args["passwordRequiresNumeric"] = llx.BoolData(boolValue(pp.IsNumericCharactersRequired))
		args["passwordRequiresSpecial"] = llx.BoolData(boolValue(pp.IsSpecialCharactersRequired))
		args["passwordUsernameContainmentAllowed"] = llx.BoolData(boolValue(pp.IsUsernameContainmentAllowed))
	}
	if np := resp.NetworkPolicy; np != nil {
		args["networkSourceIds"] = llx.ArrayData(stringsToAny(np.NetworkSourceIds), types.String)
	}
	return args, nil
}

func (o *mqlOciIdentity) authenticationPolicy() (*mqlOciIdentityAuthenticationPolicy, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	client, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	args, err := ociAuthenticationPolicyArgs(client, conn.TenantID())
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(o.MqlRuntime, "oci.identity.authenticationPolicy", args)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlOciIdentityAuthenticationPolicy), nil
}

// initOciIdentityAuthenticationPolicy resolves the tenancy authentication
// policy when it is queried directly as `oci.identity.authenticationPolicy`
// (the resource name and the field path collide, so MQL instantiates the
// resource rather than reading the `oci.identity` accessor).
func initOciIdentityAuthenticationPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// The `oci.identity` accessor already passes the full policy; only fetch
	// when the resource is instantiated bare (by name, with just `__id`).
	if _, ok := args["minimumPasswordLength"]; ok {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.OciConnection)
	client, err := conn.IdentityClient()
	if err != nil {
		return nil, nil, err
	}

	policyArgs, err := ociAuthenticationPolicyArgs(client, conn.TenantID())
	if err != nil {
		return nil, nil, err
	}
	return policyArgs, nil, nil
}

func (o *mqlOciIdentityAuthenticationPolicy) id() (string, error) {
	return "oci.identity.authenticationPolicy/" + o.CompartmentID.Data, nil
}

type mqlOciIdentityDynamicGroupInternal struct {
	ociCompartmentRef
}

type mqlOciIdentityGroupInternal struct {
	ociCompartmentRef
}

type mqlOciIdentityIdentityProviderInternal struct {
	ociCompartmentRef
}

type mqlOciIdentityNetworkSourceInternal struct {
	ociCompartmentRef
}

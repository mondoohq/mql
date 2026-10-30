// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"sync"
	"time"

	ramclient "github.com/alibabacloud-go/ram-20150501/v2/client"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// ramParseTime parses an Alibaba Cloud RFC3339 timestamp string, returning nil when
// the pointer is nil or the value cannot be parsed.
func ramParseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	return &t
}

// ramStrVal safely dereferences a *string, returning "" for a nil pointer.
func ramStrVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ramBoolPtrAny returns the bool value, or nil when the pointer is nil, so dict
// fields represent an absent value as null rather than false.
func ramBoolPtrAny(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// ramInt32PtrAny returns the int value as int64, or nil when the pointer is nil.
func ramInt32PtrAny(i *int32) any {
	if i == nil {
		return nil
	}
	return int64(*i)
}

// ramStrPtrAny returns the string value, or nil when the pointer is nil.
func ramStrPtrAny(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// ramPolicyAttachmentDict builds a dict describing a policy attached to a user,
// group, or role. The three ...ForUser/ForGroup/ForRole responses share this
// field shape.
func ramPolicyAttachmentDict(policyName, policyType, defaultVersion, description, attachDate *string) map[string]any {
	return map[string]any{
		"policyName":     ramStrVal(policyName),
		"policyType":     ramStrVal(policyType),
		"defaultVersion": ramStrVal(defaultVersion),
		"description":    ramStrVal(description),
		"attachDate":     ramStrVal(attachDate),
	}
}

func (r *mqlAlicloudRam) id() (string, error) {
	return "alicloud.ram", nil
}

func (r *mqlAlicloudRam) users() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	var marker *string
	for {
		resp, err := client.ListUsers(&ramclient.ListUsersRequest{Marker: marker})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.Users == nil {
			break
		}

		for _, u := range resp.Body.Users.User {
			if u == nil {
				continue
			}
			user, err := CreateResource(r.MqlRuntime, "alicloud.ram.user", map[string]*llx.RawData{
				"__id":        llx.StringData(ramStrVal(u.UserName)),
				"userId":      llx.StringDataPtr(u.UserId),
				"userName":    llx.StringDataPtr(u.UserName),
				"displayName": llx.StringDataPtr(u.DisplayName),
				"email":       llx.StringDataPtr(u.Email),
				"mobilePhone": llx.StringDataPtr(u.MobilePhone),
				"comments":    llx.StringDataPtr(u.Comments),
				"createDate":  llx.TimeDataPtr(ramParseTime(u.CreateDate)),
				"updateDate":  llx.TimeDataPtr(ramParseTime(u.UpdateDate)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, user)
		}

		if resp.Body.IsTruncated == nil || !*resp.Body.IsTruncated {
			break
		}
		marker = resp.Body.Marker
		if marker == nil || *marker == "" {
			break
		}
	}
	return res, nil
}

func (r *mqlAlicloudRam) groups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	var marker *string
	for {
		resp, err := client.ListGroups(&ramclient.ListGroupsRequest{Marker: marker})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.Groups == nil {
			break
		}

		for _, g := range resp.Body.Groups.Group {
			if g == nil {
				continue
			}
			group, err := CreateResource(r.MqlRuntime, "alicloud.ram.group", map[string]*llx.RawData{
				"__id":       llx.StringData(ramStrVal(g.GroupName)),
				"groupId":    llx.StringDataPtr(g.GroupId),
				"groupName":  llx.StringDataPtr(g.GroupName),
				"comments":   llx.StringDataPtr(g.Comments),
				"createDate": llx.TimeDataPtr(ramParseTime(g.CreateDate)),
				"updateDate": llx.TimeDataPtr(ramParseTime(g.UpdateDate)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, group)
		}

		if resp.Body.IsTruncated == nil || !*resp.Body.IsTruncated {
			break
		}
		marker = resp.Body.Marker
		if marker == nil || *marker == "" {
			break
		}
	}
	return res, nil
}

func (r *mqlAlicloudRam) roles() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	var marker *string
	for {
		resp, err := client.ListRoles(&ramclient.ListRolesRequest{Marker: marker})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.Roles == nil {
			break
		}

		for _, role := range resp.Body.Roles.Role {
			if role == nil {
				continue
			}

			tags := map[string]any{}
			if role.Tags != nil {
				for _, t := range role.Tags.Tag {
					if t == nil || t.TagKey == nil {
						continue
					}
					tags[*t.TagKey] = ramStrVal(t.TagValue)
				}
			}

			mqlRole, err := CreateResource(r.MqlRuntime, "alicloud.ram.role", map[string]*llx.RawData{
				"__id":               llx.StringData(ramStrVal(role.RoleName)),
				"roleId":             llx.StringDataPtr(role.RoleId),
				"roleName":           llx.StringDataPtr(role.RoleName),
				"arn":                llx.StringDataPtr(role.Arn),
				"description":        llx.StringDataPtr(role.Description),
				"createDate":         llx.TimeDataPtr(ramParseTime(role.CreateDate)),
				"updateDate":         llx.TimeDataPtr(ramParseTime(role.UpdateDate)),
				"maxSessionDuration": llx.IntDataPtr(role.MaxSessionDuration),
				"tags":               llx.MapData(tags, types.String),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRole)
		}

		if resp.Body.IsTruncated == nil || !*resp.Body.IsTruncated {
			break
		}
		marker = resp.Body.Marker
		if marker == nil || *marker == "" {
			break
		}
	}
	return res, nil
}

func (r *mqlAlicloudRam) policies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	var marker *string
	for {
		resp, err := client.ListPolicies(&ramclient.ListPoliciesRequest{Marker: marker})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.Policies == nil {
			break
		}

		for _, p := range resp.Body.Policies.Policy {
			if p == nil {
				continue
			}

			tags := map[string]any{}
			if p.Tags != nil {
				for _, t := range p.Tags.Tag {
					if t == nil || t.TagKey == nil {
						continue
					}
					tags[*t.TagKey] = ramStrVal(t.TagValue)
				}
			}

			mqlPolicy, err := CreateResource(r.MqlRuntime, "alicloud.ram.policy", map[string]*llx.RawData{
				"__id":            llx.StringData(ramStrVal(p.PolicyType) + "/" + ramStrVal(p.PolicyName)),
				"policyName":      llx.StringDataPtr(p.PolicyName),
				"policyType":      llx.StringDataPtr(p.PolicyType),
				"description":     llx.StringDataPtr(p.Description),
				"defaultVersion":  llx.StringDataPtr(p.DefaultVersion),
				"attachmentCount": llx.IntDataPtr(p.AttachmentCount),
				"createDate":      llx.TimeDataPtr(ramParseTime(p.CreateDate)),
				"updateDate":      llx.TimeDataPtr(ramParseTime(p.UpdateDate)),
				"tags":            llx.MapData(tags, types.String),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPolicy)
		}

		if resp.Body.IsTruncated == nil || !*resp.Body.IsTruncated {
			break
		}
		marker = resp.Body.Marker
		if marker == nil || *marker == "" {
			break
		}
	}
	return res, nil
}

func (r *mqlAlicloudRam) passwordPolicy() (*mqlAlicloudRamPasswordPolicy, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.GetPasswordPolicy()
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.PasswordPolicy == nil {
		return nil, errors.New("alicloud: empty password policy returned by GetPasswordPolicy")
	}
	pp := resp.Body.PasswordPolicy

	res, err := CreateResource(r.MqlRuntime, "alicloud.ram.passwordPolicy", map[string]*llx.RawData{
		"__id":                       llx.StringData("alicloud.ram.passwordPolicy"),
		"minimumPasswordLength":      llx.IntDataPtr(pp.MinimumPasswordLength),
		"requireLowercaseCharacters": llx.BoolDataPtr(pp.RequireLowercaseCharacters),
		"requireUppercaseCharacters": llx.BoolDataPtr(pp.RequireUppercaseCharacters),
		"requireNumbers":             llx.BoolDataPtr(pp.RequireNumbers),
		"requireSymbols":             llx.BoolDataPtr(pp.RequireSymbols),
		"hardExpiry":                 llx.BoolDataPtr(pp.HardExpiry),
		"maxPasswordAge":             llx.IntDataPtr(pp.MaxPasswordAge),
		"passwordReusePrevention":    llx.IntDataPtr(pp.PasswordReusePrevention),
		"maxLoginAttempts":           llx.IntDataPtr(pp.MaxLoginAttemps),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudRamPasswordPolicy), nil
}

func (r *mqlAlicloudRam) securityPreference() (any, error) {
	sp, err := r.securityPreferences()
	if err != nil {
		return nil, err
	}
	if sp == nil {
		return nil, nil
	}

	out := map[string]any{}
	if ak := sp.AccessKeyPreference; ak != nil {
		out["allowUserToManageAccessKeys"] = ramBoolPtrAny(ak.AllowUserToManageAccessKeys)
	}
	if mfa := sp.MFAPreference; mfa != nil {
		out["allowUserToManageMFADevices"] = ramBoolPtrAny(mfa.AllowUserToManageMFADevices)
	}
	if pk := sp.PublicKeyPreference; pk != nil {
		out["allowUserToManagePublicKeys"] = ramBoolPtrAny(pk.AllowUserToManagePublicKeys)
	}
	if lp := sp.LoginProfilePreference; lp != nil {
		out["allowUserToChangePassword"] = ramBoolPtrAny(lp.AllowUserToChangePassword)
		out["enableSaveMFATicket"] = ramBoolPtrAny(lp.EnableSaveMFATicket)
		out["loginNetworkMasks"] = ramStrPtrAny(lp.LoginNetworkMasks)
		out["loginSessionDuration"] = ramInt32PtrAny(lp.LoginSessionDuration)
	}
	return out, nil
}

// initAlicloudRamUser resolves a RAM user by userName via GetUser. It backs both
// direct lookups (alicloud.ram.user(userName: "x")) and cross-references from
// groups, reusing the cached instance when the user has already been listed.
func initAlicloudRamUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	rawName, ok := args["userName"]
	if !ok {
		return nil, nil, errors.New("alicloud.ram.user requires a userName to look up")
	}
	userName, ok := rawName.Value.(string)
	if !ok || userName == "" {
		return nil, nil, errors.New("alicloud.ram.user requires a userName to look up")
	}

	if x, ok := runtime.Resources.Get("alicloud.ram.user\x00" + userName); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.GetUser(&ramclient.GetUserRequest{UserName: &userName})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.User == nil {
		return nil, nil, fmt.Errorf("alicloud.ram.user %q not found", userName)
	}
	u := resp.Body.User

	args = map[string]*llx.RawData{
		"__id":        llx.StringData(ramStrVal(u.UserName)),
		"userId":      llx.StringDataPtr(u.UserId),
		"userName":    llx.StringDataPtr(u.UserName),
		"displayName": llx.StringDataPtr(u.DisplayName),
		"email":       llx.StringDataPtr(u.Email),
		"mobilePhone": llx.StringDataPtr(u.MobilePhone),
		"comments":    llx.StringDataPtr(u.Comments),
		"createDate":  llx.TimeDataPtr(ramParseTime(u.CreateDate)),
		"updateDate":  llx.TimeDataPtr(ramParseTime(u.UpdateDate)),
	}
	return args, nil, nil
}

func (r *mqlAlicloudRamUser) id() (string, error) {
	return r.UserName.Data, nil
}

// getUser fetches the full user record via GetUser for fields the list response
// omits (lastLoginDate).
func (r *mqlAlicloudRamUser) getUser() (*ramclient.GetUserResponseBodyUser, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, err
	}
	userName := r.UserName.Data
	resp, err := client.GetUser(&ramclient.GetUserRequest{UserName: &userName})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.User == nil {
		return nil, fmt.Errorf("alicloud.ram.user %q not found", userName)
	}
	return resp.Body.User, nil
}

func (r *mqlAlicloudRamUser) lastLoginDate() (*time.Time, error) {
	u, err := r.getUser()
	if err != nil {
		log.Warn().Err(err).Str("user", r.UserName.Data).Msg("alicloud: could not fetch RAM user detail")
		return nil, nil
	}
	return ramParseTime(u.LastLoginDate), nil
}

func (r *mqlAlicloudRamUser) accessKeys() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, err
	}

	userName := r.UserName.Data
	resp, err := client.ListAccessKeys(&ramclient.ListAccessKeysRequest{UserName: &userName})
	if err != nil {
		return nil, err
	}

	res := []any{}
	if resp == nil || resp.Body == nil || resp.Body.AccessKeys == nil {
		return res, nil
	}
	for _, ak := range resp.Body.AccessKeys.AccessKey {
		if ak == nil {
			continue
		}
		mqlKey, err := CreateResource(r.MqlRuntime, "alicloud.ram.accessKey", map[string]*llx.RawData{
			"__id":        llx.StringData(userName + "/" + ramStrVal(ak.AccessKeyId)),
			"userName":    llx.StringData(userName),
			"accessKeyId": llx.StringDataPtr(ak.AccessKeyId),
			"status":      llx.StringDataPtr(ak.Status),
			"createDate":  llx.TimeDataPtr(ramParseTime(ak.CreateDate)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlKey)
	}
	return res, nil
}

func (r *mqlAlicloudRamUser) groups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, err
	}

	userName := r.UserName.Data
	resp, err := client.ListGroupsForUser(&ramclient.ListGroupsForUserRequest{UserName: &userName})
	if err != nil {
		return nil, err
	}

	res := []any{}
	if resp == nil || resp.Body == nil || resp.Body.Groups == nil {
		return res, nil
	}
	for _, g := range resp.Body.Groups.Group {
		if g == nil || g.GroupName == nil {
			continue
		}
		group, err := NewResource(r.MqlRuntime, "alicloud.ram.group", map[string]*llx.RawData{
			"groupName": llx.StringDataPtr(g.GroupName),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, group)
	}
	return res, nil
}

// mqlAlicloudRamUserInternal memoizes the user's policy attachment list, which
// both the policies and attachedPolicies fields read.
type mqlAlicloudRamUserInternal struct {
	ramUserCredentialState
	attachmentsOnce sync.Once
	attachments     []*ramclient.ListPoliciesForUserResponseBodyPoliciesPolicy
	attachmentsErr  error
}

// policyAttachments lists the policies attached to the user, once. Both
// policies and attachedPolicies read the same response, so querying them
// together costs one ListPoliciesForUser call rather than two.
func (r *mqlAlicloudRamUser) policyAttachments() ([]*ramclient.ListPoliciesForUserResponseBodyPoliciesPolicy, error) {
	r.attachmentsOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.RamClient()
		if err != nil {
			r.attachmentsErr = err
			return
		}

		userName := r.UserName.Data
		resp, err := client.ListPoliciesForUser(&ramclient.ListPoliciesForUserRequest{UserName: &userName})
		if err != nil {
			r.attachmentsErr = err
			return
		}
		if resp == nil || resp.Body == nil || resp.Body.Policies == nil {
			return
		}
		r.attachments = resp.Body.Policies.Policy
	})
	return r.attachments, r.attachmentsErr
}

func (r *mqlAlicloudRamUser) policies() ([]any, error) {
	attachments, err := r.policyAttachments()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, p := range attachments {
		if p == nil {
			continue
		}
		res = append(res, ramPolicyAttachmentDict(p.PolicyName, p.PolicyType, p.DefaultVersion, p.Description, p.AttachDate))
	}
	return res, nil
}

func (r *mqlAlicloudRamUser) attachedPolicies() ([]any, error) {
	attachments, err := r.policyAttachments()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, p := range attachments {
		if p == nil {
			continue
		}
		policy, err := resolveRamPolicy(r.MqlRuntime, p.PolicyName, p.PolicyType)
		if err != nil {
			return nil, err
		}
		if policy == nil {
			continue
		}
		res = append(res, policy)
	}
	return res, nil
}

// effectivePolicies unions the user's direct attachments with the attachments
// of every group they belong to. A policy reachable both ways is listed once,
// keyed on the type and name pair that identifies a policy.
func (r *mqlAlicloudRamUser) effectivePolicies() ([]any, error) {
	direct, err := r.policyAttachments()
	if err != nil {
		return nil, err
	}

	groups := r.GetGroups()
	if groups.Error != nil {
		return nil, groups.Error
	}

	// copy rather than append onto the memoized slice, which every other
	// caller of policyAttachments shares
	attachments := make([]*ramclient.ListPoliciesForUserResponseBodyPoliciesPolicy, len(direct))
	copy(attachments, direct)

	for _, g := range groups.Data {
		group, ok := g.(*mqlAlicloudRamGroup)
		if !ok {
			continue
		}
		groupAttachments, err := group.policyAttachments()
		if err != nil {
			return nil, err
		}
		for _, p := range groupAttachments {
			if p == nil {
				continue
			}
			attachments = append(attachments, &ramclient.ListPoliciesForUserResponseBodyPoliciesPolicy{
				PolicyName: p.PolicyName,
				PolicyType: p.PolicyType,
			})
		}
	}

	seen := map[string]struct{}{}
	res := []any{}
	for _, p := range attachments {
		if p == nil {
			continue
		}
		key := ramStrVal(p.PolicyType) + "/" + ramStrVal(p.PolicyName)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		policy, err := resolveRamPolicy(r.MqlRuntime, p.PolicyName, p.PolicyType)
		if err != nil {
			return nil, err
		}
		if policy == nil {
			continue
		}
		res = append(res, policy)
	}
	return res, nil
}

func (r *mqlAlicloudRamUser) mfaDevice() (any, error) {
	dev := r.mfaDeviceDetail()
	if dev == nil {
		return nil, nil
	}
	return map[string]any{
		"serialNumber": ramStrVal(dev.SerialNumber),
		"type":         ramStrVal(dev.Type),
	}, nil
}

func (r *mqlAlicloudRamUser) loginProfile() (any, error) {
	lp := r.loginProfileDetail()
	if lp == nil {
		return nil, nil
	}
	out := map[string]any{
		"userName":              ramStrVal(lp.UserName),
		"mfaBindRequired":       ramBoolPtrAny(lp.MFABindRequired),
		"passwordResetRequired": ramBoolPtrAny(lp.PasswordResetRequired),
	}
	if t := ramParseTime(lp.CreateDate); t != nil {
		out["createDate"] = *t
	} else {
		out["createDate"] = nil
	}
	return out, nil
}

// user resolves the RAM user that owns the access key. A key cannot outlive its
// user, so a failure to read the user is a real error.
func (r *mqlAlicloudRamAccessKey) user() (*mqlAlicloudRamUser, error) {
	userName := r.UserName.Data
	if userName == "" {
		r.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.ram.user", map[string]*llx.RawData{
		"userName": llx.StringData(userName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudRamUser), nil
}

func (r *mqlAlicloudRamAccessKey) id() (string, error) {
	return r.UserName.Data + "/" + r.AccessKeyId.Data, nil
}

// initAlicloudRamGroup resolves a RAM group by groupName via GetGroup. It backs
// both direct lookups and cross-references from users, reusing the cached
// instance when the group has already been listed.
func initAlicloudRamGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	rawName, ok := args["groupName"]
	if !ok {
		return nil, nil, errors.New("alicloud.ram.group requires a groupName to look up")
	}
	groupName, ok := rawName.Value.(string)
	if !ok || groupName == "" {
		return nil, nil, errors.New("alicloud.ram.group requires a groupName to look up")
	}

	if x, ok := runtime.Resources.Get("alicloud.ram.group\x00" + groupName); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.GetGroup(&ramclient.GetGroupRequest{GroupName: &groupName})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.Group == nil {
		return nil, nil, fmt.Errorf("alicloud.ram.group %q not found", groupName)
	}
	g := resp.Body.Group

	args = map[string]*llx.RawData{
		"__id":       llx.StringData(ramStrVal(g.GroupName)),
		"groupId":    llx.StringDataPtr(g.GroupId),
		"groupName":  llx.StringDataPtr(g.GroupName),
		"comments":   llx.StringDataPtr(g.Comments),
		"createDate": llx.TimeDataPtr(ramParseTime(g.CreateDate)),
		"updateDate": llx.TimeDataPtr(ramParseTime(g.UpdateDate)),
	}
	return args, nil, nil
}

func (r *mqlAlicloudRamGroup) id() (string, error) {
	return r.GroupName.Data, nil
}

func (r *mqlAlicloudRamGroup) users() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, err
	}

	groupName := r.GroupName.Data
	res := []any{}
	var marker *string
	for {
		resp, err := client.ListUsersForGroup(&ramclient.ListUsersForGroupRequest{
			GroupName: &groupName,
			Marker:    marker,
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.Users == nil {
			break
		}

		for _, u := range resp.Body.Users.User {
			if u == nil || u.UserName == nil {
				continue
			}
			user, err := NewResource(r.MqlRuntime, "alicloud.ram.user", map[string]*llx.RawData{
				"userName": llx.StringDataPtr(u.UserName),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, user)
		}

		if resp.Body.IsTruncated == nil || !*resp.Body.IsTruncated {
			break
		}
		marker = resp.Body.Marker
		if marker == nil || *marker == "" {
			break
		}
	}
	return res, nil
}

// mqlAlicloudRamGroupInternal memoizes the group's policy attachment list,
// which both the policies and attachedPolicies fields read.
type mqlAlicloudRamGroupInternal struct {
	attachmentsOnce sync.Once
	attachments     []*ramclient.ListPoliciesForGroupResponseBodyPoliciesPolicy
	attachmentsErr  error
}

// policyAttachments lists the policies attached to the group, once.
func (r *mqlAlicloudRamGroup) policyAttachments() ([]*ramclient.ListPoliciesForGroupResponseBodyPoliciesPolicy, error) {
	r.attachmentsOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.RamClient()
		if err != nil {
			r.attachmentsErr = err
			return
		}

		groupName := r.GroupName.Data
		resp, err := client.ListPoliciesForGroup(&ramclient.ListPoliciesForGroupRequest{GroupName: &groupName})
		if err != nil {
			r.attachmentsErr = err
			return
		}
		if resp == nil || resp.Body == nil || resp.Body.Policies == nil {
			return
		}
		r.attachments = resp.Body.Policies.Policy
	})
	return r.attachments, r.attachmentsErr
}

func (r *mqlAlicloudRamGroup) policies() ([]any, error) {
	attachments, err := r.policyAttachments()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, p := range attachments {
		if p == nil {
			continue
		}
		res = append(res, ramPolicyAttachmentDict(p.PolicyName, p.PolicyType, p.DefaultVersion, p.Description, p.AttachDate))
	}
	return res, nil
}

func (r *mqlAlicloudRamGroup) attachedPolicies() ([]any, error) {
	attachments, err := r.policyAttachments()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, p := range attachments {
		if p == nil {
			continue
		}
		policy, err := resolveRamPolicy(r.MqlRuntime, p.PolicyName, p.PolicyType)
		if err != nil {
			return nil, err
		}
		if policy == nil {
			continue
		}
		res = append(res, policy)
	}
	return res, nil
}

func (r *mqlAlicloudRamRole) id() (string, error) {
	return r.RoleName.Data, nil
}

// resolveRamRole returns the typed RAM role for a role name, or (nil, nil) when
// roleName is empty (the caller sets StateIsNull). RAM is a global service, so
// the role is keyed by name alone. It backs typed ramRole() cross-references
// such as an ACK node pool's node role.
func resolveRamRole(runtime *plugin.Runtime, roleName string) (*mqlAlicloudRamRole, error) {
	if roleName == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.ram.role", map[string]*llx.RawData{
		"roleName": llx.StringData(roleName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudRamRole), nil
}

// ramRoleTags fetches the tags attached to a RAM role via ListTagResources,
// which is required because GetRole (unlike ListRoles) does not return them.
// Returns an empty map on any error so a resolved role is never a husk.
func ramRoleTags(client *ramclient.Client, roleName string) map[string]any {
	return ramTags(client, "role", roleName)
}

// ramTags reads the tags of a single RAM resource. GetRole and GetPolicy omit
// tags that their List counterparts return, so the ref-resolved form of those
// resources fills the gap from here.
func ramTags(client *ramclient.Client, resourceType, resourceName string) map[string]any {
	tags := map[string]any{}
	rt := resourceType
	name := resourceName
	resp, err := client.ListTagResources(&ramclient.ListTagResourcesRequest{
		ResourceType:  &rt,
		ResourceNames: []*string{&name},
	})
	if err != nil || resp == nil || resp.Body == nil {
		return tags
	}
	for _, t := range resp.Body.TagResources {
		if t == nil || t.TagKey == nil {
			continue
		}
		tags[ramStrVal(t.TagKey)] = ramStrVal(t.TagValue)
	}
	return tags
}

// initAlicloudRamRole resolves a RAM role by name, reusing an already-listed
// role from the resource cache and otherwise fetching it via GetRole. The
// assume-role policy document is loaded lazily by its own accessor, so the init
// only needs the role summary.
func initAlicloudRamRole(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	roleName, err := requiredStringArg(args, "roleName", "alicloud.ram.role")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.ram.role\x00" + roleName); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.GetRole(&ramclient.GetRoleRequest{RoleName: &roleName})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.Role == nil {
		return nil, nil, fmt.Errorf("alicloud.ram.role %q not found", roleName)
	}
	role := resp.Body.Role
	res, err := CreateResource(runtime, "alicloud.ram.role", map[string]*llx.RawData{
		"__id":               llx.StringDataPtr(role.RoleName),
		"roleId":             llx.StringDataPtr(role.RoleId),
		"roleName":           llx.StringDataPtr(role.RoleName),
		"arn":                llx.StringDataPtr(role.Arn),
		"description":        llx.StringDataPtr(role.Description),
		"createDate":         llx.TimeDataPtr(ramParseTime(role.CreateDate)),
		"updateDate":         llx.TimeDataPtr(ramParseTime(role.UpdateDate)),
		"maxSessionDuration": llx.IntDataPtr(role.MaxSessionDuration),
		// GetRole does not return tags (unlike ListRoles), so fetch them
		// separately to keep a ref-resolved role's tags consistent with a listed
		// one.
		"tags": llx.MapData(ramRoleTags(client, roleName), types.String),
	})
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlAlicloudRamRole) assumeRolePolicyDocument() (string, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return "", err
	}

	roleName := r.RoleName.Data
	resp, err := client.GetRole(&ramclient.GetRoleRequest{RoleName: &roleName})
	if err != nil {
		return "", err
	}
	if resp == nil || resp.Body == nil || resp.Body.Role == nil {
		return "", nil
	}
	return ramStrVal(resp.Body.Role.AssumeRolePolicyDocument), nil
}

// mqlAlicloudRamRoleInternal memoizes the role's policy attachment list, which
// both the policies and attachedPolicies fields read.
type mqlAlicloudRamRoleInternal struct {
	ramTrustState
	attachmentsOnce sync.Once
	attachments     []*ramclient.ListPoliciesForRoleResponseBodyPoliciesPolicy
	attachmentsErr  error
}

// policyAttachments lists the policies attached to the role, once.
func (r *mqlAlicloudRamRole) policyAttachments() ([]*ramclient.ListPoliciesForRoleResponseBodyPoliciesPolicy, error) {
	r.attachmentsOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.RamClient()
		if err != nil {
			r.attachmentsErr = err
			return
		}

		roleName := r.RoleName.Data
		resp, err := client.ListPoliciesForRole(&ramclient.ListPoliciesForRoleRequest{RoleName: &roleName})
		if err != nil {
			r.attachmentsErr = err
			return
		}
		if resp == nil || resp.Body == nil || resp.Body.Policies == nil {
			return
		}
		r.attachments = resp.Body.Policies.Policy
	})
	return r.attachments, r.attachmentsErr
}

func (r *mqlAlicloudRamRole) policies() ([]any, error) {
	attachments, err := r.policyAttachments()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, p := range attachments {
		if p == nil {
			continue
		}
		res = append(res, ramPolicyAttachmentDict(p.PolicyName, p.PolicyType, p.DefaultVersion, p.Description, p.AttachDate))
	}
	return res, nil
}

func (r *mqlAlicloudRamRole) attachedPolicies() ([]any, error) {
	attachments, err := r.policyAttachments()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, p := range attachments {
		if p == nil {
			continue
		}
		policy, err := resolveRamPolicy(r.MqlRuntime, p.PolicyName, p.PolicyType)
		if err != nil {
			return nil, err
		}
		if policy == nil {
			continue
		}
		res = append(res, policy)
	}
	return res, nil
}

func (r *mqlAlicloudRamPolicy) id() (string, error) {
	return r.PolicyType.Data + "/" + r.PolicyName.Data, nil
}

// initAlicloudRamPolicy resolves a single policy from its name and type.
//
// NewResource runs this before it consults the resource cache, so the cache
// probe here is what keeps a policy that is attached to many users from costing
// one GetPolicy call per attachment.
func initAlicloudRamPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	policyName, err := requiredStringArg(args, "policyName", "alicloud.ram.policy")
	if err != nil {
		return nil, nil, err
	}
	policyType, err := requiredStringArg(args, "policyType", "alicloud.ram.policy")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.ram.policy\x00" + policyType + "/" + policyName); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.RamClient()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.GetPolicy(&ramclient.GetPolicyRequest{
		PolicyName: &policyName,
		PolicyType: &policyType,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.Policy == nil {
		return nil, nil, fmt.Errorf("alicloud.ram.policy %q of type %q not found", policyName, policyType)
	}

	p := resp.Body.Policy
	res, err := CreateResource(runtime, "alicloud.ram.policy", map[string]*llx.RawData{
		"__id":            llx.StringData(policyType + "/" + policyName),
		"policyName":      llx.StringDataPtr(p.PolicyName),
		"policyType":      llx.StringDataPtr(p.PolicyType),
		"description":     llx.StringDataPtr(p.Description),
		"defaultVersion":  llx.StringDataPtr(p.DefaultVersion),
		"attachmentCount": llx.IntDataPtr(p.AttachmentCount),
		"createDate":      llx.TimeDataPtr(ramParseTime(p.CreateDate)),
		"updateDate":      llx.TimeDataPtr(ramParseTime(p.UpdateDate)),
		"tags":            llx.MapData(ramTags(client, "policy", policyName), types.String),
	})
	if err != nil {
		return nil, nil, err
	}

	// GetPolicy already returned the default version's document, so hand it to
	// the resource rather than making statements re-fetch what we just read.
	// The seeded flag is set even when there is no default version, because a
	// repeat call would return the same nothing.
	policy := res.(*mqlAlicloudRamPolicy)
	if v := resp.Body.DefaultPolicyVersion; v != nil {
		policy.cacheDocument = ramStrVal(v.PolicyDocument)
	}
	policy.documentSeeded = true
	return nil, res, nil
}

// resolveRamPolicy turns a policy name and type into a typed policy resource,
// returning nil when either is blank.
func resolveRamPolicy(runtime *plugin.Runtime, policyName, policyType *string) (*mqlAlicloudRamPolicy, error) {
	name := ramStrVal(policyName)
	policyKind := ramStrVal(policyType)
	if name == "" || policyKind == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.ram.policy", map[string]*llx.RawData{
		"policyName": llx.StringData(name),
		"policyType": llx.StringData(policyKind),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudRamPolicy), nil
}

// mqlAlicloudRamPolicyInternal memoizes the default version's policy document.
// initAlicloudRamPolicy seeds it from the GetPolicy response it already makes,
// so a policy reached through an attachment answers policyDocument and
// statements without a second call.
type mqlAlicloudRamPolicyInternal struct {
	documentOnce sync.Once
	// documentSeeded records that init already read the document, which an
	// empty cacheDocument cannot: a policy whose default version carries no
	// document is seeded with "" and must not trigger a repeat GetPolicy.
	documentSeeded  bool
	cacheDocument   string
	documentErr     error
	statementsOnce  sync.Once
	cacheStatements []policyStatement
	statementsErr   error
}

// fetchDocument returns the policy document of the default version, calling
// GetPolicy at most once per policy across every field that needs it.
func (r *mqlAlicloudRamPolicy) fetchDocument() (string, error) {
	r.documentOnce.Do(func() {
		if r.documentSeeded {
			return
		}

		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.RamClient()
		if err != nil {
			r.documentErr = err
			return
		}

		policyName := r.PolicyName.Data
		policyType := r.PolicyType.Data
		resp, err := client.GetPolicy(&ramclient.GetPolicyRequest{
			PolicyName: &policyName,
			PolicyType: &policyType,
		})
		if err != nil {
			r.documentErr = err
			return
		}
		if resp == nil || resp.Body == nil || resp.Body.DefaultPolicyVersion == nil {
			return
		}
		r.cacheDocument = ramStrVal(resp.Body.DefaultPolicyVersion.PolicyDocument)
	})
	return r.cacheDocument, r.documentErr
}

func (r *mqlAlicloudRamPolicy) policyDocument() (string, error) {
	return r.fetchDocument()
}

// parsedStatements parses the policy document once. The four fields derived
// from it share this result rather than re-parsing per field.
func (r *mqlAlicloudRamPolicy) parsedStatements() ([]policyStatement, error) {
	r.statementsOnce.Do(func() {
		doc, err := r.fetchDocument()
		if err != nil {
			r.statementsErr = err
			return
		}
		r.cacheStatements, r.statementsErr = parsePolicyDocument(doc)
	})
	return r.cacheStatements, r.statementsErr
}

func (r *mqlAlicloudRamPolicy) statements() ([]any, error) {
	parsed, err := r.parsedStatements()
	if err != nil {
		return nil, err
	}
	return newPolicyStatements(r.MqlRuntime, r.PolicyType.Data+"/"+r.PolicyName.Data, parsed)
}

// newPolicyStatements maps parsed statements into resources. It is shared by
// the permission policies of alicloud.ram.policy and the trust policy of
// alicloud.ram.role, which are the same grammar read for different questions.
// The idPrefix identifies the owning document, so a statement's cache key stays
// unique across both.
func newPolicyStatements(runtime *plugin.Runtime, idPrefix string, parsed []policyStatement) ([]any, error) {
	res := make([]any, 0, len(parsed))
	for i, s := range parsed {
		stmt, err := CreateResource(runtime, "alicloud.ram.policy.statement", map[string]*llx.RawData{
			"__id":        llx.StringData(fmt.Sprintf("%s/%d", idPrefix, i)),
			"effect":      llx.StringData(s.Effect),
			"action":      llx.ArrayData(llx.TArr2Raw(s.Action), types.String),
			"notAction":   llx.ArrayData(llx.TArr2Raw(s.NotAction), types.String),
			"resource":    llx.ArrayData(llx.TArr2Raw(s.Resource), types.String),
			"notResource": llx.ArrayData(llx.TArr2Raw(s.NotResource), types.String),
			"condition":   llx.DictData(s.Condition),
			"principal":   llx.DictData(policyPrincipalDict(s.Principal)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, stmt)
	}
	return res, nil
}

// policyPrincipalDict renders a statement's principals as a dict of JSON-native
// values, which is what an MQL dict field carries. A statement that names no
// principal, as every permission policy statement does, yields nil so the field
// reads as null rather than as an empty object.
func policyPrincipalDict(principal map[string][]string) any {
	if len(principal) == 0 {
		return nil
	}
	out := make(map[string]any, len(principal))
	for kind, entries := range principal {
		values := make([]any, 0, len(entries))
		for _, e := range entries {
			values = append(values, e)
		}
		out[kind] = values
	}
	return out
}

func (r *mqlAlicloudRamPolicy) allowsAdminAccess() (bool, error) {
	parsed, err := r.parsedStatements()
	if err != nil {
		return false, err
	}
	return policyAllowsAdminAccess(parsed), nil
}

func (r *mqlAlicloudRamPolicy) hasWildcardAction() (bool, error) {
	parsed, err := r.parsedStatements()
	if err != nil {
		return false, err
	}
	return policyHasWildcardAction(parsed), nil
}

func (r *mqlAlicloudRamPolicy) hasUnscopedResource() (bool, error) {
	parsed, err := r.parsedStatements()
	if err != nil {
		return false, err
	}
	return policyHasUnscopedResource(parsed), nil
}

func (r *mqlAlicloudRamPasswordPolicy) id() (string, error) {
	return "alicloud.ram.passwordPolicy", nil
}

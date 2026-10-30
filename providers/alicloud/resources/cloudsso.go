// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sync"
	"time"

	cloudssoclient "github.com/alibabacloud-go/cloudsso-20210515/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
)

// alicloudCloudSsoRegions are the two regions CloudSSO answers at: cn-shanghai
// for the China partition and us-east-1 for the international one. An account's
// directories live in exactly one of them, so both are probed.
var alicloudCloudSsoRegions = []string{"cn-shanghai", "us-east-1"}

// cloudssoPageSize is the per-request item count for the NextToken-paginated
// CloudSSO list APIs.
const cloudssoPageSize int32 = 100

// cloudssoParseTime parses a CloudSSO RFC3339 timestamp, returning nil when the
// pointer is nil or the value cannot be parsed.
func cloudssoParseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	return &t
}

func (r *mqlAlicloudCloudsso) id() (string, error) {
	return "alicloud.cloudsso", nil
}

// enabled reports whether CloudSSO has been turned on for the account. The
// service status is only served by the region that owns the account, so both
// regions are probed and an Enabled answer from either one wins.
func (r *mqlAlicloudCloudsso) enabled() (bool, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)

	var lastErr error
	answered := false
	for _, region := range alicloudCloudSsoRegions {
		client, err := conn.CloudSsoClient(region)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.GetServiceStatus()
		if err != nil {
			lastErr = err
			continue
		}
		answered = true
		if resp == nil || resp.Body == nil || resp.Body.ServiceStatus == nil {
			continue
		}
		if tea.StringValue(resp.Body.ServiceStatus.Status) == "Enabled" {
			return true, nil
		}
	}

	// Neither region answered: report the failure rather than claiming CloudSSO
	// is switched off, which would read as a deliberate configuration.
	if !answered && lastErr != nil {
		return false, lastErr
	}
	return false, nil
}

// directories lists the CloudSSO directories in both service regions.
func (r *mqlAlicloudCloudsso) directories() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)

	res := []any{}
	var lastErr error
	succeeded := 0
	for _, region := range alicloudCloudSsoRegions {
		client, err := conn.CloudSsoClient(region)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := client.ListDirectories()
		if err != nil {
			// wrong partition, service not enabled, or transient; a total
			// failure is surfaced after the loop
			lastErr = err
			continue
		}
		succeeded++
		if resp == nil || resp.Body == nil {
			continue
		}
		for _, d := range resp.Body.Directories {
			if d == nil || d.DirectoryId == nil {
				continue
			}
			mqlDir, err := newCloudssoDirectory(r.MqlRuntime, region, d)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDir)
		}
	}

	if succeeded == 0 && lastErr != nil {
		return nil, lastErr
	}
	return res, nil
}

// mqlAlicloudCloudssoDirectoryInternal caches the service region the directory
// was found in, which every subsequent call against the directory needs, and
// memoizes the sign-in preferences that back two separate fields.
type mqlAlicloudCloudssoDirectoryInternal struct {
	cloudssoSamlState
	serviceRegion string

	loginPreferenceOnce sync.Once
	loginPreferenceData *cloudssoclient.GetLoginPreferenceResponseBodyLoginPreference
	loginPreferenceErr  error
}

func newCloudssoDirectory(runtime *plugin.Runtime, region string, d *cloudssoclient.ListDirectoriesResponseBodyDirectories) (*mqlAlicloudCloudssoDirectory, error) {
	resource, err := CreateResource(runtime, "alicloud.cloudsso.directory", map[string]*llx.RawData{
		"__id":          llx.StringDataPtr(d.DirectoryId),
		"directoryId":   llx.StringDataPtr(d.DirectoryId),
		"directoryName": llx.StringDataPtr(d.DirectoryName),
		"region":        llx.StringDataPtr(d.Region),
		"createTime":    llx.TimeDataPtr(cloudssoParseTime(d.CreateTime)),
		"updateTime":    llx.TimeDataPtr(cloudssoParseTime(d.UpdateTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlDir := resource.(*mqlAlicloudCloudssoDirectory)
	mqlDir.serviceRegion = region
	return mqlDir, nil
}

// initAlicloudCloudssoDirectory resolves a directory from its ID by finding it
// in the directory listing, which is the only way to learn which service region
// hosts it.
func initAlicloudCloudssoDirectory(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	directoryID, err := requiredStringArg(args, "directoryId", "alicloud.cloudsso.directory")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.cloudsso.directory\x00" + directoryID); ok {
		return nil, x, nil
	}

	svc, err := CreateResource(runtime, "alicloud.cloudsso", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	dirs := svc.(*mqlAlicloudCloudsso).GetDirectories()
	if dirs.Error != nil {
		return nil, nil, dirs.Error
	}
	for _, d := range dirs.Data {
		dir, ok := d.(*mqlAlicloudCloudssoDirectory)
		if ok && dir.DirectoryId.Data == directoryID {
			return nil, dir, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.cloudsso.directory %q not found", directoryID)
}

// cloudssoClient returns the client for the region hosting this directory,
// alongside the directory ID every CloudSSO call takes.
func (r *mqlAlicloudCloudssoDirectory) cloudssoClient() (*cloudssoclient.Client, string, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CloudSsoClient(r.serviceRegion)
	if err != nil {
		return nil, "", err
	}
	return client, r.DirectoryId.Data, nil
}

// ---------------------------------------------------------------------------
// alicloud.cloudsso.user
// ---------------------------------------------------------------------------

func (r *mqlAlicloudCloudssoUser) id() (string, error) {
	return r.DirectoryId.Data + "/" + r.UserId.Data, nil
}

// mqlAlicloudCloudssoUserInternal caches the service region so a user reached
// from a listing can make its own calls without re-resolving the directory.
type mqlAlicloudCloudssoUserInternal struct {
	serviceRegion string
}

func (r *mqlAlicloudCloudssoDirectory) users() ([]any, error) {
	client, directoryID, err := r.cloudssoClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := &cloudssoclient.ListUsersRequest{
		DirectoryId: new(directoryID),
		MaxResults:  new(cloudssoPageSize),
	}
	for {
		resp, err := client.ListUsers(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		for _, u := range resp.Body.Users {
			if u == nil || u.UserId == nil {
				continue
			}
			mqlUser, err := newCloudssoUser(r.MqlRuntime, r.serviceRegion, directoryID, u.UserId, u.UserName,
				u.DisplayName, u.FirstName, u.LastName, u.Email, u.Description, u.Status, u.ProvisionType,
				u.CreateTime, u.UpdateTime)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlUser)
		}
		if !tea.BoolValue(resp.Body.IsTruncated) || tea.StringValue(resp.Body.NextToken) == "" {
			break
		}
		req.NextToken = resp.Body.NextToken
	}
	return res, nil
}

// newCloudssoUser builds a user resource. The fields are passed individually
// because ListUsers and ListGroupMembers return the same user with different
// response types.
func newCloudssoUser(runtime *plugin.Runtime, region, directoryID string,
	userID, userName, displayName, firstName, lastName, email, description, status, provisionType, createTime, updateTime *string,
) (*mqlAlicloudCloudssoUser, error) {
	resource, err := CreateResource(runtime, "alicloud.cloudsso.user", map[string]*llx.RawData{
		"__id":          llx.StringData(directoryID + "/" + tea.StringValue(userID)),
		"directoryId":   llx.StringData(directoryID),
		"userId":        llx.StringDataPtr(userID),
		"userName":      llx.StringDataPtr(userName),
		"displayName":   llx.StringDataPtr(displayName),
		"firstName":     llx.StringDataPtr(firstName),
		"lastName":      llx.StringDataPtr(lastName),
		"email":         llx.StringDataPtr(email),
		"description":   llx.StringDataPtr(description),
		"status":        llx.StringDataPtr(status),
		"provisionType": llx.StringDataPtr(provisionType),
		"createTime":    llx.TimeDataPtr(cloudssoParseTime(createTime)),
		"updateTime":    llx.TimeDataPtr(cloudssoParseTime(updateTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlUser := resource.(*mqlAlicloudCloudssoUser)
	mqlUser.serviceRegion = region
	return mqlUser, nil
}

// initAlicloudCloudssoUser resolves a user from its directory and user ID.
//
// NewResource runs an init before it consults the resource cache, so the cache
// probe here keeps a user that a listing already materialized from costing
// another GetUser call for every group or assignment that names them.
func initAlicloudCloudssoUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	directoryID, err := requiredStringArg(args, "directoryId", "alicloud.cloudsso.user")
	if err != nil {
		return nil, nil, err
	}
	userID, err := requiredStringArg(args, "userId", "alicloud.cloudsso.user")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.cloudsso.user\x00" + directoryID + "/" + userID); ok {
		return nil, x, nil
	}

	dir, err := resolveCloudssoDirectory(runtime, directoryID)
	if err != nil {
		return nil, nil, err
	}
	client, _, err := dir.cloudssoClient()
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.GetUser(&cloudssoclient.GetUserRequest{
		DirectoryId: new(directoryID),
		UserId:      new(userID),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.User == nil {
		return nil, nil, fmt.Errorf("alicloud.cloudsso.user %q not found in directory %q", userID, directoryID)
	}

	u := resp.Body.User
	res, err := newCloudssoUser(runtime, dir.serviceRegion, directoryID, u.UserId, u.UserName,
		u.DisplayName, u.FirstName, u.LastName, u.Email, u.Description, u.Status, u.ProvisionType,
		u.CreateTime, u.UpdateTime)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlAlicloudCloudssoUser) mfaDevices() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CloudSsoClient(r.serviceRegion)
	if err != nil {
		return nil, err
	}

	resp, err := client.ListMFADevicesForUser(&cloudssoclient.ListMFADevicesForUserRequest{
		DirectoryId: new(r.DirectoryId.Data),
		UserId:      new(r.UserId.Data),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	if resp == nil || resp.Body == nil {
		return res, nil
	}
	for _, d := range resp.Body.MFADevices {
		if d == nil || d.DeviceId == nil {
			continue
		}
		device, err := CreateResource(r.MqlRuntime, "alicloud.cloudsso.mfaDevice", map[string]*llx.RawData{
			// device IDs are unique within a directory, so the cache key is
			// qualified by the directory the same way the other resources are
			"__id":          llx.StringData(r.DirectoryId.Data + "/" + tea.StringValue(d.DeviceId)),
			"deviceId":      llx.StringDataPtr(d.DeviceId),
			"userId":        llx.StringDataPtr(d.UserId),
			"deviceName":    llx.StringDataPtr(d.DeviceName),
			"deviceType":    llx.StringDataPtr(d.DeviceType),
			"effectiveTime": llx.TimeDataPtr(cloudssoParseTime(d.EffectiveTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, device)
	}
	return res, nil
}

func (r *mqlAlicloudCloudssoUser) groups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CloudSsoClient(r.serviceRegion)
	if err != nil {
		return nil, err
	}

	directoryID := r.DirectoryId.Data
	res := []any{}
	req := &cloudssoclient.ListJoinedGroupsForUserRequest{
		DirectoryId: new(directoryID),
		UserId:      new(r.UserId.Data),
		MaxResults:  new(cloudssoPageSize),
	}
	for {
		resp, err := client.ListJoinedGroupsForUser(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		for _, g := range resp.Body.JoinedGroups {
			if g == nil || g.GroupId == nil {
				continue
			}
			group, err := resolveCloudssoGroup(r.MqlRuntime, directoryID, tea.StringValue(g.GroupId))
			if err != nil {
				return nil, err
			}
			if group == nil {
				continue
			}
			res = append(res, group)
		}
		if !tea.BoolValue(resp.Body.IsTruncated) || tea.StringValue(resp.Body.NextToken) == "" {
			break
		}
		req.NextToken = resp.Body.NextToken
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// alicloud.cloudsso.group
// ---------------------------------------------------------------------------

func (r *mqlAlicloudCloudssoGroup) id() (string, error) {
	return r.DirectoryId.Data + "/" + r.GroupId.Data, nil
}

// mqlAlicloudCloudssoGroupInternal caches the service region so a group reached
// from a listing can make its own calls without re-resolving the directory.
type mqlAlicloudCloudssoGroupInternal struct {
	serviceRegion string
}

func (r *mqlAlicloudCloudssoDirectory) groups() ([]any, error) {
	client, directoryID, err := r.cloudssoClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := &cloudssoclient.ListGroupsRequest{
		DirectoryId: new(directoryID),
		MaxResults:  new(cloudssoPageSize),
	}
	for {
		resp, err := client.ListGroups(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		for _, g := range resp.Body.Groups {
			if g == nil || g.GroupId == nil {
				continue
			}
			mqlGroup, err := newCloudssoGroup(r.MqlRuntime, r.serviceRegion, directoryID,
				g.GroupId, g.GroupName, g.Description, g.ProvisionType, g.CreateTime, g.UpdateTime)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlGroup)
		}
		if !tea.BoolValue(resp.Body.IsTruncated) || tea.StringValue(resp.Body.NextToken) == "" {
			break
		}
		req.NextToken = resp.Body.NextToken
	}
	return res, nil
}

func newCloudssoGroup(runtime *plugin.Runtime, region, directoryID string,
	groupID, groupName, description, provisionType, createTime, updateTime *string,
) (*mqlAlicloudCloudssoGroup, error) {
	resource, err := CreateResource(runtime, "alicloud.cloudsso.group", map[string]*llx.RawData{
		"__id":          llx.StringData(directoryID + "/" + tea.StringValue(groupID)),
		"directoryId":   llx.StringData(directoryID),
		"groupId":       llx.StringDataPtr(groupID),
		"groupName":     llx.StringDataPtr(groupName),
		"description":   llx.StringDataPtr(description),
		"provisionType": llx.StringDataPtr(provisionType),
		"createTime":    llx.TimeDataPtr(cloudssoParseTime(createTime)),
		"updateTime":    llx.TimeDataPtr(cloudssoParseTime(updateTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlGroup := resource.(*mqlAlicloudCloudssoGroup)
	mqlGroup.serviceRegion = region
	return mqlGroup, nil
}

// initAlicloudCloudssoGroup resolves a group from its directory and group ID,
// probing the resource cache first for the same reason the user init does.
func initAlicloudCloudssoGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	directoryID, err := requiredStringArg(args, "directoryId", "alicloud.cloudsso.group")
	if err != nil {
		return nil, nil, err
	}
	groupID, err := requiredStringArg(args, "groupId", "alicloud.cloudsso.group")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.cloudsso.group\x00" + directoryID + "/" + groupID); ok {
		return nil, x, nil
	}

	dir, err := resolveCloudssoDirectory(runtime, directoryID)
	if err != nil {
		return nil, nil, err
	}
	client, _, err := dir.cloudssoClient()
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.GetGroup(&cloudssoclient.GetGroupRequest{
		DirectoryId: new(directoryID),
		GroupId:     new(groupID),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.Group == nil {
		return nil, nil, fmt.Errorf("alicloud.cloudsso.group %q not found in directory %q", groupID, directoryID)
	}

	g := resp.Body.Group
	res, err := newCloudssoGroup(runtime, dir.serviceRegion, directoryID,
		g.GroupId, g.GroupName, g.Description, g.ProvisionType, g.CreateTime, g.UpdateTime)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlAlicloudCloudssoGroup) members() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CloudSsoClient(r.serviceRegion)
	if err != nil {
		return nil, err
	}

	directoryID := r.DirectoryId.Data
	res := []any{}
	req := &cloudssoclient.ListGroupMembersRequest{
		DirectoryId: new(directoryID),
		GroupId:     new(r.GroupId.Data),
		MaxResults:  new(cloudssoPageSize),
	}
	for {
		resp, err := client.ListGroupMembers(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		for _, m := range resp.Body.GroupMembers {
			if m == nil || m.UserId == nil {
				continue
			}
			// ListGroupMembers omits createTime and updateTime, so resolve the
			// user rather than creating one with those fields left unset.
			user, err := resolveCloudssoUser(r.MqlRuntime, directoryID, tea.StringValue(m.UserId))
			if err != nil {
				return nil, err
			}
			if user == nil {
				continue
			}
			res = append(res, user)
		}
		if !tea.BoolValue(resp.Body.IsTruncated) || tea.StringValue(resp.Body.NextToken) == "" {
			break
		}
		req.NextToken = resp.Body.NextToken
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// alicloud.cloudsso.mfaDevice
// ---------------------------------------------------------------------------

// The MFA device has no id method: its cache key is qualified by the directory,
// which the device resource itself does not carry, so the key is passed straight
// to CreateResource as __id.

// ---------------------------------------------------------------------------
// alicloud.cloudsso.passwordPolicy and directory sign-in settings
// ---------------------------------------------------------------------------

// The password policy has no id method: it is a per-directory singleton whose
// cache key is the directory ID, passed straight to CreateResource as __id.

func (r *mqlAlicloudCloudssoDirectory) passwordPolicy() (*mqlAlicloudCloudssoPasswordPolicy, error) {
	client, directoryID, err := r.cloudssoClient()
	if err != nil {
		return nil, err
	}

	resp, err := client.GetPasswordPolicy(&cloudssoclient.GetPasswordPolicyRequest{
		DirectoryId: new(directoryID),
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.PasswordPolicy == nil {
		r.PasswordPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	p := resp.Body.PasswordPolicy
	resource, err := CreateResource(r.MqlRuntime, "alicloud.cloudsso.passwordPolicy", map[string]*llx.RawData{
		"__id":                       llx.StringData(directoryID),
		"minPasswordLength":          llx.IntDataPtr(p.MinPasswordLength),
		"maxPasswordLength":          llx.IntDataPtr(p.MaxPasswordLength),
		"minPasswordDifferentChars":  llx.IntDataPtr(p.MinPasswordDifferentChars),
		"maxPasswordAge":             llx.IntDataPtr(p.MaxPasswordAge),
		"passwordReusePrevention":    llx.IntDataPtr(p.PasswordReusePrevention),
		"maxLoginAttempts":           llx.IntDataPtr(p.MaxLoginAttempts),
		"requireLowerCaseChars":      llx.BoolDataPtr(p.RequireLowerCaseChars),
		"requireUpperCaseChars":      llx.BoolDataPtr(p.RequireUpperCaseChars),
		"requireNumbers":             llx.BoolDataPtr(p.RequireNumbers),
		"requireSymbols":             llx.BoolDataPtr(p.RequireSymbols),
		"passwordNotContainUsername": llx.BoolDataPtr(p.PasswordNotContainUsername),
		"hardExpire":                 llx.BoolDataPtr(p.HardExpire),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAlicloudCloudssoPasswordPolicy), nil
}

func (r *mqlAlicloudCloudssoDirectory) mfaAuthenticationStatus() (string, error) {
	client, directoryID, err := r.cloudssoClient()
	if err != nil {
		return "", err
	}
	resp, err := client.GetMFAAuthenticationStatus(&cloudssoclient.GetMFAAuthenticationStatusRequest{
		DirectoryId: new(directoryID),
	})
	if err != nil {
		return "", err
	}
	if resp == nil || resp.Body == nil {
		return "", nil
	}
	return tea.StringValue(resp.Body.MFAAuthenticationStatus), nil
}

func (r *mqlAlicloudCloudssoDirectory) allowUserToGetCredentials() (bool, error) {
	pref, err := r.loginPreference()
	if err != nil || pref == nil {
		return false, err
	}
	return tea.BoolValue(pref.AllowUserToGetCredentials), nil
}

func (r *mqlAlicloudCloudssoDirectory) loginNetworkMasks() (string, error) {
	pref, err := r.loginPreference()
	if err != nil || pref == nil {
		return "", err
	}
	return tea.StringValue(pref.LoginNetworkMasks), nil
}

// loginPreference reads the directory sign-in preferences, once. Both
// allowUserToGetCredentials and loginNetworkMasks come from this one response,
// so querying them together costs a single GetLoginPreference call.
func (r *mqlAlicloudCloudssoDirectory) loginPreference() (*cloudssoclient.GetLoginPreferenceResponseBodyLoginPreference, error) {
	r.loginPreferenceOnce.Do(func() {
		client, directoryID, err := r.cloudssoClient()
		if err != nil {
			r.loginPreferenceErr = err
			return
		}
		resp, err := client.GetLoginPreference(&cloudssoclient.GetLoginPreferenceRequest{
			DirectoryId: new(directoryID),
		})
		if err != nil {
			r.loginPreferenceErr = err
			return
		}
		if resp == nil || resp.Body == nil {
			return
		}
		r.loginPreferenceData = resp.Body.LoginPreference
	})
	return r.loginPreferenceData, r.loginPreferenceErr
}

func (r *mqlAlicloudCloudssoDirectory) scimSynchronizationEnabled() (bool, error) {
	client, directoryID, err := r.cloudssoClient()
	if err != nil {
		return false, err
	}
	resp, err := client.GetSCIMSynchronizationStatus(&cloudssoclient.GetSCIMSynchronizationStatusRequest{
		DirectoryId: new(directoryID),
	})
	if err != nil {
		return false, err
	}
	if resp == nil || resp.Body == nil {
		return false, nil
	}
	return tea.StringValue(resp.Body.SCIMSynchronizationStatus) == "Enabled", nil
}

// ---------------------------------------------------------------------------
// alicloud.cloudsso.accessConfiguration
// ---------------------------------------------------------------------------

func (r *mqlAlicloudCloudssoAccessConfiguration) id() (string, error) {
	return r.DirectoryId.Data + "/" + r.AccessConfigurationId.Data, nil
}

// mqlAlicloudCloudssoAccessConfigurationInternal caches the service region so
// the configuration can read its permission policies without re-resolving the
// directory.
type mqlAlicloudCloudssoAccessConfigurationInternal struct {
	serviceRegion string
}

func (r *mqlAlicloudCloudssoDirectory) accessConfigurations() ([]any, error) {
	client, directoryID, err := r.cloudssoClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := &cloudssoclient.ListAccessConfigurationsRequest{
		DirectoryId: new(directoryID),
		MaxResults:  new(cloudssoPageSize),
	}
	for {
		resp, err := client.ListAccessConfigurations(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		for _, ac := range resp.Body.AccessConfigurations {
			if ac == nil || ac.AccessConfigurationId == nil {
				continue
			}
			mqlAc, err := newCloudssoAccessConfiguration(r.MqlRuntime, r.serviceRegion, directoryID,
				ac.AccessConfigurationId, ac.AccessConfigurationName, ac.Description,
				ac.SessionDuration, ac.RelayState, ac.CreateTime, ac.UpdateTime)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAc)
		}
		if !tea.BoolValue(resp.Body.IsTruncated) || tea.StringValue(resp.Body.NextToken) == "" {
			break
		}
		req.NextToken = resp.Body.NextToken
	}
	return res, nil
}

func newCloudssoAccessConfiguration(runtime *plugin.Runtime, region, directoryID string,
	acID, name, description *string, sessionDuration *int32, relayState, createTime, updateTime *string,
) (*mqlAlicloudCloudssoAccessConfiguration, error) {
	resource, err := CreateResource(runtime, "alicloud.cloudsso.accessConfiguration", map[string]*llx.RawData{
		"__id":                    llx.StringData(directoryID + "/" + tea.StringValue(acID)),
		"directoryId":             llx.StringData(directoryID),
		"accessConfigurationId":   llx.StringDataPtr(acID),
		"accessConfigurationName": llx.StringDataPtr(name),
		"description":             llx.StringDataPtr(description),
		"sessionDuration":         llx.IntDataPtr(sessionDuration),
		"relayState":              llx.StringDataPtr(relayState),
		"createTime":              llx.TimeDataPtr(cloudssoParseTime(createTime)),
		"updateTime":              llx.TimeDataPtr(cloudssoParseTime(updateTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlAc := resource.(*mqlAlicloudCloudssoAccessConfiguration)
	mqlAc.serviceRegion = region
	return mqlAc, nil
}

// initAlicloudCloudssoAccessConfiguration resolves an access configuration from
// its directory and configuration ID, probing the resource cache first so an
// assignment does not re-fetch a configuration a listing already produced.
func initAlicloudCloudssoAccessConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	directoryID, err := requiredStringArg(args, "directoryId", "alicloud.cloudsso.accessConfiguration")
	if err != nil {
		return nil, nil, err
	}
	acID, err := requiredStringArg(args, "accessConfigurationId", "alicloud.cloudsso.accessConfiguration")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.cloudsso.accessConfiguration\x00" + directoryID + "/" + acID); ok {
		return nil, x, nil
	}

	dir, err := resolveCloudssoDirectory(runtime, directoryID)
	if err != nil {
		return nil, nil, err
	}
	client, _, err := dir.cloudssoClient()
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.GetAccessConfiguration(&cloudssoclient.GetAccessConfigurationRequest{
		DirectoryId:           new(directoryID),
		AccessConfigurationId: new(acID),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.AccessConfiguration == nil {
		return nil, nil, fmt.Errorf("alicloud.cloudsso.accessConfiguration %q not found in directory %q", acID, directoryID)
	}

	ac := resp.Body.AccessConfiguration
	res, err := newCloudssoAccessConfiguration(runtime, dir.serviceRegion, directoryID,
		ac.AccessConfigurationId, ac.AccessConfigurationName, ac.Description,
		ac.SessionDuration, ac.RelayState, ac.CreateTime, ac.UpdateTime)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlAlicloudCloudssoAccessConfiguration) permissionPolicies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CloudSsoClient(r.serviceRegion)
	if err != nil {
		return nil, err
	}

	directoryID := r.DirectoryId.Data
	acID := r.AccessConfigurationId.Data
	resp, err := client.ListPermissionPoliciesInAccessConfiguration(&cloudssoclient.ListPermissionPoliciesInAccessConfigurationRequest{
		DirectoryId:           new(directoryID),
		AccessConfigurationId: new(acID),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	if resp == nil || resp.Body == nil {
		return res, nil
	}
	for _, p := range resp.Body.PermissionPolicies {
		if p == nil || p.PermissionPolicyName == nil {
			continue
		}
		policyName := tea.StringValue(p.PermissionPolicyName)
		policyType := tea.StringValue(p.PermissionPolicyType)
		policy, err := CreateResource(r.MqlRuntime, "alicloud.cloudsso.permissionPolicy", map[string]*llx.RawData{
			"__id":                  llx.StringData(directoryID + "/" + acID + "/" + policyType + "/" + policyName),
			"directoryId":           llx.StringData(directoryID),
			"accessConfigurationId": llx.StringData(acID),
			"policyName":            llx.StringDataPtr(p.PermissionPolicyName),
			"policyType":            llx.StringDataPtr(p.PermissionPolicyType),
			"policyDocument":        llx.StringDataPtr(p.PermissionPolicyDocument),
			"addTime":               llx.TimeDataPtr(cloudssoParseTime(p.AddTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, policy)
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// alicloud.cloudsso.permissionPolicy
// ---------------------------------------------------------------------------

// ramPolicy resolves the Alibaba Cloud managed policy behind a System
// permission policy, so its statements can be read the same way as for a RAM
// identity. An Inline policy carries its statements in policyDocument instead.
func (r *mqlAlicloudCloudssoPermissionPolicy) ramPolicy() (*mqlAlicloudRamPolicy, error) {
	if r.PolicyType.Data != "System" || r.PolicyName.Data == "" {
		r.RamPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	policyName := r.PolicyName.Data
	systemType := "System"
	return resolveRamPolicy(r.MqlRuntime, &policyName, &systemType)
}

// ---------------------------------------------------------------------------
// alicloud.cloudsso.accessAssignment
// ---------------------------------------------------------------------------

func (r *mqlAlicloudCloudssoAccessAssignment) id() (string, error) {
	return r.DirectoryId.Data + "/" + r.AccessConfigurationId.Data + "/" +
		r.PrincipalId.Data + "/" + r.TargetId.Data, nil
}

func (r *mqlAlicloudCloudssoDirectory) accessAssignments() ([]any, error) {
	client, directoryID, err := r.cloudssoClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := &cloudssoclient.ListAccessAssignmentsRequest{
		DirectoryId: new(directoryID),
		MaxResults:  new(cloudssoPageSize),
	}
	for {
		resp, err := client.ListAccessAssignments(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		for _, a := range resp.Body.AccessAssignments {
			if a == nil || a.AccessConfigurationId == nil {
				continue
			}
			assignment, err := CreateResource(r.MqlRuntime, "alicloud.cloudsso.accessAssignment", map[string]*llx.RawData{
				"__id": llx.StringData(directoryID + "/" + tea.StringValue(a.AccessConfigurationId) + "/" +
					tea.StringValue(a.PrincipalId) + "/" + tea.StringValue(a.TargetId)),
				"directoryId":             llx.StringData(directoryID),
				"principalId":             llx.StringDataPtr(a.PrincipalId),
				"principalName":           llx.StringDataPtr(a.PrincipalName),
				"principalType":           llx.StringDataPtr(a.PrincipalType),
				"accessConfigurationId":   llx.StringDataPtr(a.AccessConfigurationId),
				"accessConfigurationName": llx.StringDataPtr(a.AccessConfigurationName),
				"targetId":                llx.StringDataPtr(a.TargetId),
				"targetName":              llx.StringDataPtr(a.TargetName),
				"targetType":              llx.StringDataPtr(a.TargetType),
				"targetPath":              llx.StringDataPtr(a.TargetPath),
				"createTime":              llx.TimeDataPtr(cloudssoParseTime(a.CreateTime)),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, assignment)
		}
		if !tea.BoolValue(resp.Body.IsTruncated) || tea.StringValue(resp.Body.NextToken) == "" {
			break
		}
		req.NextToken = resp.Body.NextToken
	}
	return res, nil
}

func (r *mqlAlicloudCloudssoAccessAssignment) accessConfiguration() (*mqlAlicloudCloudssoAccessConfiguration, error) {
	if r.AccessConfigurationId.Data == "" {
		r.AccessConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.cloudsso.accessConfiguration", map[string]*llx.RawData{
		"directoryId":           llx.StringData(r.DirectoryId.Data),
		"accessConfigurationId": llx.StringData(r.AccessConfigurationId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudCloudssoAccessConfiguration), nil
}

// account resolves the resource directory member account the assignment grants
// access on. Only RD-Account targets name an account.
func (r *mqlAlicloudCloudssoAccessAssignment) account() (*mqlAlicloudResourceManagerAccount, error) {
	if r.TargetId.Data == "" || r.TargetType.Data != "RD-Account" {
		r.Account.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.resourceManager.account", map[string]*llx.RawData{
		"accountId": llx.StringData(r.TargetId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudResourceManagerAccount), nil
}

func (r *mqlAlicloudCloudssoAccessAssignment) user() (*mqlAlicloudCloudssoUser, error) {
	if r.PrincipalType.Data != "User" {
		r.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	user, err := resolveCloudssoUser(r.MqlRuntime, r.DirectoryId.Data, r.PrincipalId.Data)
	if err != nil {
		return nil, err
	}
	// resolveCloudssoUser reports a blank id or a user it could not read as a
	// nil resource rather than an error, so the field has to be marked null
	// here or the runtime never learns it was resolved.
	if user == nil {
		r.User.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return user, nil
}

func (r *mqlAlicloudCloudssoAccessAssignment) group() (*mqlAlicloudCloudssoGroup, error) {
	if r.PrincipalType.Data != "Group" {
		r.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	group, err := resolveCloudssoGroup(r.MqlRuntime, r.DirectoryId.Data, r.PrincipalId.Data)
	if err != nil {
		return nil, err
	}
	// same as user above: a blank id or an unreadable group comes back as a nil
	// resource, which must be marked null explicitly
	if group == nil {
		r.Group.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return group, nil
}

// ---------------------------------------------------------------------------
// shared resolvers
// ---------------------------------------------------------------------------

// resolveCloudssoDirectory returns the directory resource for an ID.
func resolveCloudssoDirectory(runtime *plugin.Runtime, directoryID string) (*mqlAlicloudCloudssoDirectory, error) {
	res, err := NewResource(runtime, "alicloud.cloudsso.directory", map[string]*llx.RawData{
		"directoryId": llx.StringData(directoryID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudCloudssoDirectory), nil
}

// resolveCloudssoUser returns the user resource for a directory and user ID,
// logging and skipping a user that can no longer be read rather than failing
// the surrounding list.
func resolveCloudssoUser(runtime *plugin.Runtime, directoryID, userID string) (*mqlAlicloudCloudssoUser, error) {
	if directoryID == "" || userID == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.cloudsso.user", map[string]*llx.RawData{
		"directoryId": llx.StringData(directoryID),
		"userId":      llx.StringData(userID),
	})
	if err != nil {
		log.Debug().Err(err).Str("user", userID).Str("directory", directoryID).
			Msg("alicloud: could not resolve CloudSSO user")
		return nil, nil
	}
	return res.(*mqlAlicloudCloudssoUser), nil
}

// resolveCloudssoGroup returns the group resource for a directory and group ID.
func resolveCloudssoGroup(runtime *plugin.Runtime, directoryID, groupID string) (*mqlAlicloudCloudssoGroup, error) {
	if directoryID == "" || groupID == "" {
		return nil, nil
	}
	res, err := NewResource(runtime, "alicloud.cloudsso.group", map[string]*llx.RawData{
		"directoryId": llx.StringData(directoryID),
		"groupId":     llx.StringData(groupID),
	})
	if err != nil {
		log.Debug().Err(err).Str("group", groupID).Str("directory", directoryID).
			Msg("alicloud: could not resolve CloudSSO group")
		return nil, nil
	}
	return res.(*mqlAlicloudCloudssoGroup), nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/providers/google-workspace/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/groupssettings/v1"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	directory "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/cloudidentity/v1"
)

func (g *mqlGoogleworkspace) groups() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	directoryService, err := directoryService(conn, directory.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		return nil, err
	}

	res := []any{}
	groups, err := directoryService.Groups.List().Customer(conn.CustomerID()).MaxResults(200).Do()
	if err != nil {
		return nil, err
	}

	for {
		for i := range groups.Groups {
			r, err := newMqlGoogleWorkspaceGroup(g.MqlRuntime, groups.Groups[i])
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}

		if groups.NextPageToken == "" {
			break
		}

		groups, err = directoryService.Groups.List().Customer(conn.CustomerID()).MaxResults(200).PageToken(groups.NextPageToken).Do()
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

func newMqlGoogleWorkspaceGroup(runtime *plugin.Runtime, entry *directory.Group) (any, error) {
	return CreateResource(runtime, "googleworkspace.group", map[string]*llx.RawData{
		"id":                 llx.StringData(entry.Id),
		"name":               llx.StringData(entry.Name),
		"email":              llx.StringData(entry.Email),
		"description":        llx.StringData(entry.Description),
		"aliases":            llx.ArrayData(convert.SliceAnyToInterface[string](entry.Aliases), types.Any),
		"nonEditableAliases": llx.ArrayData(convert.SliceAnyToInterface[string](entry.NonEditableAliases), types.Any),
		"directMembersCount": llx.IntData(entry.DirectMembersCount),
		"adminCreated":       llx.BoolData(entry.AdminCreated),
	})
}

func (g *mqlGoogleworkspaceGroup) id() (string, error) {
	return "googleworkspace.group/" + g.Id.Data, g.Id.Error
}

func (g *mqlGoogleworkspaceGroup) members() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	directoryService, err := directoryService(conn, directory.AdminDirectoryGroupMemberReadonlyScope)
	if err != nil {
		return nil, err
	}

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	id := g.Id.Data

	res := []any{}

	members, err := directoryService.Members.List(id).MaxResults(200).Do()
	if err != nil {
		return nil, err
	}

	for {
		for i := range members.Members {
			r, err := newMqlGoogleWorkspaceMember(g.MqlRuntime, members.Members[i])
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}

		if members.NextPageToken == "" {
			break
		}

		members, err = directoryService.Members.List(id).MaxResults(200).PageToken(members.NextPageToken).Do()
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

func newMqlGoogleWorkspaceMember(runtime *plugin.Runtime, entry *directory.Member) (any, error) {
	return CreateResource(runtime, "googleworkspace.member", map[string]*llx.RawData{
		"id":               llx.StringData(entry.Id),
		"email":            llx.StringData(entry.Email),
		"role":             llx.StringData(entry.Role),
		"status":           llx.StringData(entry.Status),
		"type":             llx.StringData(entry.Type),
		"deliverySettings": llx.StringData(entry.DeliverySettings),
	})
}

func (g *mqlGoogleworkspaceMember) id() (string, error) {
	return "googleworkspace.member/" + g.Id.Data, g.Id.Error
}

func (g *mqlGoogleworkspaceMember) user() (*mqlGoogleworkspaceUser, error) {
	if g.Email.Error != nil {
		return nil, g.Email.Error
	}
	email := g.Email.Data
	if g.Type.Error != nil {
		return nil, g.Type.Error
	}
	typ := g.Type.Data

	if strings.ToLower(typ) != "user" {
		g.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	obj, err := CreateResource(g.MqlRuntime, "googleworkspace", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	gws := obj.(*mqlGoogleworkspace)

	user, err := gws.userByEmail(email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		g.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return user, nil
}

// parseGroupSettingBool converts a Groups Settings API boolean, which the API
// encodes as the string "true"/"false", into a typed bool.
func parseGroupSettingBool(s string) bool {
	return strings.EqualFold(s, "true")
}

// groupSettingsData is the plain-struct projection of groupssettings.Groups
// used to build the typed resource. Boolean-valued API fields (returned as
// "true"/"false" strings) are normalized to Go bools here.
type groupSettingsData struct {
	WhoCanJoin                 string
	WhoCanViewMembership       string
	WhoCanViewGroup            string
	WhoCanPostMessage          string
	WhoCanContactOwner         string
	WhoCanModerateMembers      string
	WhoCanModerateContent      string
	WhoCanDiscoverGroup        string
	WhoCanLeaveGroup           string
	AllowExternalMembers       bool
	AllowWebPosting            bool
	ArchiveOnly                bool
	IsArchived                 bool
	MembersCanPostAsTheGroup   bool
	IncludeInGlobalAddressList bool
	EnableCollaborativeInbox   bool
	MessageModerationLevel     string
	SpamModerationLevel        string
}

func groupSettingsToData(settings *groupssettings.Groups) groupSettingsData {
	return groupSettingsData{
		WhoCanJoin:                 settings.WhoCanJoin,
		WhoCanViewMembership:       settings.WhoCanViewMembership,
		WhoCanViewGroup:            settings.WhoCanViewGroup,
		WhoCanPostMessage:          settings.WhoCanPostMessage,
		WhoCanContactOwner:         settings.WhoCanContactOwner,
		WhoCanModerateMembers:      settings.WhoCanModerateMembers,
		WhoCanModerateContent:      settings.WhoCanModerateContent,
		WhoCanDiscoverGroup:        settings.WhoCanDiscoverGroup,
		WhoCanLeaveGroup:           settings.WhoCanLeaveGroup,
		AllowExternalMembers:       parseGroupSettingBool(settings.AllowExternalMembers),
		AllowWebPosting:            parseGroupSettingBool(settings.AllowWebPosting),
		ArchiveOnly:                parseGroupSettingBool(settings.ArchiveOnly),
		IsArchived:                 parseGroupSettingBool(settings.IsArchived),
		MembersCanPostAsTheGroup:   parseGroupSettingBool(settings.MembersCanPostAsTheGroup),
		IncludeInGlobalAddressList: parseGroupSettingBool(settings.IncludeInGlobalAddressList),
		EnableCollaborativeInbox:   parseGroupSettingBool(settings.EnableCollaborativeInbox),
		MessageModerationLevel:     settings.MessageModerationLevel,
		SpamModerationLevel:        settings.SpamModerationLevel,
	}
}

func (g *mqlGoogleworkspaceGroup) groupSettings() (*mqlGoogleworkspaceGroupSettingsConfig, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	service, err := groupSettingsService(conn, groupssettings.AppsGroupsSettingsScope)
	if err != nil {
		return nil, err
	}

	if g.Email.Error != nil {
		return nil, g.Email.Error
	}
	email := g.Email.Data
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}

	settings, err := service.Groups.Get(email).Do()
	if err != nil {
		return nil, err
	}

	d := groupSettingsToData(settings)
	res, err := CreateResource(g.MqlRuntime, "googleworkspace.group.settingsConfig", map[string]*llx.RawData{
		"__id":                       llx.StringData("googleworkspace.group.settingsConfig/" + g.Id.Data),
		"whoCanJoin":                 llx.StringData(d.WhoCanJoin),
		"whoCanViewMembership":       llx.StringData(d.WhoCanViewMembership),
		"whoCanViewGroup":            llx.StringData(d.WhoCanViewGroup),
		"whoCanPostMessage":          llx.StringData(d.WhoCanPostMessage),
		"whoCanContactOwner":         llx.StringData(d.WhoCanContactOwner),
		"whoCanModerateMembers":      llx.StringData(d.WhoCanModerateMembers),
		"whoCanModerateContent":      llx.StringData(d.WhoCanModerateContent),
		"whoCanDiscoverGroup":        llx.StringData(d.WhoCanDiscoverGroup),
		"whoCanLeaveGroup":           llx.StringData(d.WhoCanLeaveGroup),
		"allowExternalMembers":       llx.BoolData(d.AllowExternalMembers),
		"allowWebPosting":            llx.BoolData(d.AllowWebPosting),
		"archiveOnly":                llx.BoolData(d.ArchiveOnly),
		"isArchived":                 llx.BoolData(d.IsArchived),
		"membersCanPostAsTheGroup":   llx.BoolData(d.MembersCanPostAsTheGroup),
		"includeInGlobalAddressList": llx.BoolData(d.IncludeInGlobalAddressList),
		"enableCollaborativeInbox":   llx.BoolData(d.EnableCollaborativeInbox),
		"messageModerationLevel":     llx.StringData(d.MessageModerationLevel),
		"spamModerationLevel":        llx.StringData(d.SpamModerationLevel),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGoogleworkspaceGroupSettingsConfig), nil
}

func (g *mqlGoogleworkspaceGroup) securitySettings() (any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	service, err := cloudIdentityService(conn, cloudidentity.CloudIdentityGroupsReadonlyScope)
	if err != nil {
		return nil, err
	}

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	groupId := g.Id.Data

	securitySettings, err := service.Groups.GetSecuritySettings(`groups/` + groupId + `/securitySettings`).ReadMask("*").Do()
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(securitySettings)
}

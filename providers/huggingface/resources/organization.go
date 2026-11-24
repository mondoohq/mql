// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	hfmodels "go.mondoo.com/mql/providers/huggingface/internal/huggingface-hub-go/models"
	"go.mondoo.com/mql/types"
)

// The organization settings endpoints are limited to some plans and to
// administrators. Like the provider's other listers, a refused or missing
// answer (401, 403, 404) reads as an empty list, or as null for the singular
// network security settings.
func orgSettingsUnavailable(err error) bool {
	return isAccessDenied(err) || isNotFound(err)
}

func (r *mqlHuggingfaceOrganization) members() ([]any, error) {
	client := hfConn(r.MqlRuntime).Client()
	members, err := client.ListOrgMembers(context.Background(), r.Name.Data)
	if orgSettingsUnavailable(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(members))
	for _, m := range members {
		member, err := createOrgMember(r.MqlRuntime, r.Id.Data, m)
		if err != nil {
			return nil, err
		}
		res = append(res, member)
	}
	return res, nil
}

func createOrgMember(runtime *plugin.Runtime, orgID string, m hfmodels.OrgMember) (plugin.Resource, error) {
	args := orgMemberArgs(orgID, m)
	groups := make([]any, 0, len(m.ResourceGroups))
	for _, g := range m.ResourceGroups {
		gres, err := CreateResource(runtime, "huggingface.organization.member.resourceGroup", map[string]*llx.RawData{
			"__id":         llx.StringData(args["__id"].Value.(string) + "/" + g.ID),
			"id":           llx.StringData(g.ID),
			"name":         llx.StringData(g.Name),
			"role":         optionalString(g.Role),
			"assignedRole": optionalString(g.AssignedRole),
		})
		if err != nil {
			return nil, err
		}
		groups = append(groups, gres)
	}
	args["resourceGroups"] = llx.ArrayData(groups, types.Resource("huggingface.organization.member.resourceGroup"))
	return CreateResource(runtime, "huggingface.organization.member", args)
}

// orgMemberArgs maps a member onto resource arguments. The id carries the
// organization because one account is a member of many organizations, with a
// different role in each.
func orgMemberArgs(orgID string, m hfmodels.OrgMember) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                   llx.StringData("huggingface.organization.member/" + orgID + "/" + m.ID),
		"id":                     llx.StringData(m.ID),
		"name":                   llx.StringData(m.User),
		"fullname":               llx.StringData(m.Fullname),
		"role":                   optionalString(m.Role),
		"twoFaEnabled":           llx.BoolDataPtr(m.TwoFaEnabled),
		"isExternalCollaborator": llx.BoolDataPtr(m.IsExternalCollaborator),
		"verifiedEmail":          llx.StringDataPtr(m.VerifiedEmail),
	}
}

func (r *mqlHuggingfaceOrganization) networkSecurity() (*mqlHuggingfaceOrganizationNetworkSecuritySettings, error) {
	client := hfConn(r.MqlRuntime).Client()
	ns, err := client.GetOrgNetworkSecurity(context.Background(), r.Name.Data)
	if orgSettingsUnavailable(err) {
		r.NetworkSecurity.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	base := "huggingface.organization.networkSecuritySettings/" + r.Id.Data
	blocked, err := createContentRules(r.MqlRuntime, base+"/blocked", ns.BlockedContents)
	if err != nil {
		return nil, err
	}
	allowed, err := createContentRules(r.MqlRuntime, base+"/allowed", ns.AllowedContents)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(r.MqlRuntime, "huggingface.organization.networkSecuritySettings", map[string]*llx.RawData{
		"__id":                  llx.StringData(base),
		"enforceAuth":           llx.BoolDataPtr(ns.EnforceAuth),
		"enforceIpRestriction":  llx.BoolDataPtr(ns.EnforceIPRestriction),
		"areCidrRangesApproved": llx.BoolDataPtr(ns.AreCidrRangesApproved),
		"ipRanges":              stringListOrNull(ns.IPRanges),
		"blockedContents":       blocked,
		"allowedContents":       allowed,
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlHuggingfaceOrganizationNetworkSecuritySettings), nil
}

// createContentRules builds one list of content rules. A list the Hub did not
// send stays null.
func createContentRules(runtime *plugin.Runtime, base string, rules []hfmodels.ContentRef) (*llx.RawData, error) {
	if rules == nil {
		return llx.NilData, nil
	}
	res := make([]any, 0, len(rules))
	for _, c := range rules {
		cres, err := CreateResource(runtime, "huggingface.organization.contentRule", map[string]*llx.RawData{
			"__id":     llx.StringData(base + "/" + c.Resource + "/" + c.Scope),
			"resource": llx.StringData(c.Resource),
			"scope":    llx.StringData(c.Scope),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, cres)
	}
	return llx.ArrayData(res, types.Resource("huggingface.organization.contentRule")), nil
}

type mqlHuggingfaceOrganizationMemberTokenInternal struct {
	org     *mqlHuggingfaceOrganization
	ownerID string
}

func (r *mqlHuggingfaceOrganization) memberTokens() ([]any, error) {
	client := hfConn(r.MqlRuntime).Client()
	tokens, err := client.ListOrgMemberTokens(context.Background(), r.Name.Data)
	if orgSettingsUnavailable(err) {
		return []any{}, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(tokens))
	for _, t := range tokens {
		args := orgMemberTokenArgs(r.Id.Data, t)
		args["scopedPermissions"], err = createTokenScopes(r.MqlRuntime, args["__id"].Value.(string), t.FineGrained)
		if err != nil {
			return nil, err
		}
		tres, err := CreateResource(r.MqlRuntime, "huggingface.organization.memberToken", args)
		if err != nil {
			return nil, err
		}
		token := tres.(*mqlHuggingfaceOrganizationMemberToken)
		token.org = r
		token.ownerID = t.Owner.ID
		res = append(res, token)
	}
	return res, nil
}

// orgMemberTokenArgs maps a member token onto resource arguments. The Hub
// also returns the last characters of the token value; they are never read.
func orgMemberTokenArgs(orgID string, t hfmodels.OrgMemberToken) map[string]*llx.RawData {
	var authStatus *string
	if t.Authorization != nil && t.Authorization.Status != "" {
		authStatus = &t.Authorization.Status
	}
	return map[string]*llx.RawData{
		"__id":                llx.StringData("huggingface.organization.memberToken/" + orgID + "/" + t.ID),
		"id":                  llx.StringData(t.ID),
		"displayName":         llx.StringDataPtr(t.DisplayName),
		"role":                llx.StringData(t.Role),
		"createdAt":           llx.TimeDataPtr(parseHFTime(t.CreatedAt)),
		"lastUsedAt":          llx.TimeDataPtr(parseHFTime(t.LastUsedAt)),
		"authorizationStatus": llx.StringDataPtr(authStatus),
	}
}

// createTokenScopes builds the permission scopes of a fineGrained token. A
// read or write token carries no permission list, so the field stays null.
func createTokenScopes(runtime *plugin.Runtime, tokenID string, fg *hfmodels.OrgTokenFineGrained) (*llx.RawData, error) {
	if fg == nil {
		return llx.NilData, nil
	}
	scopes := make([]any, 0, len(fg.Scoped))
	for _, s := range fg.Scoped {
		sres, err := CreateResource(runtime, "huggingface.accessToken.scope", map[string]*llx.RawData{
			// Two tokens can hold permissions on the same entity, so the id
			// carries the token.
			"__id":        llx.StringData(tokenID + "/scope/" + s.Entity.ID),
			"entityId":    llx.StringData(s.Entity.ID),
			"entityType":  llx.StringData(s.Entity.Type),
			"entityName":  optionalString(s.Entity.Name),
			"permissions": llx.ArrayData(stringsToInterface(s.Permissions), types.String),
		})
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, sres)
	}
	return llx.ArrayData(scopes, types.Resource("huggingface.accessToken.scope")), nil
}

// owner resolves the token's owner against the organization's member list,
// which is read once per organization rather than once per token.
func (r *mqlHuggingfaceOrganizationMemberToken) owner() (*mqlHuggingfaceOrganizationMember, error) {
	if r.org == nil || r.ownerID == "" {
		r.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	members := r.org.GetMembers()
	if members.Error != nil {
		return nil, members.Error
	}
	for _, m := range members.Data {
		if member, ok := m.(*mqlHuggingfaceOrganizationMember); ok && member.Id.Data == r.ownerID {
			return member, nil
		}
	}
	r.Owner.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (r *mqlHuggingfaceOrganizationMember) id() (string, error) {
	return r.__id, nil
}

func (r *mqlHuggingfaceOrganizationMemberResourceGroup) id() (string, error) {
	return r.__id, nil
}

func (r *mqlHuggingfaceOrganizationNetworkSecuritySettings) id() (string, error) {
	return r.__id, nil
}

func (r *mqlHuggingfaceOrganizationContentRule) id() (string, error) {
	return r.__id, nil
}

func (r *mqlHuggingfaceOrganizationMemberToken) id() (string, error) {
	return r.__id, nil
}

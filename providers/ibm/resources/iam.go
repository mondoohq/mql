// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/IBM/platform-services-go-sdk/iamaccessgroupsv2"
	"github.com/IBM/platform-services-go-sdk/iamidentityv1"
	"github.com/IBM/platform-services-go-sdk/iampolicymanagementv1"
	"go.mondoo.com/mql/llx"
)

// pageSize is the largest page the IAM identity APIs accept.
const pageSize = int64(100)

// ---- account settings ----

func (r *mqlIbm) iamAccountSettings() (*mqlIbmIamAccountSettings, error) {
	c := conn(r.MqlRuntime)
	accountID := c.AccountID()
	s, _, err := c.IamIdentity().GetAccountSettings(&iamidentityv1.GetAccountSettingsOptions{AccountID: &accountID})
	if err != nil {
		return nil, classifyError(err, "iam-identity.account.get")
	}
	userMfa := map[string]string{}
	for _, u := range s.UserMfa {
		if u.IamID != nil && u.Mfa != nil {
			userMfa[*u.IamID] = *u.Mfa
		}
	}
	res, err := CreateResource(r.MqlRuntime, "ibm.iam.accountSettings", map[string]*llx.RawData{
		"__id":                                  llx.StringData("ibm.iam.accountSettings/" + accountID),
		"mfa":                                   notSet(s.Mfa),
		"restrictCreateServiceId":               notSet(s.RestrictCreateServiceID),
		"restrictCreatePlatformApiKey":          notSet(s.RestrictCreatePlatformApikey),
		"restrictUserListVisibility":            notSet(s.RestrictUserListVisibility),
		"allowedIpAddresses":                    stringsData(splitList(s.AllowedIPAddresses)),
		"sessionExpirationInSeconds":            notSetInt(s.SessionExpirationInSeconds),
		"sessionInvalidationInSeconds":          notSetInt(s.SessionInvalidationInSeconds),
		"maxSessionsPerIdentity":                notSetInt(s.MaxSessionsPerIdentity),
		"systemAccessTokenExpirationInSeconds":  notSetInt(s.SystemAccessTokenExpirationInSeconds),
		"systemRefreshTokenExpirationInSeconds": notSetInt(s.SystemRefreshTokenExpirationInSeconds),
		"userMfa":                               stringMapData(userMfa),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlIbmIamAccountSettings), nil
}

// publicAccessEnabled is an access-groups setting, so it is read on demand.
func (r *mqlIbmIamAccountSettings) publicAccessEnabled() (bool, error) {
	c := conn(r.MqlRuntime)
	accountID := c.AccountID()
	s, _, err := c.IamAccessGroups().GetAccountSettings(&iamaccessgroupsv2.GetAccountSettingsOptions{AccountID: &accountID})
	if err != nil {
		return false, classifyError(err, "iam-groups.groups.read")
	}
	if s.PublicAccessEnabled == nil {
		nullResource(&r.PublicAccessEnabled)
		return false, nil
	}
	return *s.PublicAccessEnabled, nil
}

// ---- access groups ----

func (r *mqlIbm) iamAccessGroups() ([]any, error) {
	c := conn(r.MqlRuntime)
	accountID := c.AccountID()
	pager, err := c.IamAccessGroups().NewAccessGroupsPager(&iamaccessgroupsv2.ListAccessGroupsOptions{AccountID: &accountID})
	if err != nil {
		return nil, err
	}
	groups, err := pager.GetAll()
	if err != nil {
		return nil, classifyError(err, "iam-groups.groups.read")
	}
	out := make([]any, 0, len(groups))
	for _, g := range groups {
		m, err := CreateResource(r.MqlRuntime, "ibm.iam.accessGroup", map[string]*llx.RawData{
			"__id":        llx.StringData("ibm.iam.accessGroup/" + derefStr(g.ID)),
			"id":          strData(g.ID),
			"name":        strData(g.Name),
			"description": strData(g.Description),
			"crn":         strData(g.CRN),
			"isFederated": llx.BoolDataPtr(g.IsFederated),
			"createdAt":   dateTimeData(g.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmIamAccessGroup) members() ([]any, error) {
	c := conn(r.MqlRuntime)
	id := r.Id.Data
	pager, err := c.IamAccessGroups().NewAccessGroupMembersPager(&iamaccessgroupsv2.ListAccessGroupMembersOptions{AccessGroupID: &id})
	if err != nil {
		return nil, err
	}
	members, err := pager.GetAll()
	if err != nil {
		return nil, classifyError(err, "iam-groups.groups.read")
	}
	out := make([]any, 0, len(members))
	for _, m := range members {
		res, err := CreateResource(r.MqlRuntime, "ibm.iam.accessGroup.member", map[string]*llx.RawData{
			"__id":  llx.StringData("ibm.iam.accessGroup.member/" + id + "/" + derefStr(m.IamID)),
			"iamId": strData(m.IamID),
			"type":  strData(m.Type),
			"name":  strData(m.Name),
			"email": strData(m.Email),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// policies scans the listed policies for the ones whose subject is this group.
func (r *mqlIbmIamAccessGroup) policies() ([]any, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetIamPolicies()
	if list.Error != nil {
		return nil, list.Error
	}
	out := []any{}
	for _, e := range list.Data {
		p := e.(*mqlIbmIamPolicy)
		if v, ok := p.SubjectAttributes.Data["access_group_id"]; ok && v == r.Id.Data {
			out = append(out, p)
		}
	}
	return out, nil
}

// ---- policies ----

// policyAttributes flattens a policy's subject or resource attributes into a
// name to value map. Policies in this account carry one subject and one
// resource; the attributes of several are merged.
func policyAttributes[T any](items []T, attrs func(T) map[string]string) map[string]string {
	out := map[string]string{}
	for _, it := range items {
		for k, v := range attrs(it) {
			out[k] = v
		}
	}
	return out
}

func (r *mqlIbm) iamPolicies() ([]any, error) {
	c := conn(r.MqlRuntime)
	accountID := c.AccountID()
	pager, err := c.IamPolicyManagement().NewPoliciesPager(&iampolicymanagementv1.ListPoliciesOptions{AccountID: &accountID})
	if err != nil {
		return nil, err
	}
	policies, err := pager.GetAll()
	if err != nil {
		return nil, classifyError(err, "iam.policy.read")
	}
	out := make([]any, 0, len(policies))
	for _, p := range policies {
		res, err := CreateResource(r.MqlRuntime, "ibm.iam.policy", policyArgs(p))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func policyArgs(p iampolicymanagementv1.PolicyTemplateMetaData) map[string]*llx.RawData {
	roles := make([]string, 0, len(p.Roles))
	roleIDs := make([]string, 0, len(p.Roles))
	for _, role := range p.Roles {
		roles = append(roles, derefStr(role.DisplayName))
		roleIDs = append(roleIDs, derefStr(role.RoleID))
	}
	subjects := policyAttributes(p.Subjects, func(s iampolicymanagementv1.PolicySubject) map[string]string {
		m := map[string]string{}
		for _, a := range s.Attributes {
			m[derefStr(a.Name)] = derefStr(a.Value)
		}
		return m
	})
	resources := policyAttributes(p.Resources, func(r iampolicymanagementv1.PolicyResource) map[string]string {
		m := map[string]string{}
		for _, a := range r.Attributes {
			m[derefStr(a.Name)] = derefStr(a.Value)
		}
		return m
	})
	return map[string]*llx.RawData{
		"__id":               llx.StringData("ibm.iam.policy/" + derefStr(p.ID)),
		"id":                 strData(p.ID),
		"type":               strData(p.Type),
		"description":        strData(p.Description),
		"state":              strData(p.State),
		"roles":              stringsData(roles),
		"roleIds":            stringsData(roleIDs),
		"subjectAttributes":  stringMapData(subjects),
		"resourceAttributes": stringMapData(resources),
		"createdAt":          dateTimeData(p.CreatedAt),
	}
}

// ---- service IDs ----

func (r *mqlIbm) iamServiceIds() ([]any, error) {
	c := conn(r.MqlRuntime)
	accountID := c.AccountID()
	size := pageSize
	opts := &iamidentityv1.ListServiceIdsOptions{AccountID: &accountID, Pagesize: &size}
	var all []iamidentityv1.ServiceID
	for {
		res, _, err := c.IamIdentity().ListServiceIds(opts)
		if err != nil {
			return nil, classifyError(err, "iam-identity.serviceid.get")
		}
		all = append(all, res.Serviceids...)
		next := pageToken(res.Next, "pagetoken")
		if !advances(opts.Pagetoken, next) {
			break
		}
		opts.Pagetoken = next
	}
	out := make([]any, 0, len(all))
	for _, s := range all {
		args := map[string]*llx.RawData{
			"__id":                llx.StringData("ibm.iam.serviceId/" + derefStr(s.ID)),
			"id":                  strData(s.ID),
			"iamId":               strData(s.IamID),
			"name":                strData(s.Name),
			"description":         strData(s.Description),
			"crn":                 strData(s.CRN),
			"locked":              llx.BoolDataPtr(s.Locked),
			"createdAt":           dateTimeData(s.CreatedAt),
			"modifiedAt":          dateTimeData(s.ModifiedAt),
			"lastAuthentication":  llx.NilData,
			"authenticationCount": llx.NilData,
		}
		if s.Activity != nil {
			args["lastAuthentication"] = rfc3339Data(s.Activity.LastAuthn)
			args["authenticationCount"] = intPtrData(s.Activity.AuthnCount)
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.iam.serviceId", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// apiKeys scans the listed API keys for the ones owned by this service ID.
func (r *mqlIbmIamServiceId) apiKeys() ([]any, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetIamApiKeys()
	if list.Error != nil {
		return nil, list.Error
	}
	out := []any{}
	for _, e := range list.Data {
		if k := e.(*mqlIbmIamApiKey); k.IamId.Data == r.IamId.Data {
			out = append(out, k)
		}
	}
	return out, nil
}

// ---- API keys ----

func (r *mqlIbm) iamApiKeys() ([]any, error) {
	c := conn(r.MqlRuntime)
	accountID := c.AccountID()
	size := pageSize
	scope := "account"
	opts := &iamidentityv1.ListAPIKeysOptions{AccountID: &accountID, Pagesize: &size, Scope: &scope}
	var all []iamidentityv1.APIKey
	for {
		res, _, err := c.IamIdentity().ListAPIKeys(opts)
		if err != nil {
			return nil, classifyError(err, "iam-identity.apikey.list")
		}
		all = append(all, res.Apikeys...)
		next := pageToken(res.Next, "pagetoken")
		if !advances(opts.Pagetoken, next) {
			break
		}
		opts.Pagetoken = next
	}
	out := make([]any, 0, len(all))
	for _, k := range all {
		res, err := CreateResource(r.MqlRuntime, "ibm.iam.apiKey", apiKeyArgs(k))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// apiKeyArgs maps an API key's metadata. The key value itself is never read:
// the list call does not return it, and nothing here asks for it.
func apiKeyArgs(k iamidentityv1.APIKey) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id":                llx.StringData("ibm.iam.apiKey/" + derefStr(k.ID)),
		"id":                  strData(k.ID),
		"name":                strData(k.Name),
		"description":         strData(k.Description),
		"crn":                 strData(k.CRN),
		"iamId":               strData(k.IamID),
		"locked":              llx.BoolDataPtr(k.Locked),
		"disabled":            llx.BoolDataPtr(k.Disabled),
		"createdAt":           dateTimeData(k.CreatedAt),
		"createdBy":           strData(k.CreatedBy),
		"expiresAt":           rfc3339Data(k.ExpiresAt),
		"actionWhenLeaked":    strData(k.ActionWhenLeaked),
		"supportSessions":     llx.BoolDataPtr(k.SupportSessions),
		"lastAuthentication":  llx.NilData,
		"authenticationCount": llx.NilData,
	}
	if k.Activity != nil {
		args["lastAuthentication"] = rfc3339Data(k.Activity.LastAuthn)
		args["authenticationCount"] = intPtrData(k.Activity.AuthnCount)
	}
	return args
}

// serviceId resolves the owning service ID through the listed service IDs. A
// key owned by a user has no service ID and reads as null.
func (r *mqlIbmIamApiKey) serviceId() (*mqlIbmIamServiceId, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetIamServiceIds()
	if list.Error != nil {
		return nil, list.Error
	}
	if s, ok := pickOneByID(list.Data, r.IamId.Data, func(s *mqlIbmIamServiceId) string { return s.IamId.Data }); ok {
		return s, nil
	}
	nullResource(&r.ServiceId)
	return nil, nil
}

// ---- trusted profiles ----

func (r *mqlIbm) iamTrustedProfiles() ([]any, error) {
	c := conn(r.MqlRuntime)
	accountID := c.AccountID()
	size := pageSize
	opts := &iamidentityv1.ListProfilesOptions{AccountID: &accountID, Pagesize: &size}
	var all []iamidentityv1.TrustedProfile
	for {
		res, _, err := c.IamIdentity().ListProfiles(opts)
		if err != nil {
			return nil, classifyError(err, "iam-identity.profile.get")
		}
		all = append(all, res.Profiles...)
		next := pageToken(res.Next, "pagetoken")
		if !advances(opts.Pagetoken, next) {
			break
		}
		opts.Pagetoken = next
	}
	out := make([]any, 0, len(all))
	for _, p := range all {
		args := map[string]*llx.RawData{
			"__id":                llx.StringData("ibm.iam.trustedProfile/" + derefStr(p.ID)),
			"id":                  strData(p.ID),
			"iamId":               strData(p.IamID),
			"name":                strData(p.Name),
			"description":         strData(p.Description),
			"crn":                 strData(p.CRN),
			"createdAt":           dateTimeData(p.CreatedAt),
			"lastAuthentication":  llx.NilData,
			"authenticationCount": llx.NilData,
		}
		if p.Activity != nil {
			args["lastAuthentication"] = rfc3339Data(p.Activity.LastAuthn)
			args["authenticationCount"] = intPtrData(p.Activity.AuthnCount)
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.iam.trustedProfile", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

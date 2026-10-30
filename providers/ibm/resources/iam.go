// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"maps"
	"regexp"
	"time"

	"github.com/IBM/platform-services-go-sdk/accountmanagementv4"
	"github.com/IBM/platform-services-go-sdk/iamaccessgroupsv2"
	"github.com/IBM/platform-services-go-sdk/iamidentityv1"
	"github.com/IBM/platform-services-go-sdk/iampolicymanagementv1"
	"github.com/IBM/platform-services-go-sdk/usermanagementv1"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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
		maps.Copy(out, attrs(it))
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
	all, err := listServiceIDs(c.IamIdentity(), c.AccountID())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(all))
	for _, s := range all {
		res, err := CreateResource(r.MqlRuntime, "ibm.iam.serviceId", serviceIDArgs(s))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// listServiceIDs reads every service ID of the account. The list call carries
// no activity; lastAuthentication and authenticationCount are read per
// service ID.
func listServiceIDs(svc *iamidentityv1.IamIdentityV1, accountID string) ([]iamidentityv1.ServiceID, error) {
	size := pageSize
	opts := &iamidentityv1.ListServiceIdsOptions{AccountID: &accountID, Pagesize: &size}
	var all []iamidentityv1.ServiceID
	for {
		res, _, err := svc.ListServiceIds(opts)
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
	return all, nil
}

func serviceIDArgs(s iamidentityv1.ServiceID) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":        llx.StringData("ibm.iam.serviceId/" + derefStr(s.ID)),
		"id":          strData(s.ID),
		"iamId":       strData(s.IamID),
		"name":        strData(s.Name),
		"description": strData(s.Description),
		"crn":         strData(s.CRN),
		"locked":      llx.BoolDataPtr(s.Locked),
		"createdAt":   dateTimeData(s.CreatedAt),
		"modifiedAt":  dateTimeData(s.ModifiedAt),
	}
}

func (r *mqlIbmIamServiceId) activity() (*iamidentityv1.Activity, error) {
	return identityActivity(r.MqlRuntime, "serviceid", r.Id.Data, serviceIDActivity)
}

func (r *mqlIbmIamServiceId) lastAuthentication() (*time.Time, error) {
	a, err := r.activity()
	if err != nil {
		return nil, err
	}
	return lastAuthn(a, &r.LastAuthentication), nil
}

func (r *mqlIbmIamServiceId) authenticationCount() (int64, error) {
	a, err := r.activity()
	if err != nil {
		return 0, err
	}
	return authnCount(a, &r.AuthenticationCount), nil
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
	return apiKeysOf(list.Data, r.IamId.Data), nil
}

// apiKeysOf returns the listed API keys owned by an IAM ID.
func apiKeysOf(keys []any, iamID string) []any {
	out := []any{}
	if iamID == "" {
		return out
	}
	for _, e := range keys {
		if k, ok := e.(*mqlIbmIamApiKey); ok && k.IamId.Data == iamID {
			out = append(out, k)
		}
	}
	return out
}

// ---- API keys ----

func (r *mqlIbm) iamApiKeys() ([]any, error) {
	c := conn(r.MqlRuntime)
	all, err := listAPIKeys(c.IamIdentity(), c.AccountID())
	if err != nil {
		return nil, err
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

// listAPIKeys reads every API key of the account. The list call carries no
// activity; lastAuthentication and authenticationCount are read per key.
func listAPIKeys(svc *iamidentityv1.IamIdentityV1, accountID string) ([]iamidentityv1.APIKey, error) {
	size := pageSize
	scope := "account"
	opts := &iamidentityv1.ListAPIKeysOptions{AccountID: &accountID, Pagesize: &size, Scope: &scope}
	var all []iamidentityv1.APIKey
	for {
		res, _, err := svc.ListAPIKeys(opts)
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
	return all, nil
}

// apiKeyArgs maps an API key's metadata. The key value itself is never read:
// the list call does not return it, and nothing here asks for it.
func apiKeyArgs(k iamidentityv1.APIKey) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":             llx.StringData("ibm.iam.apiKey/" + derefStr(k.ID)),
		"id":               strData(k.ID),
		"name":             strData(k.Name),
		"description":      strData(k.Description),
		"crn":              strData(k.CRN),
		"iamId":            strData(k.IamID),
		"locked":           llx.BoolDataPtr(k.Locked),
		"disabled":         llx.BoolDataPtr(k.Disabled),
		"createdAt":        dateTimeData(k.CreatedAt),
		"createdBy":        strData(k.CreatedBy),
		"expiresAt":        rfc3339Data(k.ExpiresAt),
		"actionWhenLeaked": strData(k.ActionWhenLeaked),
		"supportSessions":  llx.BoolDataPtr(k.SupportSessions),
	}
}

func (r *mqlIbmIamApiKey) activity() (*iamidentityv1.Activity, error) {
	return identityActivity(r.MqlRuntime, "apikey", r.Id.Data, apiKeyActivity)
}

func (r *mqlIbmIamApiKey) lastAuthentication() (*time.Time, error) {
	a, err := r.activity()
	if err != nil {
		return nil, err
	}
	return lastAuthn(a, &r.LastAuthentication), nil
}

func (r *mqlIbmIamApiKey) authenticationCount() (int64, error) {
	a, err := r.activity()
	if err != nil {
		return 0, err
	}
	return authnCount(a, &r.AuthenticationCount), nil
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

// user resolves the owning user through the listed users. A key owned by a
// service ID has no user and reads as null.
func (r *mqlIbmIamApiKey) user() (*mqlIbmIamUser, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return resolveOne(&r.User, ns.GetIamUsers(), r.IamId.Data, func(u *mqlIbmIamUser) string { return u.IamId.Data })
}

// ---- users ----

// listUsers reads every user of the account, following the next_url cursor.
// A refusal is returned as an error, not as an empty list.
func listUsers(svc *usermanagementv1.UserManagementV1, accountID string) ([]usermanagementv1.UserProfile, error) {
	limit := pageSize
	opts := &usermanagementv1.ListUsersOptions{AccountID: &accountID, Limit: &limit}
	var all []usermanagementv1.UserProfile
	for {
		res, resp, err := svc.ListUsers(opts)
		if err != nil {
			return nil, classifyError(withStatus(err, resp), "user-management.user.read")
		}
		all = append(all, res.Resources...)
		next := pageToken(res.NextURL, "_start")
		if !advances(opts.Start, next) {
			break
		}
		opts.Start = next
	}
	return all, nil
}

func userArgs(u usermanagementv1.UserProfile) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":      llx.StringData("ibm.iam.user/" + derefStr(u.IamID)),
		"iamId":     strData(u.IamID),
		"userId":    strData(u.UserID),
		"email":     strData(u.Email),
		"firstName": strData(u.Firstname),
		"lastName":  strData(u.Lastname),
		"realm":     strData(u.Realm),
		"state":     strData(u.State),
		"addedOn":   rfc3339Data(u.AddedOn),
	}
}

func (r *mqlIbm) iamUsers() ([]any, error) {
	c := conn(r.MqlRuntime)
	svc, err := c.UserManagement()
	if err != nil {
		return nil, err
	}
	users, err := listUsers(svc, c.AccountID())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(users))
	for _, u := range users {
		res, err := CreateResource(r.MqlRuntime, "ibm.iam.user", userArgs(u))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// accountOwnerIamID reads the IAM ID of the account's owner.
func accountOwnerIamID(svc *accountmanagementv4.AccountManagementV4, accountID string) (string, error) {
	res, _, err := svc.GetAccount(&accountmanagementv4.GetAccountOptions{AccountID: &accountID})
	if err != nil {
		return "", classifyError(err, "")
	}
	return derefStr(res.OwnerIamid), nil
}

// accountOwner compares the user with the account's owner, which is read once
// per connection.
func (r *mqlIbmIamUser) accountOwner() (bool, error) {
	c := conn(r.MqlRuntime)
	v, err := c.Memo("accountOwnerIamId", func() (any, error) {
		svc, err := c.AccountManagement()
		if err != nil {
			return nil, err
		}
		return accountOwnerIamID(svc, c.AccountID())
	})
	if err != nil {
		return false, err
	}
	return isAccountOwner(r.IamId.Data, v.(string)), nil
}

func isAccountOwner(iamID, ownerIamID string) bool {
	return iamID != "" && iamID == ownerIamID
}

// mfa looks the user up in the account settings' per-user MFA list.
func (r *mqlIbmIamUser) mfa() (string, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return "", err
	}
	s := ns.GetIamAccountSettings()
	if s.Error != nil {
		return "", s.Error
	}
	um := s.Data.GetUserMfa()
	if um.Error != nil {
		return "", um.Error
	}
	if v, ok := userMfaOf(um.Data, r.IamId.Data); ok {
		return v, nil
	}
	nullResource(&r.Mfa)
	return "", nil
}

// userMfaOf returns a user's own MFA setting from the per-user MFA map.
func userMfaOf(userMfa map[string]any, iamID string) (string, bool) {
	if iamID == "" {
		return "", false
	}
	v, ok := userMfa[iamID].(string)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// policies scans the listed policies for the ones whose subject is the user.
func (r *mqlIbmIamUser) policies() ([]any, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetIamPolicies()
	if list.Error != nil {
		return nil, list.Error
	}
	return policiesForIamID(list.Data, r.IamId.Data), nil
}

// policiesForIamID returns the policies assigned to an IAM ID directly.
func policiesForIamID(policies []any, iamID string) []any {
	out := []any{}
	if iamID == "" {
		return out
	}
	for _, e := range policies {
		if p, ok := e.(*mqlIbmIamPolicy); ok {
			if v, ok := p.SubjectAttributes.Data["iam_id"]; ok && v == iamID {
				out = append(out, p)
			}
		}
	}
	return out
}

// accessGroups scans the listed access groups for the ones that list the user
// as a member.
func (r *mqlIbmIamUser) accessGroups() ([]any, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetIamAccessGroups()
	if list.Error != nil {
		return nil, list.Error
	}
	return accessGroupsWithMember(list.Data, r.IamId.Data)
}

// accessGroupsWithMember returns the access groups an IAM ID is a member of.
// A group whose members cannot be read fails the whole answer, so a refusal is
// not mistaken for "not a member".
func accessGroupsWithMember(groups []any, iamID string) ([]any, error) {
	out := []any{}
	if iamID == "" {
		return out, nil
	}
	for _, e := range groups {
		g, ok := e.(*mqlIbmIamAccessGroup)
		if !ok {
			continue
		}
		members := g.GetMembers()
		if members.Error != nil {
			return nil, members.Error
		}
		for _, m := range members.Data {
			if mm, ok := m.(*mqlIbmIamAccessGroupMember); ok && mm.IamId.Data == iamID {
				out = append(out, g)
				break
			}
		}
	}
	return out, nil
}

// apiKeys scans the listed API keys for the ones owned by the user.
func (r *mqlIbmIamUser) apiKeys() ([]any, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := ns.GetIamApiKeys()
	if list.Error != nil {
		return nil, list.Error
	}
	return apiKeysOf(list.Data, r.IamId.Data), nil
}

// ---- trusted profiles ----

func (r *mqlIbm) iamTrustedProfiles() ([]any, error) {
	c := conn(r.MqlRuntime)
	all, err := listTrustedProfiles(c.IamIdentity(), c.AccountID())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(all))
	for _, p := range all {
		res, err := CreateResource(r.MqlRuntime, "ibm.iam.trustedProfile", trustedProfileArgs(p))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// listTrustedProfiles reads every trusted profile of the account. The list
// call carries no activity; lastAuthentication and authenticationCount are
// read per profile.
func listTrustedProfiles(svc *iamidentityv1.IamIdentityV1, accountID string) ([]iamidentityv1.TrustedProfile, error) {
	size := pageSize
	opts := &iamidentityv1.ListProfilesOptions{AccountID: &accountID, Pagesize: &size}
	var all []iamidentityv1.TrustedProfile
	for {
		res, _, err := svc.ListProfiles(opts)
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
	return all, nil
}

func trustedProfileArgs(p iamidentityv1.TrustedProfile) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":        llx.StringData("ibm.iam.trustedProfile/" + derefStr(p.ID)),
		"id":          strData(p.ID),
		"iamId":       strData(p.IamID),
		"name":        strData(p.Name),
		"description": strData(p.Description),
		"crn":         strData(p.CRN),
		"createdAt":   dateTimeData(p.CreatedAt),
	}
}

func (r *mqlIbmIamTrustedProfile) activity() (*iamidentityv1.Activity, error) {
	return identityActivity(r.MqlRuntime, "profile", r.Id.Data, trustedProfileActivity)
}

func (r *mqlIbmIamTrustedProfile) lastAuthentication() (*time.Time, error) {
	a, err := r.activity()
	if err != nil {
		return nil, err
	}
	return lastAuthn(a, &r.LastAuthentication), nil
}

func (r *mqlIbmIamTrustedProfile) authenticationCount() (int64, error) {
	a, err := r.activity()
	if err != nil {
		return 0, err
	}
	return authnCount(a, &r.AuthenticationCount), nil
}

// ---- activity ----

// IBM Cloud returns an identity's activity (its last authentication and
// authentication count) only from the identity's own get call, and only when
// asked with include_activity=true. The list calls never carry it, so these
// fields are read per identity, once, and both share the one call.

// identityActivity runs get once per identity for the lifetime of the
// connection. An identity without an id has no activity.
func identityActivity(runtime *plugin.Runtime, kind string, id string, get func(*iamidentityv1.IamIdentityV1, string) (*iamidentityv1.Activity, error)) (*iamidentityv1.Activity, error) {
	if id == "" {
		return nil, nil
	}
	c := conn(runtime)
	v, err := c.Memo("iam/activity/"+kind+"/"+id, func() (any, error) {
		return get(c.IamIdentity(), id)
	})
	if err != nil {
		return nil, err
	}
	return v.(*iamidentityv1.Activity), nil
}

func apiKeyActivity(svc *iamidentityv1.IamIdentityV1, id string) (*iamidentityv1.Activity, error) {
	k, _, err := svc.GetAPIKey(&iamidentityv1.GetAPIKeyOptions{ID: &id, IncludeActivity: new(true)})
	if err != nil {
		return nil, classifyError(err, "iam-identity.apikey.get")
	}
	return k.Activity, nil
}

func serviceIDActivity(svc *iamidentityv1.IamIdentityV1, id string) (*iamidentityv1.Activity, error) {
	s, _, err := svc.GetServiceID(&iamidentityv1.GetServiceIDOptions{ID: &id, IncludeActivity: new(true)})
	if err != nil {
		return nil, classifyError(err, "iam-identity.serviceid.get")
	}
	return s.Activity, nil
}

func trustedProfileActivity(svc *iamidentityv1.IamIdentityV1, id string) (*iamidentityv1.Activity, error) {
	p, _, err := svc.GetProfile(&iamidentityv1.GetProfileOptions{ProfileID: &id, IncludeActivity: new(true)})
	if err != nil {
		return nil, classifyError(err, "iam-identity.profile.get")
	}
	return p.Activity, nil
}

// lastAuthn reads the last authentication; an identity that never
// authenticated, or that IBM Cloud has no activity for, reads as null rather
// than the zero time.
func lastAuthn(a *iamidentityv1.Activity, field *plugin.TValue[*time.Time]) *time.Time {
	if a == nil || a.LastAuthn == nil || *a.LastAuthn == "" {
		nullResource(field)
		return nil
	}
	t, ok := parseIAMTime(*a.LastAuthn)
	if !ok {
		log.Debug().Str("last_authn", *a.LastAuthn).Msg("ibm> cannot parse the last authentication time")
		nullResource(field)
		return nil
	}
	return &t
}

// iamTimeLayouts are the forms IAM Identity writes activity times in. Its
// last_authn has milliseconds after a colon (2026-10-16T06:40:12:345+0000),
// which iamMillis turns into a decimal point first; RFC 3339 and the API
// reference's form to the minute (2026-10-16T06:40+0000) are accepted too.
var iamTimeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02T15:04Z07:00",
	"2006-01-02T15:04Z0700",
}

// iamMillis is the colon before the milliseconds of an IAM activity time.
var iamMillis = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}):(\d+)`)

// parseIAMTime parses an activity time in any of iamTimeLayouts.
func parseIAMTime(s string) (time.Time, bool) {
	s = iamMillis.ReplaceAllString(s, "$1.$2")
	for _, layout := range iamTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// authnCount reads the authentication count; without activity data it is
// null.
func authnCount(a *iamidentityv1.Activity, field *plugin.TValue[int64]) int64 {
	if a == nil || a.AuthnCount == nil {
		nullResource(field)
		return 0
	}
	return *a.AuthnCount
}

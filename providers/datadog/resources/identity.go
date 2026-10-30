// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV1"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/datadog/connection"
)

// datadogRoot returns the cached datadog singleton. It owns the once-fetched
// user, role, team and key lists that the identity accessors resolve against,
// so reaching it from a child resource keeps a graph traversal to one API call
// per collection rather than one per node.
func datadogRoot(runtime *plugin.Runtime) (*mqlDatadog, error) {
	res, err := CreateResource(runtime, "datadog", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	root, ok := res.(*mqlDatadog)
	if !ok {
		return nil, errors.New("datadog> unexpected type for the datadog resource")
	}
	return root, nil
}

// --- Shared caches ---

func (r *mqlDatadog) fetchRoles() ([]datadogV2.Role, error) {
	r.rolesOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
		api := datadogV2.NewRolesApi(conn.ApiClient())

		pageSize := int64(100)
		page := int64(0)
		for {
			resp, httpResp, err := api.ListRoles(conn.AuthCtx(),
				*datadogV2.NewListRolesOptionalParameters().WithPageSize(pageSize).WithPageNumber(page))
			if err != nil {
				if isForbidden(httpResp) {
					log.Warn().Msg("datadog> roles not available (403 Forbidden)")
					return
				}
				r.rolesErr = err
				return
			}

			data := resp.GetData()
			r.rolesList = append(r.rolesList, data...)

			if int64(len(data)) < pageSize {
				return
			}
			page++
		}
	})
	return r.rolesList, r.rolesErr
}

func (r *mqlDatadog) fetchTeams() ([]datadogV2.Team, error) {
	r.teamsOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
		api := datadogV2.NewTeamsApi(conn.ApiClient())

		items, cancel := api.ListTeamsWithPagination(conn.AuthCtx(),
			*datadogV2.NewListTeamsOptionalParameters().WithPageSize(100))
		defer cancel()

		for item := range items {
			if item.Error != nil {
				r.teamsErr = item.Error
				return
			}
			r.teamsList = append(r.teamsList, item.Item)
		}
	})
	return r.teamsList, r.teamsErr
}

func (r *mqlDatadog) fetchDashboards() ([]datadogV1.DashboardSummaryDefinition, error) {
	r.dashboardsOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
		api := datadogV1.NewDashboardsApi(conn.ApiClient())

		resp, httpResp, err := api.ListDashboards(conn.AuthCtx())
		if err != nil {
			if isForbidden(httpResp) {
				log.Warn().Msg("datadog> dashboards not available (403 Forbidden)")
				return
			}
			r.dashboardsErr = err
			return
		}
		r.dashboardsList = resp.GetDashboards()
	})
	return r.dashboardsList, r.dashboardsErr
}

func (r *mqlDatadog) fetchApiKeys() ([]datadogV2.PartialAPIKey, error) {
	r.apiKeysOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
		api := datadogV2.NewKeyManagementApi(conn.ApiClient())

		pageSize := int64(100)
		page := int64(0)
		for {
			resp, httpResp, err := api.ListAPIKeys(conn.AuthCtx(),
				*datadogV2.NewListAPIKeysOptionalParameters().WithPageSize(pageSize).WithPageNumber(page))
			if err != nil {
				if isForbidden(httpResp) {
					log.Warn().Msg("datadog> API keys not available (403 Forbidden)")
					return
				}
				r.apiKeysErr = err
				return
			}

			data := resp.GetData()
			r.apiKeysList = append(r.apiKeysList, data...)

			if int64(len(data)) < pageSize {
				return
			}
			page++
		}
	})
	return r.apiKeysList, r.apiKeysErr
}

func (r *mqlDatadog) fetchApplicationKeys() ([]datadogV2.PartialApplicationKey, error) {
	r.appKeysOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
		api := datadogV2.NewKeyManagementApi(conn.ApiClient())

		pageSize := int64(100)
		page := int64(0)
		for {
			resp, httpResp, err := api.ListApplicationKeys(conn.AuthCtx(),
				*datadogV2.NewListApplicationKeysOptionalParameters().WithPageSize(pageSize).WithPageNumber(page))
			if err != nil {
				if isForbidden(httpResp) {
					log.Warn().Msg("datadog> application keys not available (403 Forbidden)")
					return
				}
				r.appKeysErr = err
				return
			}

			data := resp.GetData()
			r.appKeysList = append(r.appKeysList, data...)

			if int64(len(data)) < pageSize {
				return
			}
			page++
		}
	})
	return r.appKeysList, r.appKeysErr
}

// --- User index ---

// userIndex resolves the several identifiers Datadog uses to reference the same
// person: monitors and SLOs record a creator email address, dashboards record an
// author handle, and the key management API references users by ID.
type userIndex struct {
	byId     map[string]datadogV2.User
	byHandle map[string]datadogV2.User
	byEmail  map[string]datadogV2.User
}

func newUserIndex(users []datadogV2.User) *userIndex {
	idx := &userIndex{
		byId:     make(map[string]datadogV2.User, len(users)),
		byHandle: make(map[string]datadogV2.User, len(users)),
		byEmail:  make(map[string]datadogV2.User, len(users)),
	}
	for _, u := range users {
		if id := u.GetId(); id != "" {
			idx.byId[id] = u
		}
		attrs := u.GetAttributes()
		if handle := strings.ToLower(attrs.GetHandle()); handle != "" {
			idx.byHandle[handle] = u
		}
		if email := strings.ToLower(attrs.GetEmail()); email != "" {
			idx.byEmail[email] = u
		}
	}
	return idx
}

// lookup finds a user by ID, handle or email address. IDs are matched first
// because they are unambiguous; handles and emails are matched case
// insensitively, since Datadog echoes back whatever casing was entered.
func (idx *userIndex) lookup(ref string) (datadogV2.User, bool) {
	if idx == nil || ref == "" {
		return datadogV2.User{}, false
	}
	if u, ok := idx.byId[ref]; ok {
		return u, true
	}
	lower := strings.ToLower(ref)
	if u, ok := idx.byHandle[lower]; ok {
		return u, true
	}
	u, ok := idx.byEmail[lower]
	return u, ok
}

func (r *mqlDatadog) fetchUserIndex() (*userIndex, error) {
	users, err := r.fetchUsers()
	if err != nil {
		return nil, err
	}
	r.userIndexOnce.Do(func() {
		r.userIndexData = newUserIndex(users)
	})
	return r.userIndexData, nil
}

// resolveUserRef turns a user ID, handle or email address into a datadog.user.
// The field is marked null when the reference is empty or no longer matches an
// account, which happens whenever the person who created a resource has since
// been removed from the organization.
func resolveUserRef(runtime *plugin.Runtime, ref string, field *plugin.TValue[*mqlDatadogUser]) (*mqlDatadogUser, error) {
	if ref == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	root, err := datadogRoot(runtime)
	if err != nil {
		return nil, err
	}
	idx, err := root.fetchUserIndex()
	if err != nil {
		return nil, err
	}

	u, ok := idx.lookup(ref)
	if !ok {
		log.Debug().Str("user", ref).Msg("datadog> referenced user is not a member of the organization")
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(runtime, "datadog.user", userArgs(u))
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatadogUser), nil
}

// --- Argument builders ---

func userArgs(u datadogV2.User) map[string]*llx.RawData {
	attrs := u.GetAttributes()
	return map[string]*llx.RawData{
		"id":             llx.StringData(u.GetId()),
		"email":          llx.StringData(attrs.GetEmail()),
		"name":           llx.StringData(attrs.GetName()),
		"handle":         llx.StringData(attrs.GetHandle()),
		"status":         llx.StringData(attrs.GetStatus()),
		"title":          llx.StringData(attrs.GetTitle()),
		"serviceAccount": llx.BoolData(attrs.GetServiceAccount()),
		"verified":       llx.BoolData(attrs.GetVerified()),
		"disabled":       llx.BoolData(attrs.GetDisabled()),
		"createdAt":      llx.TimeDataPtr(timePtr(attrs.GetCreatedAt())),
		"icon":           llx.StringData(attrs.GetIcon()),
	}
}

func roleArgs(role datadogV2.Role) map[string]*llx.RawData {
	attrs := role.GetAttributes()
	return map[string]*llx.RawData{
		"id":         llx.StringData(role.GetId()),
		"name":       llx.StringData(attrs.GetName()),
		"userCount":  llx.IntData(int64(attrs.GetUserCount())),
		"createdAt":  llx.TimeDataPtr(timePtr(attrs.GetCreatedAt())),
		"modifiedAt": llx.TimeDataPtr(timePtr(attrs.GetModifiedAt())),
	}
}

func teamArgs(t datadogV2.Team) map[string]*llx.RawData {
	attrs := t.GetAttributes()
	return map[string]*llx.RawData{
		"id":          llx.StringData(t.GetId()),
		"name":        llx.StringData(attrs.GetName()),
		"handle":      llx.StringData(attrs.GetHandle()),
		"description": llx.StringData(attrs.GetDescription()),
		"userCount":   llx.IntData(int64(attrs.GetUserCount())),
		"createdAt":   llx.TimeDataPtr(timePtr(attrs.GetCreatedAt())),
		"modifiedAt":  llx.TimeDataPtr(timePtr(attrs.GetModifiedAt())),
	}
}

func dashboardArgs(d datadogV1.DashboardSummaryDefinition) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":          llx.StringData(d.GetId()),
		"title":       llx.StringData(d.GetTitle()),
		"description": llx.StringData(d.GetDescription()),
		"layoutType":  llx.StringData(string(d.GetLayoutType())),
		"url":         llx.StringData(d.GetUrl()),
		"createdAt":   llx.TimeDataPtr(timePtr(d.GetCreatedAt())),
		"modifiedAt":  llx.TimeDataPtr(timePtr(d.GetModifiedAt())),
		"isReadOnly":  llx.BoolData(d.GetIsReadOnly()),
	}
}

// newDashboard builds a dashboard and primes the author handle the authorship
// edge resolves against. Both the listing and the init go through here so a
// dashboard reached by id resolves its author the same way a listed one does.
func newDashboard(runtime *plugin.Runtime, d datadogV1.DashboardSummaryDefinition) (*mqlDatadogDashboard, error) {
	res, err := CreateResource(runtime, "datadog.dashboard", dashboardArgs(d))
	if err != nil {
		return nil, err
	}
	dashboard := res.(*mqlDatadogDashboard)
	dashboard.cacheAuthorHandle = d.GetAuthorHandle()
	return dashboard, nil
}

func permissionArgs(p datadogV2.Permission) map[string]*llx.RawData {
	attrs := p.GetAttributes()
	return map[string]*llx.RawData{
		"id":          llx.StringData(p.GetId()),
		"name":        llx.StringData(attrs.GetName()),
		"displayName": llx.StringData(attrs.GetDisplayName()),
		"description": llx.StringData(attrs.GetDescription()),
		"groupName":   llx.StringData(attrs.GetGroupName()),
		"displayType": llx.StringData(attrs.GetDisplayType()),
		"restricted":  llx.BoolData(attrs.GetRestricted()),
		"createdAt":   llx.TimeDataPtr(timePtr(attrs.GetCreated())),
	}
}

// --- Init functions ---

func initDatadogUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	id, ok := stringArg(args, "id")
	if !ok {
		return args, nil, nil
	}

	root, err := datadogRoot(runtime)
	if err != nil {
		return nil, nil, err
	}
	idx, err := root.fetchUserIndex()
	if err != nil {
		return nil, nil, err
	}

	u, found := idx.lookup(id)
	if !found {
		return nil, nil, fmt.Errorf("datadog.user %q not found", id)
	}
	return userArgs(u), nil, nil
}

func initDatadogRole(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	id, ok := stringArg(args, "id")
	if !ok {
		return args, nil, nil
	}

	root, err := datadogRoot(runtime)
	if err != nil {
		return nil, nil, err
	}
	rolesList, err := root.fetchRoles()
	if err != nil {
		return nil, nil, err
	}

	for _, role := range rolesList {
		if role.GetId() == id {
			return roleArgs(role), nil, nil
		}
	}
	return nil, nil, fmt.Errorf("datadog.role %q not found", id)
}

func initDatadogDashboard(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	id, ok := stringArg(args, "id")
	if !ok {
		return args, nil, nil
	}

	root, err := datadogRoot(runtime)
	if err != nil {
		return nil, nil, err
	}
	dashboards, err := root.fetchDashboards()
	if err != nil {
		return nil, nil, err
	}

	for _, d := range dashboards {
		if d.GetId() == id {
			res, err := newDashboard(runtime, d)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("datadog.dashboard %q not found", id)
}

func initDatadogTeam(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	id, ok := stringArg(args, "id")
	if !ok {
		return args, nil, nil
	}

	root, err := datadogRoot(runtime)
	if err != nil {
		return nil, nil, err
	}
	teamsList, err := root.fetchTeams()
	if err != nil {
		return nil, nil, err
	}

	for _, t := range teamsList {
		if t.GetId() == id {
			return teamArgs(t), nil, nil
		}
	}
	return nil, nil, fmt.Errorf("datadog.team %q not found", id)
}

// stringArg reads a non-empty string argument, reporting false when the
// argument is absent, of another type, or empty.
func stringArg(args map[string]*llx.RawData, name string) (string, bool) {
	raw, ok := args[name]
	if !ok || raw == nil {
		return "", false
	}
	s, ok := raw.Value.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// --- Organization ---

func (r *mqlDatadog) org() (*mqlDatadogOrganization, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV1.NewOrganizationsApi(conn.ApiClient())

	resp, httpResp, err := api.ListOrgs(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			return nil, errors.New("datadog> organization settings require the org_management permission")
		}
		return nil, err
	}

	orgs := resp.GetOrgs()
	if len(orgs) == 0 {
		return nil, errors.New("datadog> no organization returned for these credentials")
	}

	// ListOrgs returns the organization the credentials belong to first, plus
	// any child organizations a parent account manages. Match on the public ID
	// resolved at connect time so a parent account still reports its own org.
	org := orgs[0]
	if want := conn.OrgPublicId(); want != "" {
		for _, candidate := range orgs {
			if candidate.GetPublicId() == want {
				org = candidate
				break
			}
		}
	}

	settings := org.GetSettings()
	saml := settings.GetSaml()
	strictMode := settings.GetSamlStrictMode()
	idpInitiated := settings.GetSamlIdpInitiatedLogin()
	autocreate := settings.GetSamlAutocreateUsersDomains()

	res, err := CreateResource(r.MqlRuntime, "datadog.organization", map[string]*llx.RawData{
		"publicId":                     llx.StringData(org.GetPublicId()),
		"name":                         llx.StringData(org.GetName()),
		"description":                  llx.StringData(org.GetDescription()),
		"trial":                        llx.BoolData(org.GetTrial()),
		"createdAt":                    llx.TimeDataPtr(parseDatadogTime(org.GetCreated())),
		"samlEnabled":                  llx.BoolData(saml.GetEnabled()),
		"samlCanBeEnabled":             llx.BoolData(settings.GetSamlCanBeEnabled()),
		"samlStrictModeEnabled":        llx.BoolData(strictMode.GetEnabled()),
		"samlIdpInitiatedLoginEnabled": llx.BoolData(idpInitiated.GetEnabled()),
		"samlIdpMetadataUploaded":      llx.BoolData(settings.GetSamlIdpMetadataUploaded()),
		"samlIdpEndpoint":              llx.StringData(settings.GetSamlIdpEndpoint()),
		"samlLoginUrl":                 llx.StringData(settings.GetSamlLoginUrl()),
		"samlAutocreateUsersEnabled":   llx.BoolData(autocreate.GetEnabled()),
		"samlAutocreateUsersDomains":   llx.ArrayData(toAnyStrings(autocreate.GetDomains()), "\x02"),
		"samlAutocreateAccessRole":     llx.StringData(string(settings.GetSamlAutocreateAccessRole())),
		"privateWidgetShare":           llx.BoolData(settings.GetPrivateWidgetShare()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatadogOrganization), nil
}

func (r *mqlDatadogOrganization) id() (string, error) {
	return "datadog.organization/" + r.PublicId.Data, nil
}

type mqlDatadogOrganizationInternal struct {
	domainAllowlistOnce  sync.Once
	domainAllowlistAttrs datadogV2.DomainAllowlistResponseDataAttributes
	domainAllowlistErr   error
}

// fetchDomainAllowlist reads the invite domain allowlist, which lives behind a
// separate v2 endpoint rather than in the organization settings block. It is
// cached so that reading both domainAllowlistEnabled and domainAllowlistDomains
// costs one request.
func (r *mqlDatadogOrganization) fetchDomainAllowlist() (datadogV2.DomainAllowlistResponseDataAttributes, error) {
	r.domainAllowlistOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
		api := datadogV2.NewDomainAllowlistApi(conn.ApiClient())

		resp, httpResp, err := api.GetDomainAllowlist(conn.AuthCtx())
		if err != nil {
			if isForbidden(httpResp) {
				log.Warn().Msg("datadog> domain allowlist not available (403 Forbidden)")
				return
			}
			r.domainAllowlistErr = err
			return
		}

		data := resp.GetData()
		r.domainAllowlistAttrs = data.GetAttributes()
	})
	return r.domainAllowlistAttrs, r.domainAllowlistErr
}

func (r *mqlDatadogOrganization) domainAllowlistEnabled() (bool, error) {
	attrs, err := r.fetchDomainAllowlist()
	if err != nil {
		return false, err
	}
	return attrs.GetEnabled(), nil
}

func (r *mqlDatadogOrganization) domainAllowlistDomains() ([]any, error) {
	attrs, err := r.fetchDomainAllowlist()
	if err != nil {
		return nil, err
	}
	return toAnyStrings(attrs.GetDomains()), nil
}

// parseDatadogTime parses the timestamp formats the Datadog APIs return. Most
// endpoints emit RFC3339, but the v1 organization endpoint emits a space
// separated form, so a single parser keeps callers from having to know which.
func parseDatadogTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// --- Permissions ---

func (r *mqlDatadog) permissions() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewRolesApi(conn.ApiClient())

	resp, httpResp, err := api.ListPermissions(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> permissions not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []any
	for _, p := range resp.GetData() {
		res, err := CreateResource(r.MqlRuntime, "datadog.permission", permissionArgs(p))
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogPermission) id() (string, error) {
	return "datadog.permission/" + r.Id.Data, nil
}

// --- Role edges ---

func (r *mqlDatadogRole) permissions() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewRolesApi(conn.ApiClient())

	resp, httpResp, err := api.ListRolePermissions(conn.AuthCtx(), r.Id.Data)
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Str("role", r.Id.Data).Msg("datadog> role permissions not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []any
	for _, p := range resp.GetData() {
		res, err := CreateResource(r.MqlRuntime, "datadog.permission", permissionArgs(p))
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogRole) users() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewRolesApi(conn.ApiClient())

	var all []any
	pageSize := int64(100)
	page := int64(0)

	for {
		resp, httpResp, err := api.ListRoleUsers(conn.AuthCtx(), r.Id.Data,
			*datadogV2.NewListRoleUsersOptionalParameters().WithPageSize(pageSize).WithPageNumber(page))
		if err != nil {
			if isForbidden(httpResp) {
				log.Warn().Str("role", r.Id.Data).Msg("datadog> role members not available (403 Forbidden)")
				return nil, nil
			}
			return nil, err
		}

		data := resp.GetData()
		for _, u := range data {
			res, err := CreateResource(r.MqlRuntime, "datadog.user", userArgs(u))
			if err != nil {
				return nil, err
			}
			all = append(all, res)
		}

		if int64(len(data)) < pageSize {
			break
		}
		page++
	}
	return all, nil
}

// --- User edges ---

func (r *mqlDatadogUser) roles() ([]any, error) {
	root, err := datadogRoot(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	idx, err := root.fetchUserIndex()
	if err != nil {
		return nil, err
	}

	u, found := idx.lookup(r.Id.Data)
	if !found {
		return nil, fmt.Errorf("datadog.user %q is not a member of the organization", r.Id.Data)
	}

	roleIds := userRoleIds(u)
	if len(roleIds) == 0 {
		return []any{}, nil
	}

	rolesList, err := root.fetchRoles()
	if err != nil {
		return nil, err
	}
	byId := make(map[string]datadogV2.Role, len(rolesList))
	for _, role := range rolesList {
		byId[role.GetId()] = role
	}

	all := []any{}
	for _, id := range roleIds {
		role, ok := byId[id]
		if !ok {
			log.Warn().Str("role", id).Str("user", r.Id.Data).
				Msg("datadog> role assigned to a user was not returned by the roles API")
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "datadog.role", roleArgs(role))
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// userRoleIds extracts the role IDs the users API already reports alongside
// each account, so resolving a user's roles costs no extra request.
func userRoleIds(u datadogV2.User) []string {
	rels, ok := u.GetRelationshipsOk()
	if !ok || rels == nil {
		return nil
	}
	roles, ok := rels.GetRolesOk()
	if !ok || roles == nil {
		return nil
	}

	var ids []string
	for _, ref := range roles.GetData() {
		if id := ref.GetId(); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func (r *mqlDatadogUser) teams() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewTeamsApi(conn.ApiClient())

	resp, httpResp, err := api.GetUserMemberships(conn.AuthCtx(), r.Id.Data)
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Str("user", r.Id.Data).Msg("datadog> team memberships not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	all := []any{}
	for _, membership := range resp.GetData() {
		teamId := userTeamId(membership)
		if teamId == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "datadog.team", map[string]*llx.RawData{
			"id": llx.StringData(teamId),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// userTeamId reads the team side of a membership record.
func userTeamId(membership datadogV2.UserTeam) string {
	rels, ok := membership.GetRelationshipsOk()
	if !ok || rels == nil {
		return ""
	}
	team, ok := rels.GetTeamOk()
	if !ok || team == nil {
		return ""
	}
	data, ok := team.GetDataOk()
	if !ok || data == nil {
		return ""
	}
	return data.GetId()
}

// --- Team edges ---

func (r *mqlDatadogTeam) members() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewTeamsApi(conn.ApiClient())

	root, err := datadogRoot(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	idx, err := root.fetchUserIndex()
	if err != nil {
		return nil, err
	}

	all := []any{}
	pageSize := int64(100)
	page := int64(0)

	for {
		resp, httpResp, err := api.GetTeamMemberships(conn.AuthCtx(), r.Id.Data,
			*datadogV2.NewGetTeamMembershipsOptionalParameters().WithPageSize(pageSize).WithPageNumber(page))
		if err != nil {
			if isForbidden(httpResp) {
				log.Warn().Str("team", r.Id.Data).Msg("datadog> team members not available (403 Forbidden)")
				return nil, nil
			}
			return nil, err
		}

		data := resp.GetData()
		for _, membership := range data {
			userId := userTeamUserId(membership)
			if userId == "" {
				continue
			}
			u, found := idx.lookup(userId)
			if !found {
				log.Warn().Str("user", userId).Str("team", r.Id.Data).
					Msg("datadog> team member was not returned by the users API")
				continue
			}
			res, err := CreateResource(r.MqlRuntime, "datadog.user", userArgs(u))
			if err != nil {
				return nil, err
			}
			all = append(all, res)
		}

		if int64(len(data)) < pageSize {
			break
		}
		page++
	}
	return all, nil
}

// userTeamUserId reads the user side of a membership record.
func userTeamUserId(membership datadogV2.UserTeam) string {
	rels, ok := membership.GetRelationshipsOk()
	if !ok || rels == nil {
		return ""
	}
	user, ok := rels.GetUserOk()
	if !ok || user == nil {
		return ""
	}
	data, ok := user.GetDataOk()
	if !ok || data == nil {
		return ""
	}
	return data.GetId()
}

// --- Key ownership ---

func (r *mqlDatadogApiKey) createdBy() (*mqlDatadogUser, error) {
	created, _, err := r.keyOwners()
	if err != nil {
		return nil, err
	}
	return resolveUserRef(r.MqlRuntime, created, &r.CreatedBy)
}

func (r *mqlDatadogApiKey) modifiedBy() (*mqlDatadogUser, error) {
	_, modified, err := r.keyOwners()
	if err != nil {
		return nil, err
	}
	return resolveUserRef(r.MqlRuntime, modified, &r.ModifiedBy)
}

// keyOwners returns the user IDs that created and last modified the key. The
// relationships come from the same list call that produced the key, so both
// accessors share one request.
func (r *mqlDatadogApiKey) keyOwners() (string, string, error) {
	root, err := datadogRoot(r.MqlRuntime)
	if err != nil {
		return "", "", err
	}
	keys, err := root.fetchApiKeys()
	if err != nil {
		return "", "", err
	}

	for _, k := range keys {
		if k.GetId() != r.Id.Data {
			continue
		}
		rels, ok := k.GetRelationshipsOk()
		if !ok || rels == nil {
			return "", "", nil
		}

		created := ""
		if c, ok := rels.GetCreatedByOk(); ok && c != nil {
			if data, ok := c.GetDataOk(); ok && data != nil {
				created = data.GetId()
			}
		}

		modified := ""
		if m, ok := rels.GetModifiedByOk(); ok && m != nil {
			if data, ok := m.GetDataOk(); ok && data != nil {
				modified = data.GetId()
			}
		}
		return created, modified, nil
	}

	log.Debug().Str("apiKey", r.Id.Data).
		Msg("datadog> API key was not returned by the key management API, cannot resolve its owners")
	return "", "", nil
}

func (r *mqlDatadogApplicationKey) owner() (*mqlDatadogUser, error) {
	root, err := datadogRoot(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	keys, err := root.fetchApplicationKeys()
	if err != nil {
		return nil, err
	}

	ownerId := ""
	found := false
	for _, k := range keys {
		if k.GetId() != r.Id.Data {
			continue
		}
		found = true
		if rels, ok := k.GetRelationshipsOk(); ok && rels != nil {
			if owned, ok := rels.GetOwnedByOk(); ok && owned != nil {
				if data, ok := owned.GetDataOk(); ok && data != nil {
					ownerId = data.GetId()
				}
			}
		}
		break
	}
	if !found {
		log.Debug().Str("applicationKey", r.Id.Data).
			Msg("datadog> application key was not returned by the key management API, cannot resolve its owner")
	}
	return resolveUserRef(r.MqlRuntime, ownerId, &r.Owner)
}

// --- Authorship edges ---
//
// The API reports authorship as a bare handle or email. Each resource keeps
// that raw reference here and exposes only the user it resolves to.

type mqlDatadogMonitorInternal struct {
	cacheCreator string
}

type mqlDatadogDashboardInternal struct {
	cacheAuthorHandle string
}

type mqlDatadogSloInternal struct {
	cacheCreator string
}

type mqlDatadogSyntheticsTestInternal struct {
	cacheCreator string
}

func (r *mqlDatadogMonitor) createdBy() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheCreator, &r.CreatedBy)
}

func (r *mqlDatadogDashboard) author() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheAuthorHandle, &r.Author)
}

func (r *mqlDatadogSlo) createdBy() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheCreator, &r.CreatedBy)
}

func (r *mqlDatadogSyntheticsTest) createdBy() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheCreator, &r.CreatedBy)
}

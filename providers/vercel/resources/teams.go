// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vercel/connection"
	"go.mondoo.com/mql/types"
)

// mqlVercelTeamInternal caches the organization root team id, which is only
// present on the team payload and is resolved on demand by orgRootTeam.
type mqlVercelTeamInternal struct {
	cacheOrgRootTeamID string
}

type teamRecord struct {
	ID                                 string             `json:"id"`
	Slug                               string             `json:"slug"`
	Name                               string             `json:"name"`
	Avatar                             string             `json:"avatar"`
	CreatedAt                          flexTime           `json:"createdAt"`
	UpdatedAt                          flexTime           `json:"updatedAt"`
	CreatorID                          string             `json:"creatorId"`
	Billing                            *billingRecord     `json:"billing"`
	ParentID                           string             `json:"parentId"`
	OrgRootTeamID                      string             `json:"orgRootTeamId"`
	Saml                               *samlRecord        `json:"saml"`
	EmailDomain                        *string            `json:"emailDomain"`
	InviteCode                         string             `json:"inviteCode"`
	DpAccessRequestsMode               *string            `json:"dpAccessRequestsMode"`
	RequireVerifiedCommits             *bool              `json:"requireVerifiedCommits"`
	DisableRepositoryDispatchEvents    *bool              `json:"disableRepositoryDispatchEvents"`
	StrictDeploymentProtection         *strictSetting     `json:"strictDeploymentProtectionSettings"`
	StrictPasswordProtection           *strictSetting     `json:"strictPasswordProtectionSettings"`
	StrictShareableLinks               *strictSetting     `json:"strictShareableLinks"`
	DefaultDeploymentProtection        *defaultProtection `json:"defaultDeploymentProtection"`
	DefaultRoles                       *defaultRoles      `json:"defaultRoles"`
	DeploymentPolicy                   map[string]any     `json:"deploymentPolicy"`
	DefaultExpirationSettings          *expirationRecord  `json:"defaultExpirationSettings"`
	SensitiveEnvironmentVariablePolicy *string            `json:"sensitiveEnvironmentVariablePolicy"`
	HideIPAddresses                    *bool              `json:"hideIpAddresses"`
	HideIPAddressesInLogDrains         *bool              `json:"hideIpAddressesInLogDrains"`
	RemoteCaching                      *remoteCaching     `json:"remoteCaching"`
	Connect                            *connectRecord     `json:"connect"`
	EnablePreviewFeedback              *string            `json:"enablePreviewFeedback"`
	EnableProductionFeedback           *string            `json:"enableProductionFeedback"`
	PreviewDeploymentSuffix            *string            `json:"previewDeploymentSuffix"`
	StagingPrefix                      string             `json:"stagingPrefix"`
	PersonalAccessTokensInvalidatedAt  flexTime           `json:"personalAccessTokensInvalidatedAt"`
	AppTokensInvalidatedAt             flexTime           `json:"appTokensInvalidatedAt"`
	APIKeysInvalidatedAt               flexTime           `json:"apiKeysInvalidatedAt"`
	IntegrationTokensInvalidatedAt     flexTime           `json:"integrationTokensInvalidatedAt"`
}

type billingRecord struct {
	Plan string `json:"plan"`
}

type samlRecord struct {
	Enforced   bool              `json:"enforced"`
	Roles      map[string]string `json:"roles"`
	Connection *samlConnection   `json:"connection"`
	Directory  *samlConnection   `json:"directory"`
}

// samlConnection covers both the SAML connection and the Directory Sync
// connection, which Vercel returns with the same shape.
type samlConnection struct {
	Type        string   `json:"type"`
	State       string   `json:"state"`
	Status      string   `json:"status"`
	SyncState   string   `json:"syncState"`
	ConnectedAt flexTime `json:"connectedAt"`
	LastSynced  flexTime `json:"lastSyncedAt"`
}

type strictSetting struct {
	Enabled bool `json:"enabled"`
}

type defaultProtection struct {
	PasswordProtection *deploymentTypeHolder `json:"passwordProtection"`
	SsoProtection      *deploymentTypeHolder `json:"ssoProtection"`
}

type defaultRoles struct {
	TeamRoles       []string `json:"teamRoles"`
	TeamPermissions []string `json:"teamPermissions"`
}

// expirationRecord is the deployment retention policy, returned both as a team
// default and as the enforced policy on a project.
type expirationRecord struct {
	ExpirationDays           *int64 `json:"expirationDays"`
	ExpirationDaysProduction *int64 `json:"expirationDaysProduction"`
	ExpirationDaysCanceled   *int64 `json:"expirationDaysCanceled"`
	ExpirationDaysErrored    *int64 `json:"expirationDaysErrored"`
	DeploymentsToKeep        *int64 `json:"deploymentsToKeep"`
}

type remoteCaching struct {
	Enabled *bool `json:"enabled"`
}

type connectRecord struct {
	Enabled *bool `json:"enabled"`
}

// strictEnabled reports whether an owner-only guardrail is switched on,
// treating an absent setting as off.
func strictEnabled(s *strictSetting) bool {
	return s != nil && s.Enabled
}

func newVercelTeam(runtime *plugin.Runtime, rec *teamRecord) (*mqlVercelTeam, error) {
	samlEnforced := false
	samlRoles := map[string]any{}
	var samlConn, samlDir *samlConnection
	if rec.Saml != nil {
		samlEnforced = rec.Saml.Enforced
		samlRoles = mapStrToAny(rec.Saml.Roles)
		samlConn = rec.Saml.Connection
		samlDir = rec.Saml.Directory
	}

	var samlType, samlState, samlStatus *string
	var samlConnectedAt *time.Time
	if samlConn != nil {
		samlType, samlState, samlStatus = &samlConn.Type, &samlConn.State, &samlConn.Status
		samlConnectedAt = samlConn.ConnectedAt.Time()
	}

	var dirType, dirState *string
	var dirConnectedAt, dirLastSynced *time.Time
	if samlDir != nil {
		dirType = &samlDir.Type
		dirConnectedAt = samlDir.ConnectedAt.Time()
		dirLastSynced = samlDir.LastSynced.Time()
		if samlDir.SyncState != "" {
			dirState = &samlDir.SyncState
		}
	}

	var defaultPasswordType, defaultSsoType *string
	if rec.DefaultDeploymentProtection != nil {
		defaultPasswordType = holderType(rec.DefaultDeploymentProtection.PasswordProtection)
		defaultSsoType = holderType(rec.DefaultDeploymentProtection.SsoProtection)
	}

	defaultTeamRoles, defaultTeamPermissions := []any{}, []any{}
	if rec.DefaultRoles != nil {
		defaultTeamRoles = strSliceToAny(rec.DefaultRoles.TeamRoles)
		defaultTeamPermissions = strSliceToAny(rec.DefaultRoles.TeamPermissions)
	}

	deploymentPolicy := any(nil)
	if rec.DeploymentPolicy != nil {
		deploymentPolicy = rec.DeploymentPolicy
	}

	exp := rec.DefaultExpirationSettings
	if exp == nil {
		exp = &expirationRecord{}
	}

	res, err := CreateResource(runtime, "vercel.team", map[string]*llx.RawData{
		"id":                                 llx.StringData(rec.ID),
		"slug":                               llx.StringData(rec.Slug),
		"name":                               llx.StringData(rec.Name),
		"avatar":                             llx.StringData(rec.Avatar),
		"createdAt":                          llx.TimeDataPtr(rec.CreatedAt.Time()),
		"updatedAt":                          llx.TimeDataPtr(rec.UpdatedAt.Time()),
		"creatorId":                          llx.StringData(rec.CreatorID),
		"billingPlan":                        llx.StringData(billingPlan(rec.Billing)),
		"organizationId":                     llx.StringData(rec.ParentID),
		"samlEnforced":                       llx.BoolData(samlEnforced),
		"samlRoles":                          llx.MapData(samlRoles, types.String),
		"samlConnectionType":                 llx.StringDataPtr(samlType),
		"samlConnectionState":                llx.StringDataPtr(samlState),
		"samlConnectionStatus":               llx.StringDataPtr(samlStatus),
		"samlConnectedAt":                    llx.TimeDataPtr(samlConnectedAt),
		"directorySyncType":                  llx.StringDataPtr(dirType),
		"directorySyncState":                 llx.StringDataPtr(dirState),
		"directorySyncConnectedAt":           llx.TimeDataPtr(dirConnectedAt),
		"directoryLastSyncedAt":              llx.TimeDataPtr(dirLastSynced),
		"emailDomain":                        llx.StringDataPtr(rec.EmailDomain),
		"inviteCodeConfigured":               llx.BoolData(rec.InviteCode != ""),
		"dpAccessRequestsMode":               llx.StringDataPtr(rec.DpAccessRequestsMode),
		"requireVerifiedCommits":             llx.BoolData(rec.RequireVerifiedCommits != nil && *rec.RequireVerifiedCommits),
		"disableRepositoryDispatchEvents":    llx.BoolData(rec.DisableRepositoryDispatchEvents != nil && *rec.DisableRepositoryDispatchEvents),
		"strictDeploymentProtectionSettings": llx.BoolData(strictEnabled(rec.StrictDeploymentProtection)),
		"strictPasswordProtectionSettings":   llx.BoolData(strictEnabled(rec.StrictPasswordProtection)),
		"strictShareableLinks":               llx.BoolData(strictEnabled(rec.StrictShareableLinks)),
		"defaultPasswordProtectionDeploymentType": llx.StringDataPtr(defaultPasswordType),
		"defaultSsoProtectionDeploymentType":      llx.StringDataPtr(defaultSsoType),
		"defaultTeamRoles":                        llx.ArrayData(defaultTeamRoles, types.String),
		"defaultTeamPermissions":                  llx.ArrayData(defaultTeamPermissions, types.String),
		"deploymentPolicy":                        llx.DictData(deploymentPolicy),
		"defaultExpirationDays":                   llx.IntData(intPtrOrZero(exp.ExpirationDays)),
		"defaultExpirationDaysProduction":         llx.IntData(intPtrOrZero(exp.ExpirationDaysProduction)),
		"defaultExpirationDaysCanceled":           llx.IntData(intPtrOrZero(exp.ExpirationDaysCanceled)),
		"defaultExpirationDaysErrored":            llx.IntData(intPtrOrZero(exp.ExpirationDaysErrored)),
		"defaultDeploymentsToKeep":                llx.IntData(intPtrOrZero(exp.DeploymentsToKeep)),
		"sensitiveEnvironmentVariablePolicy":      llx.StringDataPtr(rec.SensitiveEnvironmentVariablePolicy),
		"hideIpAddresses":                         llx.BoolData(rec.HideIPAddresses != nil && *rec.HideIPAddresses),
		"hideIpAddressesInLogDrains":              llx.BoolData(rec.HideIPAddressesInLogDrains != nil && *rec.HideIPAddressesInLogDrains),
		"remoteCachingEnabled":                    llx.BoolData(rec.RemoteCaching != nil && rec.RemoteCaching.Enabled != nil && *rec.RemoteCaching.Enabled),
		"secureComputeEnabled":                    llx.BoolData(rec.Connect != nil && rec.Connect.Enabled != nil && *rec.Connect.Enabled),
		"enablePreviewFeedback":                   llx.StringDataPtr(rec.EnablePreviewFeedback),
		"enableProductionFeedback":                llx.StringDataPtr(rec.EnableProductionFeedback),
		"previewDeploymentSuffix":                 llx.StringDataPtr(rec.PreviewDeploymentSuffix),
		"stagingPrefix":                           llx.StringData(rec.StagingPrefix),
		"personalAccessTokensInvalidatedAt":       llx.TimeDataPtr(rec.PersonalAccessTokensInvalidatedAt.Time()),
		"appTokensInvalidatedAt":                  llx.TimeDataPtr(rec.AppTokensInvalidatedAt.Time()),
		"apiKeysInvalidatedAt":                    llx.TimeDataPtr(rec.APIKeysInvalidatedAt.Time()),
		"integrationTokensInvalidatedAt":          llx.TimeDataPtr(rec.IntegrationTokensInvalidatedAt.Time()),
	})
	if err != nil {
		return nil, err
	}

	team := res.(*mqlVercelTeam)
	team.cacheOrgRootTeamID = rec.OrgRootTeamID
	return team, nil
}

// billingPlan returns the subscribed plan, or an empty string when the billing
// object is absent. The plan gates several team settings, so callers use it to
// tell "not available on this plan" apart from "switched off".
func billingPlan(b *billingRecord) string {
	if b == nil {
		return ""
	}
	return b.Plan
}

// orgRootTeam resolves the organization's root billing team. Comparing it to
// this team's own id identifies the root team itself.
func (c *mqlVercelTeam) orgRootTeam() (*mqlVercelTeam, error) {
	if c.cacheOrgRootTeamID == "" {
		c.OrgRootTeam.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	team, err := NewResource(c.MqlRuntime, "vercel.team", map[string]*llx.RawData{
		"id": llx.StringData(c.cacheOrgRootTeamID),
	})
	if err != nil {
		return nil, err
	}
	return team.(*mqlVercelTeam), nil
}

// initVercelTeam resolves the team a query targets: an explicit id argument, the
// team a discovered asset is scoped to, or the --team connection option.
func initVercelTeam(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.VercelConnection)

	teamID := ""
	if idData, ok := args["id"]; ok {
		if s, ok := idData.Value.(string); ok {
			teamID = s
		}
	}
	if teamID == "" && conn.Asset() != nil {
		for _, pid := range conn.Asset().PlatformIds {
			if t, ok := strings.CutPrefix(pid, connection.PlatformIdVercelTeam); ok {
				teamID = t
				break
			}
		}
	}
	if teamID == "" {
		teamID = conn.TeamID()
	}
	if teamID == "" {
		return nil, nil, errors.New("vercel.team requires a team id")
	}

	var rec teamRecord
	if err := conn.Get(context.Background(), "/v2/teams/"+teamID, nil, &rec); err != nil {
		return nil, nil, err
	}
	if rec.ID == "" {
		rec.ID = teamID
	}

	team, err := newVercelTeam(runtime, &rec)
	if err != nil {
		return nil, nil, err
	}
	return args, team, nil
}

func (c *mqlVercelTeam) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

// --- team members ---------------------------------------------------------

// inviteRecord is one entry of the emailInviteCodes list returned alongside
// the team members. expired arrives only once the invitation has expired, so it
// is a pointer and stays null while the invitation is still redeemable rather
// than reporting a false nobody set.
type inviteRecord struct {
	ID              string            `json:"id"`
	Email           *string           `json:"email"`
	Role            *string           `json:"role"`
	TeamRoles       []string          `json:"teamRoles"`
	TeamPermissions []string          `json:"teamPermissions"`
	IsDSyncUser     *bool             `json:"isDSyncUser"`
	Expired         *bool             `json:"expired"`
	CreatedAt       flexTime          `json:"createdAt"`
	Projects        map[string]string `json:"projects"`
}

type memberRecord struct {
	UID               string      `json:"uid"`
	Email             string      `json:"email"`
	Username          string      `json:"username"`
	Name              string      `json:"name"`
	Role              string      `json:"role"`
	TeamRoles         []string    `json:"teamRoles"`
	TeamPermissions   []string    `json:"teamPermissions"`
	JoinedFrom        *joinedFrom `json:"joinedFrom"`
	Confirmed         bool        `json:"confirmed"`
	AccessRequestedAt flexTime    `json:"accessRequestedAt"`
	CreatedAt         flexTime    `json:"createdAt"`
}

// joinedFrom records the route a member took into the team, which distinguishes
// an identity-provider provisioned member from one who followed an invite link.
type joinedFrom struct {
	Origin string `json:"origin"`
}

func (c *mqlVercelTeam) members() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	records, err := connection.GetPaged[memberRecord](context.Background(), conn, "/v3/teams/"+c.Id.Data+"/members", nil, "members")
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.Members.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		var joinedOrigin *string
		if rec.JoinedFrom != nil && rec.JoinedFrom.Origin != "" {
			joinedOrigin = &rec.JoinedFrom.Origin
		}

		member, err := CreateResource(c.MqlRuntime, "vercel.team.member", map[string]*llx.RawData{
			"__id":              llx.StringData(c.Id.Data + "/" + rec.UID),
			"uid":               llx.StringData(rec.UID),
			"email":             llx.StringData(rec.Email),
			"username":          llx.StringData(rec.Username),
			"name":              llx.StringData(rec.Name),
			"role":              llx.StringData(rec.Role),
			"teamRoles":         llx.ArrayData(strSliceToAny(rec.TeamRoles), types.String),
			"teamPermissions":   llx.ArrayData(strSliceToAny(rec.TeamPermissions), types.String),
			"joinedFromOrigin":  llx.StringDataPtr(joinedOrigin),
			"confirmed":         llx.BoolData(rec.Confirmed),
			"accessRequestedAt": llx.TimeDataPtr(rec.AccessRequestedAt.Time()),
			"createdAt":         llx.TimeDataPtr(rec.CreatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, member)
	}
	return res, nil
}

// mqlVercelTeamPendingInviteInternal caches the team the invitation belongs to
// and the projects it grants, so projects() resolves without re-reading the
// member list.
type mqlVercelTeamPendingInviteInternal struct {
	teamID          string
	cacheProjectIDs []string
}

// pendingInvites lists the team invitations that have been sent and not
// accepted. They arrive under emailInviteCodes in the same envelope as the
// members, alongside the member pagination cursor. Whether Vercel repeats the
// invitations on every member page or returns them only on the first is not
// stated, so the walk collects them across pages and drops repeats by id.
func (c *mqlVercelTeam) pendingInvites() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	records, err := connection.GetPaged[inviteRecord](context.Background(), conn, "/v3/teams/"+c.Id.Data+"/members", nil, "emailInviteCodes")
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.PendingInvites.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	res := []any{}
	for i, rec := range dedupeInvites(records) {
		// dedupeInvites keeps every record whose id is empty, because an absent
		// id is not evidence that two invitations are the same one. The cache
		// key has to keep them apart too, so it falls back to the position in
		// the listing rather than collapsing them onto one resource.
		key := c.Id.Data + "/invite/" + rec.ID
		if rec.ID == "" {
			key = c.Id.Data + "/invite/#" + strconv.Itoa(i)
		}
		invite, err := CreateResource(c.MqlRuntime, "vercel.team.pendingInvite", map[string]*llx.RawData{
			"__id":            llx.StringData(key),
			"id":              llx.StringData(rec.ID),
			"email":           llx.StringDataPtr(rec.Email),
			"role":            llx.StringDataPtr(rec.Role),
			"teamRoles":       llx.ArrayData(strSliceToAny(rec.TeamRoles), types.String),
			"teamPermissions": llx.ArrayData(strSliceToAny(rec.TeamPermissions), types.String),
			"isDSyncUser":     llx.BoolDataPtr(rec.IsDSyncUser),
			"expired":         llx.BoolDataPtr(rec.Expired),
			"createdAt":       llx.TimeDataPtr(rec.CreatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		mqlInvite := invite.(*mqlVercelTeamPendingInvite)
		mqlInvite.teamID = c.Id.Data
		mqlInvite.cacheProjectIDs = inviteProjectIDs(&rec)
		res = append(res, invite)
	}
	return res, nil
}

// dedupeInvites keeps the first record for each invitation id, preserving the
// order they arrived in. An invitation with no id cannot be deduplicated and is
// kept, since dropping it would under-report.
func dedupeInvites(records []inviteRecord) []inviteRecord {
	out := make([]inviteRecord, 0, len(records))
	seen := make(map[string]bool, len(records))
	for _, rec := range records {
		if rec.ID != "" {
			if seen[rec.ID] {
				continue
			}
			seen[rec.ID] = true
		}
		out = append(out, rec)
	}
	return out
}

// inviteProjectIDs lists the projects an invitation grants access to, sorted so
// the resolved references come back in a stable order.
func inviteProjectIDs(rec *inviteRecord) []string {
	ids := make([]string, 0, len(rec.Projects))
	for id := range rec.Projects {
		if id != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (c *mqlVercelTeamPendingInvite) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

func (c *mqlVercelTeamPendingInvite) projects() ([]any, error) {
	return resolveProjectRefs(c.MqlRuntime, c.teamID, c.cacheProjectIDs)
}

// --- shared environment variables -----------------------------------------

type sharedEnvRecord struct {
	ID                           string   `json:"id"`
	Key                          string   `json:"key"`
	Type                         string   `json:"type"`
	Target                       []string `json:"target"`
	ApplyToAllCustomEnvironments *bool    `json:"applyToAllCustomEnvironments"`
	CustomEnvironmentIDs         []string `json:"customEnvironmentIds"`
	Decrypted                    *bool    `json:"decrypted"`
	Comment                      *string  `json:"comment"`
	// The key really is singular while the value is an array of project ids;
	// that is how the endpoint reports the projects a variable is linked to.
	ProjectIDs              []string `json:"projectId"`
	CreatedBy               *string  `json:"createdBy"`
	UpdatedBy               *string  `json:"updatedBy"`
	LastEditedByDisplayName *string  `json:"lastEditedByDisplayName"`
	CreatedAt               flexTime `json:"createdAt"`
	UpdatedAt               flexTime `json:"updatedAt"`
}

// sharedEnvironmentVariables lists the variables defined once on the team and
// injected into every project linked to them. Values are never requested: the
// list endpoint does not return them, and the per-variable decrypt endpoint is
// deliberately not called.
//
// The endpoint documents no pagination parameter, only a {count, next, prev}
// response envelope. That envelope is the timestamp form Vercel pairs with
// until elsewhere (/v7/deployments documents both together), so GetPaged is the
// matching reader. If it turns out to ignore until, GetPaged detects the
// echoed cursor and returns the first page once rather than looping or
// double-counting, so the worst case is truncation on a very large collection.
func (c *mqlVercelTeam) sharedEnvironmentVariables() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	records, err := connection.GetPaged[sharedEnvRecord](context.Background(), conn, "/v1/env", connection.TeamQuery(c.Id.Data), "data")
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.SharedEnvironmentVariables.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		// A 404 means the collection is not provisioned for this scope,
		// which genuinely is none.
		if connection.IsNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		variable, err := CreateResource(c.MqlRuntime, "vercel.team.sharedEnvironmentVariable", map[string]*llx.RawData{
			"id":                           llx.StringData(rec.ID),
			"key":                          llx.StringData(rec.Key),
			"type":                         llx.StringData(rec.Type),
			"target":                       llx.ArrayData(strSliceToAny(rec.Target), types.String),
			"applyToAllCustomEnvironments": llx.BoolData(rec.ApplyToAllCustomEnvironments != nil && *rec.ApplyToAllCustomEnvironments),
			"customEnvironmentIds":         llx.ArrayData(strSliceToAny(rec.CustomEnvironmentIDs), types.String),
			"decrypted":                    llx.BoolData(rec.Decrypted != nil && *rec.Decrypted),
			"comment":                      llx.StringDataPtr(rec.Comment),
			"createdBy":                    llx.StringDataPtr(rec.CreatedBy),
			"updatedBy":                    llx.StringDataPtr(rec.UpdatedBy),
			"lastEditedByDisplayName":      llx.StringDataPtr(rec.LastEditedByDisplayName),
			"createdAt":                    llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":                    llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}

		mqlVar := variable.(*mqlVercelTeamSharedEnvironmentVariable)
		mqlVar.teamID = c.Id.Data
		mqlVar.cacheProjectIDs = rec.ProjectIDs
		res = append(res, variable)
	}
	return res, nil
}

func (c *mqlVercelTeamSharedEnvironmentVariable) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

// mqlVercelTeamSharedEnvironmentVariableInternal caches the linked project ids
// so projects() can resolve them without re-reading the variable list.
type mqlVercelTeamSharedEnvironmentVariableInternal struct {
	teamID          string
	cacheProjectIDs []string
}

func (c *mqlVercelTeamSharedEnvironmentVariable) projects() ([]any, error) {
	return resolveProjectRefs(c.MqlRuntime, c.teamID, c.cacheProjectIDs)
}

// --- team domains ---------------------------------------------------------

type domainRecord struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	ServiceType         string   `json:"serviceType"`
	Verified            bool     `json:"verified"`
	Nameservers         []string `json:"nameservers"`
	IntendedNameservers []string `json:"intendedNameservers"`
	CdnEnabled          bool     `json:"cdnEnabled"`
	Renew               *bool    `json:"renew"`
	CreatedAt           flexTime `json:"createdAt"`
	ExpiresAt           flexTime `json:"expiresAt"`
	BoughtAt            flexTime `json:"boughtAt"`
}

func newVercelDomain(runtime *plugin.Runtime, teamID string, rec *domainRecord) (*mqlVercelDomain, error) {
	renew := rec.Renew != nil && *rec.Renew
	domain, err := CreateResource(runtime, "vercel.domain", map[string]*llx.RawData{
		"id":                  llx.StringData(rec.ID),
		"name":                llx.StringData(rec.Name),
		"serviceType":         llx.StringData(rec.ServiceType),
		"verified":            llx.BoolData(rec.Verified),
		"nameservers":         llx.ArrayData(strSliceToAny(rec.Nameservers), types.String),
		"intendedNameservers": llx.ArrayData(strSliceToAny(rec.IntendedNameservers), types.String),
		"cdnEnabled":          llx.BoolData(rec.CdnEnabled),
		"renewAutomatically":  llx.BoolData(renew),
		"createdAt":           llx.TimeDataPtr(rec.CreatedAt.Time()),
		"expiresAt":           llx.TimeDataPtr(rec.ExpiresAt.Time()),
		"boughtAt":            llx.TimeDataPtr(rec.BoughtAt.Time()),
	})
	if err != nil {
		return nil, err
	}
	mqlDomain := domain.(*mqlVercelDomain)
	mqlDomain.teamID = teamID
	return mqlDomain, nil
}

func (c *mqlVercelTeam) domains() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	records, err := connection.GetPaged[domainRecord](context.Background(), conn, "/v5/domains", connection.TeamQuery(c.Id.Data), "domains")
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.Domains.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		mqlDomain, err := newVercelDomain(c.MqlRuntime, c.Id.Data, &rec)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDomain)
	}
	return res, nil
}

func (c *mqlVercelDomain) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

// --- edge config ----------------------------------------------------------

type edgeConfigRecord struct {
	ID          string   `json:"id"`
	Slug        string   `json:"slug"`
	ItemCount   *int64   `json:"itemCount"`
	SizeInBytes *int64   `json:"sizeInBytes"`
	CreatedAt   flexTime `json:"createdAt"`
	UpdatedAt   flexTime `json:"updatedAt"`
}

func (c *mqlVercelTeam) edgeConfigs() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	var records []edgeConfigRecord
	if err := conn.Get(context.Background(), "/v1/edge-config", connection.TeamQuery(c.Id.Data), &records); err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.EdgeConfigs.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		ec, err := CreateResource(c.MqlRuntime, "vercel.edgeConfig", map[string]*llx.RawData{
			"id":          llx.StringData(rec.ID),
			"slug":        llx.StringData(rec.Slug),
			"itemCount":   llx.IntData(intPtrOrZero(rec.ItemCount)),
			"sizeInBytes": llx.IntData(intPtrOrZero(rec.SizeInBytes)),
			"createdAt":   llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":   llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		ec.(*mqlVercelEdgeConfig).teamID = c.Id.Data
		res = append(res, ec)
	}
	return res, nil
}

func (c *mqlVercelEdgeConfig) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

// mqlVercelEdgeConfigInternal caches the team the store belongs to so tokens()
// can scope its request.
type mqlVercelEdgeConfigInternal struct {
	teamID string
}

// edgeConfigTokenRecord is one entry of the store's read-token list. The list
// endpoint deliberately never returns the token value, only an id to reference
// it by and a masked prefix for display; neither the value nor the mask is
// read here.
type edgeConfigTokenRecord struct {
	ID        string   `json:"id"`
	Label     *string  `json:"label"`
	CreatedAt flexTime `json:"createdAt"`
}

// decodeEdgeConfigTokens reads the token list, which arrives either as a bare
// array or wrapped under a tokens key depending on the endpoint revision.
func decodeEdgeConfigTokens(raw json.RawMessage) ([]edgeConfigTokenRecord, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var list []edgeConfigTokenRecord
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, err
		}
		return list, nil
	}
	var wrapper struct {
		Tokens []edgeConfigTokenRecord `json:"tokens"`
	}
	if err := json.Unmarshal(trimmed, &wrapper); err != nil {
		return nil, err
	}
	return wrapper.Tokens, nil
}

// tokens lists the read tokens issued for the store. Each token reads the
// store's contents wherever it is presented, so the count and age are the
// exposure; the token value itself is never returned by this endpoint and is
// never reported.
func (c *mqlVercelEdgeConfig) tokens() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)

	var raw json.RawMessage
	if err := conn.Get(context.Background(), "/v1/edge-config/"+c.Id.Data+"/tokens", connection.TeamQuery(c.teamID), &raw); err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.Tokens.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		// A 404 means the store has no token collection, which genuinely is
		// none.
		if connection.IsNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}

	records, err := decodeEdgeConfigTokens(raw)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, rec := range records {
		token, err := CreateResource(c.MqlRuntime, "vercel.edgeConfig.token", map[string]*llx.RawData{
			"__id":      llx.StringData(c.Id.Data + "/token/" + rec.ID),
			"id":        llx.StringData(rec.ID),
			"label":     llx.StringDataPtr(rec.Label),
			"createdAt": llx.TimeDataPtr(rec.CreatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, token)
	}
	return res, nil
}

// --- log drains -----------------------------------------------------------

type logDrainRecord struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	URL            string   `json:"url"`
	DeliveryFormat string   `json:"deliveryFormat"`
	Sources        []string `json:"sources"`
	Environments   []string `json:"environments"`
	CreatedAt      flexTime `json:"createdAt"`
}

func (c *mqlVercelTeam) logDrains() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	var records []logDrainRecord
	if err := conn.Get(context.Background(), "/v1/log-drains", connection.TeamQuery(c.Id.Data), &records); err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.LogDrains.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		drain, err := CreateResource(c.MqlRuntime, "vercel.logDrain", map[string]*llx.RawData{
			"id":             llx.StringData(rec.ID),
			"name":           llx.StringData(rec.Name),
			"url":            llx.StringData(rec.URL),
			"deliveryFormat": llx.StringData(rec.DeliveryFormat),
			"sources":        llx.ArrayData(strSliceToAny(rec.Sources), types.String),
			"environments":   llx.ArrayData(strSliceToAny(rec.Environments), types.String),
			"createdAt":      llx.TimeDataPtr(rec.CreatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, drain)
	}
	return res, nil
}

func (c *mqlVercelLogDrain) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

// --- webhooks -------------------------------------------------------------

// mqlVercelWebhookInternal caches the team a webhook belongs to and the ids of
// the projects it is scoped to, so projects can resolve typed project
// references without re-listing the webhook.
type mqlVercelWebhookInternal struct {
	teamID          string
	cacheProjectIds []string
}

type webhookRecord struct {
	ID         string   `json:"id"`
	URL        string   `json:"url"`
	Events     []string `json:"events"`
	ProjectIds []string `json:"projectIds"`
	CreatedAt  flexTime `json:"createdAt"`
	UpdatedAt  flexTime `json:"updatedAt"`
}

func (c *mqlVercelTeam) webhooks() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	var records []webhookRecord
	if err := conn.Get(context.Background(), "/v1/webhooks", connection.TeamQuery(c.Id.Data), &records); err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.Webhooks.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		hook, err := CreateResource(c.MqlRuntime, "vercel.webhook", map[string]*llx.RawData{
			"id":        llx.StringData(rec.ID),
			"url":       llx.StringData(rec.URL),
			"events":    llx.ArrayData(strSliceToAny(rec.Events), types.String),
			"createdAt": llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt": llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		mqlHook := hook.(*mqlVercelWebhook)
		mqlHook.teamID = c.Id.Data
		mqlHook.cacheProjectIds = rec.ProjectIds
		res = append(res, mqlHook)
	}
	return res, nil
}

func (c *mqlVercelWebhook) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

func (c *mqlVercelWebhook) projects() ([]any, error) {
	return resolveProjectRefs(c.MqlRuntime, c.teamID, c.cacheProjectIds)
}

// --- integration configurations -------------------------------------------

// mqlVercelIntegrationConfigurationInternal caches the team an integration
// configuration belongs to and the ids of the projects it is scoped to, so
// projects can resolve typed project references without re-listing the
// configuration.
type mqlVercelIntegrationConfigurationInternal struct {
	teamID          string
	cacheProjectIds []string
}

type integrationConfigurationRecord struct {
	ID               string   `json:"id"`
	Slug             string   `json:"slug"`
	Scopes           []string `json:"scopes"`
	InstallationType string   `json:"installationType"`
	// Source is the fallback for the installationType field: older
	// configurations report how they were installed under "source" instead.
	Source           string   `json:"source"`
	ProjectSelection string   `json:"projectSelection"`
	Projects         []string `json:"projects"`
	CreatedAt        flexTime `json:"createdAt"`
	UpdatedAt        flexTime `json:"updatedAt"`
}

func (c *mqlVercelTeam) integrationConfigurations() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	// The endpoint requires a view; "account" lists every configuration
	// installed on the team.
	query := connection.TeamQuery(c.Id.Data)
	query.Set("view", "account")
	var records []integrationConfigurationRecord
	if err := conn.Get(context.Background(), "/v1/integrations/configurations", query, &records); err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.IntegrationConfigurations.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		cfg, err := newVercelIntegrationConfiguration(c.MqlRuntime, c.Id.Data, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, cfg)
	}
	return res, nil
}

// newVercelIntegrationConfiguration maps an installation record onto the
// resource. It is shared with the check resolver so both reach the same cached
// resource for an installation rather than building two.
func newVercelIntegrationConfiguration(runtime *plugin.Runtime, teamID string, rec *integrationConfigurationRecord) (*mqlVercelIntegrationConfiguration, error) {
	installationType := rec.InstallationType
	if installationType == "" {
		installationType = rec.Source
	}
	cfg, err := CreateResource(runtime, "vercel.integrationConfiguration", map[string]*llx.RawData{
		"id":               llx.StringData(rec.ID),
		"slug":             llx.StringData(rec.Slug),
		"scopes":           llx.ArrayData(strSliceToAny(rec.Scopes), types.String),
		"installationType": llx.StringData(installationType),
		"projectSelection": llx.StringData(rec.ProjectSelection),
		"createdAt":        llx.TimeDataPtr(rec.CreatedAt.Time()),
		"updatedAt":        llx.TimeDataPtr(rec.UpdatedAt.Time()),
	})
	if err != nil {
		return nil, err
	}
	mqlCfg := cfg.(*mqlVercelIntegrationConfiguration)
	mqlCfg.teamID = teamID
	mqlCfg.cacheProjectIds = rec.Projects
	return mqlCfg, nil
}

func (c *mqlVercelIntegrationConfiguration) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

func (c *mqlVercelIntegrationConfiguration) projects() ([]any, error) {
	return resolveProjectRefs(c.MqlRuntime, c.teamID, c.cacheProjectIds)
}

// --- access groups (enterprise) -------------------------------------------

type accessGroupRecord struct {
	ID            string   `json:"accessGroupId"`
	Name          string   `json:"name"`
	MembersCount  *int64   `json:"membersCount"`
	ProjectsCount *int64   `json:"projectsCount"`
	CreatedAt     flexTime `json:"createdAt"`
	UpdatedAt     flexTime `json:"updatedAt"`
}

func (c *mqlVercelTeam) accessGroups() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	query := connection.TeamQuery(c.Id.Data)
	query.Set("limit", "100")
	records, err := connection.GetPagedCursor[accessGroupRecord](context.Background(), conn, "/v1/access-groups", query, "accessGroups")
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.AccessGroups.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		// A 404 means the collection is not provisioned for this scope,
		// which genuinely is none.
		if connection.IsNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		group, err := CreateResource(c.MqlRuntime, "vercel.accessGroup", map[string]*llx.RawData{
			"id":            llx.StringData(rec.ID),
			"name":          llx.StringData(rec.Name),
			"membersCount":  llx.IntData(intPtrOrZero(rec.MembersCount)),
			"projectsCount": llx.IntData(intPtrOrZero(rec.ProjectsCount)),
			"createdAt":     llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":     llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		mqlGroup := group.(*mqlVercelAccessGroup)
		mqlGroup.teamID = c.Id.Data
		res = append(res, mqlGroup)
	}
	return res, nil
}

func (c *mqlVercelAccessGroup) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

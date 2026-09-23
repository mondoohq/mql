// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

// ---------- helpers ----------

// isAccessDeniedOrNotFound returns true if the error indicates the resource is
// inaccessible (404 or 403). Many GitHub Enterprise Cloud-only endpoints return
// 404 for non-enterprise orgs, or 403 if the token lacks scope.
func isAccessDeniedOrNotFound(err error) bool {
	if err == nil {
		return false
	}
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		switch ghErr.Response.StatusCode {
		case http.StatusNotFound, http.StatusForbidden:
			return true
		}
	}
	// Fallback for non-typed errors (e.g. body-decoded GraphQL errors that
	// surface as plain strings like "no available registrations").
	msg := err.Error()
	return strings.Contains(msg, "no available registrations")
}

// doRawJSON performs a raw GET request through the github client against the
// given relative URL and decodes the JSON body into v. Useful for endpoints not
// yet covered by go-github helpers.
func doRawJSON(ctx context.Context, client *github.Client, urlStr string, v any) (*github.Response, error) {
	req, err := client.NewRequest(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req, v)
}

// doRawGraphQL performs a POST against the GraphQL endpoint with the given
// query and variables, decoding the response into v.
func doRawGraphQL(ctx context.Context, client *github.Client, query string, vars map[string]any, v any) (*github.Response, error) {
	body := map[string]any{"query": query}
	if vars != nil {
		body["variables"] = vars
	}
	req, err := client.NewRequest(ctx, http.MethodPost, "graphql", body)
	if err != nil {
		return nil, err
	}
	return client.Do(req, v)
}

// The resources below are reachable both as a field of their parent
// (github.repository / github.organization) and as a standalone dotted path
// (e.g. `github.repository.codeowners`). The dotted form instantiates the
// resource directly, bypassing the parent accessor that populates it. These
// init functions delegate to the parent so a bare instantiation resolves to
// the same fully-populated resource.

func initGithubRepositoryCodeowners(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	repo, err := NewResource(runtime, "github.repository", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	codeowners := repo.(*mqlGithubRepository).GetCodeowners()
	if codeowners.Error != nil {
		return nil, nil, codeowners.Error
	}
	return args, codeowners.Data, nil
}

func initGithubOrganizationSamlConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	org, err := NewResource(runtime, "github.organization", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	samlConfig := org.(*mqlGithubOrganization).GetSamlConfig()
	if samlConfig.Error != nil {
		return nil, nil, samlConfig.Error
	}
	if samlConfig.Data == nil {
		return nil, nil, errors.New("SAML SSO configuration is not available for this organization (requires GitHub Enterprise Cloud and admin access)")
	}
	return args, samlConfig.Data, nil
}

func initGithubOrganizationIpAllowList(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	org, err := NewResource(runtime, "github.organization", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	ipAllowList := org.(*mqlGithubOrganization).GetIpAllowList()
	if ipAllowList.Error != nil {
		return nil, nil, ipAllowList.Error
	}
	if ipAllowList.Data == nil {
		return nil, nil, errors.New("IP allow list is not available for this organization (requires GitHub Enterprise Cloud and admin access)")
	}
	return args, ipAllowList.Data, nil
}

func initGithubOrganizationAuditLogStreamConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	org, err := NewResource(runtime, "github.organization", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	streamConfig := org.(*mqlGithubOrganization).GetAuditLogStreamConfig()
	if streamConfig.Error != nil {
		return nil, nil, streamConfig.Error
	}
	if streamConfig.Data == nil {
		return nil, nil, errors.New("audit log streaming configuration is not available for this organization (requires GitHub Enterprise Cloud and admin access)")
	}
	return args, streamConfig.Data, nil
}

// ---------- SAML config (GraphQL) ----------

func (g *mqlGithubOrganizationSamlConfig) id() (string, error) {
	return g.__id, nil
}

type ghSamlIdentityProvider struct {
	SsoURL          *string `json:"ssoUrl"`
	Issuer          *string `json:"issuer"`
	DigestMethod    *string `json:"digestMethod"`
	SignatureMethod *string `json:"signatureMethod"`
	IDPCertificate  *string `json:"idpCertificate"`
}

type ghSamlConfigResponse struct {
	Data struct {
		Organization struct {
			SamlIdentityProvider *ghSamlIdentityProvider `json:"samlIdentityProvider"`
		} `json:"organization"`
	} `json:"data"`
	Errors []struct {
		Type       string         `json:"type"`
		Message    string         `json:"message"`
		Extensions map[string]any `json:"extensions"`
	} `json:"errors"`
}

// isSamlScopeOrPermissionError returns true if any error in the list looks
// like a permission/scope problem (the caller should bubble these up rather
// than silently returning null, so users know to grant the required scopes).
func isSamlScopeOrPermissionError(errs []struct {
	Type       string         `json:"type"`
	Message    string         `json:"message"`
	Extensions map[string]any `json:"extensions"`
},
) bool {
	for _, e := range errs {
		t := strings.ToUpper(e.Type)
		if t == "INSUFFICIENT_SCOPES" || t == "FORBIDDEN" || t == "UNAUTHORIZED" {
			return true
		}
		if code, ok := e.Extensions["code"].(string); ok {
			cu := strings.ToUpper(code)
			if cu == "INSUFFICIENT_SCOPES" || cu == "FORBIDDEN" || cu == "UNAUTHORIZED" {
				return true
			}
		}
		mu := strings.ToLower(e.Message)
		if strings.Contains(mu, "scope") || strings.Contains(mu, "forbidden") || strings.Contains(mu, "must have admin") {
			return true
		}
	}
	return false
}

func (g *mqlGithubOrganization) samlConfig() (*mqlGithubOrganizationSamlConfig, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	query := `query($login: String!) {
		organization(login: $login) {
			samlIdentityProvider {
				ssoUrl
				issuer
				digestMethod
				signatureMethod
				idpCertificate
			}
		}
	}`
	var resp ghSamlConfigResponse
	_, err := doRawGraphQL(conn.Context(), conn.Client(), query, map[string]any{"login": orgLogin}, &resp)
	if err != nil {
		if isAccessDeniedOrNotFound(err) {
			log.Debug().Err(err).Msg("SAML config not accessible (requires GitHub Enterprise Cloud and admin scope)")
			g.SamlConfig.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if len(resp.Errors) > 0 {
		// Distinguish "no config / not enterprise" (treat as null) from
		// permission/scope errors (bubble up so users know to fix auth).
		if isSamlScopeOrPermissionError(resp.Errors) {
			log.Debug().Msgf("SAML config GraphQL permission/scope error: %s", resp.Errors[0].Message)
			return nil, fmt.Errorf("github SAML config: %s (type=%s)", resp.Errors[0].Message, resp.Errors[0].Type)
		}
		log.Debug().Msgf("SAML config GraphQL errors (treating as null): %s", resp.Errors[0].Message)
		g.SamlConfig.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	idp := resp.Data.Organization.SamlIdentityProvider
	enabled := idp != nil
	args := map[string]*llx.RawData{
		"__id":            llx.StringData("github.organization.samlConfig/" + orgLogin),
		"enabled":         llx.BoolData(enabled),
		"ssoUrl":          llx.StringData(""),
		"issuer":          llx.StringData(""),
		"digestMethod":    llx.StringData(""),
		"signatureMethod": llx.StringData(""),
		"idpCertificate":  llx.StringData(""),
	}
	if idp != nil {
		if idp.SsoURL != nil {
			args["ssoUrl"] = llx.StringData(*idp.SsoURL)
		}
		if idp.Issuer != nil {
			args["issuer"] = llx.StringData(*idp.Issuer)
		}
		if idp.DigestMethod != nil {
			args["digestMethod"] = llx.StringData(*idp.DigestMethod)
		}
		if idp.SignatureMethod != nil {
			args["signatureMethod"] = llx.StringData(*idp.SignatureMethod)
		}
		if idp.IDPCertificate != nil {
			args["idpCertificate"] = llx.StringData(*idp.IDPCertificate)
		}
	}
	res, err := CreateResource(g.MqlRuntime, "github.organization.samlConfig", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubOrganizationSamlConfig), nil
}

// ---------- IP allow list (GraphQL) ----------

func (g *mqlGithubOrganizationIpAllowList) id() (string, error) {
	return g.__id, nil
}

func (g *mqlGithubOrganizationIpAllowListEntry) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "github.organization.ipAllowList.entry/" + g.Id.Data, nil
}

type ghIpAllowListEntry struct {
	ID             string     `json:"id"`
	Name           *string    `json:"name"`
	AllowListValue string     `json:"allowListValue"`
	IsActive       bool       `json:"isActive"`
	CreatedAt      *time.Time `json:"createdAt"`
	UpdatedAt      *time.Time `json:"updatedAt"`
}

type ghIpAllowListResponse struct {
	Data struct {
		Organization struct {
			IpAllowListEnabledSetting                 *string `json:"ipAllowListEnabledSetting"`
			IpAllowListForInstalledAppsEnabledSetting *string `json:"ipAllowListForInstalledAppsEnabledSetting"`
			IpAllowListEntries                        struct {
				Nodes    []ghIpAllowListEntry `json:"nodes"`
				PageInfo struct {
					EndCursor   *string `json:"endCursor"`
					HasNextPage bool    `json:"hasNextPage"`
				} `json:"pageInfo"`
			} `json:"ipAllowListEntries"`
		} `json:"organization"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (g *mqlGithubOrganization) ipAllowList() (*mqlGithubOrganizationIpAllowList, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	query := `query($login: String!, $after: String) {
		organization(login: $login) {
			ipAllowListEnabledSetting
			ipAllowListForInstalledAppsEnabledSetting
			ipAllowListEntries(first: 100, after: $after) {
				nodes {
					id
					name
					allowListValue
					isActive
					createdAt
					updatedAt
				}
				pageInfo {
					endCursor
					hasNextPage
				}
			}
		}
	}`

	var (
		allNodes       []ghIpAllowListEntry
		enabled        bool
		enabledForApps bool
		cursor         *string
	)
	for {
		vars := map[string]any{"login": orgLogin}
		if cursor != nil {
			vars["after"] = *cursor
		} else {
			vars["after"] = nil
		}
		var resp ghIpAllowListResponse
		_, err := doRawGraphQL(conn.Context(), conn.Client(), query, vars, &resp)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				g.IpAllowList.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}
		if len(resp.Errors) > 0 {
			log.Debug().Msgf("ip allow list GraphQL errors: %s", resp.Errors[0].Message)
			g.IpAllowList.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}

		// settings live on the organization object; same on every page
		enabled = resp.Data.Organization.IpAllowListEnabledSetting != nil &&
			strings.EqualFold(*resp.Data.Organization.IpAllowListEnabledSetting, "ENABLED")
		enabledForApps = resp.Data.Organization.IpAllowListForInstalledAppsEnabledSetting != nil &&
			strings.EqualFold(*resp.Data.Organization.IpAllowListForInstalledAppsEnabledSetting, "ENABLED")

		allNodes = append(allNodes, resp.Data.Organization.IpAllowListEntries.Nodes...)

		pi := resp.Data.Organization.IpAllowListEntries.PageInfo
		if !pi.HasNextPage || pi.EndCursor == nil {
			break
		}
		cursor = pi.EndCursor
	}

	entries := []any{}
	for _, e := range allNodes {
		var name string
		if e.Name != nil {
			name = *e.Name
		}
		entryArgs := map[string]*llx.RawData{
			"id":           llx.StringData(e.ID),
			"name":         llx.StringData(name),
			"allowedValue": llx.StringData(e.AllowListValue),
			"isActive":     llx.BoolData(e.IsActive),
			"createdAt":    llx.TimeDataPtr(e.CreatedAt),
			"updatedAt":    llx.TimeDataPtr(e.UpdatedAt),
		}
		r, err := CreateResource(g.MqlRuntime, "github.organization.ipAllowList.entry", entryArgs)
		if err != nil {
			return nil, err
		}
		entries = append(entries, r)
	}

	res, err := CreateResource(g.MqlRuntime, "github.organization.ipAllowList", map[string]*llx.RawData{
		"__id":                    llx.StringData("github.organization.ipAllowList/" + orgLogin),
		"enabled":                 llx.BoolData(enabled),
		"enabledForInstalledApps": llx.BoolData(enabledForApps),
		"entries":                 llx.ArrayData(entries, types.Resource("github.organization.ipAllowList.entry")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubOrganizationIpAllowList), nil
}

// ---------- Custom org roles ----------

func (g *mqlGithubOrganizationCustomRole) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "github.organization.customRole/" + strconv.FormatInt(g.Id.Data, 10), nil
}

func (g *mqlGithubOrganization) customRoles() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	roles, _, err := conn.Client().Organizations.ListRoles(conn.Context(), orgLogin)
	if err != nil {
		if isAccessDeniedOrNotFound(err) {
			log.Debug().Err(err).Msg("Custom org roles not accessible (requires GitHub Enterprise Cloud)")
			return nil, nil
		}
		return nil, err
	}
	if roles == nil {
		return nil, nil
	}

	res := []any{}
	for _, role := range roles.CustomRepoRoles {
		var id int64
		if role.ID != nil {
			id = *role.ID
		}
		r, err := CreateResource(g.MqlRuntime, "github.organization.customRole", map[string]*llx.RawData{
			"id":          llx.IntData(id),
			"name":        llx.StringDataPtr(role.Name),
			"description": llx.StringDataPtr(role.Description),
			"baseRole":    llx.StringDataPtr(role.BaseRole),
			"permissions": llx.ArrayData(convert.SliceAnyToInterface[string](role.Permissions), types.String),
			"source":      llx.StringData(""),
			"createdAt":   llx.TimeDataPtr(githubTimestamp(role.CreatedAt)),
			"updatedAt":   llx.TimeDataPtr(githubTimestamp(role.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlGithubOrganizationCustomRole).cacheOrgLogin = orgLogin
		res = append(res, r)
	}
	return res, nil
}

// ---------- OAuth apps / SAML SSO credential authorizations ----------

type mqlGithubOrganizationOauthAppInternal struct {
	cacheOrgLogin  string
	cacheUserLogin string
	// fallback __id suffix when the API returned a nil credential id
	cacheCompositeID string
}

func (g *mqlGithubOrganizationOauthApp) id() (string, error) {
	if g.CredentialId.Error != nil {
		return "", g.CredentialId.Error
	}
	// CredentialID can be nil for some org listings; fall back to a
	// composite key to avoid every nil-id row colliding under "/0".
	if g.CredentialId.Data == 0 && g.cacheCompositeID != "" {
		return "github.organization.oauthApp/" + g.cacheCompositeID, nil
	}
	return "github.organization.oauthApp/" + strconv.FormatInt(g.CredentialId.Data, 10), nil
}

func (g *mqlGithubOrganization) oauthApps() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	opts := &github.CredentialAuthorizationsListOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}
	var allCreds []*github.CredentialAuthorization
	for {
		creds, resp, err := conn.Client().Organizations.ListCredentialAuthorizations(conn.Context(), orgLogin, opts)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				log.Debug().Err(err).Msg("Credential authorizations not accessible (requires GitHub Enterprise Cloud and SAML SSO)")
				return nil, nil
			}
			return nil, err
		}
		allCreds = append(allCreds, creds...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	res := []any{}
	for _, c := range allCreds {
		var credID int64
		if c.CredentialID != nil {
			credID = *c.CredentialID
		}
		// composite fallback for rows where CredentialID is nil
		var compositeID string
		if credID == 0 {
			var login, lastEight, authAt string
			if c.Login != nil {
				login = *c.Login
			}
			if c.TokenLastEight != nil {
				lastEight = *c.TokenLastEight
			}
			if ts := githubTimestamp(c.CredentialAuthorizedAt); ts != nil {
				authAt = ts.UTC().Format(time.RFC3339Nano)
			}
			compositeID = login + "/" + lastEight + "/" + authAt
		}
		args := map[string]*llx.RawData{
			"login":                         llx.StringDataPtr(c.Login),
			"credentialId":                  llx.IntData(credID),
			"credentialType":                llx.StringDataPtr(c.CredentialType),
			"tokenLastEight":                llx.StringDataPtr(c.TokenLastEight),
			"scopes":                        llx.ArrayData(convert.SliceAnyToInterface[string](c.Scopes), types.String),
			"authorizedAt":                  llx.TimeDataPtr(githubTimestamp(c.CredentialAuthorizedAt)),
			"lastAccessedAt":                llx.TimeDataPtr(githubTimestamp(c.CredentialAccessedAt)),
			"authorizedCredentialTitle":     llx.StringDataPtr(c.AuthorizedCredentialTitle),
			"authorizedCredentialNote":      llx.StringDataPtr(c.AuthorizedCredentialNote),
			"authorizedCredentialExpiresAt": llx.TimeDataPtr(githubTimestamp(c.AuthorizedCredentialExpiresAt)),
			"fingerprint":                   llx.StringDataPtr(c.Fingerprint),
		}
		r, err := CreateResource(g.MqlRuntime, "github.organization.oauthApp", args)
		if err != nil {
			return nil, err
		}
		oauthApp := r.(*mqlGithubOrganizationOauthApp)
		oauthApp.cacheOrgLogin = orgLogin
		if c.Login != nil {
			oauthApp.cacheUserLogin = *c.Login
		}
		oauthApp.cacheCompositeID = compositeID
		res = append(res, oauthApp)
	}
	return res, nil
}

func (g *mqlGithubOrganizationOauthApp) organization() (*mqlGithubOrganization, error) {
	if g.cacheOrgLogin == "" {
		g.Organization.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	o, err := NewResource(g.MqlRuntime, "github.organization", map[string]*llx.RawData{
		"login": llx.StringData(g.cacheOrgLogin),
	})
	if err != nil {
		return nil, err
	}
	return o.(*mqlGithubOrganization), nil
}

func (g *mqlGithubOrganizationOauthApp) user() (*mqlGithubUser, error) {
	if g.cacheUserLogin == "" {
		g.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	u, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
		"login": llx.StringData(g.cacheUserLogin),
	})
	if err != nil {
		return nil, err
	}
	return u.(*mqlGithubUser), nil
}

// ---------- Personal access tokens (fine-grained, org-level) ----------

func (g *mqlGithubOrganizationPersonalAccessToken) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	if g.Id.Data != 0 {
		return "github.organization.personalAccessToken/" + strconv.FormatInt(g.Id.Data, 10), nil
	}
	// Fall back to a composite key when the API didn't return an id, so we
	// don't collide every nil-id row under "/0".
	var owner, name, expires string
	if g.OwnerLogin.IsSet() && g.OwnerLogin.Error == nil {
		owner = g.OwnerLogin.Data
	}
	if g.TokenName.IsSet() && g.TokenName.Error == nil {
		name = g.TokenName.Data
	}
	if g.ExpiresAt.IsSet() && g.ExpiresAt.Error == nil && g.ExpiresAt.Data != nil {
		expires = g.ExpiresAt.Data.UTC().Format(time.RFC3339Nano)
	}
	return "github.organization.personalAccessToken/" + owner + "/" + name + "/" + expires, nil
}

func (g *mqlGithubOrganizationPersonalAccessToken) owner() (*mqlGithubUser, error) {
	if g.OwnerLogin.Error != nil {
		return nil, g.OwnerLogin.Error
	}
	if g.OwnerLogin.Data == "" {
		g.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	u, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
		"login": llx.StringData(g.OwnerLogin.Data),
	})
	if err != nil {
		return nil, err
	}
	return u.(*mqlGithubUser), nil
}

func (g *mqlGithubOrganization) personalAccessTokens() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	opts := &github.ListFineGrainedPATOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}
	var allPATs []*github.PersonalAccessToken
	for {
		pats, resp, err := conn.Client().Organizations.ListFineGrainedPersonalAccessTokens(conn.Context(), orgLogin, opts)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				log.Debug().Err(err).Msg("Fine-grained PATs not accessible (requires GitHub Enterprise Cloud)")
				return nil, nil
			}
			return nil, err
		}
		allPATs = append(allPATs, pats...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	res := []any{}
	for _, p := range allPATs {
		permsDict, _ := convert.JsonToDict(p.Permissions)

		var ownerLogin string
		if p.Owner != nil {
			ownerLogin = p.Owner.GetLogin()
		}
		var idVal int64
		if p.ID != nil {
			idVal = *p.ID
		}
		args := map[string]*llx.RawData{
			"id":                  llx.IntData(idVal),
			"tokenId":             llx.IntDataPtr(p.TokenID),
			"tokenName":           llx.StringDataPtr(p.TokenName),
			"ownerLogin":          llx.StringData(ownerLogin),
			"repositorySelection": llx.StringDataPtr(p.RepositorySelection),
			"permissions":         llx.MapData(permsDict, types.Any),
			"accessGrantedAt":     llx.TimeDataPtr(githubTimestamp(p.AccessGrantedAt)),
			"expired":             llx.BoolData(p.GetTokenExpired()),
			"expiresAt":           llx.TimeDataPtr(githubTimestamp(p.TokenExpiresAt)),
			"lastUsedAt":          llx.TimeDataPtr(githubTimestamp(p.TokenLastUsedAt)),
		}
		r, err := CreateResource(g.MqlRuntime, "github.organization.personalAccessToken", args)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// ---------- Audit log streaming destination ----------

func (g *mqlGithubOrganizationAuditLogStreamConfig) id() (string, error) {
	return g.__id, nil
}

// ghAuditLogStream represents the response of the GitHub audit log stream
// config endpoint, GET /orgs/{org}/audit-log/stream-config. The path is absent
// from GitHub's published REST descriptions for github.com, GitHub Enterprise
// Cloud and GitHub Enterprise Server, all of which carry audit log streaming
// only under /enterprises/{enterprise}/audit-log/streams.
type ghAuditLogStream struct {
	ID         int64      `json:"id"`
	StreamType string     `json:"stream_type"`
	Enabled    *bool      `json:"enabled"`
	PausedAt   *time.Time `json:"paused_at"`
	CreatedAt  *time.Time `json:"created_at"`
	UpdatedAt  *time.Time `json:"updated_at"`
}

// httpStatusOf returns the HTTP status a GitHub API failure carries, taken from
// the response when the client returned one and otherwise from the typed error.
// Transport failures carry no status and report 0.
func httpStatusOf(resp *github.Response, err error) int {
	if resp != nil && resp.Response != nil {
		return resp.StatusCode
	}
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.StatusCode
	}
	return 0
}

// auditLogStreamConfigError reports why an organization's audit log streaming
// configuration could not be read. A failed read is never turned into a null
// resource: a policy asserting `enabled` would then read "we could not tell" as
// "streaming is off".
func auditLogStreamConfigError(orgLogin string, resp *github.Response, err error) error {
	if err == nil {
		return nil
	}
	switch httpStatusOf(resp, err) {
	case http.StatusNotFound:
		return fmt.Errorf("audit log streaming configuration for organization %q could not be read: GitHub serves audit log streams from the enterprise endpoints (GET /enterprises/{enterprise}/audit-log/streams): %w", orgLogin, err)
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("audit log streaming configuration for organization %q could not be read: access denied, this requires organization owner access on GitHub Enterprise Cloud: %w", orgLogin, err)
	}
	return fmt.Errorf("audit log streaming configuration for organization %q could not be read: %w", orgLogin, err)
}

func (g *mqlGithubOrganization) auditLogStreamConfig() (*mqlGithubOrganizationAuditLogStreamConfig, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	urlStr := fmt.Sprintf("orgs/%s/audit-log/stream-config", orgLogin)
	var stream ghAuditLogStream
	resp, err := doRawJSON(conn.Context(), conn.Client(), urlStr, &stream)
	if err != nil {
		return nil, auditLogStreamConfigError(orgLogin, resp, err)
	}

	// Prefer the API's `enabled` field; fall back to "stream is configured" if
	// the API didn't return it (older responses or the field being omitted).
	enabled := stream.ID != 0
	if stream.Enabled != nil {
		enabled = *stream.Enabled
	}

	args := map[string]*llx.RawData{
		"__id":                llx.StringData("github.organization.auditLogStreamConfig/" + orgLogin),
		"enabled":             llx.BoolData(enabled),
		"streamType":          llx.StringData(stream.StreamType),
		"streamId":            llx.IntData(stream.ID),
		"enabledStreamPaused": llx.BoolData(stream.PausedAt != nil),
	}
	if stream.CreatedAt != nil {
		args["createdAt"] = llx.TimeData(*stream.CreatedAt)
	}
	if stream.UpdatedAt != nil {
		args["updatedAt"] = llx.TimeData(*stream.UpdatedAt)
	}

	res, err := CreateResource(g.MqlRuntime, "github.organization.auditLogStreamConfig", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubOrganizationAuditLogStreamConfig), nil
}

// ---------- Installation augmentation ----------

type mqlGithubInstallationInternal struct {
	cacheOrgLogin       string
	cacheInstallationID int64
}

func (g *mqlGithubInstallation) repositories() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	// only meaningful for "selected" repository_selection
	sel := ""
	if g.RepositorySelection.IsSet() && g.RepositorySelection.Error == nil {
		sel = g.RepositorySelection.Data
	}
	if sel != "" && sel != "selected" {
		return []any{}, nil
	}

	if g.cacheInstallationID == 0 {
		// without an installation ID we cannot enumerate the installation's repos
		return []any{}, nil
	}

	// List repos accessible to the user-authenticated token under this
	// installation. Endpoint: GET /user/installations/{installation_id}/repositories
	opts := &github.ListOptions{PerPage: paginationPerPage}
	var allRepos []*github.Repository
	for {
		r, resp, err := conn.Client().Apps.ListUserRepos(conn.Context(), g.cacheInstallationID, opts)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				return []any{}, nil
			}
			return nil, err
		}
		if r != nil {
			allRepos = append(allRepos, r.Repositories...)
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	res := make([]any, 0, len(allRepos))
	for _, repo := range allRepos {
		mqlRepo, err := newMqlGithubRepository(g.MqlRuntime, repo)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRepo)
	}
	return res, nil
}

// ---------- Deploy keys (repo + user) ----------

type mqlGithubDeployKeyInternal struct {
	cacheRepoOwner    string
	cacheRepoName     string
	cacheAddedByLogin string
}

func (g *mqlGithubDeployKey) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "github.deployKey/" + strconv.FormatInt(g.Id.Data, 10), nil
}

// keyAge returns the age of a key in days based on a CreatedAt timestamp; -1 if
// CreatedAt is unknown.
func keyAgeInDays(createdAt *github.Timestamp) int64 {
	if createdAt == nil || createdAt.IsZero() {
		return -1
	}
	return int64(time.Since(createdAt.Time).Hours() / 24)
}

// newMqlDeployKey builds a deploy key. repo is the repository the key was read
// from, when the caller has it; passing it sets the key's repository field
// outright, so repository() -- one Repositories.Get per key, for a repository
// the scan is already holding, repeated for every key on the same one -- never
// runs. A caller without the repository passes nil and keeps that fallback.
func newMqlDeployKey(runtime *plugin.Runtime, k *github.Key, repo *mqlGithubRepository, repoOwner, repoName string) (*mqlGithubDeployKey, error) {
	var idVal int64
	if k.ID != nil {
		idVal = *k.ID
	}
	args := map[string]*llx.RawData{
		"id":        llx.IntData(idVal),
		"title":     llx.StringDataPtr(k.Title),
		"key":       llx.StringDataPtr(k.Key),
		"readOnly":  llx.BoolData(k.GetReadOnly()),
		"verified":  llx.BoolData(k.GetVerified()),
		"createdAt": llx.TimeDataPtr(githubTimestamp(k.CreatedAt)),
		"lastUsed":  llx.TimeDataPtr(githubTimestamp(k.LastUsed)),
		"ageInDays": llx.IntData(keyAgeInDays(k.CreatedAt)),
	}
	r, err := CreateResource(runtime, "github.deployKey", args)
	if err != nil {
		return nil, err
	}
	dk := r.(*mqlGithubDeployKey)
	dk.cacheRepoOwner = repoOwner
	dk.cacheRepoName = repoName
	if k.AddedBy != nil {
		dk.cacheAddedByLogin = *k.AddedBy
	}
	switch {
	case repo != nil:
		dk.Repository = plugin.TValue[*mqlGithubRepository]{Data: repo, State: plugin.StateIsSet}
	case repoOwner == "" || repoName == "":
		dk.Repository.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return dk, nil
}

func (g *mqlGithubDeployKey) addedBy() (*mqlGithubUser, error) {
	if g.cacheAddedByLogin == "" {
		g.AddedBy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	u, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
		"login": llx.StringData(g.cacheAddedByLogin),
	})
	if err != nil {
		return nil, err
	}
	return u.(*mqlGithubUser), nil
}

func (g *mqlGithubDeployKey) repository() (*mqlGithubRepository, error) {
	if g.cacheRepoOwner == "" || g.cacheRepoName == "" {
		g.Repository.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	repo, _, err := conn.Client().Repositories.Get(conn.Context(), g.cacheRepoOwner, g.cacheRepoName)
	if err != nil {
		if isAccessDeniedOrNotFound(err) {
			g.Repository.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return newMqlGithubRepository(g.MqlRuntime, repo)
}

func (g *mqlGithubRepository) deployKeys() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	listOpts := &github.ListOptions{PerPage: paginationPerPage}
	var allKeys []*github.Key
	for {
		keys, resp, err := conn.Client().Repositories.ListKeys(conn.Context(), ownerLogin, repoName, listOpts)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		allKeys = append(allKeys, keys...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := make([]any, 0, len(allKeys))
	for _, k := range allKeys {
		dk, err := newMqlDeployKey(g.MqlRuntime, k, g, ownerLogin, repoName)
		if err != nil {
			return nil, err
		}
		res = append(res, dk)
	}
	return res, nil
}

func (g *mqlGithubUser) publicKeys() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	userLogin := g.Login.Data

	listOpts := &github.ListOptions{PerPage: paginationPerPage}
	var allKeys []*github.Key
	for {
		keys, resp, err := conn.Client().Users.ListKeys(conn.Context(), userLogin, listOpts)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		allKeys = append(allKeys, keys...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := make([]any, 0, len(allKeys))
	for _, k := range allKeys {
		pk, err := newMqlPublicKey(g.MqlRuntime, k, userLogin)
		if err != nil {
			return nil, err
		}
		res = append(res, pk)
	}
	return res, nil
}

// ---------- User public keys ----------

type mqlGithubPublicKeyInternal struct {
	cacheUserLogin string
}

func (g *mqlGithubPublicKey) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "github.publicKey/" + strconv.FormatInt(g.Id.Data, 10), nil
}

func newMqlPublicKey(runtime *plugin.Runtime, k *github.Key, userLogin string) (*mqlGithubPublicKey, error) {
	var idVal int64
	if k.ID != nil {
		idVal = *k.ID
	}
	args := map[string]*llx.RawData{
		"id":        llx.IntData(idVal),
		"title":     llx.StringDataPtr(k.Title),
		"key":       llx.StringDataPtr(k.Key),
		"verified":  llx.BoolData(k.GetVerified()),
		"createdAt": llx.TimeDataPtr(githubTimestamp(k.CreatedAt)),
		"ageInDays": llx.IntData(keyAgeInDays(k.CreatedAt)),
	}
	r, err := CreateResource(runtime, "github.publicKey", args)
	if err != nil {
		return nil, err
	}
	pk := r.(*mqlGithubPublicKey)
	pk.cacheUserLogin = userLogin
	if userLogin == "" {
		pk.User.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return pk, nil
}

func (g *mqlGithubPublicKey) user() (*mqlGithubUser, error) {
	if g.cacheUserLogin == "" {
		g.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	u, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
		"login": llx.StringData(g.cacheUserLogin),
	})
	if err != nil {
		return nil, err
	}
	return u.(*mqlGithubUser), nil
}

// ---------- CODEOWNERS ----------

func (g *mqlGithubRepositoryCodeowners) id() (string, error) {
	return g.__id, nil
}

func (g *mqlGithubCodeownersRule) id() (string, error) {
	if g.LineNumber.Error != nil {
		return "", g.LineNumber.Error
	}
	if g.Pattern.Error != nil {
		return "", g.Pattern.Error
	}
	return fmt.Sprintf("github.codeowners.rule/%s/%d", g.Pattern.Data, g.LineNumber.Data), nil
}

// codeownersRuleID keys a CODEOWNERS rule by repository. Patterns repeat across
// repositories (`*` on line 1 is near-universal), so an unqualified key made
// every repository after the first report the first one's owners.
func codeownersRuleID(ownerLogin, repoName, pattern string, lineNumber int) string {
	return fmt.Sprintf("github.codeowners.rule/%s/%s/%s/%d", ownerLogin, repoName, pattern, lineNumber)
}

// codeownersCandidatePaths returns the locations CODEOWNERS may live at, in
// resolution priority order.
var codeownersCandidatePaths = []string{
	".github/CODEOWNERS",
	"CODEOWNERS",
	"docs/CODEOWNERS",
}

// parseCodeowners parses the contents of a CODEOWNERS file and returns the
// rules as raw struct values; empty/comment lines are skipped.
type codeownersRule struct {
	pattern    string
	owners     []string
	lineNumber int
}

// isCodeownersCommentLine reports whether the line is a comment per the
// GitHub CODEOWNERS spec: a line is a comment only when `#` is the first
// non-whitespace character. Inline `#` is treated as part of the pattern or
// owner token (e.g. `path/to/#special`), not as a comment marker.
func isCodeownersCommentLine(line string) bool {
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == ' ' || c == '\t' {
			continue
		}
		return c == '#'
	}
	return false
}

func parseCodeowners(content string) []codeownersRule {
	rules := []codeownersRule{}
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		if isCodeownersCommentLine(line) {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		rule := codeownersRule{
			pattern:    fields[0],
			owners:     fields[1:],
			lineNumber: i + 1,
		}
		rules = append(rules, rule)
	}
	return rules
}

func (g *mqlGithubRepository) codeowners() (*mqlGithubRepositoryCodeowners, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	resID := llx.StringData(fmt.Sprintf("github.repository.codeowners/%s/%s", ownerLogin, repoName))

	var foundPath, content string
	for _, p := range codeownersCandidatePaths {
		fc, _, _, err := conn.Client().Repositories.GetContents(conn.Context(), ownerLogin, repoName, p, nil)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				continue
			}
			return nil, err
		}
		if fc == nil {
			continue
		}
		c, err := fc.GetContent()
		if err != nil {
			return nil, err
		}
		foundPath = p
		content = c
		break
	}

	rules := []any{}
	for _, r := range parseCodeowners(content) {
		rr, err := CreateResource(g.MqlRuntime, "github.codeowners.rule", map[string]*llx.RawData{
			"__id":       llx.StringData(codeownersRuleID(ownerLogin, repoName, r.pattern, r.lineNumber)),
			"pattern":    llx.StringData(r.pattern),
			"owners":     llx.ArrayData(convert.SliceAnyToInterface[string](r.owners), types.String),
			"lineNumber": llx.IntData(int64(r.lineNumber)),
		})
		if err != nil {
			return nil, err
		}
		rules = append(rules, rr)
	}

	res, err := CreateResource(g.MqlRuntime, "github.repository.codeowners", map[string]*llx.RawData{
		"__id":    resID,
		"path":    llx.StringData(foundPath),
		"exists":  llx.BoolData(foundPath != ""),
		"content": llx.StringData(content),
		"rules":   llx.ArrayData(rules, types.Resource("github.codeowners.rule")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGithubRepositoryCodeowners), nil
}

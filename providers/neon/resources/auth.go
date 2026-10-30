// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/url"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/neon/connection"
	"go.mondoo.com/mql/types"
)

// mqlNeonAuthInternal caches the branch the integration runs on and memoizes
// the reads that back the fields the main auth payload does not carry. Each of
// those sits behind its own endpoint, so a query touching several of the
// email-and-password fields would otherwise read the same endpoint once per
// field.
type mqlNeonAuthInternal struct {
	cacheProjectID string
	cacheBranchID  string

	emailPasswordOnce sync.Once
	emailPassword     *emailPasswordRecord
	emailPasswordErr  error

	localhostOnce sync.Once
	localhost     *bool
	localhostErr  error

	domainsOnce sync.Once
	domains     []string
	domainsRead bool
}

type authRecord struct {
	AuthProvider          string   `json:"auth_provider"`
	AuthProviderProjectID string   `json:"auth_provider_project_id"`
	BranchID              string   `json:"branch_id"`
	DbName                string   `json:"db_name"`
	JwksURL               string   `json:"jwks_url"`
	BaseURL               *string  `json:"base_url"`
	Name                  *string  `json:"name"`
	OwnedBy               string   `json:"owned_by"`
	TransferStatus        *string  `json:"transfer_status"`
	CreatedAt             neonTime `json:"created_at"`
}

// emailPasswordRecord holds the self-registration controls. Every field is
// documented as always present, so an absent one is reported as null rather
// than as a setting that is switched off.
type emailPasswordRecord struct {
	Enabled                       *bool   `json:"enabled"`
	EmailVerificationMethod       *string `json:"email_verification_method"`
	RequireEmailVerification      *bool   `json:"require_email_verification"`
	AutoSignInAfterVerification   *bool   `json:"auto_sign_in_after_verification"`
	SendVerificationEmailOnSignUp *bool   `json:"send_verification_email_on_sign_up"`
	SendVerificationEmailOnSignIn *bool   `json:"send_verification_email_on_sign_in"`
	DisableSignUp                 *bool   `json:"disable_sign_up"`
}

type authDomainRecord struct {
	Domain       string `json:"domain"`
	AuthProvider string `json:"auth_provider"`
}

type oauthProviderRecord struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"`
	ClientID *string `json:"client_id"`
	// The client secret the payload also carries is deliberately not decoded.
	// It is credential material and has no place in a schema field.
}

// authBasePath is the branch-scoped root every Neon Auth endpoint hangs off.
func authBasePath(projectID, branchID string) string {
	return "/projects/" + url.PathEscape(projectID) +
		"/branches/" + url.PathEscape(branchID) + "/auth"
}

// auth resolves the Neon Auth integration on the branch. A branch with none
// set up answers 404, which is reported as no integration rather than as a
// failure.
func (b *mqlNeonBranch) auth() (*mqlNeonAuth, error) {
	c := neonConn(b.MqlRuntime)

	var rec authRecord
	err := c.Get(context.Background(), authBasePath(b.cacheProjectID, b.Id.Data), nil, &rec)
	if err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			b.Auth.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	// The integration is keyed by the branch it runs on, so the cache key
	// carries the project and branch and cannot alias one on another branch.
	res, err := CreateResource(b.MqlRuntime, "neon.auth", map[string]*llx.RawData{
		"__id":                  llx.StringData(b.cacheProjectID + "/" + b.Id.Data + "/auth"),
		"authProvider":          llx.StringData(rec.AuthProvider),
		"authProviderProjectId": llx.StringData(rec.AuthProviderProjectID),
		"dbName":                llx.StringData(rec.DbName),
		"jwksUrl":               llx.StringData(rec.JwksURL),
		"baseUrl":               optionalString(rec.BaseURL),
		"name":                  optionalString(rec.Name),
		"ownedBy":               llx.StringData(rec.OwnedBy),
		"transferStatus":        optionalString(rec.TransferStatus),
		"createdAt":             llx.TimeDataPtr(rec.CreatedAt.Time()),
	})
	if err != nil {
		return nil, err
	}

	auth := res.(*mqlNeonAuth)
	auth.cacheProjectID = b.cacheProjectID
	auth.cacheBranchID = b.Id.Data
	return auth, nil
}

// branch resolves the branch the integration runs on.
func (a *mqlNeonAuth) branch() (*mqlNeonBranch, error) {
	branch, err := branchByID(a.MqlRuntime, a.cacheProjectID, a.cacheBranchID)
	if err != nil {
		return nil, err
	}
	if branch == nil {
		a.Branch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return branch, nil
}

// fetchEmailPassword reads the self-registration controls once and hands the
// same answer to each of the fields that come from them. A read the key is not
// allowed to make yields nil, which every caller reports as null. A read that
// failed for any other reason is reported as the failure it was, because a
// network fault reported as null would read as a control that is switched off.
func (a *mqlNeonAuth) fetchEmailPassword() (*emailPasswordRecord, error) {
	a.emailPasswordOnce.Do(func() {
		c := neonConn(a.MqlRuntime)
		var rec emailPasswordRecord
		err := c.Get(context.Background(),
			authBasePath(a.cacheProjectID, a.cacheBranchID)+"/email_and_password", nil, &rec)
		if err != nil {
			if !connection.IsForbidden(err) && !connection.IsNotFound(err) {
				a.emailPasswordErr = err
			}
			return
		}
		a.emailPassword = &rec
	})
	return a.emailPassword, a.emailPasswordErr
}

func (a *mqlNeonAuth) emailPasswordEnabled() (bool, error) {
	rec, err := a.fetchEmailPassword()
	if err != nil {
		return false, err
	}
	if rec == nil || rec.Enabled == nil {
		a.EmailPasswordEnabled = plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
		return false, nil
	}
	return *rec.Enabled, nil
}

func (a *mqlNeonAuth) emailVerificationMethod() (string, error) {
	rec, err := a.fetchEmailPassword()
	if err != nil {
		return "", err
	}
	if rec == nil || rec.EmailVerificationMethod == nil {
		a.EmailVerificationMethod = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
		return "", nil
	}
	return *rec.EmailVerificationMethod, nil
}

func (a *mqlNeonAuth) requireEmailVerification() (bool, error) {
	rec, err := a.fetchEmailPassword()
	if err != nil {
		return false, err
	}
	if rec == nil || rec.RequireEmailVerification == nil {
		a.RequireEmailVerification = plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
		return false, nil
	}
	return *rec.RequireEmailVerification, nil
}

func (a *mqlNeonAuth) autoSignInAfterVerification() (bool, error) {
	rec, err := a.fetchEmailPassword()
	if err != nil {
		return false, err
	}
	if rec == nil || rec.AutoSignInAfterVerification == nil {
		a.AutoSignInAfterVerification = plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
		return false, nil
	}
	return *rec.AutoSignInAfterVerification, nil
}

func (a *mqlNeonAuth) sendVerificationEmailOnSignUp() (bool, error) {
	rec, err := a.fetchEmailPassword()
	if err != nil {
		return false, err
	}
	if rec == nil || rec.SendVerificationEmailOnSignUp == nil {
		a.SendVerificationEmailOnSignUp = plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
		return false, nil
	}
	return *rec.SendVerificationEmailOnSignUp, nil
}

func (a *mqlNeonAuth) sendVerificationEmailOnSignIn() (bool, error) {
	rec, err := a.fetchEmailPassword()
	if err != nil {
		return false, err
	}
	if rec == nil || rec.SendVerificationEmailOnSignIn == nil {
		a.SendVerificationEmailOnSignIn = plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
		return false, nil
	}
	return *rec.SendVerificationEmailOnSignIn, nil
}

func (a *mqlNeonAuth) disableSignUp() (bool, error) {
	rec, err := a.fetchEmailPassword()
	if err != nil {
		return false, err
	}
	if rec == nil || rec.DisableSignUp == nil {
		a.DisableSignUp = plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
		return false, nil
	}
	return *rec.DisableSignUp, nil
}

// allowLocalhost reports whether a callback to a localhost address is accepted.
func (a *mqlNeonAuth) allowLocalhost() (bool, error) {
	a.localhostOnce.Do(func() {
		c := neonConn(a.MqlRuntime)
		var resp struct {
			AllowLocalhost *bool `json:"allow_localhost"`
		}
		err := c.Get(context.Background(),
			authBasePath(a.cacheProjectID, a.cacheBranchID)+"/allow_localhost", nil, &resp)
		if err != nil {
			if !connection.IsForbidden(err) && !connection.IsNotFound(err) {
				a.localhostErr = err
			}
			return
		}
		a.localhost = resp.AllowLocalhost
	})
	if a.localhostErr != nil {
		return false, a.localhostErr
	}

	if a.localhost == nil {
		a.AllowLocalhost = plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
		return false, nil
	}
	return *a.localhost, nil
}

// trustedDomains lists the domains a sign-in flow may redirect back to.
func (a *mqlNeonAuth) trustedDomains() ([]any, error) {
	var readErr error
	a.domainsOnce.Do(func() {
		c := neonConn(a.MqlRuntime)
		records, err := connection.GetList[authDomainRecord](context.Background(), c,
			authBasePath(a.cacheProjectID, a.cacheBranchID)+"/domains", nil, "domains")
		if err != nil {
			if connection.IsForbidden(err) || connection.IsNotFound(err) {
				return
			}
			readErr = err
			return
		}
		domains := make([]string, 0, len(records))
		for _, rec := range records {
			domains = append(domains, rec.Domain)
		}
		a.domains = domains
		a.domainsRead = true
	})
	if readErr != nil {
		return nil, readErr
	}

	// An allowlist that could not be read is not an empty allowlist, which
	// would read as a boundary that permits nothing.
	if !a.domainsRead {
		a.TrustedDomains = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	return strSliceToAny(a.domains), nil
}

// oauthProviders lists the outside providers users may sign in with.
func (a *mqlNeonAuth) oauthProviders() ([]any, error) {
	c := neonConn(a.MqlRuntime)

	records, err := connection.GetList[oauthProviderRecord](context.Background(), c,
		authBasePath(a.cacheProjectID, a.cacheBranchID)+"/oauth_providers", nil, "providers")
	if err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			a.OauthProviders = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		// A provider is named once per integration, so the cache key carries
		// the branch the integration runs on.
		provider, err := CreateResource(a.MqlRuntime, "neon.auth.oauthProvider", map[string]*llx.RawData{
			"__id":     llx.StringData(a.cacheProjectID + "/" + a.cacheBranchID + "/oauth/" + rec.ID),
			"provider": llx.StringData(rec.ID),
			"type":     llx.StringData(rec.Type),
			"clientId": optionalString(rec.ClientID),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, provider)
	}
	return res, nil
}

// --- data api -------------------------------------------------------------

// mqlNeonDataApiInternal caches the database the interface publishes.
type mqlNeonDataApiInternal struct {
	cacheProjectID    string
	cacheBranchID     string
	cacheDatabaseName string
}

type dataApiRecord struct {
	URL              string           `json:"url"`
	Status           string           `json:"status"`
	Settings         *dataApiSettings `json:"settings"`
	AvailableSchemas *[]string        `json:"available_schemas"`
}

// dataApiSettings holds the interface's configuration. Neon omits a setting
// that was never given a value, so every field is optional and an absent one
// is reported as null rather than as a documented default that may not be what
// the deployment is actually running.
type dataApiSettings struct {
	DbAggregatesEnabled     *bool     `json:"db_aggregates_enabled"`
	DbAnonRole              *string   `json:"db_anon_role"`
	DbExtraSearchPath       *string   `json:"db_extra_search_path"`
	DbMaxRows               *int64    `json:"db_max_rows"`
	DbSchemas               *[]string `json:"db_schemas"`
	JwtRoleClaimKey         *string   `json:"jwt_role_claim_key"`
	JwtCacheMaxLifetime     *int64    `json:"jwt_cache_max_lifetime"`
	OpenapiMode             *string   `json:"openapi_mode"`
	ServerCorsAllowedOrigin *string   `json:"server_cors_allowed_origins"`
	ServerTimingEnabled     *bool     `json:"server_timing_enabled"`
}

// dataApi resolves the Data API publishing the database. A database with none
// deployed answers 404, which is reported as no interface rather than as a
// failure.
func (d *mqlNeonDatabase) dataApi() (*mqlNeonDataApi, error) {
	c := neonConn(d.MqlRuntime)

	path := "/projects/" + url.PathEscape(d.cacheProjectID) +
		"/branches/" + url.PathEscape(d.cacheBranchID) +
		"/data-api/" + url.PathEscape(d.Name.Data)

	var rec dataApiRecord
	if err := c.Get(context.Background(), path, nil, &rec); err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			d.DataApi.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	settings := rec.Settings
	if settings == nil {
		settings = &dataApiSettings{}
	}

	dbSchemas := llx.NilData
	if settings.DbSchemas != nil {
		dbSchemas = llx.ArrayData(strSliceToAny(*settings.DbSchemas), types.String)
	}
	availableSchemas := llx.NilData
	if rec.AvailableSchemas != nil {
		availableSchemas = llx.ArrayData(strSliceToAny(*rec.AvailableSchemas), types.String)
	}

	// The interface is keyed by the database it publishes, so the cache key
	// carries the project, branch, and database name.
	res, err := CreateResource(d.MqlRuntime, "neon.dataApi", map[string]*llx.RawData{
		"__id":                llx.StringData(d.cacheProjectID + "/" + d.cacheBranchID + "/data-api/" + d.Name.Data),
		"url":                 llx.StringData(rec.URL),
		"status":              llx.StringData(rec.Status),
		"dbAnonRole":          optionalString(settings.DbAnonRole),
		"dbSchemas":           dbSchemas,
		"availableSchemas":    availableSchemas,
		"dbExtraSearchPath":   optionalString(settings.DbExtraSearchPath),
		"dbMaxRows":           llx.IntDataPtr(settings.DbMaxRows),
		"dbAggregatesEnabled": llx.BoolDataPtr(settings.DbAggregatesEnabled),
		"corsAllowedOrigins":  optionalString(settings.ServerCorsAllowedOrigin),
		"jwtRoleClaimKey":     optionalString(settings.JwtRoleClaimKey),
		"jwtCacheMaxLifetime": llx.IntDataPtr(settings.JwtCacheMaxLifetime),
		"openapiMode":         optionalString(settings.OpenapiMode),
		"serverTimingEnabled": llx.BoolDataPtr(settings.ServerTimingEnabled),
	})
	if err != nil {
		return nil, err
	}

	api := res.(*mqlNeonDataApi)
	api.cacheProjectID = d.cacheProjectID
	api.cacheBranchID = d.cacheBranchID
	api.cacheDatabaseName = d.Name.Data
	return api, nil
}

// database resolves the database the interface publishes.
func (a *mqlNeonDataApi) database() (*mqlNeonDatabase, error) {
	branch, err := branchByID(a.MqlRuntime, a.cacheProjectID, a.cacheBranchID)
	if err != nil {
		return nil, err
	}
	if branch == nil {
		a.Database.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	databases := branch.GetDatabases()
	if databases.Error != nil {
		return nil, databases.Error
	}
	for _, it := range databases.Data {
		database, ok := it.(*mqlNeonDatabase)
		if ok && database.Name.Data == a.cacheDatabaseName {
			return database, nil
		}
	}

	a.Database.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

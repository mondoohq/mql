// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/netlify/connection"
	"go.mondoo.com/mql/types"
)

// mqlNetlifySiteInternal caches the identifiers the site's own child lookups
// need: the account the environment-variable endpoint is keyed on, and the
// deploy key the build clones with.
type mqlNetlifySiteInternal struct {
	cacheAccountID   string
	cacheDeployKeyID string

	// The site's TLS certificate is a single record behind its own endpoint
	// that several fields read from, so it is fetched once for the site rather
	// than once per field. certErr holds a genuine failure; a site with no
	// certificate leaves both nil.
	certOnce sync.Once
	cert     *sniCertificateRecord
	certErr  error
}

type siteRecord struct {
	ID                        string             `json:"id"`
	Name                      string             `json:"name"`
	State                     string             `json:"state"`
	Plan                      string             `json:"plan"`
	URL                       string             `json:"url"`
	SslURL                    string             `json:"ssl_url"`
	AdminURL                  string             `json:"admin_url"`
	CustomDomain              string             `json:"custom_domain"`
	DomainAliases             []string           `json:"domain_aliases"`
	BranchDeployCustomDomain  string             `json:"branch_deploy_custom_domain"`
	DeployPreviewCustomDomain string             `json:"deploy_preview_custom_domain"`
	NotificationEmail         string             `json:"notification_email"`
	IDDomain                  string             `json:"id_domain"`
	Ssl                       bool               `json:"ssl"`
	ForceSsl                  bool               `json:"force_ssl"`
	ManagedDns                bool               `json:"managed_dns"`
	PreventNonGitProdDeploys  bool               `json:"prevent_non_git_prod_deploys"`
	BuildImage                string             `json:"build_image"`
	Prerender                 string             `json:"prerender"`
	FunctionsRegion           string             `json:"functions_region"`
	AccountID                 string             `json:"account_id"`
	AccountSlug               string             `json:"account_slug"`
	CreatedAt                 netlifyTime        `json:"created_at"`
	UpdatedAt                 netlifyTime        `json:"updated_at"`
	BuildSettings             *buildSettingsData `json:"build_settings"`

	// Capabilities is the plan entitlement map, whose value shape varies by
	// capability name, so it is carried as raw JSON and reported as a dict.
	Capabilities json.RawMessage `json:"capabilities"`

	// Password is the site's visitor password as the API reports it. It is
	// held as raw JSON so the value never lands in a field, and so an absent
	// key stays distinguishable from a reported one. A non-pointer
	// json.RawMessage is deliberate: a pointer would collapse an explicit
	// JSON null back into the absent case. Only its presence is surfaced,
	// through passwordProtected.
	Password json.RawMessage `json:"password"`
}

// sitePasswordProtected reports whether a site is gated behind a visitor
// password, from the raw password value the API returned.
//
// The password itself is a secret and is never modelled. Only its presence is
// the finding, and presence survives every form the API may report the value
// in: a literal password, a redacted placeholder such as "****", or a
// boolean-ish marker. A key the API did not return at all yields nil, which
// reaches MQL as null rather than as a confident "not protected", because an
// unreported field is indistinguishable from a site that never set one.
func sitePasswordProtected(raw json.RawMessage) *bool {
	if len(raw) == 0 {
		return nil
	}

	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// The key was returned in a shape we cannot read. A value is present,
		// which is the signal we report.
		return new(true)
	}

	switch t := v.(type) {
	case nil:
		// Explicitly reported as having no password.
		return new(false)
	case string:
		// A literal password or a redacted placeholder. Either way a password
		// is set; an empty string is the API saying none is.
		return new(t != "")
	case bool:
		return new(t)
	case float64:
		return new(t != 0)
	default:
		return new(true)
	}
}

//go:fix inline
func ptr[T any](v T) *T { return new(v) }

// buildSettingsData is the repository configuration a build runs from. Netlify
// returns it inline with the site.
type buildSettingsData struct {
	Provider            string   `json:"provider"`
	RepoURL             string   `json:"repo_url"`
	RepoBranch          string   `json:"repo_branch"`
	RepoPath            string   `json:"repo_path"`
	Cmd                 string   `json:"cmd"`
	Dir                 string   `json:"dir"`
	FunctionsDir        string   `json:"functions_dir"`
	AllowedBranches     []string `json:"allowed_branches"`
	PublicRepo          bool     `json:"public_repo"`
	PrivateLogs         *bool    `json:"private_logs"`
	StopBuilds          bool     `json:"stop_builds"`
	UntrustedFlow       string   `json:"untrusted_flow"`
	SkipPrs             *bool    `json:"skip_prs"`
	SkipAutomaticBuilds *bool    `json:"skip_automatic_builds"`
	DeployKeyID         string   `json:"deploy_key_id"`
	InstallationID      *int64   `json:"installation_id"`
}

// sites lists the account's sites, narrowed to the site a discovered asset is
// scoped to.
func (a *mqlNetlifyAccount) sites() ([]any, error) {
	c := netlifyConn(a.MqlRuntime)

	slug := a.accountSlug()
	if slug == "" {
		return nil, errors.New("netlify.account.sites requires the account slug")
	}

	records, err := connection.GetPaged[siteRecord](context.Background(), c,
		"/"+url.PathEscape(slug)+"/sites", nil)
	if err != nil {
		return nil, err
	}

	siteFilter := c.SiteFilter()

	var res []any
	for i := range records {
		rec := records[i]
		if siteFilter != "" && rec.ID != siteFilter {
			continue
		}
		site, err := newNetlifySite(a.MqlRuntime, &rec)
		if err != nil {
			return nil, err
		}
		res = append(res, site)
	}
	return res, nil
}

func newNetlifySite(runtime *plugin.Runtime, rec *siteRecord) (*mqlNetlifySite, error) {
	build := rec.BuildSettings
	if build == nil {
		build = &buildSettingsData{}
	}

	res, err := CreateResource(runtime, "netlify.site", map[string]*llx.RawData{
		"id":                        llx.StringData(rec.ID),
		"name":                      llx.StringData(rec.Name),
		"state":                     llx.StringData(rec.State),
		"plan":                      llx.StringData(rec.Plan),
		"url":                       llx.StringData(rec.URL),
		"sslUrl":                    llx.StringData(rec.SslURL),
		"adminUrl":                  llx.StringData(rec.AdminURL),
		"customDomain":              llx.StringData(rec.CustomDomain),
		"domainAliases":             llx.ArrayData(strSliceToAny(rec.DomainAliases), types.String),
		"branchDeployCustomDomain":  llx.StringData(rec.BranchDeployCustomDomain),
		"deployPreviewCustomDomain": llx.StringData(rec.DeployPreviewCustomDomain),
		"notificationEmail":         llx.StringData(rec.NotificationEmail),
		"ssl":                       llx.BoolData(rec.Ssl),
		"forceSsl":                  llx.BoolData(rec.ForceSsl),
		"managedDns":                llx.BoolData(rec.ManagedDns),
		"preventNonGitProdDeploys":  llx.BoolData(rec.PreventNonGitProdDeploys),
		"buildImage":                llx.StringData(rec.BuildImage),
		"prerender":                 llx.StringData(rec.Prerender),
		"functionsRegion":           llx.StringData(rec.FunctionsRegion),
		"createdAt":                 llx.TimeDataPtr(rec.CreatedAt.Time()),
		"updatedAt":                 llx.TimeDataPtr(rec.UpdatedAt.Time()),
		"repoProvider":              llx.StringData(build.Provider),
		"repoUrl":                   llx.StringData(build.RepoURL),
		"repoBranch":                llx.StringData(build.RepoBranch),
		"repoPath":                  llx.StringData(build.RepoPath),
		"buildCommand":              llx.StringData(build.Cmd),
		"publishDirectory":          llx.StringData(build.Dir),
		"functionsDirectory":        llx.StringData(build.FunctionsDir),
		"allowedBranches":           llx.ArrayData(strSliceToAny(build.AllowedBranches), types.String),
		"publicRepo":                llx.BoolData(build.PublicRepo),
		"privateLogs":               optionalBool(build.PrivateLogs),
		"untrustedFlow":             llx.StringData(build.UntrustedFlow),
		"skipPrs":                   optionalBool(build.SkipPrs),
		"skipAutomaticBuilds":       optionalBool(build.SkipAutomaticBuilds),
		"idDomain":                  llx.StringData(rec.IDDomain),
		"stopBuilds":                llx.BoolData(build.StopBuilds),
		"passwordProtected":         optionalBool(sitePasswordProtected(rec.Password)),
		"installationId":            optionalInt(build.InstallationID),
		"capabilities":              rawJSONToDict(rec.Capabilities),
	})
	if err != nil {
		return nil, err
	}

	site := res.(*mqlNetlifySite)
	site.cacheAccountID = rec.AccountID
	site.cacheDeployKeyID = build.DeployKeyID
	return site, nil
}

// initNetlifySite resolves the site a query targets: an explicit id argument or
// the site a discovered asset is scoped to.
func initNetlifySite(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	c := netlifyConn(runtime)

	siteID := ""
	if data, ok := args["id"]; ok {
		if s, ok := data.Value.(string); ok {
			siteID = s
		}
	}
	if siteID == "" && c.Asset() != nil {
		for _, pid := range c.Asset().PlatformIds {
			if t, ok := strings.CutPrefix(pid, connection.PlatformIdNetlifySite); ok {
				siteID = t
				break
			}
		}
	}
	if siteID == "" {
		siteID = c.SiteFilter()
	}
	if siteID == "" {
		return nil, nil, errors.New("netlify.site requires a site id")
	}

	var rec siteRecord
	if err := c.Get(context.Background(), "/sites/"+url.PathEscape(siteID), nil, &rec); err != nil {
		return nil, nil, err
	}
	if rec.ID == "" {
		rec.ID = siteID
	}

	site, err := newNetlifySite(runtime, &rec)
	if err != nil {
		return nil, nil, err
	}
	return args, site, nil
}

func (s *mqlNetlifySite) id() (string, error) {
	return s.Id.Data, s.Id.Error
}

// account resolves the account the site is billed to and administered from.
//
// The match runs against the account list the root resource has already
// fetched, so a query over many sites does not walk the accounts endpoint per
// site. An account outside the scope the connection is narrowed to is absent
// from that list, so a miss falls back to the direct lookup.
func (s *mqlNetlifySite) account() (*mqlNetlifyAccount, error) {
	if s.cacheAccountID == "" {
		s.Account.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	root, err := getNetlify(s.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if account, ok := findCachedResource(root.GetAccounts(), netlifyAccountID, s.cacheAccountID); ok {
		return account, nil
	}

	res, err := NewResource(s.MqlRuntime, "netlify.account", map[string]*llx.RawData{
		"id": llx.StringData(s.cacheAccountID),
	})
	if err != nil {
		// The account lookup runs against the accounts the token is a member
		// of, so a site reached through a shared resource can name an account
		// this token cannot read. That is not a reason to fail the site.
		if connection.IsForbidden(err) || connection.IsNotFound(err) || errors.Is(err, errAccountNotFound) {
			s.Account.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlNetlifyAccount), nil
}

// deployKey resolves the key the build clones the repository with. A site
// building from a public repository or from manual uploads has none.
//
// The match runs against the deploy keys the root resource has already
// fetched, so a query over many sites does not read one key per site. A key
// registered by another account member is not in that list, so a miss falls
// back to the direct lookup.
func (s *mqlNetlifySite) deployKey() (*mqlNetlifyDeployKey, error) {
	if s.cacheDeployKeyID == "" {
		s.DeployKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	root, err := getNetlify(s.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if key, ok := findCachedResource(root.GetDeployKeys(), netlifyDeployKeyID, s.cacheDeployKeyID); ok {
		return key, nil
	}

	res, err := NewResource(s.MqlRuntime, "netlify.deployKey", map[string]*llx.RawData{
		"id": llx.StringData(s.cacheDeployKeyID),
	})
	if err != nil {
		// A key registered by another account member is not readable with this
		// token, which is not a reason to fail the whole site.
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			s.DeployKey.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlNetlifyDeployKey), nil
}

func (s *mqlNetlifySite) environmentVariables() ([]any, error) {
	if s.cacheAccountID == "" {
		s.EnvironmentVariables = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	query := url.Values{}
	query.Set("site_id", s.Id.Data)

	res, err := fetchEnvVars(s.MqlRuntime, s.cacheAccountID, s.Id.Data, query)
	if err != nil {
		// The variable endpoint is keyed on the account, so a token that can
		// read the site without administering its account cannot read them.
		// Reporting them as null keeps that apart from a site that has none.
		if connection.IsForbidden(err) {
			s.EnvironmentVariables = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

// --- build hooks ----------------------------------------------------------

type buildHookRecord struct {
	ID        string      `json:"id"`
	Title     string      `json:"title"`
	Branch    string      `json:"branch"`
	CreatedAt netlifyTime `json:"created_at"`
}

func (s *mqlNetlifySite) buildHooks() ([]any, error) {
	c := netlifyConn(s.MqlRuntime)

	records, err := connection.GetPaged[buildHookRecord](context.Background(), c,
		"/sites/"+url.PathEscape(s.Id.Data)+"/build_hooks", nil)
	if err != nil {
		if connection.IsForbidden(err) {
			s.BuildHooks = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		// The hook URL is an unauthenticated deploy trigger, so it is left out
		// of the resource rather than carried into scan results.
		hook, err := CreateResource(s.MqlRuntime, "netlify.site.buildHook", map[string]*llx.RawData{
			"id":        llx.StringData(rec.ID),
			"title":     llx.StringData(rec.Title),
			"branch":    llx.StringData(rec.Branch),
			"createdAt": llx.TimeDataPtr(rec.CreatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, hook)
	}
	return res, nil
}

func (h *mqlNetlifySiteBuildHook) id() (string, error) {
	return h.Id.Data, h.Id.Error
}

// --- notification hooks ---------------------------------------------------

type notificationHookRecord struct {
	ID        string      `json:"id"`
	Type      string      `json:"type"`
	Event     string      `json:"event"`
	Disabled  bool        `json:"disabled"`
	CreatedAt netlifyTime `json:"created_at"`
	UpdatedAt netlifyTime `json:"updated_at"`

	// Data is the hook's delivery configuration. It carries the full webhook
	// address, whose path and query are the bearer part of it, and the secret
	// that signs deliveries. It is held as raw JSON so neither ever lands in a
	// field; only the destination host and whether a secret is set are
	// reported, through hookDestination.
	Data json.RawMessage `json:"data"`
}

// hookSecretKeys are the keys a notification hook's delivery settings hold
// signing or bearer material under. The webhook signing secret is the one that
// matters here: a receiver cannot tell a signed delivery from a forged request
// without it.
var hookSecretKeys = []string{"jwt_secret", "signing_secret", "secret", "token", "access_token"}

// hookDestination reports where a notification hook delivers and whether its
// deliveries are signed, from the raw delivery settings the API returned.
//
// Both are null when the API reported no delivery settings at all, because a
// token that cannot read them is indistinguishable from a hook that has none,
// and reporting false would say the deliveries are known to be unsigned.
//
// The host is reported without the path or query string. A webhook address
// carries its authorization in the path for most receivers, so the full URL is
// a credential while the host alone is the destination.
func hookDestination(raw json.RawMessage) (host *string, hasSigningSecret *bool) {
	if len(raw) == 0 {
		return nil, nil
	}

	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		// Settings were reported in a shape we cannot read. Nothing about them
		// is known, so nothing is claimed.
		return nil, nil
	}

	secret := false
	for _, key := range hookSecretKeys {
		if isNonEmptyValue(fields[key]) {
			secret = true
			break
		}
	}

	if raw, ok := fields["url"].(string); ok && raw != "" {
		if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
			h := parsed.Hostname()
			return &h, &secret
		}
	}
	return nil, &secret
}

// isNonEmptyValue reports whether a decoded JSON value carries something. A key
// present with an empty string or an explicit null is the API saying the
// setting is not configured.
func isNonEmptyValue(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case float64:
		return t != 0
	default:
		return true
	}
}

func (s *mqlNetlifySite) notificationHooks() ([]any, error) {
	c := netlifyConn(s.MqlRuntime)

	query := url.Values{}
	query.Set("site_id", s.Id.Data)

	records, err := connection.GetPaged[notificationHookRecord](context.Background(), c, "/hooks", query)
	if err != nil {
		if connection.IsForbidden(err) {
			s.NotificationHooks = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		host, hasSigningSecret := hookDestination(rec.Data)
		hook, err := CreateResource(s.MqlRuntime, "netlify.site.notificationHook", map[string]*llx.RawData{
			"id":               llx.StringData(rec.ID),
			"type":             llx.StringData(rec.Type),
			"event":            llx.StringData(rec.Event),
			"disabled":         llx.BoolData(rec.Disabled),
			"destinationHost":  optionalString(host),
			"hasSigningSecret": optionalBool(hasSigningSecret),
			"createdAt":        llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":        llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, hook)
	}
	return res, nil
}

func (h *mqlNetlifySiteNotificationHook) id() (string, error) {
	return h.Id.Data, h.Id.Error
}

// --- snippets -------------------------------------------------------------

type snippetRecord struct {
	ID              int64  `json:"id"`
	Title           string `json:"title"`
	General         string `json:"general"`
	GeneralPosition string `json:"general_position"`
	Goal            string `json:"goal"`
	GoalPosition    string `json:"goal_position"`
}

func (s *mqlNetlifySite) snippets() ([]any, error) {
	c := netlifyConn(s.MqlRuntime)

	records, err := connection.GetPaged[snippetRecord](context.Background(), c,
		"/sites/"+url.PathEscape(s.Id.Data)+"/snippets", nil)
	if err != nil {
		if connection.IsForbidden(err) {
			s.Snippets = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		snippet, err := CreateResource(s.MqlRuntime, "netlify.site.snippet", map[string]*llx.RawData{
			"id":              llx.StringData(strconv.FormatInt(rec.ID, 10)),
			"title":           llx.StringData(rec.Title),
			"general":         llx.StringData(rec.General),
			"generalPosition": llx.StringData(rec.GeneralPosition),
			"goal":            llx.StringData(rec.Goal),
			"goalPosition":    llx.StringData(rec.GoalPosition),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, snippet)
	}
	return res, nil
}

func (s *mqlNetlifySiteSnippet) id() (string, error) {
	return s.Id.Data, s.Id.Error
}

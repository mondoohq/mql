// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vercel/connection"
	"go.mondoo.com/mql/types"
)

// mqlVercelProjectInternal caches the team a project belongs to so project-scoped
// API calls (environment variables, deployments, firewall) can pass teamId, and
// the Secure Compute attachments returned inline with the project so
// connectConfigurations avoids a second API call.
type mqlVercelProjectInternal struct {
	teamID              string
	cacheConnectConfigs []connectConfigRecord
}

type deploymentTypeHolder struct {
	DeploymentType string `json:"deploymentType"`
}

type passportRecord struct {
	DeploymentType string `json:"deploymentType"`
	ConnectorID    string `json:"connectorId"`
}

type trustedIpsRecord struct {
	DeploymentType string           `json:"deploymentType"`
	ProtectionMode string           `json:"protectionMode"`
	Addresses      []map[string]any `json:"addresses"`
}

type projectLink struct {
	Type             string  `json:"type"`
	Org              string  `json:"org"`
	Repo             string  `json:"repo"`
	ProductionBranch *string `json:"productionBranch"`
}

type cronsRecord struct {
	Definitions []map[string]any `json:"definitions"`
}

type gitProviderOptions struct {
	CreateDeployments               *string `json:"createDeployments"`
	RequireVerifiedCommits          *bool   `json:"requireVerifiedCommits"`
	DisableRepositoryDispatchEvents *bool   `json:"disableRepositoryDispatchEvents"`
}

type gitCommentsRecord struct {
	OnCommit      *bool `json:"onCommit"`
	OnPullRequest *bool `json:"onPullRequest"`
}

type resourceConfigRecord struct {
	FunctionDefaultRegions    []string `json:"functionDefaultRegions"`
	FunctionDefaultTimeout    *int64   `json:"functionDefaultTimeout"`
	FunctionDefaultMemoryType *string  `json:"functionDefaultMemoryType"`
	BuildMachineType          *string  `json:"buildMachineType"`
	BuildMachineSelection     *string  `json:"buildMachineSelection"`
}

type staticIpsRecord struct {
	Enabled *bool    `json:"enabled"`
	Builds  *bool    `json:"builds"`
	Regions []string `json:"regions"`
}

type connectConfigRecord struct {
	ConnectConfigurationID string      `json:"connectConfigurationId"`
	EnvID                  string      `json:"envId"`
	DC                     string      `json:"dc"`
	Passive                *bool       `json:"passive"`
	BuildsEnabled          *bool       `json:"buildsEnabled"`
	AWS                    *connectAWS `json:"aws"`
}

type connectAWS struct {
	SubnetIDs []string `json:"subnetIds"`
}

type projectRecord struct {
	ID                                   string                `json:"id"`
	Name                                 string                `json:"name"`
	Framework                            *string               `json:"framework"`
	NodeVersion                          string                `json:"nodeVersion"`
	RootDirectory                        *string               `json:"rootDirectory"`
	BuildCommand                         *string               `json:"buildCommand"`
	DevCommand                           *string               `json:"devCommand"`
	InstallCommand                       *string               `json:"installCommand"`
	OutputDirectory                      *string               `json:"outputDirectory"`
	CommandForIgnoringBuildStep          *string               `json:"commandForIgnoringBuildStep"`
	PublicSource                         *bool                 `json:"publicSource"`
	AutoExposeSystemEnvs                 *bool                 `json:"autoExposeSystemEnvs"`
	GitForkProtection                    *bool                 `json:"gitForkProtection"`
	GitLFS                               *bool                 `json:"gitLFS"`
	Live                                 *bool                 `json:"live"`
	Paused                               *bool                 `json:"paused"`
	Tier                                 string                `json:"tier"`
	CreatedAt                            flexTime              `json:"createdAt"`
	UpdatedAt                            flexTime              `json:"updatedAt"`
	SsoProtection                        *deploymentTypeHolder `json:"ssoProtection"`
	PasswordProtection                   *deploymentTypeHolder `json:"passwordProtection"`
	Passport                             *passportRecord       `json:"passport"`
	TrustedIps                           *trustedIpsRecord     `json:"trustedIps"`
	TrustedSources                       map[string]any        `json:"trustedSources"`
	OidcTokenConfig                      map[string]any        `json:"oidcTokenConfig"`
	DeploymentPolicy                     map[string]any        `json:"deploymentPolicy"`
	RollingRelease                       map[string]any        `json:"rollingRelease"`
	DeploymentExpiration                 *expirationRecord     `json:"deploymentExpiration"`
	DirectoryListing                     *bool                 `json:"directoryListing"`
	SourceFilesOutsideRootDirectory      *bool                 `json:"sourceFilesOutsideRootDirectory"`
	CustomerSupportCodeVisibility        *bool                 `json:"customerSupportCodeVisibility"`
	ServerlessFunctionZeroConfigFailover *bool                 `json:"serverlessFunctionZeroConfigFailover"`
	AutoAssignCustomDomains              *bool                 `json:"autoAssignCustomDomains"`
	ServerlessFunctionRegion             string                `json:"serverlessFunctionRegion"`
	ResourceConfig                       *resourceConfigRecord `json:"resourceConfig"`
	StaticIps                            *staticIpsRecord      `json:"staticIps"`
	ConnectConfigurations                []connectConfigRecord `json:"connectConfigurations"`
	SkewProtectionBoundaryAt             flexTime              `json:"skewProtectionBoundaryAt"`
	SkewProtectionMaxAge                 *int64                `json:"skewProtectionMaxAge"`
	SkewProtectionAllowedDomains         []string              `json:"skewProtectionAllowedDomains"`
	TransferStartedAt                    flexTime              `json:"transferStartedAt"`
	TransferCompletedAt                  flexTime              `json:"transferCompletedAt"`
	TransferToAccountID                  string                `json:"transferToAccountId"`
	TransferredFromAccountID             string                `json:"transferredFromAccountId"`
	GitProviderOptions                   *gitProviderOptions   `json:"gitProviderOptions"`
	GitComments                          *gitCommentsRecord    `json:"gitComments"`
	Link                                 *projectLink          `json:"link"`
	Crons                                *cronsRecord          `json:"crons"`
	OptionsAllowlist                     *optionsAllowlist     `json:"optionsAllowlist"`
	// Keyed by the bypass secret itself, so the keys are credential material
	// and only the entry values may be surfaced.
	ProtectionBypass map[string]protectionBypassEntry `json:"protectionBypass"`
}

// optionsAllowlist carries the paths a project exempts from deployment
// protection for OPTIONS requests. Vercel wraps each path in an object rather
// than returning a plain string list.
type optionsAllowlist struct {
	Paths []struct {
		Value string `json:"value"`
	} `json:"paths"`
}

// allowlistPaths flattens the wrapped path objects to the bare path strings.
// Entries with an empty value are dropped, so an allowlist that reports paths
// never yields blank ones.
func allowlistPaths(a *optionsAllowlist) []any {
	if a == nil {
		return []any{}
	}
	paths := []any{}
	for _, p := range a.Paths {
		if p.Value != "" {
			paths = append(paths, p.Value)
		}
	}
	return paths
}

func holderType(h *deploymentTypeHolder) *string {
	if h == nil {
		return nil
	}
	return &h.DeploymentType
}

// boolPtrOrFalse dereferences an optional flag, treating an absent value as
// off. Vercel omits most boolean settings when they are at their default.
func boolPtrOrFalse(v *bool) bool {
	return v != nil && *v
}

// dictOrNil passes a decoded JSON object through as a dict value, preserving a
// null when the API omitted the object entirely.
func dictOrNil(m map[string]any) any {
	if m == nil {
		return nil
	}
	return m
}

func newVercelProject(runtime *plugin.Runtime, teamID string, rec *projectRecord) (*mqlVercelProject, error) {
	var trustedMode, trustedType *string
	trustedAddresses := []any{}
	if rec.TrustedIps != nil {
		trustedMode = &rec.TrustedIps.ProtectionMode
		trustedType = &rec.TrustedIps.DeploymentType
		trustedAddresses = dictSliceToAny(rec.TrustedIps.Addresses)
	}

	var repoType, repoOwner, repoName, productionBranch *string
	if rec.Link != nil {
		repoType = &rec.Link.Type
		repoOwner = &rec.Link.Org
		repoName = &rec.Link.Repo
		productionBranch = rec.Link.ProductionBranch
	}

	cronJobs := []any{}
	if rec.Crons != nil {
		cronJobs = dictSliceToAny(rec.Crons.Definitions)
	}

	var passportType, passportConnector *string
	if rec.Passport != nil {
		passportType, passportConnector = &rec.Passport.DeploymentType, &rec.Passport.ConnectorID
	}

	var gitCreateDeployments *string
	var gitRequireVerified, gitDisableDispatch *bool
	if rec.GitProviderOptions != nil {
		gitCreateDeployments = rec.GitProviderOptions.CreateDeployments
		gitRequireVerified = rec.GitProviderOptions.RequireVerifiedCommits
		gitDisableDispatch = rec.GitProviderOptions.DisableRepositoryDispatchEvents
	}

	var gitOnCommit, gitOnPullRequest *bool
	if rec.GitComments != nil {
		gitOnCommit, gitOnPullRequest = rec.GitComments.OnCommit, rec.GitComments.OnPullRequest
	}

	resourceConfig := rec.ResourceConfig
	if resourceConfig == nil {
		resourceConfig = &resourceConfigRecord{}
	}

	staticIps := rec.StaticIps
	if staticIps == nil {
		staticIps = &staticIpsRecord{}
	}

	exp := rec.DeploymentExpiration
	if exp == nil {
		exp = &expirationRecord{}
	}

	res, err := CreateResource(runtime, "vercel.project", map[string]*llx.RawData{
		"id":                               llx.StringData(rec.ID),
		"name":                             llx.StringData(rec.Name),
		"framework":                        llx.StringDataPtr(rec.Framework),
		"nodeVersion":                      llx.StringData(rec.NodeVersion),
		"rootDirectory":                    llx.StringDataPtr(rec.RootDirectory),
		"buildCommand":                     llx.StringDataPtr(rec.BuildCommand),
		"devCommand":                       llx.StringDataPtr(rec.DevCommand),
		"installCommand":                   llx.StringDataPtr(rec.InstallCommand),
		"outputDirectory":                  llx.StringDataPtr(rec.OutputDirectory),
		"publicSource":                     llx.BoolData(rec.PublicSource != nil && *rec.PublicSource),
		"autoExposeSystemEnvs":             llx.BoolData(rec.AutoExposeSystemEnvs != nil && *rec.AutoExposeSystemEnvs),
		"gitForkProtection":                llx.BoolData(rec.GitForkProtection != nil && *rec.GitForkProtection),
		"gitLFS":                           llx.BoolData(rec.GitLFS != nil && *rec.GitLFS),
		"live":                             llx.BoolData(rec.Live != nil && *rec.Live),
		"createdAt":                        llx.TimeDataPtr(rec.CreatedAt.Time()),
		"updatedAt":                        llx.TimeDataPtr(rec.UpdatedAt.Time()),
		"ssoProtectionDeploymentType":      llx.StringDataPtr(holderType(rec.SsoProtection)),
		"passwordProtectionDeploymentType": llx.StringDataPtr(holderType(rec.PasswordProtection)),
		"trustedIpsProtectionMode":         llx.StringDataPtr(trustedMode),
		"trustedIpsDeploymentType":         llx.StringDataPtr(trustedType),
		"trustedIpsAddresses":              llx.ArrayData(trustedAddresses, types.Dict),
		"optionsAllowlistPaths":            llx.ArrayData(allowlistPaths(rec.OptionsAllowlist), types.String),
		"protectionBypassCount":            llx.IntData(int64(len(rec.ProtectionBypass))),
		"protectionBypassScopes":           llx.ArrayData(bypassScopes(rec.ProtectionBypass), types.String),
		"repositoryType":                   llx.StringDataPtr(repoType),
		"repositoryOwner":                  llx.StringDataPtr(repoOwner),
		"repositoryName":                   llx.StringDataPtr(repoName),
		"productionBranch":                 llx.StringDataPtr(productionBranch),
		"cronJobs":                         llx.ArrayData(cronJobs, types.Dict),

		"trustedSources":                       llx.DictData(dictOrNil(rec.TrustedSources)),
		"passportDeploymentType":               llx.StringDataPtr(passportType),
		"passportConnectorId":                  llx.StringDataPtr(passportConnector),
		"oidcTokenConfig":                      llx.DictData(dictOrNil(rec.OidcTokenConfig)),
		"requireVerifiedCommits":               llx.BoolData(boolPtrOrFalse(gitRequireVerified)),
		"gitCreateDeployments":                 llx.StringDataPtr(gitCreateDeployments),
		"disableRepositoryDispatchEvents":      llx.BoolData(boolPtrOrFalse(gitDisableDispatch)),
		"gitCommentsOnCommit":                  llx.BoolData(boolPtrOrFalse(gitOnCommit)),
		"gitCommentsOnPullRequest":             llx.BoolData(boolPtrOrFalse(gitOnPullRequest)),
		"deploymentPolicy":                     llx.DictData(dictOrNil(rec.DeploymentPolicy)),
		"directoryListing":                     llx.BoolData(boolPtrOrFalse(rec.DirectoryListing)),
		"sourceFilesOutsideRootDirectory":      llx.BoolData(boolPtrOrFalse(rec.SourceFilesOutsideRootDirectory)),
		"customerSupportCodeVisibility":        llx.BoolData(boolPtrOrFalse(rec.CustomerSupportCodeVisibility)),
		"paused":                               llx.BoolData(boolPtrOrFalse(rec.Paused)),
		"serverlessFunctionZeroConfigFailover": llx.BoolData(boolPtrOrFalse(rec.ServerlessFunctionZeroConfigFailover)),
		"autoAssignCustomDomains":              llx.BoolData(boolPtrOrFalse(rec.AutoAssignCustomDomains)),
		"commandForIgnoringBuildStep":          llx.StringDataPtr(rec.CommandForIgnoringBuildStep),
		"serverlessFunctionRegion":             llx.StringData(rec.ServerlessFunctionRegion),
		"functionDefaultRegions":               llx.ArrayData(strSliceToAny(resourceConfig.FunctionDefaultRegions), types.String),
		"functionDefaultTimeout":               llx.IntData(intPtrOrZero(resourceConfig.FunctionDefaultTimeout)),
		"functionDefaultMemoryType":            llx.StringDataPtr(resourceConfig.FunctionDefaultMemoryType),
		"buildMachineType":                     llx.StringDataPtr(resourceConfig.BuildMachineType),
		"buildMachineSelection":                llx.StringDataPtr(resourceConfig.BuildMachineSelection),
		"staticIpsEnabled":                     llx.BoolData(boolPtrOrFalse(staticIps.Enabled)),
		"staticIpsForBuilds":                   llx.BoolData(boolPtrOrFalse(staticIps.Builds)),
		"staticIpsRegions":                     llx.ArrayData(strSliceToAny(staticIps.Regions), types.String),
		"expirationDays":                       llx.IntData(intPtrOrZero(exp.ExpirationDays)),
		"expirationDaysProduction":             llx.IntData(intPtrOrZero(exp.ExpirationDaysProduction)),
		"expirationDaysCanceled":               llx.IntData(intPtrOrZero(exp.ExpirationDaysCanceled)),
		"expirationDaysErrored":                llx.IntData(intPtrOrZero(exp.ExpirationDaysErrored)),
		"deploymentsToKeep":                    llx.IntData(intPtrOrZero(exp.DeploymentsToKeep)),
		"skewProtectionBoundaryAt":             llx.TimeDataPtr(rec.SkewProtectionBoundaryAt.Time()),
		"skewProtectionMaxAge":                 llx.IntData(intPtrOrZero(rec.SkewProtectionMaxAge)),
		"skewProtectionAllowedDomains":         llx.ArrayData(strSliceToAny(rec.SkewProtectionAllowedDomains), types.String),
		"rollingRelease":                       llx.DictData(dictOrNil(rec.RollingRelease)),
		"tier":                                 llx.StringData(rec.Tier),
		"transferStartedAt":                    llx.TimeDataPtr(rec.TransferStartedAt.Time()),
		"transferCompletedAt":                  llx.TimeDataPtr(rec.TransferCompletedAt.Time()),
		"transferToAccountId":                  llx.StringData(rec.TransferToAccountID),
		"transferredFromAccountId":             llx.StringData(rec.TransferredFromAccountID),
	})
	if err != nil {
		return nil, err
	}
	project := res.(*mqlVercelProject)
	project.cacheConnectConfigs = rec.ConnectConfigurations
	project.teamID = teamID
	return project, nil
}

func (c *mqlVercelTeam) projects() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	// v10 is the current list endpoint and the only one that returns the
	// project security settings below; it pages with a continuation token
	// passed back as from, not the until cursor the older endpoints use.
	records, err := connection.GetPagedFrom[projectRecord](context.Background(), conn, "/v10/projects", connection.TeamQuery(c.Id.Data), "projects")
	if err != nil {
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		project, err := newVercelProject(c.MqlRuntime, c.Id.Data, &rec)
		if err != nil {
			return nil, err
		}
		res = append(res, project)
	}
	return res, nil
}

// initVercelProject resolves the project a query targets from an explicit id, the
// project a discovered asset is scoped to, or the connection options.
func initVercelProject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.VercelConnection)

	projectID := ""
	if idData, ok := args["id"]; ok {
		if s, ok := idData.Value.(string); ok {
			projectID = s
		}
	}
	if projectID == "" && conn.Asset() != nil {
		for _, pid := range conn.Asset().PlatformIds {
			if p, ok := strings.CutPrefix(pid, connection.PlatformIdVercelProject); ok {
				projectID = p
				break
			}
		}
	}
	if projectID == "" {
		projectID = conn.ProjectID()
	}
	if projectID == "" {
		return nil, nil, errors.New("vercel.project requires a project id")
	}

	teamID := conn.TeamID()
	var rec projectRecord
	if err := conn.Get(context.Background(), "/v9/projects/"+projectID, connection.TeamQuery(teamID), &rec); err != nil {
		return nil, nil, err
	}
	if rec.ID == "" {
		rec.ID = projectID
	}

	project, err := newVercelProject(runtime, teamID, &rec)
	if err != nil {
		return nil, nil, err
	}
	return args, project, nil
}

func (c *mqlVercelProject) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

// connectConfigurations reports the Secure Compute networks the project runs
// in. The attachments arrive inline with the project payload, so this builds
// them from the cached records rather than making another call.
func (c *mqlVercelProject) connectConfigurations() ([]any, error) {
	res := []any{}
	for i := range c.cacheConnectConfigs {
		rec := c.cacheConnectConfigs[i]

		subnetIDs := []any{}
		if rec.AWS != nil {
			subnetIDs = strSliceToAny(rec.AWS.SubnetIDs)
		}

		cfg, err := CreateResource(c.MqlRuntime, "vercel.project.connectConfiguration", map[string]*llx.RawData{
			"__id":                   llx.StringData(c.Id.Data + "/connect/" + rec.ConnectConfigurationID + "/" + rec.EnvID),
			"connectConfigurationId": llx.StringData(rec.ConnectConfigurationID),
			"envId":                  llx.StringData(rec.EnvID),
			"dc":                     llx.StringData(rec.DC),
			"passive":                llx.BoolData(boolPtrOrFalse(rec.Passive)),
			"buildsEnabled":          llx.BoolData(boolPtrOrFalse(rec.BuildsEnabled)),
			"awsSubnetIds":           llx.ArrayData(subnetIDs, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, cfg)
	}
	return res, nil
}

// resolveProjectRefs resolves a list of project ids into typed vercel.project
// references. Ids that no longer resolve (project deleted, or not visible to the
// token) are skipped rather than failing the whole list; other errors propagate.
//
// This makes one project-by-id call per id (N+1); the Vercel API has no
// filter-by-id-list endpoint, and webhooks / integrations are typically scoped
// to a handful of projects, so the simple per-id resolve matches the existing
// store.connectedProjects pattern.
func resolveProjectRefs(runtime *plugin.Runtime, teamID string, projectIDs []string) ([]any, error) {
	conn := runtime.Connection.(*connection.VercelConnection)

	out := []any{}
	for _, projectID := range projectIDs {
		if projectID == "" {
			continue
		}
		var rec projectRecord
		if err := conn.Get(context.Background(), "/v9/projects/"+projectID, connection.TeamQuery(teamID), &rec); err != nil {
			if connection.IsForbidden(err) || connection.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		if rec.ID == "" {
			rec.ID = projectID
		}
		project, err := newVercelProject(runtime, teamID, &rec)
		if err != nil {
			return nil, err
		}
		out = append(out, project)
	}
	return out, nil
}

// --- environment variables ------------------------------------------------

// envRecord is one project environment variable. The value fields the endpoint
// can carry are deliberately not declared: the request never asks for a
// decrypted value, and nothing here reads one. Only the metadata that describes
// how the value is stored and where it reaches is decoded.
//
// decrypted, system and visibility are pointers because a variable predating
// the field is returned without it, and reporting a false there would claim the
// value is hidden, or that it is not supplied by the platform, on a variable
// Vercel said nothing about.
type envRecord struct {
	ID                   string          `json:"id"`
	Key                  string          `json:"key"`
	Type                 string          `json:"type"`
	Target               json.RawMessage `json:"target"`
	GitBranch            *string         `json:"gitBranch"`
	Decrypted            *bool           `json:"decrypted"`
	Visibility           *string         `json:"visibility"`
	System               *bool           `json:"system"`
	Comment              *string         `json:"comment"`
	CustomEnvironmentIDs []string        `json:"customEnvironmentIds"`
	ContentHint          map[string]any  `json:"contentHint"`
	CreatedAt            flexTime        `json:"createdAt"`
	UpdatedAt            flexTime        `json:"updatedAt"`
}

// parseTargets normalizes the env target, which Vercel returns as either a
// string array or a single string.
func parseTargets(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" || len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] == '[' {
		var arr []string
		if json.Unmarshal(raw, &arr) == nil {
			return arr
		}
		return nil
	}
	var single string
	if json.Unmarshal(raw, &single) == nil && single != "" {
		return []string{single}
	}
	return nil
}

func (c *mqlVercelProject) environmentVariables() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	// The v10 list is the current revision and the only one carrying the
	// sensitivity metadata below; v9 answers without decrypted, visibility,
	// system, comment, customEnvironmentIds or contentHint. The decrypt query
	// parameter is deliberately never set, so no value is ever requested.
	records, err := connection.GetPaged[envRecord](context.Background(), conn, "/v10/projects/"+c.Id.Data+"/env", connection.TeamQuery(c.teamID), "envs")
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			c.EnvironmentVariables.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		var contentHint *llx.RawData
		if rec.ContentHint == nil {
			contentHint = llx.NilData
		} else {
			contentHint = llx.DictData(rec.ContentHint)
		}

		env, err := CreateResource(c.MqlRuntime, "vercel.project.environmentVariable", map[string]*llx.RawData{
			"id":                   llx.StringData(rec.ID),
			"key":                  llx.StringData(rec.Key),
			"type":                 llx.StringData(rec.Type),
			"target":               llx.ArrayData(strSliceToAny(parseTargets(rec.Target)), types.String),
			"gitBranch":            llx.StringDataPtr(rec.GitBranch),
			"decrypted":            llx.BoolDataPtr(rec.Decrypted),
			"visibility":           llx.StringDataPtr(rec.Visibility),
			"system":               llx.BoolDataPtr(rec.System),
			"comment":              llx.StringDataPtr(rec.Comment),
			"customEnvironmentIds": llx.ArrayData(strSliceToAny(rec.CustomEnvironmentIDs), types.String),
			"contentHint":          contentHint,
			"createdAt":            llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":            llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, env)
	}
	return res, nil
}

func (c *mqlVercelProjectEnvironmentVariable) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

// --- deployments ----------------------------------------------------------

type deploymentCreator struct {
	UID      string `json:"uid"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

// mqlVercelDeploymentInternal caches the team and project a deployment belongs
// to so project() can resolve without re-listing deployments.
type mqlVercelDeploymentInternal struct {
	teamID    string
	projectID string
}

type deploymentRecord struct {
	// The list endpoint keys deployments by uid, the detail endpoint by id.
	ID           string             `json:"id"`
	UID          string             `json:"uid"`
	ProjectID    string             `json:"projectId"`
	Name         string             `json:"name"`
	URL          string             `json:"url"`
	State        string             `json:"state"`
	ReadyState   string             `json:"readyState"`
	Target       *string            `json:"target"`
	Source       string             `json:"source"`
	Type         string             `json:"type"`
	Creator      *deploymentCreator `json:"creator"`
	InspectorURL string             `json:"inspectorUrl"`
	Created      flexTime           `json:"created"`
	CreatedAt    flexTime           `json:"createdAt"`
	// Both check fields are pointers: a deployment created before Vercel
	// recorded them, or one no check applies to, arrives without them, and
	// reporting a conclusion nobody set would claim the checks passed.
	ChecksState      *string `json:"checksState"`
	ChecksConclusion *string `json:"checksConclusion"`
}

func (c *mqlVercelProject) deployments() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	query := connection.TeamQuery(c.teamID)
	query.Set("projectId", c.Id.Data)
	// v7 is the current revision of the deployment list; v6 is no longer in
	// the API reference and does not report the check fields below.
	records, err := connection.GetPaged[deploymentRecord](context.Background(), conn, "/v7/deployments", query, "deployments")
	if err != nil {
		return nil, err
	}

	var res []any
	for i := range records {
		deployment, err := newVercelDeployment(c.MqlRuntime, c.teamID, c.Id.Data, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, deployment)
	}
	return res, nil
}

// newVercelDeployment maps a deployment record onto the resource. projectID is
// the project the deployment was reached through, used only when the record
// itself does not carry one.
func newVercelDeployment(runtime *plugin.Runtime, teamID, projectID string, rec *deploymentRecord) (*mqlVercelDeployment, error) {
	id := rec.UID
	if id == "" {
		id = rec.ID
	}
	state := rec.State
	if state == "" {
		state = rec.ReadyState
	}
	created := rec.Created.Time()
	if created == nil {
		created = rec.CreatedAt.Time()
	}
	var creatorUID, creatorUsername, creatorEmail string
	if rec.Creator != nil {
		creatorUID = rec.Creator.UID
		creatorUsername = rec.Creator.Username
		creatorEmail = rec.Creator.Email
	}

	res, err := CreateResource(runtime, "vercel.deployment", map[string]*llx.RawData{
		"id":               llx.StringData(id),
		"name":             llx.StringData(rec.Name),
		"url":              llx.StringData(rec.URL),
		"state":            llx.StringData(state),
		"target":           llx.StringDataPtr(rec.Target),
		"source":           llx.StringData(rec.Source),
		"deploymentType":   llx.StringData(rec.Type),
		"creatorUid":       llx.StringData(creatorUID),
		"creatorUsername":  llx.StringData(creatorUsername),
		"creatorEmail":     llx.StringData(creatorEmail),
		"inspectorUrl":     llx.StringData(rec.InspectorURL),
		"checksState":      llx.StringDataPtr(rec.ChecksState),
		"checksConclusion": llx.StringDataPtr(rec.ChecksConclusion),
		"createdAt":        llx.TimeDataPtr(created),
	})
	if err != nil {
		return nil, err
	}

	deployment := res.(*mqlVercelDeployment)
	deployment.teamID = teamID
	deployment.projectID = projectID
	if rec.ProjectID != "" {
		deployment.projectID = rec.ProjectID
	}
	return deployment, nil
}

func initVercelDeployment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	deploymentID := ""
	if idData, ok := args["id"]; ok {
		if s, ok := idData.Value.(string); ok {
			deploymentID = s
		}
	}
	if deploymentID == "" {
		return nil, nil, errors.New("vercel.deployment requires a deployment id")
	}

	conn := runtime.Connection.(*connection.VercelConnection)
	teamID := conn.TeamID()

	var rec deploymentRecord
	if err := conn.Get(context.Background(), "/v13/deployments/"+deploymentID, connection.TeamQuery(teamID), &rec); err != nil {
		return nil, nil, err
	}
	if rec.UID == "" && rec.ID == "" {
		rec.ID = deploymentID
	}

	deployment, err := newVercelDeployment(runtime, teamID, "", &rec)
	if err != nil {
		return nil, nil, err
	}
	return args, deployment, nil
}

func (c *mqlVercelDeployment) project() (*mqlVercelProject, error) {
	if c.projectID == "" {
		c.Project.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(c.MqlRuntime, "vercel.project", map[string]*llx.RawData{
		"id": llx.StringData(c.projectID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVercelProject), nil
}

func (c *mqlVercelDeployment) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

// --- project domains ------------------------------------------------------

// mqlVercelProjectDomainInternal caches the team a project domain belongs to and
// its apex name, so apexDomain can resolve the typed team-domain reference.
type mqlVercelProjectDomainInternal struct {
	teamID   string
	apexName string
}

type projectDomainRecord struct {
	Name               string   `json:"name"`
	ApexName           string   `json:"apexName"`
	Redirect           *string  `json:"redirect"`
	RedirectStatusCode *int64   `json:"redirectStatusCode"`
	GitBranch          *string  `json:"gitBranch"`
	Verified           bool     `json:"verified"`
	CreatedAt          flexTime `json:"createdAt"`
	UpdatedAt          flexTime `json:"updatedAt"`
}

func (c *mqlVercelProject) domains() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	records, err := connection.GetPaged[projectDomainRecord](context.Background(), conn, "/v9/projects/"+c.Id.Data+"/domains", connection.TeamQuery(c.teamID), "domains")
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
		domain, err := CreateResource(c.MqlRuntime, "vercel.project.domain", map[string]*llx.RawData{
			"__id":               llx.StringData(c.Id.Data + "/" + rec.Name),
			"name":               llx.StringData(rec.Name),
			"apexName":           llx.StringData(rec.ApexName),
			"redirect":           llx.StringDataPtr(rec.Redirect),
			"redirectStatusCode": llx.IntDataPtr(rec.RedirectStatusCode),
			"gitBranch":          llx.StringDataPtr(rec.GitBranch),
			"verified":           llx.BoolData(rec.Verified),
			"createdAt":          llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":          llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		mqlDomain := domain.(*mqlVercelProjectDomain)
		mqlDomain.teamID = c.teamID
		mqlDomain.apexName = rec.ApexName
		res = append(res, mqlDomain)
	}
	return res, nil
}

// apexDomain resolves the apex to the Vercel-managed team domain. Not every apex
// is Vercel-managed (external or delegated domains exist), so the accessor
// degrades to null when the domain is not found or not accessible.
func (c *mqlVercelProjectDomain) apexDomain() (*mqlVercelDomain, error) {
	if c.apexName == "" {
		c.ApexDomain.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := c.MqlRuntime.Connection.(*connection.VercelConnection)
	var wrapper struct {
		Domain domainRecord `json:"domain"`
	}
	if err := conn.Get(context.Background(), "/v5/domains/"+c.apexName, connection.TeamQuery(c.teamID), &wrapper); err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			c.ApexDomain.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	rec := wrapper.Domain
	if rec.Name == "" {
		rec.Name = c.apexName
	}
	return newVercelDomain(c.MqlRuntime, c.teamID, &rec)
}

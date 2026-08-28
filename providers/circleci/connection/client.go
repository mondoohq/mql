// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/cockroachdb/errors"
)

// DefaultBaseURL is the CircleCI API v2 base URL.
const DefaultBaseURL = "https://circleci.com/api/v2"

// DefaultRunnerBaseURL is the CircleCI self-hosted runner API base URL. The
// runner API is served from a separate host (runner.circleci.com) and is
// versioned independently of the main API v2. It uses the same Circle-Token
// header for authentication.
const DefaultRunnerBaseURL = "https://runner.circleci.com/api/v3"

// Client is a minimal, hand-written net/http client for the CircleCI API v2
// read endpoints this provider's schema needs. ADR-035's production intent
// is a client generated from CircleCI's published OpenAPI 3.0 spec; see
// providers/circleci/README.md for that note. This client covers only the
// GET endpoints backing circleci.lr, all under the Circle-Token header.
type Client struct {
	httpClient    *http.Client
	baseURL       string
	runnerBaseURL string
	token         string
}

// NewClient creates a CircleCI API v2 client authenticated with token.
func NewClient(token string) *Client {
	return &Client{
		httpClient:    &http.Client{Timeout: 30 * time.Second},
		baseURL:       DefaultBaseURL,
		runnerBaseURL: DefaultRunnerBaseURL,
		token:         token,
	}
}

// APIError represents a non-2xx response from the CircleCI API.
type APIError struct {
	StatusCode int
	Path       string
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("circleci api request to %s failed with status %d: %s", e.Path, e.StatusCode, e.Body)
}

// IsAccessDenied reports whether err represents a 401/403 response from the
// CircleCI API, mirroring the codebase's Is400AccessDeniedError convention.
func IsAccessDenied(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden
	}
	return false
}

func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	return c.getFrom(ctx, c.baseURL, path, query, out)
}

func (c *Client) getFrom(ctx context.Context, baseURL, path string, query url.Values, out any) error {
	reqURL := baseURL + path
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return errors.Wrap(err, "failed to build circleci request")
	}
	req.Header.Set("Circle-Token", c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to call circleci api")
	}
	defer resp.Body.Close()

	// cap the response body at 10 MB to guard against an unexpectedly large
	// response exhausting memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return errors.Wrap(err, "failed to read circleci response")
	}

	if resp.StatusCode >= 300 {
		return &APIError{StatusCode: resp.StatusCode, Path: path, Body: string(body)}
	}

	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return errors.Wrap(err, "failed to decode circleci response")
	}
	return nil
}

// User is the currently authenticated CircleCI account, GET /me.
type User struct {
	ID    string `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
}

// GetMe returns the currently authenticated user.
func (c *Client) GetMe(ctx context.Context) (*User, error) {
	var u User
	if err := c.get(ctx, "/me", nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// Collaboration is a single organization the current token can see,
// GET /me/collaborations.
type Collaboration struct {
	ID      string `json:"id"`
	VcsType string `json:"vcs_type"`
	Name    string `json:"name"`
}

// GetCollaborations returns every organization the current token can see.
// This endpoint is not paginated: the API returns the full array directly.
func (c *Client) GetCollaborations(ctx context.Context) ([]Collaboration, error) {
	var out []Collaboration
	if err := c.get(ctx, "/me/collaborations", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// VCSInfo is a project's version control linkage.
type VCSInfo struct {
	VcsURL        string `json:"vcs_url"`
	Provider      string `json:"provider"`
	DefaultBranch string `json:"default_branch"`
}

// AdvancedSettings are the project's advanced settings, returned under the
// "advanced" key of GET /project/{project-slug}/settings. The project detail
// response (GET /project/{project-slug}) does not carry these values.
// Each flag is a pointer so that a key the API omits stays null rather
// than reading as a confident false, which would let a policy pass on a
// setting that was never returned.
type AdvancedSettings struct {
	BuildForkPrs               *bool    `json:"build_fork_prs"`
	ForksReceiveSecretEnvVars  *bool    `json:"forks_receive_secret_env_vars"`
	BuildPrsOnly               *bool    `json:"build_prs_only"`
	WriteSettingsRequiresAdmin *bool    `json:"write_settings_requires_admin"`
	DisableSsh                 *bool    `json:"disable_ssh"`
	SetGithubStatus            *bool    `json:"set_github_status"`
	AutocancelBuilds           *bool    `json:"autocancel_builds"`
	PrOnlyBranchOverrides      []string `json:"pr_only_branch_overrides"`
}

// ProjectSettings is the response from GET /project/{project-slug}/settings,
// which wraps the advanced settings under an "advanced" key.
type ProjectSettings struct {
	Advanced AdvancedSettings `json:"advanced"`
}

// Project is a single CircleCI project, GET /project/{project-slug}.
type Project struct {
	ID               string  `json:"id"`
	Slug             string  `json:"slug"`
	Name             string  `json:"name"`
	OrganizationName string  `json:"organization_name"`
	OrganizationSlug string  `json:"organization_slug"`
	OrganizationID   string  `json:"organization_id"`
	VCSInfo          VCSInfo `json:"vcs_info"`
}

// GetProject fetches a single project by its slug (e.g. "gh/org/repo").
func (c *Client) GetProject(ctx context.Context, projectSlug string) (*Project, error) {
	var p Project
	// The slug already carries its own "/"-separated segments; it is placed
	// directly in the path rather than escaped as a single path element.
	if err := c.get(ctx, "/project/"+projectSlug, nil, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// GetProjectSettings fetches a project's advanced settings by its slug
// (e.g. "gh/org/repo") from GET /project/{project-slug}/settings and returns
// the unwrapped "advanced" block.
func (c *Client) GetProjectSettings(ctx context.Context, projectSlug string) (*AdvancedSettings, error) {
	var s ProjectSettings
	// The slug already carries its own "/"-separated segments; it is placed
	// directly in the path rather than escaped as a single path element.
	if err := c.get(ctx, "/project/"+projectSlug+"/settings", nil, &s); err != nil {
		return nil, err
	}
	return &s.Advanced, nil
}

// Pipeline is a single pipeline entry, used only to discover distinct
// project slugs owned by an organization (see ListPipelines).
type Pipeline struct {
	ID          string `json:"id"`
	ProjectSlug string `json:"project_slug"`
}

// PipelineListResponse is the paginated response from GET /pipeline.
type PipelineListResponse struct {
	Items         []Pipeline `json:"items"`
	NextPageToken string     `json:"next_page_token"`
}

// ListPipelines returns one page of pipelines for the given org slug
// (e.g. "gh/org"). CircleCI API v2 has no bulk list-projects endpoint;
// pipelines are the only org-scoped listing that carries project_slug, so
// project discovery for an organization walks this endpoint and
// deduplicates by slug. Pass an empty pageToken for the first page.
func (c *Client) ListPipelines(ctx context.Context, orgSlug, pageToken string) (*PipelineListResponse, error) {
	q := url.Values{}
	q.Set("org-slug", orgSlug)
	if pageToken != "" {
		q.Set("page-token", pageToken)
	}
	var out PipelineListResponse
	if err := c.get(ctx, "/pipeline", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Context is a single named group of environment variables,
// GET /context.
type Context struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

// ContextListResponse is the paginated response from GET /context.
type ContextListResponse struct {
	Items         []Context `json:"items"`
	NextPageToken string    `json:"next_page_token"`
}

// ListContexts returns one page of contexts owned by the organization
// identified by ownerId. Pass an empty pageToken for the first page.
func (c *Client) ListContexts(ctx context.Context, ownerId, pageToken string) (*ContextListResponse, error) {
	q := url.Values{}
	q.Set("owner-id", ownerId)
	q.Set("owner-type", "organization")
	if pageToken != "" {
		q.Set("page-token", pageToken)
	}
	var out ContextListResponse
	if err := c.get(ctx, "/context", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ContextEnvVar is a single environment variable name configured in a
// context. CircleCI never returns a value for context environment
// variables, not even masked.
type ContextEnvVar struct {
	Variable  string `json:"variable"`
	ContextID string `json:"context_id"`
	CreatedAt string `json:"created_at"`
}

// ContextEnvVarListResponse is the paginated response from
// GET /context/{context-id}/environment-variable.
type ContextEnvVarListResponse struct {
	Items         []ContextEnvVar `json:"items"`
	NextPageToken string          `json:"next_page_token"`
}

// ListContextEnvVars returns one page of environment variable names
// configured in the given context. Pass an empty pageToken for the first
// page.
func (c *Client) ListContextEnvVars(ctx context.Context, contextId, pageToken string) (*ContextEnvVarListResponse, error) {
	q := url.Values{}
	if pageToken != "" {
		q.Set("page-token", pageToken)
	}
	var out ContextEnvVarListResponse
	if err := c.get(ctx, "/context/"+contextId+"/environment-variable", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ProjectEnvVar is a single environment variable set directly on a
// project. Only the name is decoded: the API also returns a truncated
// suffix of the value, which is real secret material and is deliberately
// not read.
type ProjectEnvVar struct {
	Name string `json:"name"`
}

// ProjectEnvVarListResponse is the paginated response from
// GET /project/{project-slug}/envvar.
type ProjectEnvVarListResponse struct {
	Items         []ProjectEnvVar `json:"items"`
	NextPageToken string          `json:"next_page_token"`
}

// ListProjectEnvVars returns one page of environment variables set
// directly on the given project. Pass an empty pageToken for the first
// page.
func (c *Client) ListProjectEnvVars(ctx context.Context, projectSlug, pageToken string) (*ProjectEnvVarListResponse, error) {
	q := url.Values{}
	if pageToken != "" {
		q.Set("page-token", pageToken)
	}
	var out ProjectEnvVarListResponse
	if err := c.get(ctx, "/project/"+projectSlug+"/envvar", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CheckoutKey is a deploy credential CircleCI uses to check out a
// project's source, GET /project/{project-slug}/checkout-key.
type CheckoutKey struct {
	PublicKey   string `json:"public-key"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Preferred   *bool  `json:"preferred"`
	CreatedAt   string `json:"created-at"`
}

// CheckoutKeyListResponse is the paginated response from
// GET /project/{project-slug}/checkout-key.
type CheckoutKeyListResponse struct {
	Items         []CheckoutKey `json:"items"`
	NextPageToken string        `json:"next_page_token"`
}

// ListCheckoutKeys returns one page of checkout keys for the given
// project. Pass an empty pageToken for the first page.
func (c *Client) ListCheckoutKeys(ctx context.Context, projectSlug, pageToken string) (*CheckoutKeyListResponse, error) {
	q := url.Values{}
	if pageToken != "" {
		q.Set("page-token", pageToken)
	}
	var out CheckoutKeyListResponse
	if err := c.get(ctx, "/project/"+projectSlug+"/checkout-key", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ContextRestriction is a single restriction scoping which projects or
// groups may use a context, GET /context/{context-id}/restrictions.
type ContextRestriction struct {
	ID               string `json:"id"`
	ContextID        string `json:"context_id"`
	Name             string `json:"name"`
	RestrictionType  string `json:"restriction_type"`
	RestrictionValue string `json:"restriction_value"`
}

// ContextRestrictionListResponse is the paginated response from
// GET /context/{context-id}/restrictions.
type ContextRestrictionListResponse struct {
	Items         []ContextRestriction `json:"items"`
	NextPageToken string               `json:"next_page_token"`
}

// ListContextRestrictions returns one page of restrictions configured on
// the given context. Pass an empty pageToken for the first page. A context
// with no restrictions is usable by every project in the organization.
func (c *Client) ListContextRestrictions(ctx context.Context, contextId, pageToken string) (*ContextRestrictionListResponse, error) {
	q := url.Values{}
	if pageToken != "" {
		q.Set("page-token", pageToken)
	}
	var out ContextRestrictionListResponse
	if err := c.get(ctx, "/context/"+contextId+"/restrictions", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// WebhookScope is the scope a webhook is attached to (e.g. a project).
type WebhookScope struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// Webhook is a single outbound webhook, GET /webhook. CircleCI never
// returns the configured signing secret; SigningSecret is empty when no
// secret is set and a masked placeholder otherwise.
type Webhook struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	URL           string       `json:"url"`
	VerifyTLS     *bool        `json:"verify-tls"`
	SigningSecret string       `json:"signing-secret"`
	Events        []string     `json:"events"`
	Scope         WebhookScope `json:"scope"`
}

// WebhookListResponse is the paginated response from GET /webhook.
type WebhookListResponse struct {
	Items         []Webhook `json:"items"`
	NextPageToken string    `json:"next_page_token"`
}

// ListWebhooks returns one page of outbound webhooks configured on the
// scope identified by scopeId (a project's UUID) with scopeType "project".
// Pass an empty pageToken for the first page.
func (c *Client) ListWebhooks(ctx context.Context, scopeId, scopeType, pageToken string) (*WebhookListResponse, error) {
	q := url.Values{}
	q.Set("scope-id", scopeId)
	q.Set("scope-type", scopeType)
	if pageToken != "" {
		q.Set("page-token", pageToken)
	}
	var out WebhookListResponse
	if err := c.get(ctx, "/webhook", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RunnerResourceClass is a single self-hosted runner resource class,
// GET /runner/resource on the runner API.
type RunnerResourceClass struct {
	ID            string `json:"id"`
	ResourceClass string `json:"resource_class"`
	Description   string `json:"description"`
}

// RunnerResourceClassListResponse wraps the runner resource-class list. The
// runner API returns the full set in one response (no pagination token).
type RunnerResourceClassListResponse struct {
	Items []RunnerResourceClass `json:"items"`
}

// ListRunnerResourceClasses returns the self-hosted runner resource classes
// registered under the given namespace (an organization's name).
func (c *Client) ListRunnerResourceClasses(ctx context.Context, namespace string) (*RunnerResourceClassListResponse, error) {
	q := url.Values{}
	q.Set("namespace", namespace)
	var out RunnerResourceClassListResponse
	if err := c.getFrom(ctx, c.runnerBaseURL, "/runner/resource", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RunnerToken is a single resource-class token, GET /runner/token on the
// runner API. The secret token value is only shown once at creation and is
// never returned by this endpoint.
type RunnerToken struct {
	ID            string `json:"id"`
	ResourceClass string `json:"resource_class"`
	Nickname      string `json:"nickname"`
	CreatedAt     string `json:"created_at"`
}

// RunnerTokenListResponse wraps the runner token list. The runner API
// returns the full set in one response (no pagination token).
type RunnerTokenListResponse struct {
	Items []RunnerToken `json:"items"`
}

// ListRunnerTokens returns the resource-class tokens for the given fully
// qualified resource class name ("<namespace>/<class>").
func (c *Client) ListRunnerTokens(ctx context.Context, resourceClass string) (*RunnerTokenListResponse, error) {
	q := url.Values{}
	q.Set("resource-class", resourceClass)
	var out RunnerTokenListResponse
	if err := c.getFrom(ctx, c.runnerBaseURL, "/runner/token", q, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VcsSlugPrefix maps a collaboration's vcs_type (as returned by
// GET /me/collaborations, e.g. "github", "bitbucket", "circleci") to the
// abbreviation CircleCI uses as the first segment of a project/org slug
// ("gh", "bb", "circleci").
func VcsSlugPrefix(vcsType string) string {
	switch vcsType {
	case "github":
		return "gh"
	case "bitbucket":
		return "bb"
	default:
		return vcsType
	}
}

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

// Client is a minimal, hand-written net/http client for the CircleCI API v2
// read endpoints this provider's schema needs. ADR-035's production intent
// is a client generated from CircleCI's published OpenAPI 3.0 spec; see
// providers/circleci/README.md for that note. This client covers only the
// GET endpoints backing circleci.lr, all under the Circle-Token header.
type Client struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

// NewClient creates a CircleCI API v2 client authenticated with token.
func NewClient(token string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    DefaultBaseURL,
		token:      token,
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
	reqURL := c.baseURL + path
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

	body, err := io.ReadAll(resp.Body)
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

// AdvancedSettings are the project settings CircleCI returns inline on the
// project detail response.
type AdvancedSettings struct {
	BuildForkPrs               bool `json:"build_fork_prs"`
	ForksReceiveSecretEnvVars  bool `json:"forks_receive_secret_env_vars"`
	BuildPrsOnly               bool `json:"build_prs_only"`
	WriteSettingsRequiresAdmin bool `json:"write_settings_requires_admin"`
	DisableSsh                 bool `json:"disable_ssh"`
	SetGithubStatus            bool `json:"set_github_status"`
}

// Project is a single CircleCI project, GET /project/{project-slug}.
type Project struct {
	ID               string           `json:"id"`
	Slug             string           `json:"slug"`
	Name             string           `json:"name"`
	OrganizationName string           `json:"organization_name"`
	OrganizationSlug string           `json:"organization_slug"`
	OrganizationID   string           `json:"organization_id"`
	VCSInfo          VCSInfo          `json:"vcs_info"`
	AdvancedSettings AdvancedSettings `json:"advanced_settings"`
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
// project. Value is already truncated by CircleCI to a non-secret suffix
// (e.g. "xxxx1234").
type ProjectEnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
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
	Preferred   bool   `json:"preferred"`
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

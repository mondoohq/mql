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
	"sync"
	"time"

	"github.com/cockroachdb/errors"
)

// bitbucketAPIBaseURL is the Bitbucket Cloud REST API 2.0 base URL.
const bitbucketAPIBaseURL = "https://api.bitbucket.org/2.0"

// bitbucketLegacyAPIBaseURL is Bitbucket's older 1.0 API. The 2.0 API has no
// replacement for listing a group's members, so ListGroupsLegacy is the only
// way to resolve full group membership; see its doc comment.
const bitbucketLegacyAPIBaseURL = "https://api.bitbucket.org/1.0"

// ErrNotFound is returned by single-resource lookups (GetWorkspace,
// GetProject, GetRepository) when the API responds 404.
var ErrNotFound = errors.New("bitbucket: resource not found")

// Client is a minimal, hand-written net/http client for the read endpoints
// of the Bitbucket Cloud REST API 2.0 this provider needs. It is NOT
// generated from Bitbucket's OpenAPI/Swagger spec; see
// providers/bitbucket/README.md for why, and for the production intent (an
// OpenAPI-generated client per ADR-034).
type Client struct {
	httpClient *http.Client

	// legacyGroups memoizes ListGroupsLegacy per workspace so a query that
	// iterates a workspace's groups reading members hits the 1.0 API at most
	// once per workspace per scan, instead of once per group.
	legacyGroupsMu    sync.Mutex
	legacyGroupsCache map[string][]LegacyGroup
}

// NewClient wraps an already-authenticated *http.Client (see
// bitbucketAuthTransport in connection.go) with the Bitbucket API base URLs.
func NewClient(httpClient *http.Client) *Client {
	return &Client{httpClient: httpClient}
}

// page is the pagination envelope every Bitbucket Cloud API 2.0 list
// endpoint wraps its results in: values on this page, and a full "next" URL
// (already carrying the following page number) when more pages remain.
type page[T any] struct {
	Values []T     `json:"values"`
	Next   *string `json:"next"`
}

// get issues an authenticated GET against rawURL (an absolute URL, either
// one this client built or a "next" page URL returned by a previous
// response) and decodes the JSON response body into out.
func (c *Client) get(ctx context.Context, rawURL string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return errors.Wrapf(err, "bitbucket: request to %s failed", rawURL)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrapf(err, "bitbucket: failed to read response body for %s", rawURL)
	}

	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.Newf("bitbucket: request to %s failed with status %d: %s", rawURL, resp.StatusCode, string(body))
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return errors.Wrapf(err, "bitbucket: failed to decode response for %s", rawURL)
	}
	return nil
}

// listAllPages walks every page of a paginated 2.0 API endpoint, starting at
// firstURL, following the response's "next" URL until it is nil.
func listAllPages[T any](ctx context.Context, c *Client, firstURL string) ([]T, error) {
	var all []T
	next := firstURL
	for next != "" {
		var pg page[T]
		if err := c.get(ctx, next, &pg); err != nil {
			return nil, err
		}
		all = append(all, pg.Values...)
		// Guard against a stuck pagination cursor: if the API returns no
		// "next" URL, or the same URL we just fetched, stop rather than loop
		// forever.
		if pg.Next == nil || *pg.Next == "" || *pg.Next == next {
			break
		}
		next = *pg.Next
	}
	return all, nil
}

// apiURL builds an absolute Bitbucket Cloud API 2.0 URL for path with the
// given query parameters (pagelen is always set to a generous page size so
// small result sets fit in a single page).
func apiURL(path string, query url.Values) string {
	if query == nil {
		query = url.Values{}
	}
	if query.Get("pagelen") == "" {
		query.Set("pagelen", "100")
	}
	return bitbucketAPIBaseURL + path + "?" + query.Encode()
}

// WorkspaceRef is the abbreviated workspace reference embedded in project
// and repository payloads.
type WorkspaceRef struct {
	UUID string `json:"uuid"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// Workspace is a Bitbucket Cloud workspace, GET /2.0/workspaces/{workspace}.
type Workspace struct {
	UUID              string     `json:"uuid"`
	Slug              string     `json:"slug"`
	Name              string     `json:"name"`
	IsPrivate         *bool      `json:"is_private"`
	IsPrivacyEnforced *bool      `json:"is_privacy_enforced"`
	CreatedOn         *time.Time `json:"created_on"`
}

// GetWorkspace reads a single workspace by its slug.
func (c *Client) GetWorkspace(ctx context.Context, slug string) (*Workspace, error) {
	var w Workspace
	if err := c.get(ctx, apiURL("/workspaces/"+url.PathEscape(slug), nil), &w); err != nil {
		return nil, err
	}
	return &w, nil
}

// ListWorkspaces lists every workspace the authenticated identity can access.
func (c *Client) ListWorkspaces(ctx context.Context) ([]Workspace, error) {
	return listAllPages[Workspace](ctx, c, apiURL("/workspaces", nil))
}

// ProjectRef is the abbreviated project reference embedded in repository
// payloads.
type ProjectRef struct {
	UUID string `json:"uuid"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

// Project is a Bitbucket Cloud project,
// GET /2.0/workspaces/{workspace}/projects/{project_key}.
type Project struct {
	UUID        string        `json:"uuid"`
	Key         string        `json:"key"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	IsPrivate   *bool         `json:"is_private"`
	CreatedOn   *time.Time    `json:"created_on"`
	UpdatedOn   *time.Time    `json:"updated_on"`
	Workspace   *WorkspaceRef `json:"workspace"`
}

// GetProject reads a single project by its key within a workspace.
func (c *Client) GetProject(ctx context.Context, workspace, key string) (*Project, error) {
	var p Project
	path := "/workspaces/" + url.PathEscape(workspace) + "/projects/" + url.PathEscape(key)
	if err := c.get(ctx, apiURL(path, nil), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ListProjects lists every project in a workspace.
func (c *Client) ListProjects(ctx context.Context, workspace string) ([]Project, error) {
	path := "/workspaces/" + url.PathEscape(workspace) + "/projects"
	return listAllPages[Project](ctx, c, apiURL(path, nil))
}

// MainBranch identifies a repository's default branch.
type MainBranch struct {
	Name string `json:"name"`
}

// Repository is a Bitbucket Cloud repository,
// GET /2.0/repositories/{workspace}/{repo_slug}.
type Repository struct {
	UUID        string        `json:"uuid"`
	Slug        string        `json:"slug"`
	FullName    string        `json:"full_name"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	IsPrivate   *bool         `json:"is_private"`
	ForkPolicy  string        `json:"fork_policy"`
	Language    string        `json:"language"`
	Size        int64         `json:"size"`
	HasIssues   *bool         `json:"has_issues"`
	HasWiki     *bool         `json:"has_wiki"`
	MainBranch  *MainBranch   `json:"mainbranch"`
	Project     *ProjectRef   `json:"project"`
	Workspace   *WorkspaceRef `json:"workspace"`
	CreatedOn   *time.Time    `json:"created_on"`
	UpdatedOn   *time.Time    `json:"updated_on"`
}

// GetRepository reads a single repository by its slug within a workspace.
func (c *Client) GetRepository(ctx context.Context, workspace, repoSlug string) (*Repository, error) {
	var r Repository
	path := "/repositories/" + url.PathEscape(workspace) + "/" + url.PathEscape(repoSlug)
	if err := c.get(ctx, apiURL(path, nil), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ListRepositories lists every repository in a workspace.
func (c *Client) ListRepositories(ctx context.Context, workspace string) ([]Repository, error) {
	path := "/repositories/" + url.PathEscape(workspace)
	return listAllPages[Repository](ctx, c, apiURL(path, nil))
}

// ListRepositoriesByProject lists every repository in a workspace that
// belongs to the given project key.
func (c *Client) ListRepositoriesByProject(ctx context.Context, workspace, projectKey string) ([]Repository, error) {
	path := "/repositories/" + url.PathEscape(workspace)
	q := url.Values{"q": {fmt.Sprintf(`project.key="%s"`, projectKey)}}
	return listAllPages[Repository](ctx, c, apiURL(path, q))
}

// User is a Bitbucket account (a person or, for default reviewers and
// branch-restriction exemptions, occasionally a team) as embedded in
// member, deploy-key, and branch-restriction payloads.
type User struct {
	UUID        string `json:"uuid"`
	AccountID   string `json:"account_id"`
	Nickname    string `json:"nickname"`
	DisplayName string `json:"display_name"`
	Type        string `json:"type"`
}

// GroupRef is the abbreviated group reference embedded in branch-restriction
// and group-permission payloads.
type GroupRef struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// BranchRestriction is a single branch restriction rule,
// GET /2.0/repositories/{workspace}/{repo_slug}/branch-restrictions.
type BranchRestriction struct {
	ID      int64      `json:"id"`
	Kind    string     `json:"kind"`
	Pattern string     `json:"pattern"`
	Value   *int64     `json:"value"`
	Users   []User     `json:"users"`
	Groups  []GroupRef `json:"groups"`
}

// ListBranchRestrictions lists every branch restriction on a repository.
func (c *Client) ListBranchRestrictions(ctx context.Context, workspace, repoSlug string) ([]BranchRestriction, error) {
	path := "/repositories/" + url.PathEscape(workspace) + "/" + url.PathEscape(repoSlug) + "/branch-restrictions"
	return listAllPages[BranchRestriction](ctx, c, apiURL(path, nil))
}

// DeployKey is a repository deploy key,
// GET /2.0/repositories/{workspace}/{repo_slug}/deploy-keys.
type DeployKey struct {
	ID        int64      `json:"id"`
	Label     string     `json:"label"`
	Key       string     `json:"key"`
	CreatedOn *time.Time `json:"added_on"`
	LastUsed  *time.Time `json:"last_used"`
}

// ListDeployKeys lists every deploy key registered on a repository.
func (c *Client) ListDeployKeys(ctx context.Context, workspace, repoSlug string) ([]DeployKey, error) {
	path := "/repositories/" + url.PathEscape(workspace) + "/" + url.PathEscape(repoSlug) + "/deploy-keys"
	return listAllPages[DeployKey](ctx, c, apiURL(path, nil))
}

// ListDefaultReviewers lists the users configured as default reviewers on a
// repository. The endpoint returns plain user records; Bitbucket does not
// attach a permission level to a default-reviewer assignment.
func (c *Client) ListDefaultReviewers(ctx context.Context, workspace, repoSlug string) ([]User, error) {
	path := "/repositories/" + url.PathEscape(workspace) + "/" + url.PathEscape(repoSlug) + "/default-reviewers"
	return listAllPages[User](ctx, c, apiURL(path, nil))
}

// WorkspacePermission is a single workspace membership record with its
// permission level, GET /2.0/workspaces/{workspace}/permissions.
type WorkspacePermission struct {
	Permission string `json:"permission"`
	User       User   `json:"user"`
}

// ListWorkspaceMembers lists every member of a workspace together with
// their permission level.
func (c *Client) ListWorkspaceMembers(ctx context.Context, workspace string) ([]WorkspacePermission, error) {
	path := "/workspaces/" + url.PathEscape(workspace) + "/permissions"
	return listAllPages[WorkspacePermission](ctx, c, apiURL(path, nil))
}

// GroupPermission is a single group's explicit permission grant on a
// repository or project, as returned by the permissions-config/groups
// endpoints. Bitbucket exposes no equivalent group-permission surface at the
// workspace level.
type GroupPermission struct {
	Permission string   `json:"permission"`
	Group      GroupRef `json:"group"`
}

// LegacyGroup is a workspace group as returned by Bitbucket's older 1.0 API.
type LegacyGroup struct {
	Slug    string `json:"slug"`
	Name    string `json:"name"`
	Members []User `json:"members"`
}

// ListGroupsLegacy lists every group in a workspace with its full member
// list, via Bitbucket's 1.0 API (GET /1.0/groups/{workspace}). The 2.0 API's
// only group endpoint (permissions/groups) reports a group's workspace
// permission but not its membership, and Bitbucket has not republished a 2.0
// equivalent for group membership, so this deprecated endpoint is the only
// way to resolve bitbucket.group.members. Revisit once/if Atlassian ships a
// 2.0 replacement.
func (c *Client) ListGroupsLegacy(ctx context.Context, workspace string) ([]LegacyGroup, error) {
	c.legacyGroupsMu.Lock()
	defer c.legacyGroupsMu.Unlock()

	if groups, ok := c.legacyGroupsCache[workspace]; ok {
		return groups, nil
	}

	var groups []LegacyGroup
	u := bitbucketLegacyAPIBaseURL + "/groups/" + url.PathEscape(workspace)
	if err := c.get(ctx, u, &groups); err != nil {
		return nil, err
	}

	if c.legacyGroupsCache == nil {
		c.legacyGroupsCache = map[string][]LegacyGroup{}
	}
	c.legacyGroupsCache[workspace] = groups
	return groups, nil
}

// Webhook is a Bitbucket Cloud webhook, as returned by
// GET /2.0/repositories/{workspace}/{repo_slug}/hooks and
// GET /2.0/workspaces/{workspace}/hooks. SecretSet reports whether a signing
// secret is configured; the secret itself is write-only and never returned.
type Webhook struct {
	UUID                 string     `json:"uuid"`
	URL                  string     `json:"url"`
	Description          string     `json:"description"`
	Active               *bool      `json:"active"`
	Events               []string   `json:"events"`
	SkipCertVerification *bool      `json:"skip_cert_verification"`
	SecretSet            *bool      `json:"secret_set"`
	CreatedAt            *time.Time `json:"created_at"`
}

// ListRepositoryWebhooks lists every webhook configured on a repository.
func (c *Client) ListRepositoryWebhooks(ctx context.Context, workspace, repoSlug string) ([]Webhook, error) {
	path := "/repositories/" + url.PathEscape(workspace) + "/" + url.PathEscape(repoSlug) + "/hooks"
	return listAllPages[Webhook](ctx, c, apiURL(path, nil))
}

// ListWorkspaceWebhooks lists every webhook configured on a workspace.
func (c *Client) ListWorkspaceWebhooks(ctx context.Context, workspace string) ([]Webhook, error) {
	path := "/workspaces/" + url.PathEscape(workspace) + "/hooks"
	return listAllPages[Webhook](ctx, c, apiURL(path, nil))
}

// PipelineVariable is a Bitbucket Pipelines configuration variable, shared by
// the repository, workspace, and deployment-environment variable endpoints.
// The value is deliberately not decoded: Bitbucket returns it in the clear
// for an unsecured variable, which is exactly where an accidentally
// plaintext credential lives.
type PipelineVariable struct {
	UUID    string `json:"uuid"`
	Key     string `json:"key"`
	Secured *bool  `json:"secured"`
}

// ListRepositoryPipelineVariables lists the Pipelines variables defined for a
// repository, GET /2.0/repositories/{workspace}/{repo_slug}/pipelines_config/variables/.
func (c *Client) ListRepositoryPipelineVariables(ctx context.Context, workspace, repoSlug string) ([]PipelineVariable, error) {
	path := "/repositories/" + url.PathEscape(workspace) + "/" + url.PathEscape(repoSlug) + "/pipelines_config/variables/"
	return listAllPages[PipelineVariable](ctx, c, apiURL(path, nil))
}

// ListWorkspacePipelineVariables lists the Pipelines variables defined for a
// workspace, GET /2.0/workspaces/{workspace}/pipelines-config/variables/ (note
// the endpoint spells the segment with a dash, unlike the repository one).
func (c *Client) ListWorkspacePipelineVariables(ctx context.Context, workspace string) ([]PipelineVariable, error) {
	path := "/workspaces/" + url.PathEscape(workspace) + "/pipelines-config/variables/"
	return listAllPages[PipelineVariable](ctx, c, apiURL(path, nil))
}

// ListDeploymentVariables lists the variables defined for a single deployment
// environment, GET /2.0/repositories/{workspace}/{repo_slug}/deployments_config/environments/{env_uuid}/variables/.
func (c *Client) ListDeploymentVariables(ctx context.Context, workspace, repoSlug, environmentUUID string) ([]PipelineVariable, error) {
	path := "/repositories/" + url.PathEscape(workspace) + "/" + url.PathEscape(repoSlug) +
		"/deployments_config/environments/" + url.PathEscape(environmentUUID) + "/variables/"
	return listAllPages[PipelineVariable](ctx, c, apiURL(path, nil))
}

// EnvironmentType names a deployment environment's tier (Test, Staging,
// Production).
type EnvironmentType struct {
	Name string `json:"name"`
}

// Environment is a Bitbucket deployment environment,
// GET /2.0/repositories/{workspace}/{repo_slug}/environments/.
type Environment struct {
	UUID            string           `json:"uuid"`
	Name            string           `json:"name"`
	EnvironmentType *EnvironmentType `json:"environment_type"`
}

// ListEnvironments lists every deployment environment configured on a
// repository.
func (c *Client) ListEnvironments(ctx context.Context, workspace, repoSlug string) ([]Environment, error) {
	path := "/repositories/" + url.PathEscape(workspace) + "/" + url.PathEscape(repoSlug) + "/environments/"
	return listAllPages[Environment](ctx, c, apiURL(path, nil))
}

// ListRepositoryUserPermissions lists the explicit per-user permission grants
// on a repository,
// GET /2.0/repositories/{workspace}/{repo_slug}/permissions-config/users.
func (c *Client) ListRepositoryUserPermissions(ctx context.Context, workspace, repoSlug string) ([]WorkspacePermission, error) {
	path := "/repositories/" + url.PathEscape(workspace) + "/" + url.PathEscape(repoSlug) + "/permissions-config/users"
	return listAllPages[WorkspacePermission](ctx, c, apiURL(path, nil))
}

// ListRepositoryGroupPermissions lists the explicit per-group permission
// grants on a repository,
// GET /2.0/repositories/{workspace}/{repo_slug}/permissions-config/groups.
func (c *Client) ListRepositoryGroupPermissions(ctx context.Context, workspace, repoSlug string) ([]GroupPermission, error) {
	path := "/repositories/" + url.PathEscape(workspace) + "/" + url.PathEscape(repoSlug) + "/permissions-config/groups"
	return listAllPages[GroupPermission](ctx, c, apiURL(path, nil))
}

// ListProjectUserPermissions lists the explicit per-user permission grants on
// a project,
// GET /2.0/workspaces/{workspace}/projects/{project_key}/permissions-config/users.
func (c *Client) ListProjectUserPermissions(ctx context.Context, workspace, projectKey string) ([]WorkspacePermission, error) {
	path := "/workspaces/" + url.PathEscape(workspace) + "/projects/" + url.PathEscape(projectKey) + "/permissions-config/users"
	return listAllPages[WorkspacePermission](ctx, c, apiURL(path, nil))
}

// ListProjectGroupPermissions lists the explicit per-group permission grants
// on a project,
// GET /2.0/workspaces/{workspace}/projects/{project_key}/permissions-config/groups.
func (c *Client) ListProjectGroupPermissions(ctx context.Context, workspace, projectKey string) ([]GroupPermission, error) {
	path := "/workspaces/" + url.PathEscape(workspace) + "/projects/" + url.PathEscape(projectKey) + "/permissions-config/groups"
	return listAllPages[GroupPermission](ctx, c, apiURL(path, nil))
}

// bitbucketAuthTransport injects either a bearer Access Token or HTTP Basic
// App Password credentials into every request made by Client.
type bitbucketAuthTransport struct {
	base        http.RoundTripper
	token       string // Access Token, sent as "Bearer <token>"
	username    string // App Password username (Basic auth)
	appPassword string // App Password secret (Basic auth)
}

func (t *bitbucketAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	} else {
		req.SetBasicAuth(t.username, t.appPassword)
	}
	return t.base.RoundTrip(req)
}

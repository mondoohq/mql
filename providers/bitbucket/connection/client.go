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
		if pg.Next == nil {
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
//
// EnforceTwoStepVerification, IPAllowlistEnabled, and IPAllowlist are read
// directly from this same payload using field names that are NOT part of
// Bitbucket's public REST API 2.0 documentation as of this writing (Atlassian
// documents no 2FA-enforcement or IP-allowlist field on this endpoint, and
// this pragmatic hand-written client has no way to verify the real shape
// without live-testing against a tenant that has these workspace security
// settings configured). Until verified, expect these three fields to decode
// to their Go zero value (false / empty) on every workspace rather than a
// fabricated result. See providers/bitbucket/README.md.
type Workspace struct {
	UUID                       string     `json:"uuid"`
	Slug                       string     `json:"slug"`
	Name                       string     `json:"name"`
	IsPrivate                  bool       `json:"is_private"`
	CreatedOn                  *time.Time `json:"created_on"`
	EnforceTwoStepVerification bool       `json:"enforce_two_step_verification"`
	IPAllowlistEnabled         bool       `json:"ip_allowlist_enabled"`
	IPAllowlist                []string   `json:"ip_allowlist"`
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
	IsPrivate   bool          `json:"is_private"`
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
	IsPrivate   bool          `json:"is_private"`
	ForkPolicy  string        `json:"fork_policy"`
	Language    string        `json:"language"`
	Size        int64         `json:"size"`
	HasIssues   bool          `json:"has_issues"`
	HasWiki     bool          `json:"has_wiki"`
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
// and workspace-group-permission payloads.
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
	CreatedOn *time.Time `json:"created_on"`
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

// GroupPermission is a single group's default permission on a workspace,
// GET /2.0/workspaces/{workspace}/permissions/groups.
type GroupPermission struct {
	Permission string   `json:"permission"`
	Group      GroupRef `json:"group"`
}

// ListGroupPermissions lists every group defined in a workspace together
// with the default permission it grants.
func (c *Client) ListGroupPermissions(ctx context.Context, workspace string) ([]GroupPermission, error) {
	path := "/workspaces/" + url.PathEscape(workspace) + "/permissions/groups"
	return listAllPages[GroupPermission](ctx, c, apiURL(path, nil))
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
	var groups []LegacyGroup
	u := bitbucketLegacyAPIBaseURL + "/groups/" + url.PathEscape(workspace)
	if err := c.get(ctx, u, &groups); err != nil {
		return nil, err
	}
	return groups, nil
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

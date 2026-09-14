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
	"strings"
	"time"
)

const adminAPIVersion = "2023-06-01"

type AdminClient struct {
	apiKey  string
	baseURL string
	http    *http.Client
}

func NewAdminClient(apiKey, baseURL string) *AdminClient {
	return &AdminClient{
		apiKey:  apiKey,
		baseURL: baseURL,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *AdminClient) get(ctx context.Context, path string) ([]byte, error) {
	return c.doRequest(ctx, http.MethodGet, path, nil)
}

type paginatedResponse[T any] struct {
	Data    []T    `json:"data"`
	HasMore bool   `json:"has_more"`
	LastID  string `json:"last_id"`
}

// withQuery appends one query parameter to a request path. Callers hand in
// paths that already carry parameters, so the separator is chosen from what is
// already there rather than assumed to be "?".
func withQuery(path, key, value string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + key + "=" + url.QueryEscape(value)
}

func paginate[T any](ctx context.Context, c *AdminClient, path string) ([]T, error) {
	const maxPages = 1000
	var all []T
	afterID := ""
	for page := 0; page < maxPages; page++ {
		reqURL := withQuery(path, "limit", "100")
		if afterID != "" {
			reqURL = withQuery(reqURL, "after_id", afterID)
		}
		body, err := c.get(ctx, reqURL)
		if err != nil {
			return nil, err
		}
		var resp paginatedResponse[T]
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parsing %s response: %w", path, err)
		}
		all = append(all, resp.Data...)
		if !resp.HasMore || resp.LastID == "" || len(resp.Data) == 0 {
			break
		}
		afterID = resp.LastID
	}
	return all, nil
}

// Organization info

type AdminOrganization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *AdminClient) GetOrganization(ctx context.Context) (*AdminOrganization, error) {
	body, err := c.get(ctx, "/v1/organizations/me")
	if err != nil {
		return nil, err
	}
	var org AdminOrganization
	if err := json.Unmarshal(body, &org); err != nil {
		return nil, fmt.Errorf("parsing organization response: %w", err)
	}
	return &org, nil
}

// Workspaces

type AdminWorkspace struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	DisplayColor string  `json:"display_color"`
	CreatedAt    string  `json:"created_at"`
	ArchivedAt   *string `json:"archived_at"`
	// ExternalKeyID names the customer-managed encryption key protecting this
	// workspace's data. Null when the workspace uses Anthropic-managed
	// encryption.
	ExternalKeyID *string `json:"external_key_id"`
	// CompartmentID identifies the workspace's encryption compartment, which
	// is the value a KMS key policy scopes a key to.
	CompartmentID string              `json:"compartment_id"`
	Tags          map[string]string   `json:"tags"`
	DataResidency *AdminDataResidency `json:"data_residency"`
}

type AdminDataResidency struct {
	WorkspaceGeo         string              `json:"workspace_geo"`
	DefaultInferenceGeo  string              `json:"default_inference_geo"`
	AllowedInferenceGeos FlexibleStringSlice `json:"allowed_inference_geos"`
}

type FlexibleStringSlice []string

func (f *FlexibleStringSlice) UnmarshalJSON(data []byte) error {
	// A JSON null (e.g. "allowed_inference_geos": null for an unrestricted
	// workspace) must decode to an empty slice, not [""]. json.Unmarshal of
	// null into a string is a no-op that returns no error, so without this
	// guard the string branch below would win and yield a bogus [""].
	if string(data) == "null" {
		*f = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = []string{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(data, &ss); err != nil {
		return err
	}
	*f = ss
	return nil
}

// ListWorkspaces returns every workspace in the organization, archived ones
// included. The endpoint defaults include_archived to false, and an archived
// workspace still holds its member list and its encryption binding, so an
// offboarding review that cannot see it is reviewing an incomplete estate.
func (c *AdminClient) ListWorkspaces(ctx context.Context) ([]AdminWorkspace, error) {
	path := withQuery("/v1/organizations/workspaces", "include_archived", "true")
	return paginate[AdminWorkspace](ctx, c, path)
}

// Users

type AdminUser struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Role    string `json:"role"`
	AddedAt string `json:"added_at"`
}

func (c *AdminClient) ListUsers(ctx context.Context) ([]AdminUser, error) {
	return paginate[AdminUser](ctx, c, "/v1/organizations/users")
}

// Invites

type AdminInvite struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	InvitedAt string `json:"invited_at"`
	ExpiresAt string `json:"expires_at"`
}

func (c *AdminClient) ListInvites(ctx context.Context) ([]AdminInvite, error) {
	return paginate[AdminInvite](ctx, c, "/v1/organizations/invites")
}

func (c *AdminClient) doRequest(ctx context.Context, method string, path string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", adminAPIVersion)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	const maxResponseSize = 10 * 1024 * 1024 // 10 MB
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errMsg := string(respBody)
		if len(errMsg) > 512 {
			errMsg = errMsg[:512] + "..."
		}
		return nil, fmt.Errorf("admin API %s %s returned %d: %s", method, path, resp.StatusCode, errMsg)
	}

	return respBody, nil
}

// Workspace Members

type AdminWorkspaceMember struct {
	UserID        string `json:"user_id"`
	WorkspaceID   string `json:"workspace_id"`
	WorkspaceRole string `json:"workspace_role"`
}

func (c *AdminClient) ListWorkspaceMembers(ctx context.Context, workspaceID string) ([]AdminWorkspaceMember, error) {
	return paginate[AdminWorkspaceMember](ctx, c, "/v1/organizations/workspaces/"+url.PathEscape(workspaceID)+"/members")
}

// Rate Limits

type AdminRateLimit struct {
	GroupType string             `json:"group_type"`
	Models    []string           `json:"models"`
	Limits    []AdminRateLimiter `json:"limits"`
}

type AdminRateLimiter struct {
	Type  string `json:"type"`
	Value int64  `json:"value"`
}

func (r *AdminRateLimit) LimitValue(limitType string) int64 {
	for _, l := range r.Limits {
		if l.Type == limitType {
			return l.Value
		}
	}
	return 0
}

type pageTokenResponse[T any] struct {
	Data     []T     `json:"data"`
	HasMore  bool    `json:"has_more"`
	NextPage *string `json:"next_page"`
}

func paginatePageToken[T any](ctx context.Context, client *AdminClient, basePath string) ([]T, error) {
	const maxPages = 1000
	var all []T
	pageToken := ""
	for i := 0; i < maxPages; i++ {
		reqURL := basePath
		if pageToken != "" {
			reqURL = withQuery(reqURL, "page", pageToken)
		}
		body, err := client.get(ctx, reqURL)
		if err != nil {
			return nil, err
		}
		var resp pageTokenResponse[T]
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parsing %s response: %w", basePath, err)
		}
		all = append(all, resp.Data...)
		if resp.NextPage == nil || *resp.NextPage == "" || len(resp.Data) == 0 {
			break
		}
		pageToken = *resp.NextPage
	}
	return all, nil
}

func (c *AdminClient) ListRateLimits(ctx context.Context) ([]AdminRateLimit, error) {
	return paginatePageToken[AdminRateLimit](ctx, c, "/v1/organizations/rate_limits")
}

func (c *AdminClient) ListWorkspaceRateLimits(ctx context.Context, workspaceID string) ([]AdminRateLimit, error) {
	return paginatePageToken[AdminRateLimit](ctx, c, "/v1/organizations/workspaces/"+url.PathEscape(workspaceID)+"/rate_limits")
}

// Usage Report

type AdminUsageBucket struct {
	StartingAt string             `json:"starting_at"`
	EndingAt   string             `json:"ending_at"`
	Results    []AdminUsageResult `json:"results"`
}

type AdminUsageResult struct {
	UncachedInputTokens  int64  `json:"uncached_input_tokens"`
	CacheReadInputTokens int64  `json:"cache_read_input_tokens"`
	OutputTokens         int64  `json:"output_tokens"`
	Model                string `json:"model"`
	WorkspaceID          string `json:"workspace_id"`
	ServiceTier          string `json:"service_tier"`
}

func (c *AdminClient) ListUsageReport(ctx context.Context) ([]AdminUsageBucket, error) {
	startingAt := time.Now().UTC().AddDate(0, 0, -7).Format("2006-01-02T00:00:00Z")
	return paginatePageToken[AdminUsageBucket](ctx, c, "/v1/organizations/usage_report/messages?bucket_width=1d&starting_at="+startingAt+"&group_by[]=workspace_id&group_by[]=model")
}

// Cost Report

type AdminCostBucket struct {
	StartingAt string            `json:"starting_at"`
	EndingAt   string            `json:"ending_at"`
	Results    []AdminCostResult `json:"results"`
}

type AdminCostResult struct {
	Amount      string `json:"amount"`
	Currency    string `json:"currency"`
	CostType    string `json:"cost_type"`
	Model       string `json:"model"`
	WorkspaceID string `json:"workspace_id"`
}

func (c *AdminClient) ListCostReport(ctx context.Context) ([]AdminCostBucket, error) {
	startingAt := time.Now().UTC().AddDate(0, 0, -7).Format("2006-01-02T00:00:00Z")
	return paginatePageToken[AdminCostBucket](ctx, c, "/v1/organizations/cost_report?bucket_width=1d&starting_at="+startingAt+"&group_by[]=workspace_id")
}

// Compliance Activities

type AdminActivity struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Actor     AdminActorInfo `json:"actor"`
	CreatedAt string         `json:"created_at"`
}

// AdminActorInfo is the decoded form of the activity feed's actor union. The
// union is discriminated by Type, and each variant carries a different subset
// of these values, so a field left empty means the variant does not define it.
// New variants are expected: an unrecognized Type still decodes, carrying
// whatever of the shared values it happens to include.
type AdminActorInfo struct {
	// Type is the union discriminator, one of user_actor, api_actor,
	// admin_api_key_actor, unauthenticated_user_actor, anthropic_actor or
	// scim_directory_sync_actor.
	Type string
	// Email is the address of a signed-in user. Only user_actor defines it,
	// and anthropic_actor always reports it as null.
	Email string
	// ID is the organization member id behind a user_actor.
	ID string
	// UnauthenticatedEmail is the address supplied before sign-in completed.
	// It is a claim, not a verified identity.
	UnauthenticatedEmail string
	// IPAddress and UserAgent are shared by the user, API, admin key and
	// unauthenticated variants.
	IPAddress string
	UserAgent string
	// APIKeyID identifies the customer-issued API key behind an api_actor,
	// AdminAPIKeyID the admin key behind an admin_api_key_actor.
	APIKeyID      string
	AdminAPIKeyID string
	// DirectoryID, IdpConnectionType and WorkosEventID describe a change
	// pushed by an identity provider through SCIM directory sync.
	DirectoryID       string
	IdpConnectionType string
	WorkosEventID     string
}

// adminActorPayload is the wire shape of the actor union. It is decoded
// separately from AdminActorInfo so the union's per-variant key names stay in
// one place, rather than every consumer having to know that a user's address
// arrives as email_address while an unauthenticated one arrives under its own
// key.
type adminActorPayload struct {
	Type                        string  `json:"type"`
	EmailAddress                *string `json:"email_address"`
	UnauthenticatedEmailAddress *string `json:"unauthenticated_email_address"`
	UserID                      string  `json:"user_id"`
	IPAddress                   string  `json:"ip_address"`
	UserAgent                   string  `json:"user_agent"`
	APIKeyID                    string  `json:"api_key_id"`
	AdminAPIKeyID               string  `json:"admin_api_key_id"`
	DirectoryID                 string  `json:"directory_id"`
	IdpConnectionType           *string `json:"idp_connection_type"`
	WorkosEventID               string  `json:"workos_event_id"`
}

func (a *AdminActorInfo) UnmarshalJSON(data []byte) error {
	var p adminActorPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}

	*a = AdminActorInfo{
		Type:              p.Type,
		ID:                p.UserID,
		IPAddress:         p.IPAddress,
		UserAgent:         p.UserAgent,
		APIKeyID:          p.APIKeyID,
		AdminAPIKeyID:     p.AdminAPIKeyID,
		DirectoryID:       p.DirectoryID,
		WorkosEventID:     p.WorkosEventID,
		IdpConnectionType: derefString(p.IdpConnectionType),
	}
	a.Email = derefString(p.EmailAddress)
	a.UnauthenticatedEmail = derefString(p.UnauthenticatedEmailAddress)
	return nil
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (c *AdminClient) ListActivities(ctx context.Context) ([]AdminActivity, error) {
	return paginate[AdminActivity](ctx, c, "/v1/compliance/activities")
}

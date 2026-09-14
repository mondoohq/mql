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
	ID            string              `json:"id"`
	Name          string              `json:"name"`
	DisplayColor  string              `json:"display_color"`
	CreatedAt     string              `json:"created_at"`
	ArchivedAt    *string             `json:"archived_at"`
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

type AdminActorInfo struct {
	Email string `json:"email"`
	ID    string `json:"id"`
}

func (c *AdminClient) ListActivities(ctx context.Context) ([]AdminActivity, error) {
	return paginate[AdminActivity](ctx, c, "/v1/compliance/activities")
}

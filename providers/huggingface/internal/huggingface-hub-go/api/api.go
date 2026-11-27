// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"go.mondoo.com/mql/providers/huggingface/internal/huggingface-hub-go/models"
)

const (
	maxFileDownloadSize = 10 << 20 // 10 MB
	maxErrorBodySize    = 64 << 10 // 64 KB
)

// defaultInferenceEndpointsBaseURL is the Inference Endpoints API, which is
// served from its own host rather than the Hub's.
const defaultInferenceEndpointsBaseURL = "https://api.endpoints.huggingface.cloud"

type API struct {
	baseURL          string
	endpointsBaseURL string
	httpClient       *http.Client
	token            string
}

func NewAPI(baseURL string, httpClient *http.Client, token string) *API {
	return &API{
		baseURL:          baseURL,
		endpointsBaseURL: defaultInferenceEndpointsBaseURL,
		httpClient:       httpClient,
		token:            token,
	}
}

func (a *API) SetToken(token string)             { a.token = token }
func (a *API) SetHTTPClient(client *http.Client) { a.httpClient = client }
func (a *API) SetBaseURL(url string)             { a.baseURL = url }

// escapeRepoID escapes each segment of an "owner/repo" ID individually,
// preserving the "/" separator needed by the HuggingFace API.
func escapeRepoID(id string) string {
	parts := strings.SplitN(id, "/", 2)
	if len(parts) == 2 {
		return url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
	}
	return url.PathEscape(id)
}

// buildURL turns a relative API endpoint (optionally carrying a query string)
// into the absolute URL under the "/api" base path.
func (a *API) buildURL(endpoint string) (string, error) {
	u, err := url.Parse(a.baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	pathPart := endpoint
	queryPart := ""
	if before, after, ok := strings.Cut(endpoint, "?"); ok {
		pathPart = before
		queryPart = after
	}

	u.Path = path.Join(u.Path, "api", pathPart)

	if queryPart != "" {
		u.RawQuery = queryPart
	}

	return u.String(), nil
}

// parseNextLink extracts the URL marked rel="next" from an RFC 8288 Link
// header. The HuggingFace list endpoints paginate by returning a cursor in
// this header; an empty string means there is no further page.
func parseNextLink(header string) string {
	if header == "" {
		return ""
	}
	for part := range strings.SplitSeq(header, ",") {
		segments := strings.Split(part, ";")
		if len(segments) < 2 {
			continue
		}
		rawURL := strings.TrimSpace(segments[0])
		if !strings.HasPrefix(rawURL, "<") || !strings.HasSuffix(rawURL, ">") {
			continue
		}
		for _, param := range segments[1:] {
			param = strings.TrimSpace(param)
			if param == `rel="next"` || param == "rel=next" {
				return rawURL[1 : len(rawURL)-1]
			}
		}
	}
	return ""
}

// setExpand writes the expand[] selector onto a list request.
//
// expand[] is restrictive rather than additive: the Hub returns only the named
// fields, so the caller has to name every field it intends to read. When it is
// set the server ignores full=true, so full is only sent on its own to keep the
// request saying what it means.
func setExpand(params url.Values, expand []string, full bool) {
	if len(expand) == 0 {
		if full {
			params.Set("full", "true")
		}
		return
	}
	for _, field := range expand {
		params.Add("expand[]", field)
	}
}

// getPaged performs a GET against a relative endpoint or an absolute URL (as
// returned by parseNextLink), decodes the body into result, and returns the
// URL of the next page (empty when the response has no rel="next" link).
func (a *API) getPaged(ctx context.Context, endpointOrURL string, result any) (string, error) {
	rawURL := endpointOrURL
	if !strings.HasPrefix(endpointOrURL, "http://") && !strings.HasPrefix(endpointOrURL, "https://") {
		var err error
		rawURL, err = a.buildURL(endpointOrURL)
		if err != nil {
			return "", err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		var apiErr models.Error
		if err := json.Unmarshal(bodyBytes, &apiErr); err != nil {
			return "", fmt.Errorf("request failed (status: %d)", resp.StatusCode)
		}
		return "", fmt.Errorf("API error: %s (status: %d)", apiErr.Error, resp.StatusCode)
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return "", fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return parseNextLink(resp.Header.Get("Link")), nil
}

func (a *API) request(ctx context.Context, method, endpoint string, body any, result any) error {
	rawURL, err := a.buildURL(endpoint)
	if err != nil {
		return err
	}

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		var apiErr models.Error
		if err := json.Unmarshal(bodyBytes, &apiErr); err != nil {
			return fmt.Errorf("request failed (status: %d)", resp.StatusCode)
		}
		return fmt.Errorf("API error: %s (status: %d)", apiErr.Error, resp.StatusCode)
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

func (a *API) GetModel(ctx context.Context, modelID string) (*models.Model, error) {
	var model models.Model
	err := a.request(ctx, http.MethodGet, fmt.Sprintf("models/%s", escapeRepoID(modelID)), nil, &model)
	if err != nil {
		return nil, err
	}
	return &model, nil
}

func (a *API) GetDataset(ctx context.Context, datasetID string) (*models.Dataset, error) {
	var dataset models.Dataset
	err := a.request(ctx, http.MethodGet, fmt.Sprintf("datasets/%s", escapeRepoID(datasetID)), nil, &dataset)
	if err != nil {
		return nil, err
	}
	return &dataset, nil
}

func (a *API) GetSpace(ctx context.Context, spaceID string) (*models.Space, error) {
	var space models.Space
	err := a.request(ctx, http.MethodGet, fmt.Sprintf("spaces/%s", escapeRepoID(spaceID)), nil, &space)
	if err != nil {
		return nil, err
	}
	return &space, nil
}

// GetRepoScan reads the Hub's malware and unsafe-serialization verdict for one
// repository. Models, datasets, and Spaces all serve it at the same path under
// their own type segment.
func (a *API) GetRepoScan(ctx context.Context, repoType models.RepoType, repoID string) (*models.RepoScan, error) {
	var scan models.RepoScan
	err := a.request(ctx, http.MethodGet, fmt.Sprintf("%s/%s/scan", repoType, escapeRepoID(repoID)), nil, &scan)
	if err != nil {
		return nil, err
	}
	return &scan, nil
}

func (a *API) ListModels(ctx context.Context, opts *models.ModelListOptions) (*models.ModelList, error) {
	if opts == nil {
		opts = models.NewModelListOptions()
	}

	params := url.Values{}
	if opts.Author != "" {
		params.Set("author", opts.Author)
	}
	if opts.Search != "" {
		params.Set("search", opts.Search)
	}
	if opts.Filter != "" {
		params.Set("filter", opts.Filter)
	}
	if opts.SortBy != "" {
		params.Set("sort", opts.SortBy)
		if opts.SortBy == "trendingScore" {
			params.Set("direction", "1")
		} else {
			params.Set("direction", opts.SortDirection)
		}
	}
	if opts.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", opts.Limit))
	}
	setExpand(params, opts.Expand, opts.Full)

	endpoint := "models"
	if len(params) > 0 {
		endpoint = fmt.Sprintf("%s?%s", endpoint, params.Encode())
	}

	var modelList models.ModelList
	next := endpoint
	seen := map[string]bool{}
	for next != "" && !seen[next] {
		seen[next] = true
		var page models.ModelList
		nextURL, err := a.getPaged(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		modelList.Models = append(modelList.Models, page.Models...)
		next = nextURL
	}
	return &modelList, nil
}

func (a *API) ListDatasets(ctx context.Context, opts *models.DatasetListOptions) (*models.DatasetList, error) {
	if opts == nil {
		opts = models.NewDatasetListOptions()
	}

	params := url.Values{}
	if opts.Author != "" {
		params.Set("author", opts.Author)
	}
	if opts.Search != "" {
		params.Set("search", opts.Search)
	}
	if opts.Filter != "" {
		params.Set("filter", opts.Filter)
	}
	if opts.SortBy != "" {
		params.Set("sort", opts.SortBy)
		if opts.SortBy == "trendingScore" {
			params.Set("direction", "1")
		} else {
			params.Set("direction", opts.SortDirection)
		}
	}
	if opts.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", opts.Limit))
	}
	setExpand(params, opts.Expand, opts.Full)

	endpoint := "datasets"
	if len(params) > 0 {
		endpoint = fmt.Sprintf("%s?%s", endpoint, params.Encode())
	}

	var datasetList models.DatasetList
	next := endpoint
	seen := map[string]bool{}
	for next != "" && !seen[next] {
		seen[next] = true
		var page models.DatasetList
		nextURL, err := a.getPaged(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		datasetList.Datasets = append(datasetList.Datasets, page.Datasets...)
		next = nextURL
	}
	return &datasetList, nil
}

func (a *API) ListSpaces(ctx context.Context, opts *models.SpaceListOptions) (*models.SpaceList, error) {
	if opts == nil {
		opts = models.NewSpaceListOptions()
	}

	params := url.Values{}
	if opts.Author != "" {
		params.Set("author", opts.Author)
	}
	if opts.Search != "" {
		params.Set("search", opts.Search)
	}
	if opts.Filter != "" {
		params.Set("filter", opts.Filter)
	}
	if opts.SortBy != "" {
		params.Set("sort", opts.SortBy)
		if opts.SortBy == "trendingScore" {
			params.Set("direction", "1")
		} else {
			params.Set("direction", opts.SortDirection)
		}
	}
	if opts.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", opts.Limit))
	}
	setExpand(params, opts.Expand, opts.Full)

	endpoint := "spaces"
	if len(params) > 0 {
		endpoint = fmt.Sprintf("%s?%s", endpoint, params.Encode())
	}

	var spaceList models.SpaceList
	next := endpoint
	seen := map[string]bool{}
	for next != "" && !seen[next] {
		seen[next] = true
		var page models.SpaceList
		nextURL, err := a.getPaged(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		spaceList.Spaces = append(spaceList.Spaces, page.Spaces...)
		next = nextURL
	}
	return &spaceList, nil
}

// ListInferenceEndpoints returns every inference endpoint in the namespace.
// The list paginates with a nextCursor in the body, which alone decides
// whether another page follows: an empty page can still carry one. A cursor
// seen twice, or more pages than any namespace holds, stops the walk with an
// error instead of returning a partial list.
func (a *API) ListInferenceEndpoints(ctx context.Context, namespace string) (*models.InferenceEndpointList, error) {
	const maxPages = 1000
	base := fmt.Sprintf("%s/v2/endpoint/%s", a.endpointsBaseURL, url.PathEscape(namespace))

	all := &models.InferenceEndpointList{}
	seen := map[string]bool{}
	cursor := ""
	for range maxPages {
		u := base
		if cursor != "" {
			u += "?cursor=" + url.QueryEscape(cursor)
		}
		page, err := a.getInferenceEndpointPage(ctx, u)
		if err != nil {
			return nil, err
		}
		all.Endpoints = append(all.Endpoints, page.Endpoints...)
		if page.NextCursor == nil || *page.NextCursor == "" {
			return all, nil
		}
		cursor = *page.NextCursor
		if seen[cursor] {
			return nil, fmt.Errorf("inference endpoint list returned cursor %q twice", cursor)
		}
		seen[cursor] = true
	}
	return nil, fmt.Errorf("inference endpoint list exceeded %d pages", maxPages)
}

func (a *API) getInferenceEndpointPage(ctx context.Context, u string) (*models.InferenceEndpointList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return nil, fmt.Errorf("API error: %s (status: %d)", string(bodyBytes), resp.StatusCode)
	}

	var page models.InferenceEndpointList
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &page, nil
}

func (a *API) ListWebhooks(ctx context.Context, opts *models.WebhookListOptions) ([]models.Webhook, error) {
	if opts == nil {
		opts = models.NewWebhookListOptions()
	}

	params := url.Values{}
	if opts.Search != "" {
		params.Set("search", opts.Search)
	}
	if opts.Filter != "" {
		params.Set("filter", opts.Filter)
	}
	if opts.SortBy != "" {
		params.Set("sort", opts.SortBy)
		params.Set("direction", opts.SortDirection)
	}
	if opts.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Full {
		params.Set("full", "true")
	}

	endpoint := "settings/webhooks"
	if len(params) > 0 {
		endpoint = fmt.Sprintf("%s?%s", endpoint, params.Encode())
	}

	// Follow cursor pagination like the other list endpoints. The settings
	// endpoint may not paginate today, in which case the loop simply runs once
	// (no Link header, so next is empty).
	var webhookList models.WebhookList
	next := endpoint
	seen := map[string]bool{}
	for next != "" && !seen[next] {
		seen[next] = true
		var page models.WebhookList
		nextURL, err := a.getPaged(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		webhookList = append(webhookList, page...)
		next = nextURL
	}
	return []models.Webhook(webhookList), nil
}

// listAllPages walks a Hub list that returns a JSON array per page and names
// the next page in an RFC 8288 Link header. A next link seen before stops the
// walk, so a server pointing back at a page it already served cannot loop it.
func listAllPages[T any](ctx context.Context, a *API, endpoint string) ([]T, error) {
	var all []T
	next := endpoint
	seen := map[string]bool{}
	for next != "" && !seen[next] {
		seen[next] = true
		var page []T
		nextURL, err := a.getPaged(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		next = nextURL
	}
	return all, nil
}

// ListOrgMembers returns every member of an organization. External
// collaborators are requested too; the Hub honors that only for organization
// administrators.
func (a *API) ListOrgMembers(ctx context.Context, org string) ([]models.OrgMember, error) {
	params := url.Values{}
	params.Set("limit", "1000")
	params.Set("includeExternal", "true")
	endpoint := fmt.Sprintf("organizations/%s/members?%s", url.PathEscape(org), params.Encode())
	return listAllPages[models.OrgMember](ctx, a, endpoint)
}

// GetOrgNetworkSecurity reads an organization's network security settings
// (Team and Enterprise plans).
func (a *API) GetOrgNetworkSecurity(ctx context.Context, org string) (*models.OrgNetworkSecurity, error) {
	var ns models.OrgNetworkSecurity
	err := a.request(ctx, http.MethodGet, fmt.Sprintf("organizations/%s/settings/network-security", url.PathEscape(org)), nil, &ns)
	if err != nil {
		return nil, err
	}
	return &ns, nil
}

// ListOrgMemberTokens returns the access tokens of an organization's members
// (Team and Enterprise plans). The Hub's default filter leaves revoked tokens
// out.
func (a *API) ListOrgMemberTokens(ctx context.Context, org string) ([]models.OrgMemberToken, error) {
	endpoint := fmt.Sprintf("organizations/%s/settings/tokens?limit=100", url.PathEscape(org))
	return listAllPages[models.OrgMemberToken](ctx, a, endpoint)
}

// ListTrustedPublishers returns the trusted publishers configured on one
// repository. The endpoint does not paginate.
func (a *API) ListTrustedPublishers(ctx context.Context, repoType models.RepoType, repoID string) ([]models.TrustedPublisher, error) {
	var pubs []models.TrustedPublisher
	err := a.request(ctx, http.MethodGet, fmt.Sprintf("%s/%s/settings/trusted-publishers", repoType, escapeRepoID(repoID)), nil, &pubs)
	if err != nil {
		return nil, err
	}
	return pubs, nil
}

// ListAccessRequests returns the access requests with one status on a gated
// model or dataset.
func (a *API) ListAccessRequests(ctx context.Context, repoType models.RepoType, repoID string, status models.AccessRequestStatus) ([]models.AccessRequest, error) {
	endpoint := fmt.Sprintf("%s/%s/user-access-request/%s?limit=1000", repoType, escapeRepoID(repoID), url.PathEscape(string(status)))
	return listAllPages[models.AccessRequest](ctx, a, endpoint)
}

func (a *API) WhoAmI(ctx context.Context) (*models.User, error) {
	var user models.User
	err := a.request(ctx, http.MethodGet, "whoami-v2", nil, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (a *API) GetModelCard(ctx context.Context, modelID string, revision string) (*models.ModelCard, error) {
	if revision == "" {
		revision = "HEAD"
	}
	var card models.ModelCard
	err := a.request(ctx, http.MethodGet, fmt.Sprintf("models/%s/revision/%s", escapeRepoID(modelID), url.PathEscape(revision)), nil, &card)
	if err != nil {
		return nil, err
	}
	return &card, nil
}

func (a *API) GetDatasetCard(ctx context.Context, datasetID string, revision string) (*models.DatasetCard, error) {
	if revision == "" {
		revision = "HEAD"
	}
	var card models.DatasetCard
	err := a.request(ctx, http.MethodGet, fmt.Sprintf("datasets/%s/revision/%s", escapeRepoID(datasetID), url.PathEscape(revision)), nil, &card)
	if err != nil {
		return nil, err
	}
	return &card, nil
}

func (a *API) GetModelDetail(ctx context.Context, modelID string) (*models.ModelDetail, error) {
	var detail models.ModelDetail
	err := a.request(ctx, http.MethodGet, fmt.Sprintf("models/%s", escapeRepoID(modelID)), nil, &detail)
	if err != nil {
		return nil, err
	}
	return &detail, nil
}

func (a *API) DownloadModelFile(ctx context.Context, modelID, filePath string) ([]byte, error) {
	u, err := url.Parse(a.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	u.Path = path.Join(u.Path, escapeRepoID(modelID), "resolve", "main", filePath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("download failed (status: %d)", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFileDownloadSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	return data, nil
}

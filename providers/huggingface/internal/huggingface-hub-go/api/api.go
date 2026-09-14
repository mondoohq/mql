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

type API struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

func NewAPI(baseURL string, httpClient *http.Client, token string) *API {
	return &API{
		baseURL:    baseURL,
		httpClient: httpClient,
		token:      token,
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
	if idx := strings.Index(endpoint, "?"); idx != -1 {
		pathPart = endpoint[:idx]
		queryPart = endpoint[idx+1:]
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
	for _, part := range strings.Split(header, ",") {
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
func (a *API) getPaged(ctx context.Context, endpointOrURL string, result interface{}) (string, error) {
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

func (a *API) request(ctx context.Context, method, endpoint string, body interface{}, result interface{}) error {
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

func (a *API) ListInferenceEndpoints(ctx context.Context, namespace string) (*models.InferenceEndpointList, error) {
	u := fmt.Sprintf("https://api.endpoints.huggingface.cloud/v2/endpoint/%s", url.PathEscape(namespace))

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

	var endpointList models.InferenceEndpointList
	if err := json.NewDecoder(resp.Body).Decode(&endpointList); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &endpointList, nil
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

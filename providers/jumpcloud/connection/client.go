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
	"strconv"
	"time"
)

// DefaultBaseURL is the JumpCloud REST API root. The v1 endpoints live directly
// under it (for example /systemusers) and the v2 endpoints under /v2.
const DefaultBaseURL = "https://console.jumpcloud.com/api"

// pageLimit is the page size requested from every paginated endpoint. JumpCloud
// caps most list endpoints at 100 records per page.
const pageLimit = 100

// maxItems bounds how many records a single list call will accumulate. It is a
// safety valve against an endpoint that never signals the final page, not an
// expected limit; real organizations stay well under it.
const maxItems = 100000

const userAgent = "mondoo-jumpcloud-provider"

// maxBodyBytes caps how much of a response body is buffered into memory. It
// guards against a misbehaving or compromised endpoint forcing the provider to
// buffer an unbounded response; real JumpCloud pages stay far under it.
const maxBodyBytes = 64 << 20 // 64 MiB

// Client is a thin, read-only HTTP client for the JumpCloud REST API. It
// authenticates with an API key (and an optional organization id for
// multi-tenant admins) and knows how to page through both the v1 envelope
// responses and the v2 bare-array responses.
type Client struct {
	http    *http.Client
	baseURL string
	apiKey  string
	orgID   string
}

// NewClient builds a JumpCloud client. baseURL may be empty, in which case
// DefaultBaseURL is used. orgID may be empty for single-organization API keys.
func NewClient(apiKey, orgID, baseURL string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		http:    &http.Client{Timeout: 60 * time.Second},
		baseURL: baseURL,
		apiKey:  apiKey,
		orgID:   orgID,
	}
}

// getJSON issues a GET against the given path (relative to baseURL), decoding a
// successful JSON body into out. A non-2xx response is returned as an error
// carrying the truncated response body, which is where JumpCloud reports the
// reason an API key was rejected.
func (c *Client) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	u := c.baseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", c.apiKey)
	if c.orgID != "" {
		req.Header.Set("x-org-id", c.orgID)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("jumpcloud API request to %s failed with status %d: %s", path, resp.StatusCode, truncate(string(body), 256))
	}

	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("failed to decode jumpcloud response from %s: %w", path, err)
		}
	}
	return nil
}

// listV1 pages through a JumpCloud v1 list endpoint. These wrap their records in
// a { "results": [...], "totalCount": N } envelope and page with limit/skip.
func listV1[T any](ctx context.Context, c *Client, path string) ([]*T, error) {
	var all []*T
	skip := 0
	for {
		var env struct {
			Results    []*T `json:"results"`
			TotalCount int  `json:"totalCount"`
		}
		q := url.Values{"limit": {strconv.Itoa(pageLimit)}, "skip": {strconv.Itoa(skip)}}
		if err := c.getJSON(ctx, path, q, &env); err != nil {
			return nil, err
		}
		all = append(all, env.Results...)

		if len(env.Results) < pageLimit || len(all) >= env.TotalCount || len(all) >= maxItems {
			break
		}
		skip += pageLimit
	}
	return all, nil
}

// listV2 pages through a JumpCloud v2 list endpoint. These return a bare JSON
// array and page with limit/skip; the final page is the one shorter than the
// requested limit.
func listV2[T any](ctx context.Context, c *Client, path string) ([]*T, error) {
	var all []*T
	skip := 0
	for {
		var page []*T
		q := url.Values{"limit": {strconv.Itoa(pageLimit)}, "skip": {strconv.Itoa(skip)}}
		if err := c.getJSON(ctx, path, q, &page); err != nil {
			return nil, err
		}
		all = append(all, page...)

		if len(page) < pageLimit || len(all) >= maxItems {
			break
		}
		skip += pageLimit
	}
	return all, nil
}

// SystemUsers returns every user account in the organization.
func (c *Client) SystemUsers(ctx context.Context) ([]*SystemUser, error) {
	return listV1[SystemUser](ctx, c, "/systemusers")
}

// GetSystemUser fetches a single user account by id.
func (c *Client) GetSystemUser(ctx context.Context, id string) (*SystemUser, error) {
	var u SystemUser
	if err := c.getJSON(ctx, "/systemusers/"+url.PathEscape(id), nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// Systems returns every enrolled system (device) in the organization.
func (c *Client) Systems(ctx context.Context) ([]*System, error) {
	return listV1[System](ctx, c, "/systems")
}

// GetSystem fetches a single system by id.
func (c *Client) GetSystem(ctx context.Context, id string) (*System, error) {
	var s System
	if err := c.getJSON(ctx, "/systems/"+url.PathEscape(id), nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// UserGroups returns every user group in the organization.
func (c *Client) UserGroups(ctx context.Context) ([]*Group, error) {
	return listV2[Group](ctx, c, "/v2/usergroups")
}

// GetUserGroup fetches a single user group by id.
func (c *Client) GetUserGroup(ctx context.Context, id string) (*Group, error) {
	var g Group
	if err := c.getJSON(ctx, "/v2/usergroups/"+url.PathEscape(id), nil, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// SystemGroups returns every system group in the organization.
func (c *Client) SystemGroups(ctx context.Context) ([]*Group, error) {
	return listV2[Group](ctx, c, "/v2/systemgroups")
}

// GetSystemGroup fetches a single system group by id.
func (c *Client) GetSystemGroup(ctx context.Context, id string) (*Group, error) {
	var g Group
	if err := c.getJSON(ctx, "/v2/systemgroups/"+url.PathEscape(id), nil, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// Applications returns every SSO application in the organization.
func (c *Client) Applications(ctx context.Context) ([]*Application, error) {
	return listV2[Application](ctx, c, "/v2/applications")
}

// GetApplication fetches a single application by id.
func (c *Client) GetApplication(ctx context.Context, id string) (*Application, error) {
	var a Application
	if err := c.getJSON(ctx, "/v2/applications/"+url.PathEscape(id), nil, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// Policies returns every policy in the organization.
func (c *Client) Policies(ctx context.Context) ([]*Policy, error) {
	return listV2[Policy](ctx, c, "/v2/policies")
}

// Commands returns every command defined in the organization.
func (c *Client) Commands(ctx context.Context) ([]*Command, error) {
	return listV1[Command](ctx, c, "/commands")
}

// RadiusServers returns every RADIUS server in the organization.
func (c *Client) RadiusServers(ctx context.Context) ([]*RadiusServer, error) {
	return listV2[RadiusServer](ctx, c, "/v2/radiusservers")
}

// Directories returns every external directory integration in the organization.
func (c *Client) Directories(ctx context.Context) ([]*Directory, error) {
	return listV2[Directory](ctx, c, "/v2/directories")
}

// Organizations returns the organizations the API key can see. It is used to
// derive a stable platform identifier for the connected organization.
func (c *Client) Organizations(ctx context.Context) ([]*Organization, error) {
	return listV1[Organization](ctx, c, "/organizations")
}

// GraphConnections pages through a JumpCloud v2 graph endpoint (a membership or
// association relation) and returns the raw connection entries. Each entry
// carries a `to` target that names the related object by id and type.
func (c *Client) GraphConnections(ctx context.Context, path string) ([]*GraphConnection, error) {
	return listV2[GraphConnection](ctx, c, path)
}

// GraphPath builds the path to a graph endpoint, escaping the object id the
// same way the single-object getters do so an id carrying a reserved character
// cannot reshape the request. JumpCloud ids are hex ObjectIds today, but the
// escaping keeps every path in this package built the one way.
func GraphPath(collection, id, relation string) string {
	return collection + "/" + url.PathEscape(id) + "/" + relation
}

// truncate shortens s to at most n runes, appending an ellipsis when it had to
// cut, so an oversized error body does not flood the logs.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

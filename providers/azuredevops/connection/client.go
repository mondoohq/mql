// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// DefaultAPIVersion is the REST api-version sent on every versioned call.
	DefaultAPIVersion = "7.1"

	// DefaultEndpoint is the Azure DevOps Services REST host.
	DefaultEndpoint = "https://dev.azure.com"

	continuationHeader = "x-ms-continuationtoken"
	costHeader         = "x-ratelimit-cost"
	projectPageSize    = 100

	maxRetries     = 5
	firstBackoff   = 5 * time.Second
	maxBackoff     = 60 * time.Second
	maxRetryAfter  = 5 * time.Minute
	maxResponseLen = 128 << 20
)

var orgNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)

// ParseOrganization returns the organization name from a bare name, from
// https://dev.azure.com/<org>, or from the legacy https://<org>.visualstudio.com.
func ParseOrganization(input string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", errors.New("azure devops: the organization is empty")
	}

	name := s
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("azure devops: cannot parse the organization %q: %w", input, err)
		}
		host := strings.ToLower(u.Hostname())
		switch {
		case host == "dev.azure.com":
			name, _, _ = strings.Cut(strings.Trim(u.Path, "/"), "/")
		case strings.HasSuffix(host, ".visualstudio.com"):
			name = strings.TrimSuffix(host, ".visualstudio.com")
		default:
			return "", fmt.Errorf("azure devops: %q is not an Azure DevOps Services address", input)
		}
	}

	if !orgNamePattern.MatchString(name) {
		return "", fmt.Errorf("azure devops: %q is not a valid organization name", name)
	}
	return name, nil
}

// APIError is a non-success answer from Azure DevOps.
type APIError struct {
	Status  int
	Path    string
	Message string
	// TypeKey is the exception name the service reports, for example
	// GitItemNotFoundException.
	TypeKey string
	// RetryAfter is the server's Retry-After, when it sent one.
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("azure devops: HTTP %d on %s: %s", e.Status, e.Path, msg)
}

func (e *APIError) retryable() bool {
	switch e.Status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func apiStatus(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status
	}
	return 0
}

// IsUnauthorized reports a rejected credential: HTTP 401, the HTTP 203 sign-in
// page, or the redirect to the sign-in page Azure DevOps answers with for some
// bad tokens.
func IsUnauthorized(err error) bool { return apiStatus(err) == http.StatusUnauthorized }

// IsForbidden reports HTTP 403.
func IsForbidden(err error) bool { return apiStatus(err) == http.StatusForbidden }

// IsNotFound reports HTTP 404. Azure DevOps answers it, with TF200016 or
// TF401019, for a project or repository the principal cannot see as well as for
// one that does not exist.
func IsNotFound(err error) bool { return apiStatus(err) == http.StatusNotFound }

// IsNoAccess reports that the principal may not read the thing it asked for.
func IsNoAccess(err error) bool { return IsUnauthorized(err) || IsForbidden(err) }

// IsEmptyRepoError reports the 404 VS403403 answer of the Items API for a
// repository that has no branches.
func IsEmptyRepoError(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusNotFound {
		return false
	}
	return strings.Contains(apiErr.TypeKey, "GitItemNotFoundException") || strings.Contains(apiErr.Message, "VS403403")
}

// ClientOptions tunes a Client. The zero value is the production setup.
type ClientOptions struct {
	// Endpoint replaces https://dev.azure.com. Only a loopback address is
	// accepted, so a token can never be pointed at another host. Tests use it
	// to reach an httptest server.
	Endpoint string
	// HTTPClient replaces the default client.
	HTTPClient *http.Client
	// Sleep replaces the wait between retries. Tests make it instant.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Client is the REST client of one organization.
type Client struct {
	org     string
	base    string
	auth    *Authenticator
	http    *http.Client
	sleep   func(ctx context.Context, d time.Duration) error
	costMu  sync.Mutex
	costSum float64
}

// NewClient builds a client for one organization.
func NewClient(org string, auth *Authenticator, opts ClientOptions) (*Client, error) {
	if _, err := ParseOrganization(org); err != nil {
		return nil, err
	}
	if auth == nil {
		return nil, errors.New("azure devops: a client needs an authenticator")
	}
	endpoint, err := validateEndpoint(opts.Endpoint)
	if err != nil {
		return nil, err
	}

	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Timeout: 2 * time.Minute,
			// Azure DevOps answers a rejected Bearer token with a 302 to its
			// sign-in page on the same host. Following it would turn a bad
			// credential into a JSON decode error, so getOnce reads the 3xx itself.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	sleep := opts.Sleep
	if sleep == nil {
		sleep = sleepContext
	}
	return &Client{
		org:   org,
		base:  endpoint + "/" + url.PathEscape(org),
		auth:  auth,
		http:  hc,
		sleep: sleep,
	}, nil
}

// validateEndpoint accepts the empty default or a loopback address.
func validateEndpoint(raw string) (string, error) {
	if raw == "" {
		return DefaultEndpoint, nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("azure devops: %q is not a usable api endpoint", raw)
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
		return strings.TrimRight(u.String(), "/"), nil
	}
	return "", fmt.Errorf("azure devops: the api endpoint %q must be a loopback address", raw)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Org is the organization name the client talks to.
func (c *Client) Org() string { return c.org }

// BaseURL is the organization root, for example https://dev.azure.com/<org>.
func (c *Client) BaseURL() string { return c.base }

// CostUnits is the sum of the x-ratelimit-cost headers seen so far. Azure
// DevOps throttles by cost, so this is what to watch when tuning parallelism.
func (c *Client) CostUnits() float64 {
	c.costMu.Lock()
	defer c.costMu.Unlock()
	return c.costSum
}

func (c *Client) addCost(h http.Header) {
	v := h.Get(costHeader)
	if v == "" {
		return
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return
	}
	c.costMu.Lock()
	c.costSum += f
	c.costMu.Unlock()
}

type request struct {
	segments  []string
	query     url.Values
	noVersion bool
}

func (c *Client) urlFor(r request) string {
	var b strings.Builder
	b.WriteString(c.base)
	for _, seg := range r.segments {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(seg))
	}
	q := url.Values{}
	for k, v := range r.query {
		q[k] = v
	}
	if !r.noVersion {
		q.Set("api-version", DefaultAPIVersion)
	}
	if len(q) > 0 {
		b.WriteByte('?')
		b.WriteString(q.Encode())
	}
	return b.String()
}

// getJSON runs one GET with retries and decodes the body into out.
func (c *Client) getJSON(ctx context.Context, r request, out any) (http.Header, error) {
	target := c.urlFor(r)
	backoff := firstBackoff
	for attempt := 0; ; attempt++ {
		hdr, err := c.getOnce(ctx, target, r.segments, out)
		if err == nil {
			return hdr, nil
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || !apiErr.retryable() || attempt >= maxRetries {
			return nil, err
		}

		wait := backoff
		if apiErr.RetryAfter > 0 {
			wait = apiErr.RetryAfter
			if wait > maxRetryAfter {
				return nil, err
			}
		} else {
			backoff = min(backoff*2, maxBackoff)
		}
		log.Debug().Int("status", apiErr.Status).Dur("wait", wait).Int("attempt", attempt+1).
			Msg("azure devops asked to slow down, retrying")
		if err := c.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

func (c *Client) getOnce(ctx context.Context, target string, segments []string, out any) (http.Header, error) {
	path := "/" + strings.Join(segments, "/")

	authz, err := c.auth.AuthorizationHeader(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("azure devops: cannot build the request for %s: %w", path, err)
	}
	req.Header.Set("Authorization", authz)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure devops: GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	c.addCost(resp.Header)

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseLen))
	if err != nil {
		return nil, fmt.Errorf("azure devops: reading the answer for %s: %w", path, err)
	}

	switch {
	case resp.StatusCode == http.StatusNonAuthoritativeInfo:
		// A bad token can be answered with the HTML sign-in page and a 203.
		return nil, &APIError{Status: http.StatusUnauthorized, Path: path,
			Message: "Azure DevOps answered with its sign-in page, so the credential was not accepted"}
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// The client does not follow redirects. Neither the Location header nor
		// the body goes into the error.
		return nil, &APIError{Status: http.StatusUnauthorized, Path: path,
			Message: "Azure DevOps redirected the request to its sign-in page, so the credential was not accepted"}
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if out == nil {
			return resp.Header, nil
		}
		if err := json.Unmarshal(body, out); err != nil {
			return nil, fmt.Errorf("azure devops: cannot decode the answer for %s: %w", path, err)
		}
		return resp.Header, nil
	}

	apiErr := &APIError{Status: resp.StatusCode, Path: path, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	var detail struct {
		Message string `json:"message"`
		TypeKey string `json:"typeKey"`
	}
	if json.Unmarshal(body, &detail) == nil {
		apiErr.Message = detail.Message
		apiErr.TypeKey = detail.TypeKey
	}
	return nil, apiErr
}

func parseRetryAfter(v string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

type listResponse[T any] struct {
	Count int `json:"count"`
	Value []T `json:"value"`
}

// listAll reads every page of a list endpoint. A page that carries an
// x-ms-continuationtoken header is followed with continuationToken; a token
// the server repeats ends the walk with an error instead of looping.
func listAll[T any](ctx context.Context, c *Client, r request, pageSize int) ([]T, error) {
	var all []T
	seen := map[string]bool{}
	token := ""
	for {
		q := url.Values{}
		for k, v := range r.query {
			q[k] = v
		}
		if token != "" {
			q.Set("continuationToken", token)
		}
		page := listResponse[T]{}
		hdr, err := c.getJSON(ctx, request{segments: r.segments, query: q, noVersion: r.noVersion}, &page)
		if err != nil {
			return nil, err
		}
		all = append(all, page.Value...)

		next := hdr.Get(continuationHeader)
		if next == "" {
			if pageSize > 0 && len(page.Value) >= pageSize {
				log.Warn().Str("path", "/"+strings.Join(r.segments, "/")).Int("page-size", pageSize).
					Msg("azure devops returned a full page without a continuation token, the list may be truncated")
			}
			return all, nil
		}
		if seen[next] || next == token {
			return nil, fmt.Errorf("azure devops: %s repeated the continuation token, stopping to avoid a loop",
				"/"+strings.Join(r.segments, "/"))
		}
		seen[next] = true
		token = next
	}
}

// ConnectionData reads the organization identity. It is the cheapest call that
// proves the credential is a member of the organization.
func (c *Client) ConnectionData(ctx context.Context) (*ConnectionData, error) {
	data := &ConnectionData{}
	if _, err := c.getJSON(ctx, request{segments: []string{"_apis", "connectionData"}, noVersion: true}, data); err != nil {
		return nil, err
	}
	return data, nil
}

// Projects lists every project the principal can see.
func (c *Client) Projects(ctx context.Context) ([]Project, error) {
	return listAll[Project](ctx, c, request{
		segments: []string{"_apis", "projects"},
		query:    url.Values{"$top": {strconv.Itoa(projectPageSize)}},
	}, projectPageSize)
}

// Repositories lists the repositories of one project.
func (c *Client) Repositories(ctx context.Context, project string) ([]Repository, error) {
	return listAll[Repository](ctx, c, request{
		segments: []string{project, "_apis", "git", "repositories"},
	}, 0)
}

// Repository reads one repository by name or id.
func (c *Client) Repository(ctx context.Context, project, repo string) (*Repository, error) {
	out := &Repository{}
	if _, err := c.getJSON(ctx, request{segments: []string{project, "_apis", "git", "repositories", repo}}, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Project reads one project by name or id.
func (c *Client) Project(ctx context.Context, project string) (*Project, error) {
	out := &Project{}
	if _, err := c.getJSON(ctx, request{segments: []string{"_apis", "projects", project}}, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Items lists the whole tree of a repository's default branch. A repository
// with no branches answers 404 VS403403, which IsEmptyRepoError recognizes.
func (c *Client) Items(ctx context.Context, project, repoID string) ([]Item, error) {
	return listAll[Item](ctx, c, request{
		segments: []string{project, "_apis", "git", "repositories", repoID, "items"},
		query: url.Values{
			"scopePath":      {"/"},
			"recursionLevel": {"Full"},
		},
	}, 0)
}

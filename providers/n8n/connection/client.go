// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
)

const (
	// pageLimit is the largest page the Public API serves.
	pageLimit = "250"

	// maxPages caps a cursor walk. At 250 items a page it allows 2.5 million
	// records, far beyond any instance, so reaching it means the cursor is
	// not advancing.
	maxPages = 10000

	// maxResponseBytes caps one response body, so a misbehaving server or
	// proxy cannot exhaust memory. A page of 250 workflows with their nodes
	// stays far below it.
	maxResponseBytes = 64 << 20
)

// Client calls the n8n Public API with pagination and error classification,
// and decodes the records the resources read.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// Workflow is a workflow record from GET /workflows.
type Workflow struct {
	ID              string
	Name            string
	ActiveVersionID string
	IsArchived      bool
	VersionID       string
	TriggerCount    int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
	TagIDs          []string
	Nodes           []Node
	Settings        WorkflowSettings
}

// Active reports whether the workflow has a published version that runs on
// its triggers. The `active` flag on the record is deprecated upstream in
// favor of checking activeVersionId.
func (w Workflow) Active() bool {
	return w.ActiveVersionID != ""
}

// WorkflowSettings holds the execution settings of a workflow. Empty strings
// and nil pointers mean the setting is not set on the workflow, so the
// instance default applies.
type WorkflowSettings struct {
	CallerPolicy             string
	CallerIDs                []string
	ErrorWorkflowID          string
	ExecutionOrder           string
	ExecutionTimeout         *int64
	Timezone                 string
	SaveDataErrorExecution   string
	SaveDataSuccessExecution string
	RedactionPolicy          string
	AvailableInMCP           *bool
}

// Node is one node of a workflow. Parameters are free-form per node type and
// can hold secrets typed in directly, such as header values or code, so only
// the security settings in nodeSecurity are read from them (see node.go).
type Node struct {
	ID            string
	Name          string
	Type          string
	TypeVersion   float64
	Disabled      bool
	WebhookID     string
	OnError       string
	RetryOnFail   bool
	CredentialIDs []string
	nodeSecurity
}

// Credential is a credential record from GET /credentials. The API never
// returns the secret data.
type Credential struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// User is a user record from GET /users.
type User struct {
	ID         string     `json:"id"`
	Email      string     `json:"email"`
	FirstName  string     `json:"firstName"`
	LastName   string     `json:"lastName"`
	Role       string     `json:"role"`
	IsPending  *bool      `json:"isPending"`
	MfaEnabled *bool      `json:"mfaEnabled"`
	CreatedAt  *time.Time `json:"createdAt"`
	UpdatedAt  *time.Time `json:"updatedAt"`
}

// Tag is a tag record from GET /tags.
type Tag struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt *time.Time `json:"createdAt"`
	UpdatedAt *time.Time `json:"updatedAt"`
}

// CommunityPackage is an installed community node package.
type CommunityPackage struct {
	Name             string
	InstalledVersion string
	UpdateAvailable  string
	FailedLoading    bool
	AuthorName       string
	AuthorEmail      string
	NodeTypes        []string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// AuditReport is one risk report of the security audit, for example the
// credentials or the nodes report.
type AuditReport struct {
	Risk     string         `json:"risk"`
	Sections []AuditSection `json:"sections"`
}

// AuditSection is one finding of a risk report. Locations point at the
// workflows, nodes, credentials, or community packages the finding is about;
// their shape depends on the `kind` key of each location.
type AuditSection struct {
	Title          string           `json:"title"`
	Description    string           `json:"description"`
	Recommendation string           `json:"recommendation"`
	Locations      []map[string]any `json:"location"`
	Settings       map[string]any   `json:"settings"`
}

// The record types below mirror the JSON the Public API returns, as read
// from a live instance. Fields the provider does not read are left out.

type page[T any] struct {
	Data       []T     `json:"data"`
	NextCursor *string `json:"nextCursor"`
}

type workflowRecord struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	ActiveVersionID *string   `json:"activeVersionId"`
	IsArchived      bool      `json:"isArchived"`
	VersionID       string    `json:"versionId"`
	TriggerCount    int64     `json:"triggerCount"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
	Tags            []struct {
		ID string `json:"id"`
	} `json:"tags"`
	Nodes    []nodeRecord    `json:"nodes"`
	Settings *settingsRecord `json:"settings"`
}

type nodeRecord struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	TypeVersion float64        `json:"typeVersion"`
	Disabled    bool           `json:"disabled"`
	Parameters  map[string]any `json:"parameters"`
	WebhookID   string         `json:"webhookId"`
	OnError     string         `json:"onError"`
	RetryOnFail bool           `json:"retryOnFail"`
	Credentials map[string]any `json:"credentials"`
}

type settingsRecord struct {
	CallerPolicy             string   `json:"callerPolicy"`
	CallerIDs                string   `json:"callerIds"`
	ErrorWorkflow            string   `json:"errorWorkflow"`
	ExecutionOrder           string   `json:"executionOrder"`
	ExecutionTimeout         *float64 `json:"executionTimeout"`
	Timezone                 string   `json:"timezone"`
	SaveDataErrorExecution   string   `json:"saveDataErrorExecution"`
	SaveDataSuccessExecution string   `json:"saveDataSuccessExecution"`
	RedactionPolicy          string   `json:"redactionPolicy"`
	AvailableInMCP           *bool    `json:"availableInMCP"`
}

type communityPackageRecord struct {
	PackageName      string    `json:"packageName"`
	InstalledVersion string    `json:"installedVersion"`
	UpdateAvailable  string    `json:"updateAvailable"`
	FailedLoading    bool      `json:"failedLoading"`
	AuthorName       string    `json:"authorName"`
	AuthorEmail      string    `json:"authorEmail"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
	InstalledNodes   []struct {
		Type string `json:"type"`
	} `json:"installedNodes"`
}

type discoverRecord struct {
	Data struct {
		Scopes []string `json:"scopes"`
	} `json:"data"`
}

// Workflows lists every workflow, including archived ones. Pinned data is
// excluded: it holds sample execution data, which is not configuration.
func (c *Client) Workflows(ctx context.Context) ([]Workflow, error) {
	records, err := listAll[workflowRecord](ctx, c, "/workflows", url.Values{"excludePinnedData": {"true"}}, "workflow:list")
	if err != nil {
		return nil, err
	}
	out := make([]Workflow, 0, len(records))
	for _, r := range records {
		out = append(out, toWorkflow(r))
	}
	return out, nil
}

func toWorkflow(r workflowRecord) Workflow {
	wf := Workflow{
		ID:           r.ID,
		Name:         r.Name,
		IsArchived:   r.IsArchived,
		VersionID:    r.VersionID,
		TriggerCount: r.TriggerCount,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
	if r.ActiveVersionID != nil {
		wf.ActiveVersionID = *r.ActiveVersionID
	}
	for _, t := range r.Tags {
		if t.ID != "" {
			wf.TagIDs = append(wf.TagIDs, t.ID)
		}
	}
	for _, n := range r.Nodes {
		wf.Nodes = append(wf.Nodes, Node{
			ID:            n.ID,
			Name:          n.Name,
			Type:          n.Type,
			TypeVersion:   n.TypeVersion,
			Disabled:      n.Disabled,
			WebhookID:     n.WebhookID,
			OnError:       n.OnError,
			RetryOnFail:   n.RetryOnFail,
			CredentialIDs: nodeCredentialIDs(n.Credentials),
			nodeSecurity:  readNodeSecurity(n.Type, n.TypeVersion, n.Parameters),
		})
	}
	if s := r.Settings; s != nil {
		wf.Settings = WorkflowSettings{
			CallerPolicy:             s.CallerPolicy,
			CallerIDs:                splitList(s.CallerIDs),
			ErrorWorkflowID:          s.ErrorWorkflow,
			ExecutionOrder:           s.ExecutionOrder,
			Timezone:                 s.Timezone,
			SaveDataErrorExecution:   s.SaveDataErrorExecution,
			SaveDataSuccessExecution: s.SaveDataSuccessExecution,
			RedactionPolicy:          s.RedactionPolicy,
			AvailableInMCP:           s.AvailableInMCP,
		}
		if s.ExecutionTimeout != nil {
			v := int64(*s.ExecutionTimeout)
			wf.Settings.ExecutionTimeout = &v
		}
	}
	return wf
}

// nodeCredentialIDs reads the credential IDs a node references. The map is
// keyed by credential type, and each value names the credential by id and
// name, for example {"httpHeaderAuth": {"id": "Y2IL...", "name": "Jira"}}.
// Workflows imported from templates can carry a name without an id; those
// reference no stored credential and are skipped.
func nodeCredentialIDs(creds map[string]any) []string {
	var ids []string
	for _, v := range creds {
		ref, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if id, ok := ref["id"].(string); ok && id != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// Credentials lists every credential the API key can see.
func (c *Client) Credentials(ctx context.Context) ([]Credential, error) {
	return listAll[Credential](ctx, c, "/credentials", nil, "credential:list")
}

// Users lists every user of the instance, with the global role.
func (c *Client) Users(ctx context.Context) ([]User, error) {
	return listAll[User](ctx, c, "/users", url.Values{"includeRole": {"true"}}, "user:list")
}

// Tags lists every tag.
func (c *Client) Tags(ctx context.Context) ([]Tag, error) {
	return listAll[Tag](ctx, c, "/tags", nil, "tag:list")
}

// CommunityPackages lists the installed community node packages. The
// endpoint returns the whole list in one response.
func (c *Client) CommunityPackages(ctx context.Context) ([]CommunityPackage, error) {
	body, err := c.do(ctx, http.MethodGet, "/community-packages", nil, nil, "communityPackage:list")
	if err != nil {
		return nil, err
	}
	var records []communityPackageRecord
	if err := decode(body, &records, "community packages"); err != nil {
		return nil, err
	}
	out := make([]CommunityPackage, 0, len(records))
	for _, r := range records {
		p := CommunityPackage{
			Name:             r.PackageName,
			InstalledVersion: r.InstalledVersion,
			UpdateAvailable:  r.UpdateAvailable,
			FailedLoading:    r.FailedLoading,
			AuthorName:       r.AuthorName,
			AuthorEmail:      r.AuthorEmail,
			CreatedAt:        r.CreatedAt,
			UpdatedAt:        r.UpdatedAt,
		}
		for _, n := range r.InstalledNodes {
			if n.Type != "" {
				p.NodeTypes = append(p.NodeTypes, n.Type)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// APIKeyScopes returns the scopes of the API key the provider authenticates
// with.
func (c *Client) APIKeyScopes(ctx context.Context) ([]string, error) {
	body, err := c.do(ctx, http.MethodGet, "/discover", nil, nil, "")
	if err != nil {
		return nil, err
	}
	var rec discoverRecord
	if err := decode(body, &rec, "discover"); err != nil {
		return nil, err
	}
	return rec.Data.Scopes, nil
}

// Audit runs the instance's built-in security audit over every risk
// category. n8n computes the report on request; it does not change the
// instance.
func (c *Client) Audit(ctx context.Context) ([]AuditReport, error) {
	body, err := c.do(ctx, http.MethodPost, "/audit", nil, []byte(`{}`), "securityAudit:generate")
	if err != nil {
		return nil, err
	}
	return decodeAudit(body)
}

// decodeAudit reads the audit body: an object keyed by report title, such as
// "Credentials Risk Report", or an empty array when no category found a risk.
// Reports are returned in title order.
func decodeAudit(body []byte) ([]AuditReport, error) {
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
		var empty []any
		if err := decode(body, &empty, "audit report"); err != nil {
			return nil, err
		}
		return []AuditReport{}, nil
	}
	var byTitle map[string]AuditReport
	if err := decode(body, &byTitle, "audit report"); err != nil {
		return nil, err
	}
	titles := make([]string, 0, len(byTitle))
	for t := range byTitle {
		titles = append(titles, t)
	}
	sort.Strings(titles)
	out := make([]AuditReport, 0, len(titles))
	for _, t := range titles {
		out = append(out, byTitle[t])
	}
	return out, nil
}

// listAll walks a cursor-paginated collection.
func listAll[T any](ctx context.Context, c *Client, path string, query url.Values, scope string) ([]T, error) {
	var out []T
	err := walkCursor(func(cursor *string) (*string, error) {
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		q.Set("limit", pageLimit)
		if cursor != nil {
			q.Set("cursor", *cursor)
		}
		body, err := c.do(ctx, http.MethodGet, path, q, nil, scope)
		if err != nil {
			return nil, err
		}
		var p page[T]
		if err := decode(body, &p, strings.TrimPrefix(path, "/")); err != nil {
			return nil, err
		}
		out = append(out, p.Data...)
		return p.NextCursor, nil
	})
	return out, err
}

// do sends one request and returns the response body, or the classified
// error for a non-2xx answer. scope names the API key scope the endpoint
// requires, when one does.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body []byte, scope string) ([]byte, error) {
	u := c.baseURL + "/api/v1" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set(apiKeyHeader, c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, transportError(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, transportError(err)
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("n8n API %s %s: response larger than %d MB", method, path, maxResponseBytes>>20)
	}
	if err := responseError(resp, data, scope); err != nil {
		return nil, err
	}
	return data, nil
}

func decode(body []byte, out any, what string) error {
	if err := json.Unmarshal(body, out); err != nil {
		return llx.MalformedData(fmt.Errorf("n8n API returned an unexpected %s response: %w", what, err))
	}
	return nil
}

// walkCursor calls fetch once per page, passing the cursor the previous page
// returned, until a page returns no cursor. A cursor the API already returned
// means the walk would never end, so it stops there with an error.
func walkCursor(fetch func(cursor *string) (*string, error)) error {
	var cursor *string
	seen := map[string]struct{}{}
	for page := 0; page < maxPages; page++ {
		next, err := fetch(cursor)
		if err != nil {
			return err
		}
		if next == nil || *next == "" {
			return nil
		}
		if _, ok := seen[*next]; ok {
			return fmt.Errorf("n8n API returned the cursor %q twice", *next)
		}
		seen[*next] = struct{}{}
		cursor = next
	}
	return fmt.Errorf("n8n API pagination did not finish after %d pages", maxPages)
}

// apiErrorBody is the error envelope the Public API returns.
type apiErrorBody struct {
	Message string `json:"message"`
}

// licenseDeniedMarker starts the message n8n returns when the instance's
// license does not include the feature an endpoint belongs to, for example
// "Your license does not allow for feat:variables. ...".
const licenseDeniedMarker = "your license does not allow"

// responseError classifies a non-2xx response by what the instance said.
// scope names the API key scope the endpoint requires, when one does.
func responseError(resp *http.Response, body []byte, scope string) error {
	if resp == nil {
		return llx.Unavailable(errors.New("n8n API returned no response"))
	}
	status := resp.StatusCode
	if status >= 200 && status < 300 {
		return nil
	}

	msg := strings.TrimSpace(string(body))
	var parsed apiErrorBody
	if json.Unmarshal(body, &parsed) == nil && parsed.Message != "" {
		msg = parsed.Message
	}
	if msg == "" {
		msg = http.StatusText(status)
	}
	err := fmt.Errorf("n8n API: %d %s", status, msg)
	if req := resp.Request; req != nil && req.URL != nil {
		err = fmt.Errorf("n8n API %s %s: %d %s", req.Method, req.URL.Path, status, msg)
	}

	switch {
	case status == http.StatusUnauthorized:
		// The key is missing, revoked, or expired, so every call on the
		// connection fails the same way.
		return llx.Unauthenticated(err, llx.WithScope(llx.ErrorScope_ERROR_SCOPE_ASSET, ""))
	case status == http.StatusForbidden && strings.Contains(strings.ToLower(msg), licenseDeniedMarker):
		return llx.NotApplicable(err)
	case status == http.StatusForbidden:
		if scope != "" {
			return llx.Forbidden(err, llx.WithPermissions(scope))
		}
		return llx.Forbidden(err)
	case status == http.StatusTooManyRequests:
		var opts []llx.ErrorOption
		if d, ok := retryAfter(resp.Header.Get("Retry-After")); ok {
			opts = append(opts, llx.WithRetryAfter(d))
		}
		return llx.TooManyRequests(err, opts...)
	case status >= 500:
		return llx.Unavailable(err)
	default:
		return err
	}
}

// retryAfter reads a Retry-After header given in seconds.
func retryAfter(v string) (time.Duration, bool) {
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || secs < 0 {
		return 0, false
	}
	return time.Duration(secs) * time.Second, true
}

// transportError classifies a request that never got a response. Timeouts,
// refused connections, and failed lookups mean the instance is not reachable.
func transportError(err error) error {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return llx.Unavailable(err)
	}
	return err
}

// splitList splits a comma-separated list, dropping blanks.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

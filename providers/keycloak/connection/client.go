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
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
)

// APIError captures a non-2xx response from the Keycloak admin API.
type APIError struct {
	StatusCode int
	Message    string
	Path       string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("keycloak API %s: %d (%s)", e.Path, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("keycloak API %s: %d", e.Path, e.StatusCode)
}

// IsForbidden reports whether err is a 401 or 403 response. Callers degrade
// such a field to null rather than failing the scan, since an admin role can
// grant view-realm without view-users and a service account is often scoped to
// a single realm.
func IsForbidden(err error) bool {
	if apiErr, ok := errors.AsType[*APIError](err); ok {
		return apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden
	}
	return false
}

// IsNotFound reports whether err is a 404 response.
func IsNotFound(err error) bool {
	if apiErr, ok := errors.AsType[*APIError](err); ok {
		return apiErr.StatusCode == http.StatusNotFound
	}
	return false
}

// AdminPath builds a path under the admin API for the given realm. Each segment
// is escaped, since a realm, a group name or a flow alias can carry characters
// that are otherwise read as path structure.
func AdminPath(realm string, segments ...string) string {
	var path strings.Builder
	path.WriteString("/admin/realms/" + url.PathEscape(realm))
	for _, s := range segments {
		path.WriteString("/" + url.PathEscape(s))
	}
	return path.String()
}

// Get performs a GET against the admin API and decodes the JSON body into out.
func (c *KeycloakConnection) Get(ctx context.Context, path string, query url.Values, out any) error {
	body, err := c.do(ctx, path, query)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("keycloak API %s: decode response: %w", path, err)
	}
	return nil
}

func (c *KeycloakConnection) do(ctx context.Context, path string, query url.Values) ([]byte, error) {
	body, status, err := c.request(ctx, path, query)
	if err != nil {
		return nil, err
	}

	// A token the cache still holds can be rejected after a session is revoked
	// or after the server restarts. Mint a new one and try once more before
	// reporting the failure, so a scan is not lost to a single stale token.
	if status == http.StatusUnauthorized {
		c.tokens.Invalidate()
		body, status, err = c.request(ctx, path, query)
		if err != nil {
			return nil, err
		}
	}

	if status < 200 || status >= 300 {
		return nil, newAPIError(path, status, body)
	}
	return body, nil
}

func newAPIError(path string, status int, body []byte) *APIError {
	apiErr := &APIError{StatusCode: status, Path: path}
	var envelope struct {
		Error            string `json:"error"`
		ErrorMessage     string `json:"errorMessage"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(body, &envelope) == nil {
		for _, candidate := range []string{envelope.ErrorMessage, envelope.ErrorDescription, envelope.Error} {
			if candidate != "" {
				apiErr.Message = candidate
				break
			}
		}
	}
	return apiErr
}

func (c *KeycloakConnection) request(ctx context.Context, path string, query url.Values) ([]byte, int, error) {
	token, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, 0, err
	}

	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("keycloak API %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("keycloak API %s: read response: %w", path, err)
	}
	return body, resp.StatusCode, nil
}

// pageSize is how many records are requested per page. Keycloak caps several
// list endpoints well below this, and answering a short page ends the walk, so
// a server-side cap costs an extra request rather than losing records.
const pageSize = 100

// maxPages bounds a paginated walk. An endpoint that ignores the first
// parameter answers every request with the same page, which would otherwise
// loop until the realm's user count is multiplied by the cap.
const maxPages = 500

// FullRepresentation asks a list endpoint for the complete record. Several
// endpoints, among them groups and roles, answer with a brief representation
// by default, which omits the attributes and the role mappings. Reading those
// fields from a brief response would report them as empty rather than as
// absent.
func FullRepresentation() url.Values {
	return url.Values{"briefRepresentation": []string{"false"}}
}

// GetPaged walks the first and max pagination the admin API list endpoints use
// and returns every record. Endpoints that ignore paging return their single
// response unchanged.
func GetPaged[T any](ctx context.Context, c *KeycloakConnection, path string, query url.Values) ([]T, error) {
	page := url.Values{}
	maps.Copy(page, query)
	page.Set("max", strconv.Itoa(pageSize))

	var results []T
	var previous []byte
	complete := false
	for i := range maxPages {
		page.Set("first", strconv.Itoa(i*pageSize))

		body, err := c.do(ctx, path, page)
		if err != nil {
			return nil, err
		}

		// An endpoint that ignores first answers every request with the same
		// page. Detect that by the response repeating verbatim and stop,
		// instead of appending the same records until the page cap is reached.
		if previous != nil && bytes.Equal(previous, body) {
			complete = true
			break
		}
		previous = body

		var batch []T
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, fmt.Errorf("keycloak API %s: decode response: %w", path, err)
		}

		results = append(results, batch...)

		// A short page is the last page.
		if len(batch) < pageSize {
			complete = true
			break
		}
	}

	// Reaching the cap means the endpoint still had records to give. Say so,
	// because a caller that reads a truncated list as the whole list reports
	// an absence that was never established.
	if !complete {
		log.Warn().
			Str("path", path).
			Int("records", len(results)).
			Int("pages", maxPages).
			Msg("keycloak> stopped paging at the page cap, the list is incomplete")
	}

	return results, nil
}

// Query parameters that ask a client policy endpoint for the profiles and
// policies Keycloak ships alongside the realm's own. The two endpoints spell
// the parameter differently, and the policies endpoint has used more than one
// spelling across versions.
const (
	IncludeGlobalProfilesParam = "include-global-profiles"
	IncludeGlobalPoliciesParam = "include-global-policies"
	// IncludeGlobalClientPoliciesParam is the spelling some versions use for
	// the policies endpoint.
	IncludeGlobalClientPoliciesParam = "include-global-client-policies"
)

// IncludeGlobals asks an endpoint for the built-in records as well as the
// realm's own. A policy may name a built-in profile, so reading only the
// realm's own would report that profile as missing.
//
// Every given key is sent. Keycloak ignores a query parameter it does not
// know, so naming both spellings of the policies parameter is harmless and
// avoids silently dropping the built-in records on whichever version spells it
// the other way.
func IncludeGlobals(keys ...string) url.Values {
	query := url.Values{}
	for _, key := range keys {
		query.Set(key, "true")
	}
	return query
}

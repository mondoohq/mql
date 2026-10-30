// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
)

// errNoAccountBound guards the account-scoped accessors. An empty account id
// interpolates into a request against /accounts//… , which the API answers 404;
// isUnavailable then degrades that to an empty list, so a malformed request
// reads as "nothing configured" and any all()/none() check over it passes. Fail
// instead, so the query reports why it could not run.
var errNoAccountBound = errors.New("no Cloudflare account bound to this resource")

// connectionAccountID returns the account this connection is scoped to, read
// from the asset's platform id — the same source initCloudflareAccount uses to
// resolve the singular cloudflare.account.
//
// Account-scoped resources reached bare (cloudflare.r2, cloudflare.workers) have
// no parent to inherit an account from, so they resolve it through this.
func connectionAccountID(runtime *plugin.Runtime) (string, error) {
	conn, ok := runtime.Connection.(*connection.CloudflareConnection)
	if !ok || conn.Asset() == nil {
		return "", errors.New("no asset found")
	}

	for _, platformID := range conn.Asset().PlatformIds {
		if accID, ok := strings.CutPrefix(platformID, connection.PlatformIdCloudflareAccount); ok {
			return accID, nil
		}
	}
	return "", errors.New("cannot determine the Cloudflare account for this asset; " +
		"scan an account, or reach this resource through cloudflare.account")
}

// timeOrNil converts a cloudflare-go time.Time value into MQL time data,
// returning a null value when the timestamp is the zero value. The current SDK
// models optional/nullable timestamps as a plain time.Time (a JSON `null`
// decodes to the zero value), whereas the v0 SDK used *time.Time. This helper
// preserves the original null semantics in the MQL schema.
func timeOrNil(t time.Time) *llx.RawData {
	if t.IsZero() {
		return llx.NilData
	}
	tt := t
	return llx.TimeDataPtr(&tt)
}

// cfGetPaged walks a page-numbered Cloudflare list endpoint via the client's
// generic Get, decoding each page's `result` array into T and following
// `result_info.total_pages`. It's used for endpoints whose typed cloudflare-go
// representation is a polymorphic union (or drops fields we expose), where
// decoding the raw payload into our own shape is simpler and preserves the MQL
// schema. uriBase is the path without pagination query params.
func cfGetPaged[T any](conn *connection.CloudflareConnection, uriBase string) ([]T, error) {
	var all []T
	page := 1
	for {
		var env struct {
			Result     []T `json:"result"`
			ResultInfo struct {
				Page       int `json:"page"`
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}
		sep := "?"
		if strings.Contains(uriBase, "?") {
			sep = "&"
		}
		uri := fmt.Sprintf("%s%spage=%d&per_page=100", uriBase, sep, page)
		if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
			return nil, err
		}
		all = append(all, env.Result...)
		// Terminate on the local page counter, not the server-echoed
		// ResultInfo.Page: if the API ever returned page:0 with total_pages>0
		// the echoed-page comparison would never satisfy and the loop would
		// spin forever appending empty pages.
		if env.ResultInfo.TotalPages == 0 || page >= env.ResultInfo.TotalPages {
			break
		}
		page++
	}
	return all, nil
}

// degradedList maps an unavailable-resource error (401/403/404, via
// isUnavailable) to an empty list, so a gated add-on or permission-limited
// collection endpoint reads as "nothing here" instead of failing the whole
// query. Other errors propagate unchanged. Callers use it as the error branch
// of a list accessor: `if err != nil { return degradedList(err) }`.
func degradedList(err error) ([]any, error) {
	if isUnavailable(err) {
		return []any{}, nil
	}
	return nil, err
}

// cloudflareTimeLayouts are the timestamp formats seen on Cloudflare endpoints
// that report a date as a JSON string rather than an RFC 3339 timestamp. The
// client-certificate and content-scanning endpoints are the two cases we hit:
// both type the field as a string in cloudflare-go, and the wire format
// varies between RFC 3339 and Go's default time.Time rendering.
var cloudflareTimeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02 15:04:05.999999999 -0700 MST",
	"2006-01-02 15:04:05 -0700 MST",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

// parseCloudflareTime parses a string-typed Cloudflare timestamp, trying each
// known layout in turn. It reports false for an empty or unrecognized value so
// callers can surface the field as null rather than as a zero time, which would
// read as January 1 year 1 in a query result.
//
// This is a superset of parseRFC3339 in devices.go, which stays strict because
// the device endpoints are documented to emit RFC 3339. Use this one for the
// endpoints that type a date as a plain string in cloudflare-go, where the
// layout is not guaranteed.
func parseCloudflareTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range cloudflareTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// cfTimeString converts a string-typed Cloudflare timestamp into MQL time data,
// yielding null when the value is absent or unparseable.
func cfTimeString(s string) *llx.RawData {
	t, ok := parseCloudflareTime(s)
	if !ok {
		return llx.NilData
	}
	return llx.TimeDataPtr(&t)
}

// credentialScopeCodes are the Cloudflare error codes that blame the caller's
// credentials rather than the resource: the token is the wrong kind, or lacks the
// permission outright. The API still answers 403, so status alone cannot tell
// them apart from a plan-gated or unprovisioned product.
//
// They must not degrade to an empty result. cnspec scores on what the provider
// returns, so an empty list makes `list.all(...)`/`none(...)` pass vacuously and
// the account is reported compliant on data that was never read. An account with
// five API tokens scanned by an account-scoped token hits exactly this: the
// user-scoped token endpoint answers 9109, and all three api-token checks pass.
// Surfacing the error makes those checks report as errored, which is visible.
//
// The deny-list stays deliberately narrow. Cloudflare overloads 403 for
// plan-gated features too (bot management, leaked-credential checks, security.txt
// on a free zone), and those carry the generic code 10000. A zone whose plan does
// not include a feature genuinely has nothing to assess, so those keep degrading.
var credentialScopeCodes = map[int64]struct{}{
	// "Valid user-level authentication not found" — an account-scoped token used
	// against a user-scoped endpoint such as /user/tokens.
	9109: {},
	// "Authorization Failure: The authentication credentials are not authorized
	// to perform the request. Verify the credentials and try again."
	10002: {},
}

// isUnavailable reports whether err may be degraded to a null/empty result
// instead of failing the query.
//
// 401, 403, and 404 mean the resource isn't available to the calling token — an
// unsupported plan, an unprovisioned product, or an absent resource — and empty
// is the honest answer for those. The exception is a failure the API attributes
// to the credentials themselves, which says nothing about whether the resource
// exists and so must surface. See credentialScopeCodes.
//
// cloudflare-go collapses the v0 typed *AuthenticationError/*AuthorizationError/
// *NotFoundError into a single *cloudflare.Error with a StatusCode.
func isUnavailable(err error) bool {
	var apiErr *cloudflare.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		if isCredentialScope(apiErr) {
			return false
		}
	case http.StatusNotFound:
	default:
		return false
	}
	logDegraded(apiErr)
	return true
}

// logDegraded records that a response was turned into an empty/null result. The
// scan still succeeds, so without this the difference between "nothing is
// configured" and "nothing was readable" leaves no trace at all. Mirrors the
// warning the AWS provider emits when it degrades an AccessDenied region
// (providers/aws/resources/aws_acm.go).
func logDegraded(apiErr *cloudflare.Error) {
	ev := log.Warn().Int("status", apiErr.StatusCode)
	if apiErr.Request != nil && apiErr.Request.URL != nil {
		ev = ev.Str("path", apiErr.Request.URL.Path)
	}
	if len(apiErr.Errors) > 0 {
		ev = ev.Int64("code", apiErr.Errors[0].Code).Str("error", apiErr.Errors[0].Message)
	}
	ev.Msg("cloudflare> no data returned; reporting an empty result for this resource")
}

// isCredentialScope reports whether the API blamed the caller's credentials, as
// opposed to the resource being absent or not enabled.
func isCredentialScope(apiErr *cloudflare.Error) bool {
	for _, e := range apiErr.Errors {
		if _, ok := credentialScopeCodes[e.Code]; ok {
			return true
		}
	}
	return false
}

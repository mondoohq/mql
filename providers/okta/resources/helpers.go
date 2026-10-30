// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/resources/sdk"
)

// The Okta SDK is OpenAPI-generated and models most scalars as a pointer so it
// can distinguish "unset" from a zero value. These helpers dereference those
// pointers back to the zero-value semantics the resource mappers (and existing
// MQL queries) expect.

func oktaStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// oktaTimeFromUnixMillis converts a Unix millisecond timestamp to a time.
//
// A nil timestamp stays nil so the field reports null rather than the Unix
// epoch, which would read as a real date in 1970 rather than as "never
// connected" or "not reported".
func oktaTimeFromUnixMillis(ms *int64) *time.Time {
	if ms == nil {
		return nil
	}
	t := time.UnixMilli(*ms).UTC()
	return &t
}

// oktaInt64 widens an optional 32-bit count to the width llx reports ints at,
// keeping nil as nil so an unreported count stays null rather than becoming a
// confident zero.
func oktaInt64(v *int32) *int64 {
	if v == nil {
		return nil
	}
	widened := int64(*v)
	return &widened
}

// oktaStrFrom reads a string out of a value the SDK collected into
// AdditionalProperties, yielding "" when the key was absent or held something
// other than a string. See oktaStringMapFrom for why these reads exist.
func oktaStrFrom(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// oktaAnySliceFrom reads a list out of a value the SDK collected into
// AdditionalProperties, in the shape llx.ArrayData expects. A missing key or a
// non-list value yields an empty list.
func oktaAnySliceFrom(v any) []any {
	items, ok := v.([]any)
	if !ok {
		return []any{}
	}
	return items
}

// oktaStringMapFrom reads a string-keyed map out of a value the SDK collected
// into AdditionalProperties.
//
// The generated models drop fields between releases while the API keeps
// sending them, and anything the model does not declare lands in
// AdditionalProperties instead. Reading from there keeps a shipped MQL field
// populated rather than silently reporting empty, which would read as "there
// is nothing set" when the value was in the response all along.
//
// Values that are not strings are rendered through their JSON encoding, so a
// nested object reaches the caller as its serialized form rather than being
// dropped. A missing or non-object value yields an empty map.
func oktaStringMapFrom(v any) map[string]any {
	out := map[string]any{}
	m, ok := v.(map[string]any)
	if !ok {
		return out
	}
	for k, val := range m {
		switch s := val.(type) {
		case string:
			out[k] = s
		case nil:
			out[k] = ""
		default:
			if raw, err := json.Marshal(val); err == nil {
				out[k] = string(raw)
			}
		}
	}
	return out
}

// resolveOktaResourceTarget maps an Okta resource reference (an ORN and/or a
// self-link URL) to a modeled resource type and id. It returns "user",
// "group", or "application" with the target id, or two empty strings when the
// reference does not name one of those resources.
//
// ORN form:  orn:okta:<service>:<orgId>:<resourceType>:<id>[:...]
// URL form:  https://<org>/api/v1/<collection>/<id>[/...]
func resolveOktaResourceTarget(orn, href string) (targetType string, id string) {
	if orn != "" {
		parts := strings.Split(orn, ":")
		for i := 0; i+1 < len(parts); i++ {
			switch parts[i] {
			case "users":
				return "user", parts[i+1]
			case "groups":
				return "group", parts[i+1]
			case "apps":
				// app ORNs carry an app-type segment before the id
				// (orn:okta:idp:<org>:apps:<appType>:<appId>).
				return "application", parts[len(parts)-1]
			}
		}
	}

	if href != "" {
		for _, m := range []struct{ seg, typ string }{
			{"/users/", "user"},
			{"/groups/", "group"},
			{"/apps/", "application"},
		} {
			if i := strings.Index(href, m.seg); i >= 0 {
				rest := href[i+len(m.seg):]
				if j := strings.IndexByte(rest, '/'); j >= 0 {
					rest = rest[:j]
				}
				if rest != "" {
					return m.typ, rest
				}
			}
		}
	}

	return "", ""
}

// oktaLinkHref extracts an href from an Okta HAL `_links` entry, which the
// SDK surfaces as an untyped map[string]interface{} of the shape
// {"href": "..."}. Returns "" when the entry is missing or malformed.
func oktaLinkHref(link any) string {
	m, ok := link.(map[string]any)
	if !ok {
		return ""
	}
	href, ok := m["href"].(string)
	if !ok {
		return ""
	}
	return href
}

// lastPathSegment returns the final non-empty segment of a URL path.
func lastPathSegment(s string) string {
	s = strings.TrimRight(s, "/")
	if _, after, ok := strings.CutLast(s, "/"); ok {
		return after
	}
	return s
}

// oktaRoleIdFromPermissionsHref pulls a custom-role id out of a permissions
// self-link of the form ".../iam/roles/<roleId>/permissions".
func oktaRoleIdFromPermissionsHref(href string) string {
	const marker = "/roles/"
	_, after, ok := strings.Cut(href, marker)
	if !ok {
		return ""
	}
	rest := after
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// oktaCollectPages appends every remaining page of a paginated SDK call to the
// first page already fetched. The SDK exposes paging through the response
// rather than the request, so callers pass both back in and receive the full
// collection.
func oktaCollectPages[T any](first []T, resp *okta.APIResponse) ([]T, error) {
	all := first
	for resp != nil && resp.HasNextPage() {
		var page []T
		var err error
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
	}
	return all, nil
}

// oktaUnreadableList marks a list field as read but absent, for the case where
// the org will not answer for it at all: an unlicensed feature, a retired
// endpoint, or a token whose admin role cannot reach it. Returning an empty
// slice instead would report "this account has none" as fact, and an audit
// written on that list would pass without anything having been checked.
func oktaUnreadableList(field *plugin.TValue[[]any]) ([]any, error) {
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func oktaBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

// oktaErrCodeFeatureNotEnabled is the Okta error code for a feature the org is
// not licensed for. Okta answers it with 401 rather than 403, which is the same
// status it uses for a token that is invalid or expired (E0000011), so the two
// can only be told apart by the code in the body.
const oktaErrCodeFeatureNotEnabled = "E0000015"

// oktaErrorCode returns the Okta error code (for example "E0000015") carried in
// an API error's response body, or "" when the error is not an Okta API error
// or the body does not parse. The SDK only decodes the error model for a
// couple of status codes but always keeps the raw body, so the body is the one
// place the code can be read from reliably.
func oktaErrorCode(err error) string {
	var apiErr *okta.GenericOpenAPIError
	if !errors.As(err, &apiErr) {
		return ""
	}
	var body struct {
		ErrorCode string `json:"errorCode"`
	}
	if json.Unmarshal(apiErr.Body(), &body) != nil {
		return ""
	}
	return body.ErrorCode
}

// isOktaFeatureUnavailable reports whether an API error means the org simply
// does not have the thing being asked about, rather than that the request
// failed. Okta answers 404 for an endpoint belonging to a feature the org has
// not enabled, 410 for one that has been retired, 403 when the token's admin
// role cannot reach it, and 401 E0000015 for a feature the org is not licensed
// for. All of those describe an org with nothing to report, so callers degrade
// to an empty result instead of failing the query and taking every other
// resource in the scan down with them.
//
// A bare 401 is deliberately not enough: it is also what an invalid or expired
// token returns, and degrading that would report a dead credential as a clean,
// empty scan.
func isOktaFeatureUnavailable(resp *okta.APIResponse, err error) bool {
	// The SDK wraps a nil *http.Response in a non-nil *APIResponse whenever the
	// request never produced a response at all (a transport error, or a
	// rate-limit retry that ran out of attempts). StatusCode is a promoted
	// field, so reading it in that state dereferences the nil embed and panics.
	if err == nil || resp == nil || resp.Response == nil {
		return false
	}
	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusNotFound, http.StatusGone:
		return true
	case http.StatusUnauthorized:
		return oktaErrorCode(err) == oktaErrCodeFeatureNotEnabled
	}
	return false
}

// isOktaRawFeatureUnavailable is isOktaFeatureUnavailable for the endpoints
// served outside the generated SDK. Those hand back a bare *http.Response and a
// *sdk.APIError rather than the SDK's wrappers, but the reading is the same: an
// org with nothing to report rather than a request that failed.
//
// The status can come from either argument. A caller that kept the response
// passes it; one that only kept the error still classifies correctly, because
// the error carries the status too. A bare 401 stays an error here as well, so
// a dead credential is never reported as a clean, empty result.
func isOktaRawFeatureUnavailable(resp *http.Response, err error) bool {
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}

	code := ""
	if apiErr, ok := errors.AsType[*sdk.APIError](err); ok {
		code = apiErr.Code
		if status == 0 {
			status = apiErr.StatusCode
		}
	}

	switch status {
	case http.StatusForbidden, http.StatusNotFound, http.StatusGone:
		return true
	case http.StatusUnauthorized:
		return code == oktaErrCodeFeatureNotEnabled
	}
	return false
}

// errOktaResourceNotFound marks a reference to an object the org does not
// expose through the API: a deleted user, an internal application that is
// absent from `/api/v1/apps`, or a principal id that belongs to something other
// than the resource being resolved (Okta stamps `createdBy` with system
// principal ids that are not users). Reference accessors report it as a null
// field rather than failing the whole collection they were read from.
var errOktaResourceNotFound = errors.New("okta resource not found")

// isOktaStatus reports whether a response carries the given status code. Like
// the classifiers above it tolerates the SDK's response-less *APIResponse.
func isOktaStatus(resp *okta.APIResponse, status int) bool {
	return resp != nil && resp.Response != nil && resp.StatusCode == status
}

// isOktaNotFound reports whether a response says the object does not exist.
func isOktaNotFound(resp *okta.APIResponse) bool {
	return isOktaStatus(resp, http.StatusNotFound)
}

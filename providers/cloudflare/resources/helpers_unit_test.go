// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestTimeOrNil(t *testing.T) {
	// A zero time (how the SDK models a JSON null timestamp) must resolve to
	// MQL null, not the 0001-01-01 zero value — the basis of the null-time fix.
	assert.Equal(t, llx.NilData, timeOrNil(time.Time{}))

	ts := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	got := timeOrNil(ts)
	require.NotEqual(t, llx.NilData, got)
	gotTime, ok := got.Value.(*time.Time)
	require.True(t, ok, "non-zero time must carry a *time.Time value")
	assert.True(t, gotTime.Equal(ts))
}

func TestParseRFC3339(t *testing.T) {
	assert.True(t, parseRFC3339("").IsZero(), "empty string is zero time")
	assert.True(t, parseRFC3339("not-a-timestamp").IsZero(), "unparseable string is zero time")

	got := parseRFC3339("2026-07-20T12:00:00Z")
	require.False(t, got.IsZero())
	assert.Equal(t, 2026, got.Year())
	assert.Equal(t, time.July, got.Month())
}

// apiErr builds a *cloudflare.Error carrying the per-error code/message the API
// actually returns, which is what separates "product not enabled" from "this
// token may not read it".
func apiErr(status int, code int64, msg string) *cloudflare.Error {
	return &cloudflare.Error{
		StatusCode: status,
		Errors:     []shared.ErrorData{{Code: code, Message: msg}},
	}
}

func TestIsUnavailable(t *testing.T) {
	// 401/403/404 still degrade by default: an absent resource, an unprovisioned
	// product, or a plan-gated feature genuinely has nothing to assess. Codes and
	// messages below are copied from live API responses.
	unavailable := []*cloudflare.Error{
		{StatusCode: http.StatusNotFound},
		{StatusCode: http.StatusForbidden},
		apiErr(http.StatusForbidden, 10042, "Please enable R2 through the Cloudflare Dashboard."),
		apiErr(http.StatusForbidden, 9999, "access.api.error.not_enabled: Access is not enabled."),
		// A 401 carrying a not-provisioned code: Zero Trust/Gateway on an account
		// that never initialized it. This is why 401 is not blanket-surfaced.
		apiErr(http.StatusUnauthorized, 1001, "Account ID is invalid or has not been initialized."),
		// Plan-gated zone features answer with the generic code.
		apiErr(http.StatusForbidden, 10000, "Forbidden"),
	}
	for _, e := range unavailable {
		assert.Truef(t, isUnavailable(e), "should degrade: %+v", e.Errors)
	}

	// A failure the API blames on the credentials must NOT degrade. Swallowing
	// these is what let an under-scoped token produce vacuous passes.
	credentialScope := []*cloudflare.Error{
		apiErr(http.StatusForbidden, 9109, "Valid user-level authentication not found"),
		apiErr(http.StatusForbidden, 10002, "Authorization Failure: The authentication credentials are not authorized to perform the request."),
		// The deny-list is keyed on the error code, not the status, so it applies
		// to a 401 too. Cloudflare does populate Errors on 401 responses — the
		// 1001 case above is an observed one — so this branch is live, not a
		// no-op that happens to reproduce the old behavior.
		apiErr(http.StatusUnauthorized, 9109, "Valid user-level authentication not found"),
		apiErr(http.StatusUnauthorized, 10002, "Authorization Failure: The authentication credentials are not authorized to perform the request."),
	}
	for _, e := range credentialScope {
		assert.Falsef(t, isUnavailable(e), "credential-scope failure must surface: %+v", e.Errors)
	}

	for _, code := range []int{http.StatusInternalServerError, http.StatusTooManyRequests, http.StatusBadRequest} {
		assert.Falsef(t, isUnavailable(&cloudflare.Error{StatusCode: code}), "status %d should NOT be unavailable", code)
	}
	assert.False(t, isUnavailable(errors.New("plain error")))
	assert.False(t, isUnavailable(nil))
}

func TestDegradedList(t *testing.T) {
	// An unavailable-resource error degrades to an empty (non-nil) list.
	got, err := degradedList(&cloudflare.Error{StatusCode: http.StatusForbidden})
	require.NoError(t, err)
	assert.Equal(t, []any{}, got)

	// A 404 likewise degrades.
	got, err = degradedList(&cloudflare.Error{StatusCode: http.StatusNotFound})
	require.NoError(t, err)
	assert.Empty(t, got)

	// A credential-scope failure propagates, so the check reports errored rather
	// than passing vacuously over an empty list.
	got, err = degradedList(apiErr(http.StatusForbidden, 9109, "Valid user-level authentication not found"))
	assert.Nil(t, got)
	require.Error(t, err)

	// Any other error propagates unchanged (not swallowed).
	sentinel := errors.New("rate limited")
	got, err = degradedList(&cloudflare.Error{StatusCode: http.StatusTooManyRequests})
	assert.Nil(t, got)
	require.Error(t, err)

	got, err = degradedList(sentinel)
	assert.Nil(t, got)
	assert.Equal(t, sentinel, err)
}

type pagedTestItem struct {
	ID string `json:"id"`
}

// TestCfGetPagedTerminatesOnZeroEchoedPage is the regression guard for the
// pagination-termination fix: when the API advertises total_pages>1 but echoes
// result_info.page as 0 (or omits it), the old `ResultInfo.Page >= TotalPages`
// check never became true and the loop spun forever. The fix compares the local
// page counter instead, so the walk stops after total_pages requests.
func TestCfGetPagedTerminatesOnZeroEchoedPage(t *testing.T) {
	env := setupTestEnv(t)

	const totalPages = 3
	var calls atomic.Int32
	env.Mux.HandleFunc("/widgets", func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if int(n) > totalPages+2 {
			// Bound a regression so it fails loudly instead of hanging CI.
			t.Errorf("cfGetPaged did not terminate: %d requests for %d pages", n, totalPages)
			jsonResponse(w, `{"success":true,"result":[],"result_info":{"page":0,"total_pages":0}}`)
			return
		}
		reqPage, _ := strconv.Atoi(r.URL.Query().Get("page"))
		// Echo page:0 regardless of the requested page while advertising 3 pages.
		jsonResponse(w, fmt.Sprintf(`{"success":true,"errors":[],"messages":[],
			"result":[{"id":"w%d"}],
			"result_info":{"page":0,"per_page":100,"total_pages":%d}}`, reqPage, totalPages))
	})

	got, err := cfGetPaged[pagedTestItem](env.Conn, "widgets")
	require.NoError(t, err)
	require.Len(t, got, totalPages, "one item collected per page, then stop")
	assert.Equal(t, int32(totalPages), calls.Load(), "exactly one request per page — no infinite loop")
	assert.Equal(t, []string{"w1", "w2", "w3"}, []string{got[0].ID, got[1].ID, got[2].ID})
}

func TestParseCloudflareTime(t *testing.T) {
	want := time.Date(2033, 2, 20, 20, 54, 0, 0, time.UTC)

	for _, tc := range []struct {
		name  string
		input string
	}{
		{"rfc3339", "2033-02-20T20:54:00Z"},
		{"rfc3339 nano", "2033-02-20T20:54:00.000000000Z"},
		{"go time.String rendering", "2033-02-20 20:54:00 +0000 UTC"},
		{"space separated, no zone", "2033-02-20 20:54:00"},
		{"surrounding whitespace", "  2033-02-20T20:54:00Z  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseCloudflareTime(tc.input)
			require.True(t, ok, "layout must be recognized")
			assert.True(t, got.Equal(want), "got %s, want %s", got, want)
		})
	}

	t.Run("date only", func(t *testing.T) {
		got, ok := parseCloudflareTime("2033-02-20")
		require.True(t, ok)
		assert.Equal(t, 2033, got.Year())
		assert.Equal(t, time.February, got.Month())
		assert.Equal(t, 20, got.Day())
	})

	// An unparseable value must be reported as such rather than silently
	// yielding the zero time, which would render as January 1 year 1 and read
	// as a certificate that expired two millennia ago.
	for _, bad := range []string{"", "   ", "not-a-timestamp", "20/02/2033"} {
		t.Run("rejects "+strconv.Quote(bad), func(t *testing.T) {
			_, ok := parseCloudflareTime(bad)
			assert.False(t, ok)
		})
	}
}

func TestCfTimeString(t *testing.T) {
	assert.Equal(t, llx.NilData, cfTimeString(""), "empty value is null")
	assert.Equal(t, llx.NilData, cfTimeString("garbage"), "unparseable value is null, not the zero time")

	got := cfTimeString("2033-02-20T20:54:00Z")
	require.NotEqual(t, llx.NilData, got)
	gotTime, ok := got.Value.(*time.Time)
	require.True(t, ok, "parsed value must carry a *time.Time")
	assert.Equal(t, 2033, gotTime.Year())
}

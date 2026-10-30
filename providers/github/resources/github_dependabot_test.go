// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// alertPage renders a JSON array of dependabot alerts with the given numbers.
func alertPage(numbers ...int) string {
	entries := make([]string, 0, len(numbers))
	for _, n := range numbers {
		entries = append(entries, fmt.Sprintf(`{"number": %d, "state": "open"}`, n))
	}
	return "[" + strings.Join(entries, ",") + "]"
}

func seq(from, to int) []int {
	out := []int{}
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

// The dependabot alerts endpoint is cursor paginated: its Link header advertises
// the next page as `after=<cursor>`, never `page=N`. A walk driven by the
// page-based NextPage therefore stops after the first page and silently drops
// every alert beyond it.
func TestListDependabotAlertsRawFollowsCursorPagination(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v3/repos/o/r/dependabot/alerts", r.URL.Path)
		after := r.URL.Query().Get("after")
		seen = append(seen, after)
		w.Header().Set("Content-Type", "application/json")
		switch after {
		case "":
			w.Header().Set("Link", fmt.Sprintf(
				`<%s/api/v3/repos/o/r/dependabot/alerts?per_page=100&after=CUR2>; rel="next"`, serverURL(r)))
			fmt.Fprint(w, alertPage(seq(1, 100)...))
		case "CUR2":
			w.Header().Set("Link", fmt.Sprintf(
				`<%s/api/v3/repos/o/r/dependabot/alerts?per_page=100&after=CUR3>; rel="next"`, serverURL(r)))
			fmt.Fprint(w, alertPage(seq(101, 200)...))
		case "CUR3":
			fmt.Fprint(w, alertPage(seq(201, 231)...))
		default:
			t.Fatalf("unexpected cursor %q", after)
		}
	}))
	defer server.Close()

	client := newTestGithubClient(t, server)
	alerts, err := listDependabotAlertsRaw(context.Background(), client, "o", "r")
	require.NoError(t, err)

	require.Len(t, alerts, 231, "every page must be collected, not just the first")
	assert.Equal(t, 1, alerts[0].GetNumber())
	assert.Equal(t, 231, alerts[230].GetNumber())
	assert.Equal(t, []string{"", "CUR2", "CUR3"}, seen)
}

// A server that keeps handing back the same cursor must not spin forever.
func TestListDependabotAlertsRawStopsOnRepeatedCursor(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", fmt.Sprintf(
			`<%s/api/v3/repos/o/r/dependabot/alerts?per_page=100&after=STUCK>; rel="next"`, serverURL(r)))
		fmt.Fprint(w, alertPage(1))
	}))
	defer server.Close()

	client := newTestGithubClient(t, server)
	alerts, err := listDependabotAlertsRaw(context.Background(), client, "o", "r")
	require.NoError(t, err)

	assert.Equal(t, 2, calls, "a repeated cursor must end the walk instead of looping")
	assert.Len(t, alerts, 2)
}

// A repository with fewer alerts than one page still returns them all, and does
// not issue a second request.
func TestListDependabotAlertsRawSinglePage(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, alertPage(seq(1, 41)...))
	}))
	defer server.Close()

	client := newTestGithubClient(t, server)
	alerts, err := listDependabotAlertsRaw(context.Background(), client, "o", "r")
	require.NoError(t, err)

	assert.Equal(t, 1, calls)
	assert.Len(t, alerts, 41)
}

func serverURL(r *http.Request) string {
	u := url.URL{Scheme: "http", Host: r.Host}
	return u.String()
}

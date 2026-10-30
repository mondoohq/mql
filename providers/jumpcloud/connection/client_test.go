// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientAuthHeaders verifies that every request carries the API key and,
// when set, the organization id.
func TestClientAuthHeaders(t *testing.T) {
	var gotKey, gotOrg, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotOrg = r.Header.Get("x-org-id")
		gotAccept = r.Header.Get("Accept")
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := NewClient("secret-key", "org-42", srv.URL)
	_, err := c.UserGroups(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "secret-key", gotKey)
	assert.Equal(t, "org-42", gotOrg)
	assert.Equal(t, "application/json", gotAccept)
}

// TestClientOmitsOrgHeaderWhenEmpty verifies that a single-org key does not send
// an empty x-org-id header.
func TestClientOmitsOrgHeaderWhenEmpty(t *testing.T) {
	orgHeaderPresent := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, orgHeaderPresent = r.Header["X-Org-Id"]
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := NewClient("secret-key", "", srv.URL)
	_, err := c.UserGroups(context.Background())
	require.NoError(t, err)
	assert.False(t, orgHeaderPresent, "x-org-id header should be omitted when no org id is set")
}

// TestListV1Pagination verifies that the v1 envelope paginator walks every page
// until totalCount is reached and aggregates the results.
func TestListV1Pagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/systemusers", r.URL.Path)
		skip, _ := strconv.Atoi(r.URL.Query().Get("skip"))
		assert.Equal(t, strconv.Itoa(pageLimit), r.URL.Query().Get("limit"))

		var results []string
		switch skip {
		case 0:
			results = makeUserPage(0, pageLimit) // full page -> more to come
		case pageLimit:
			results = makeUserPage(pageLimit, 30) // short page -> final
		default:
			t.Fatalf("unexpected skip value %d", skip)
		}
		fmt.Fprintf(w, `{"results":[%s],"totalCount":130}`, strings.Join(results, ","))
	}))
	defer srv.Close()

	c := NewClient("k", "", srv.URL)
	users, err := c.SystemUsers(context.Background())
	require.NoError(t, err)
	require.Len(t, users, 130)
	assert.Equal(t, "user-0", users[0].EffectiveID())
	assert.Equal(t, "user-129", users[129].EffectiveID())
}

// TestListV2Pagination verifies that the v2 bare-array paginator stops on the
// first short page.
func TestListV2Pagination(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/usergroups", r.URL.Path)
		skip, _ := strconv.Atoi(r.URL.Query().Get("skip"))

		var results []string
		switch skip {
		case 0:
			results = makeGroupPage(0, pageLimit)
		case pageLimit:
			results = makeGroupPage(pageLimit, 5)
		default:
			t.Fatalf("unexpected skip value %d", skip)
		}
		fmt.Fprintf(w, `[%s]`, strings.Join(results, ","))
	}))
	defer srv.Close()

	c := NewClient("k", "", srv.URL)
	groups, err := c.UserGroups(context.Background())
	require.NoError(t, err)
	require.Len(t, groups, 105)
	assert.Equal(t, "group-0", groups[0].ID)
	assert.Equal(t, "group-104", groups[104].ID)
}

// TestClientErrorIncludesBody verifies that a non-2xx response surfaces the
// status code and the response body, which is where JumpCloud explains a
// rejected key.
func TestClientErrorIncludesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"invalid api key"}`))
	}))
	defer srv.Close()

	c := NewClient("bad", "", srv.URL)
	_, err := c.Systems(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
	assert.Contains(t, err.Error(), "invalid api key")
}

// TestGraphConnectionsDecode verifies that a graph endpoint decodes into the
// target-bearing connection entries the accessors rely on.
func TestGraphConnectionsDecode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/users/u1/memberof", r.URL.Path)
		w.Write([]byte(`[{"to":{"id":"g1","type":"user_group"}},{"to":{"id":"g2","type":"user_group"}}]`))
	}))
	defer srv.Close()

	c := NewClient("k", "", srv.URL)
	conns, err := c.GraphConnections(context.Background(), "/v2/users/u1/memberof")
	require.NoError(t, err)
	assert.Equal(t, []string{"g1", "g2"}, GraphTargetIDs(conns, ""))
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "abc", truncate("abc", 5))
	assert.Equal(t, "abc", truncate("abc", 3))
	assert.Equal(t, "ab...", truncate("abcde", 2))
}

func makeUserPage(start, n int) []string {
	out := make([]string, 0, n)
	for i := start; i < start+n; i++ {
		out = append(out, fmt.Sprintf(`{"id":"user-%d","email":"u%d@example.com"}`, i, i))
	}
	return out
}

func makeGroupPage(start, n int) []string {
	out := make([]string, 0, n)
	for i := start; i < start+n; i++ {
		out = append(out, fmt.Sprintf(`{"id":"group-%d","name":"g%d"}`, i, i))
	}
	return out
}

// TestGraphPathEscapesID verifies the id segment of a graph path is escaped, so
// an id carrying a reserved character cannot reshape the request the way raw
// concatenation would.
func TestGraphPathEscapesID(t *testing.T) {
	assert.Equal(t, "/v2/users/5f0a/memberof", GraphPath("/v2/users", "5f0a", "memberof"))
	assert.Equal(t, "/v2/users/a%2F..%2Fsystems/memberof", GraphPath("/v2/users", "a/../systems", "memberof"))
	assert.Equal(t, "/v2/systems/a%20b/users", GraphPath("/v2/systems", "a b", "users"))
}

// TestOrganizationIDResolvedOnce verifies concurrent callers share a single
// resolution. Run under -race this also proves the lazy write is synchronized.
func TestOrganizationIDResolvedOnce(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"results":[{"_id":"org_1"}],"totalCount":1}`))
	}))
	defer srv.Close()

	conn := &JumpcloudConnection{client: NewClient("key", "", srv.URL)}

	var wg sync.WaitGroup
	ids := make([]string, 8)
	errs := make([]error, 8)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ids[i], errs[i] = conn.OrganizationID()
		}(i)
	}
	wg.Wait()

	for i := range ids {
		require.NoError(t, errs[i])
		assert.Equal(t, "org_1", ids[i])
	}
	assert.Equal(t, int32(1), calls.Load(), "expected a single resolution across concurrent callers")
}

// TestOrganizationIDPrefersConfiguredValue verifies a caller-supplied org id
// short-circuits the lookup entirely.
func TestOrganizationIDPrefersConfiguredValue(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"results":[{"_id":"resolved"}],"totalCount":1}`))
	}))
	defer srv.Close()

	conn := &JumpcloudConnection{orgID: "configured", client: NewClient("key", "configured", srv.URL)}
	id, err := conn.OrganizationID()
	require.NoError(t, err)
	assert.Equal(t, "configured", id)
	assert.Equal(t, int32(0), calls.Load(), "a configured org id must not trigger a lookup")
}

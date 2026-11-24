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
	"sync"
	"testing"

	"github.com/microsoft/kiota-abstractions-go/authentication"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// job()/contact() resolve from the bulk user list response (userSelectFields)
// instead of an N+1 per-user Get. That optimization only holds if every field
// the job/contact dicts read is also requested by the bulk list. This guards
// against silently reintroducing the N+1 (or dropping data) by removing a field
// from userSelectFields.
func TestUserSelectFieldsCoverJobContactFields(t *testing.T) {
	selected := make(map[string]bool, len(userSelectFields))
	for _, f := range userSelectFields {
		selected[f] = true
	}
	for _, f := range userJobContactFields {
		assert.Truef(t, selected[f],
			"userJobContactFields[%q] is not in userSelectFields; job()/contact() "+
				"would fall back to an N+1 per-user Get (or lose this field)", f)
	}
}

// authMethods.registrationDetails comes from the tenant-wide registration
// report. Reaching it must not list the methods of every user: CIS
// isMfaCapable walks all members that way. The runtime here has no
// connection, so a per-user fetch would fail the test.
func TestUserAuthMethodsRegistrationDetailsSkipsMethodListing(t *testing.T) {
	runtime, ms := licenseTestEnv(t, nil, nil, nil)
	details := models.NewUserRegistrationDetails()
	id, capable := "alice", true
	details.SetId(&id)
	details.SetIsMfaCapable(&capable)
	ms.regOnce.Do(func() {
		ms.regDetails = map[string]userRegistrationDetail{id: newUserRegistrationDetail(details)}
	})

	authMethods, err := testUser(t, runtime, id).authMethods()
	require.NoError(t, err)
	reg, err := authMethods.registrationDetails()
	require.NoError(t, err)
	assert.True(t, reg.IsMfaCapable.Data)
	assert.Nil(t, ms.userBatches.authMethods.loaded, "the per-user method listing ran")

	// the method fields still read the per-user listing
	phone := models.NewPhoneAuthenticationMethod()
	phoneID, number := "p1", "+1 555 0100"
	phone.SetId(&phoneID)
	phone.SetPhoneNumber(&number)
	ms.userBatches.authMethods.data = map[string]any{id: buildUserAuthentication(id, []models.AuthenticationMethodable{phone})}
	ms.userBatches.authMethods.errs = map[string]error{}
	ms.userBatches.authMethods.loaded = map[string]bool{id: true}

	count, err := authMethods.count()
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
	phones, err := authMethods.phoneMethods()
	require.NoError(t, err)
	require.Len(t, phones, 1)
	assert.Equal(t, number, phones[0].(map[string]any)["phoneNumber"])
	emails, err := authMethods.emailMethods()
	require.NoError(t, err)
	assert.Empty(t, emails)
}

// The filter and search a count sends to Graph. Every filter string below is
// one Graph was sent as is.
//
// Measured: Microsoft Graph v1.0 GET /users/$count, 2026-11-19, on a tenant
// with one member and no guests. Graph accepted each filter and answered with
// the count noted on the case.
func TestUsersCountQuery(t *testing.T) {
	set := func(v string) plugin.TValue[string] {
		return plugin.TValue[string]{Data: v, State: plugin.StateIsSet}
	}

	tests := []struct {
		name       string
		filter     plugin.TValue[string]
		search     plugin.TValue[string]
		userType   string
		wantFilter string
		wantSearch string
	}{
		// Measured: answered 1.
		{name: "every user"},
		// Measured: answered 1.
		{name: "members", userType: "Member", wantFilter: "userType eq 'Member'"},
		// Measured: answered 0.
		{name: "guests", userType: "Guest", wantFilter: "userType eq 'Guest'"},
		// Measured: answered 0. Before, count dropped the filter and reported
		// every user of the tenant for this query.
		{
			name:       "filter without a type",
			filter:     set("accountEnabled eq false"),
			wantFilter: "accountEnabled eq false",
		},
		// Measured: answered 0.
		{
			name:       "filter narrowed to guests",
			filter:     set("accountEnabled eq true"),
			userType:   "Guest",
			wantFilter: "(accountEnabled eq true) and userType eq 'Guest'",
		},
		// Measured: answered 1. Without the parentheses the type would only
		// narrow the right-hand side of the `or`, and guestCount would count
		// every disabled account whatever its type.
		{
			name:       "filter with an or",
			filter:     set("accountEnabled eq false or accountEnabled eq true"),
			userType:   "Member",
			wantFilter: "(accountEnabled eq false or accountEnabled eq true) and userType eq 'Member'",
		},
		// Measured: answered 0, with the search quoted this way.
		{
			name:       "search narrowed to members",
			search:     set("displayName:a"),
			userType:   "Member",
			wantFilter: "userType eq 'Member'",
			wantSearch: `"displayName:a"`,
		},
		// Synthetic: a filter argument passed as null is no filter; no target
		// showed this.
		{
			name:       "null filter",
			filter:     plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull},
			userType:   "Guest",
			wantFilter: "userType eq 'Guest'",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := &mqlMicrosoftUsers{Filter: tt.filter, Search: tt.search}
			filter, search, err := users.countQuery(tt.userType)
			require.NoError(t, err)
			assert.Equal(t, tt.wantFilter, filter)
			assert.Equal(t, tt.wantSearch, search)
		})
	}

	// Synthetic: a search with no property to search in is refused before
	// anything is sent, as list refuses it; no target showed this.
	t.Run("malformed search", func(t *testing.T) {
		users := &mqlMicrosoftUsers{Search: set("no property")}
		_, _, err := users.countQuery("Guest")
		assert.Error(t, err)
	})
}

// userCountGraph serves GET /users/$count the way Microsoft Graph v1.0 was
// measured to on 2026-11-19: the count as a bare number in a text/plain body,
// and a 400 Request_UnsupportedQuery when the request lacks the
// ConsistencyLevel: eventual header. A test can make it refuse instead.
type userCountGraph struct {
	// count is the body of a successful answer
	count string
	// refuse, when set, is answered instead of the count
	refuse *fakeRoute

	mu      sync.Mutex
	queries []url.Values
}

func (g *userCountGraph) client(t *testing.T) *msgraphsdkgo.GraphServiceClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.0/users/$count" {
			http.NotFound(w, r)
			return
		}
		g.mu.Lock()
		g.queries = append(g.queries, r.URL.Query())
		g.mu.Unlock()

		answer := g.refuse
		if r.Header.Get("ConsistencyLevel") != "eventual" {
			answer = &fakeRoute{
				status: http.StatusBadRequest,
				body:   `{"error":{"code":"Request_UnsupportedQuery","message":"Raw count (/$count) is not supported because the 'ConsistencyLevel:eventual' header is missing."}}`,
			}
		}
		if answer != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(answer.status)
			_, _ = w.Write([]byte(answer.body))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(g.count))
	}))
	t.Cleanup(srv.Close)

	adapter, err := msgraphsdkgo.NewGraphRequestAdapter(&authentication.AnonymousAuthenticationProvider{})
	require.NoError(t, err)
	adapter.SetBaseUrl(srv.URL + "/v1.0")
	return msgraphsdkgo.NewGraphServiceClient(adapter)
}

// lastQuery returns the query of the one request a test expects.
func (g *userCountGraph) lastQuery(t *testing.T) url.Values {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	require.Len(t, g.queries, 1)
	return g.queries[0]
}

// The count comes back from the text/plain body, and the filter and search
// reach Graph as query parameters. The fake refuses a request without the
// ConsistencyLevel header as Graph does, so every case here also fails when
// that header is dropped.
func TestFetchUserCount(t *testing.T) {
	tests := []struct {
		name   string
		filter string
		search string
		count  string
		want   int64
	}{
		// Measured: Microsoft Graph v1.0, 2026-11-19, a tenant with one member
		// and no guests.
		{name: "every user", count: "1", want: 1},
		{name: "members", filter: "userType eq 'Member'", count: "1", want: 1},
		{name: "guests", filter: "userType eq 'Guest'", count: "0", want: 0},
		{name: "search and filter", filter: "userType eq 'Member'", search: `"displayName:a"`, count: "0", want: 0},
		// Synthetic: a count the size of a large tenant; the measured tenant
		// has a single user.
		{name: "large tenant", filter: "userType eq 'Guest'", count: "48213", want: 48213},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graph := &userCountGraph{count: tt.count}
			got, err := fetchUserCount(context.Background(), graph.client(t), tt.filter, tt.search)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)

			// an empty filter or search must not be sent at all
			query := graph.lastQuery(t)
			assert.Equal(t, tt.filter != "", query.Has("$filter"))
			assert.Equal(t, tt.filter, query.Get("$filter"))
			assert.Equal(t, tt.search != "", query.Has("$search"))
			assert.Equal(t, tt.search, query.Get("$search"))
		})
	}
}

func TestFetchUserCountRefused(t *testing.T) {
	// Synthetic: a credential without User.Read.All; no target showed this.
	// A refusal is a Forbidden error, never a count of zero.
	t.Run("forbidden", func(t *testing.T) {
		graph := &userCountGraph{refuse: &fakeRoute{
			status: http.StatusForbidden,
			body:   `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}`,
		}}
		_, err := fetchUserCount(context.Background(), graph.client(t), "userType eq 'Guest'", "")
		require.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	})

	// Measured: Microsoft Graph v1.0, 2026-11-19, answered the filter
	// `externalUserState ne null` with this 400. A filter Graph rejects is an
	// error carrying Graph's reason.
	t.Run("unsupported filter", func(t *testing.T) {
		graph := &userCountGraph{refuse: &fakeRoute{
			status: http.StatusBadRequest,
			body:   `{"error":{"code":"Request_UnsupportedQuery","message":"An unsupported property was specified."}}`,
		}}
		_, err := fetchUserCount(context.Background(), graph.client(t), "externalUserState ne null", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "An unsupported property was specified.")
	})
}

func TestGroupsWithID(t *testing.T) {
	// Synthetic: Graph can return null entries in a collection page; no target showed one.
	withID := models.NewGroup()
	idA := "group-a"
	withID.SetId(&idA)
	emptyID := models.NewGroup()
	blank := ""
	emptyID.SetId(&blank)
	noID := models.NewGroup()

	got := groupsWithID([]models.Groupable{withID, nil, emptyID, noID})
	require.Len(t, got, 1)
	assert.Equal(t, "group-a", *got[0].GetId())

	assert.Empty(t, groupsWithID(nil))
}

func TestFetchUserGroupMemberships(t *testing.T) {
	// Synthetic: three users covering one page, a second page, and a refusal;
	// the bodies follow the Graph v1.0 group collection shape.
	f := newFakeGraph(t, map[string]fakeRoute{
		"/users/u-1/transitiveMemberOf/graph.group": {status: 200, body: `{
			"@odata.nextLink": "{{base}}/users/u-1/transitiveMemberOf/graph.group/page2",
			"value": [
				{"id": "g-1", "displayName": "Engineering"},
				{"id": "g-2", "displayName": "All staff"}
			]}`},
		"/users/u-1/transitiveMemberOf/graph.group/page2": {status: 200, body: `{
			"value": [{"id": "g-3", "displayName": "Azure owners", "isAssignableToRole": true}]}`},
		"/users/u-2/transitiveMemberOf/graph.group": {status: 200, body: `{"value": []}`},
		"/users/u-3/transitiveMemberOf/graph.group": {status: 403, body: `{"error":{"code":"Authorization_RequestDenied","message":"denied"}}`},
		"/users/u-1/memberOf/graph.group":           {status: 200, body: `{"value": [{"id": "g-1", "displayName": "Engineering"}]}`},
	})

	got, errs, err := fetchUserGroupMemberships(context.Background(), f.client(), []string{"u-1", "u-2", "u-3"}, true)
	require.NoError(t, err)

	names := []string{}
	for _, g := range got["u-1"] {
		names = append(names, *g.GetDisplayName())
	}
	assert.Equal(t, []string{"Engineering", "All staff", "Azure owners"}, names, "the second page is followed")

	assert.NoError(t, errs["u-2"])
	assert.Contains(t, got, "u-2")
	assert.Empty(t, got["u-2"])

	assert.Error(t, errs["u-3"])
	assert.NotContains(t, got, "u-3", "a refused lookup is an error, not an empty membership")

	for _, step := range f.steps {
		assert.Contains(t, step, "/transitiveMemberOf/graph.group")
		assert.Contains(t, step, "top=999")
	}

	direct, errs, err := fetchUserGroupMemberships(context.Background(), f.client(), []string{"u-1"}, false)
	require.NoError(t, err)
	assert.NoError(t, errs["u-1"])
	require.Len(t, direct["u-1"], 1)
	assert.Equal(t, "g-1", *direct["u-1"][0].GetId())
}

// signInActivityIDs returns n user ids, more than one $batch call holds when
// n exceeds batchChunkSize.
func signInActivityIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("u-%02d", i+1)
	}
	return ids
}

func TestFetchUserSignInActivityListsLargeFetches(t *testing.T) {
	// Synthetic: two pages of the v1.0 user listing with signInActivity
	// selected; no per-user route exists, so a request per user would 404.
	ids := signInActivityIDs(batchChunkSize + 1)
	var page1, page2 []string
	for i, id := range ids {
		row := `{"id": "` + id + `", "signInActivity": {"lastSignInDateTime": "2026-11-01T10:00:00Z"}}`
		switch i {
		case 1: // never signed in
			row = `{"id": "` + id + `"}`
		case 2: // never signed in, as the listing of a live tenant returns it
			row = `{"id": "` + id + `", "signInActivity": {"lastSignInDateTime": null, "lastNonInteractiveSignInDateTime": null}}`
		}
		if i < 10 {
			page1 = append(page1, row)
		} else {
			page2 = append(page2, row)
		}
	}
	page2 = append(page2, `{"id": "not-asked-for", "signInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z"}}`)
	f := newFakeGraph(t, map[string]fakeRoute{
		"/users": {status: 200, body: `{
			"@odata.nextLink": "{{base}}/users/page2",
			"value": [` + strings.Join(page1, ",") + `]}`},
		"/users/page2": {status: 200, body: `{"value": [` + strings.Join(page2, ",") + `]}`},
	})

	got, errs, err := fetchUserSignInActivity(context.Background(), f.client(), ids)
	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Zero(t, f.batchCalls, "every user is read from the listing, none with a request of its own")
	require.Len(t, got, len(ids), "both pages are read and a user that was not asked for is left out")

	first, ok := got[ids[0]].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "2026-11-01T10:00:00Z", first["lastSignInDateTime"])
	assert.Contains(t, got, ids[1], "a user without sign-in activity is loaded")
	assert.Nil(t, got[ids[1]], "and has none")
	assert.Contains(t, got, ids[2])
	assert.Nil(t, got[ids[2]], "an empty signInActivity reads as none, as a read by id does")
	last, ok := got[ids[len(ids)-1]].(map[string]any)
	require.True(t, ok, "the second page is followed")
	assert.Equal(t, "2026-11-01T10:00:00Z", last["lastSignInDateTime"])
}

func TestFetchUserSignInActivityListsPastUnreadableEntries(t *testing.T) {
	// Synthetic: the first page of the listing holds a null entry and a user
	// of a derived type (an agent user), the two kinds of entry that used to
	// end the listing at their page. No per-user route exists, so a user the
	// listing lost would be read by id and fail the batch-call count.
	ids := signInActivityIDs(batchChunkSize + 1)
	var page1, page2 []string
	for i, id := range ids {
		row := `{"id": "` + id + `", "signInActivity": {"lastSignInDateTime": "2026-11-01T10:00:00Z"}}`
		switch {
		case i == 1:
			page1 = append(page1, "null", `{"@odata.type": "#microsoft.graph.agentUser", "id": "`+id+`", "signInActivity": {"lastSignInDateTime": "2026-11-02T10:00:00Z"}}`)
		case i < 10:
			page1 = append(page1, row)
		default:
			page2 = append(page2, row)
		}
	}
	f := newFakeGraph(t, map[string]fakeRoute{
		"/users": {status: 200, body: `{
			"@odata.nextLink": "{{base}}/users/page2",
			"value": [` + strings.Join(page1, ",") + `]}`},
		"/users/page2": {status: 200, body: `{"value": [` + strings.Join(page2, ",") + `]}`},
	})

	got, errs, err := fetchUserSignInActivity(context.Background(), f.client(), ids)
	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Zero(t, f.batchCalls, "no user is lost from the listing and read with a request of its own")
	require.Len(t, got, len(ids))

	agent, ok := got[ids[1]].(map[string]any)
	require.True(t, ok, "the derived user's sign-in activity is read")
	assert.Equal(t, "2026-11-02T10:00:00Z", agent["lastSignInDateTime"])
	last, ok := got[ids[len(ids)-1]].(map[string]any)
	require.True(t, ok, "the page after the unreadable entries is followed")
	assert.Equal(t, "2026-11-01T10:00:00Z", last["lastSignInDateTime"])
}

func TestFetchUserSignInActivityReadsUsersMissingFromListing(t *testing.T) {
	// Synthetic: the listing leaves out the last two users; one is readable
	// by id, the other is refused.
	ids := signInActivityIDs(batchChunkSize + 1)
	absent, refused := ids[len(ids)-2], ids[len(ids)-1]
	var rows []string
	for _, id := range ids[:len(ids)-2] {
		rows = append(rows, `{"id": "`+id+`"}`)
	}
	f := newFakeGraph(t, map[string]fakeRoute{
		"/users":            {status: 200, body: `{"value": [` + strings.Join(rows, ",") + `]}`},
		"/users/" + absent:  {status: 200, body: `{"id": "` + absent + `", "signInActivity": {"lastSignInDateTime": "2026-10-05T07:30:00Z"}}`},
		"/users/" + refused: {status: 403, body: `{"error":{"code":"Authorization_RequestDenied","message":"denied"}}`},
	})

	got, errs, err := fetchUserSignInActivity(context.Background(), f.client(), ids)
	require.NoError(t, err)
	assert.Equal(t, 1, f.batchCalls, "only the users the listing left out are read by id")
	assert.Len(t, f.steps, 2)

	activity, ok := got[absent].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "2026-10-05T07:30:00Z", activity["lastSignInDateTime"])
	assert.Error(t, errs[refused])
	assert.NotContains(t, got, refused, "a refused lookup is an error, not a user that never signed in")
}

func TestFetchUserSignInActivityReadsFewUsersByID(t *testing.T) {
	// Synthetic: a single user, as when one user is looked up by id; the
	// listing has no route, so reading it would fail the fetch.
	f := newFakeGraph(t, map[string]fakeRoute{
		"/users/u-1": {status: 200, body: `{"id": "u-1", "signInActivity": {"lastSignInDateTime": "2026-11-01T10:00:00Z"}}`},
	})

	got, errs, err := fetchUserSignInActivity(context.Background(), f.client(), []string{"u-1"})
	require.NoError(t, err)
	assert.Empty(t, errs)
	assert.Equal(t, 1, f.batchCalls)
	activity, ok := got["u-1"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "2026-11-01T10:00:00Z", activity["lastSignInDateTime"])
}

func TestFetchUserSignInActivityListingRefused(t *testing.T) {
	// Synthetic: Graph answers 403 for a tenant without Entra ID P1/P2 or
	// without AuditLog.Read.All.
	f := newFakeGraph(t, map[string]fakeRoute{
		"/users": {status: 403, body: `{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant","message":"Neither tenant is B2C or tenant doesn't have premium license"}}`},
	})
	_, _, err := fetchUserSignInActivity(context.Background(), f.client(), signInActivityIDs(batchChunkSize+1))
	assert.Error(t, err, "a refusal is an error, never users that read as 'never signed in'")
	assert.Zero(t, f.batchCalls)
}

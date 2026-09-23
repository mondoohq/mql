// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-github/v92/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---------- error classifiers ----------

// The classifiers decide whether a failed read is a posture verdict or an
// unknown. Getting that wrong in either direction is a silent audit failure: a
// 403 read as "the feature is off" clears an org nobody was allowed to inspect,
// and a transport error read as either one turns a network blip into a verdict.
func TestGithubErrorClassifiers(t *testing.T) {
	transport := &net.OpError{Op: "dial", Err: errors.New("connection refused")}

	tests := []struct {
		name         string
		err          error
		notAvailable bool
		forbidden    bool
	}{
		{name: "nil", err: nil},
		{name: "404 feature absent", err: ghErrorResponse(http.StatusNotFound), notAvailable: true},
		{name: "409 setting in another mode", err: ghErrorResponse(http.StatusConflict), notAvailable: true},
		{name: "403 read refused", err: ghErrorResponse(http.StatusForbidden), forbidden: true},
		{name: "401 unauthenticated", err: ghErrorResponse(http.StatusUnauthorized)},
		{name: "500 server error", err: ghErrorResponse(http.StatusInternalServerError)},
		{name: "429 rate limited", err: ghErrorResponse(http.StatusTooManyRequests)},
		{name: "transport error", err: transport},
		{name: "wrapped transport error", err: fmt.Errorf("get repo: %w", transport)},
		{name: "plain error", err: errors.New("boom")},
		{name: "wrapped 403", err: fmt.Errorf("get settings: %w", ghErrorResponse(http.StatusForbidden)), forbidden: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.notAvailable, githubNotAvailable(tc.err), "githubNotAvailable")
			assert.Equal(t, tc.forbidden, githubForbidden(tc.err), "githubForbidden")
		})
	}
}

// ---------- timestamps ----------

// GitHub omits a timestamp it holds no value for. go-github decodes the absent
// value to the zero time, and reporting that verbatim writes 1 January year 1
// into an audit as though the event really happened then.
func TestGithubTimeKeepsAbsentTimestampsNull(t *testing.T) {
	assert.Nil(t, githubTime(nil), "an absent timestamp is null")
	assert.Nil(t, githubTime(&github.Timestamp{}), "a zero timestamp is null, not year 1")
	assert.Nil(t, githubTimeValue(github.Timestamp{}), "a zero value timestamp is null")

	real := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	require.NotNil(t, githubTime(&github.Timestamp{Time: real}))
	assert.Equal(t, real, *githubTime(&github.Timestamp{Time: real}))
	assert.Equal(t, real, *githubTimeValue(github.Timestamp{Time: real}))
}

// ---------- GPG derived predicates ----------

// A key generated with GnuPG's defaults certifies with its primary key and
// signs with a subkey, so can_sign on the primary key is false while the key is
// perfectly able to sign commits. Reading only the primary key reports every
// such member as unable to satisfy a signed-commits rule.
func TestGpgKeyCanSignCommits(t *testing.T) {
	yes, no := github.Ptr(true), github.Ptr(false)

	tests := []struct {
		name string
		key  *github.GPGKey
		want bool
	}{
		{name: "nil key", key: nil, want: false},
		{name: "no capability reported", key: &github.GPGKey{}, want: false},
		{name: "primary signs", key: &github.GPGKey{CanSign: yes}, want: true},
		{name: "primary cannot sign, no subkeys", key: &github.GPGKey{CanSign: no}, want: false},
		{
			name: "signing subkey",
			key:  &github.GPGKey{CanSign: no, Subkeys: []*github.GPGKey{{CanSign: yes}}},
			want: true,
		},
		{
			name: "only non-signing subkeys",
			key:  &github.GPGKey{CanSign: no, Subkeys: []*github.GPGKey{{CanSign: no}, {}}},
			want: false,
		},
		{
			name: "nested signing subkey",
			key:  &github.GPGKey{CanSign: no, Subkeys: []*github.GPGKey{{CanSign: no, Subkeys: []*github.GPGKey{{CanSign: yes}}}}},
			want: true,
		},
		{
			name: "nil subkey entry is skipped",
			key:  &github.GPGKey{CanSign: no, Subkeys: []*github.GPGKey{nil, {CanSign: yes}}},
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, gpgKeyCanSignCommits(tc.key))
		})
	}
}

func TestGpgKeyExpired(t *testing.T) {
	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		expiresAt *github.Timestamp
		want      bool
	}{
		{name: "no expiry never expires", expiresAt: nil, want: false},
		{name: "zero expiry is treated as no expiry", expiresAt: &github.Timestamp{}, want: false},
		{name: "expiry in the past", expiresAt: &github.Timestamp{Time: now.Add(-time.Hour)}, want: true},
		{name: "expiry in the future", expiresAt: &github.Timestamp{Time: now.Add(time.Hour)}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, gpgKeyExpired(tc.expiresAt, now))
		})
	}
}

// Git only accepts a signature as the account's when the committer address is
// one of the verified ones, so the verified flag has to survive per address.
func TestGpgKeyEmails(t *testing.T) {
	key := &github.GPGKey{Emails: []*github.GPGEmail{
		{Email: github.Ptr("verified@example.com"), Verified: github.Ptr(true)},
		{Email: github.Ptr("unverified@example.com"), Verified: github.Ptr(false)},
		{Email: github.Ptr("unreported@example.com")},
		{Email: github.Ptr("")},
		nil,
	}}
	assert.Equal(t, map[string]any{
		"verified@example.com":   true,
		"unverified@example.com": false,
		"unreported@example.com": false,
	}, gpgKeyEmails(key))

	assert.Equal(t, map[string]any{}, gpgKeyEmails(&github.GPGKey{}))
}

// ---------- struct-tag decoding ----------

// A mistyped json tag decodes to the zero value rather than failing, so
// can_sign reads false on a signing key and query_suite reads empty on an
// extended-suite repository. Pin the shapes these fields are read from.
func TestGpgKeyDecoding(t *testing.T) {
	var key github.GPGKey
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": 3,
		"key_id": "3262EFF25BA0D270",
		"public_key": "xsBNBFayYZ0BCAC4hScoI",
		"emails": [{"email": "octocat@users.noreply.github.com", "verified": true}],
		"can_sign": false,
		"can_encrypt_comms": true,
		"created_at": "2026-04-05T06:07:08Z",
		"expires_at": "2027-04-05T06:07:08Z",
		"subkeys": [{"id": 4, "can_sign": true}]
	}`), &key))

	assert.Equal(t, int64(3), key.GetID())
	assert.Equal(t, "3262EFF25BA0D270", key.GetKeyID())
	assert.Equal(t, "xsBNBFayYZ0BCAC4hScoI", key.GetPublicKey())
	assert.False(t, key.GetCanSign(), "the primary key does not sign")
	assert.True(t, gpgKeyCanSignCommits(&key), "the subkey does")
	assert.Equal(t, map[string]any{"octocat@users.noreply.github.com": true}, gpgKeyEmails(&key))
	require.NotNil(t, githubTime(key.CreatedAt))
	assert.Equal(t, 2026, githubTime(key.CreatedAt).Year())
	require.NotNil(t, githubTime(key.ExpiresAt))
	assert.False(t, gpgKeyExpired(key.ExpiresAt, time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)))
}

func TestDefaultSetupConfigurationDecoding(t *testing.T) {
	var cfg github.DefaultSetupConfiguration
	require.NoError(t, json.Unmarshal([]byte(`{
		"state": "configured",
		"languages": ["go", "javascript"],
		"query_suite": "extended",
		"updated_at": "2026-06-07T00:00:00Z"
	}`), &cfg))

	assert.Equal(t, "configured", cfg.GetState())
	assert.Equal(t, "extended", cfg.GetQuerySuite())
	assert.Equal(t, []string{"go", "javascript"}, cfg.Languages)
	require.NotNil(t, githubTime(cfg.UpdatedAt))

	// A repository running code scanning from its own workflow answers here
	// with a bare not-configured, and neither the suite nor the languages are
	// reported. Both have to stay absent rather than becoming "" and [].
	var advanced github.DefaultSetupConfiguration
	require.NoError(t, json.Unmarshal([]byte(`{"state": "not-configured"}`), &advanced))
	assert.Equal(t, "not-configured", advanced.GetState())
	assert.Nil(t, advanced.QuerySuite, "an unreported query suite must stay absent")
	assert.Nil(t, advanced.Languages, "an unreported language list must stay absent")
	assert.Nil(t, githubTime(advanced.UpdatedAt))
}

// When allowedActions is "selected" this payload is the entire content of the
// control, so every field of it has to survive decoding. A dropped
// patterns_allowed makes a scope that permits */* look like one that permits
// nothing.
func TestActionsAllowedDecoding(t *testing.T) {
	var allowed github.ActionsAllowed
	require.NoError(t, json.Unmarshal([]byte(`{
		"github_owned_allowed": true,
		"verified_allowed": false,
		"patterns_allowed": ["monalisa/octocat@*", "docker/*"]
	}`), &allowed))

	require.NotNil(t, allowed.GithubOwnedAllowed)
	assert.True(t, *allowed.GithubOwnedAllowed)
	require.NotNil(t, allowed.VerifiedAllowed)
	assert.False(t, *allowed.VerifiedAllowed)
	assert.Equal(t, []string{"monalisa/octocat@*", "docker/*"}, allowed.PatternsAllowed)

	// An allowlist that permits no third-party actions reports an empty list,
	// which is a real answer and not the same as an unreported switch.
	var strict github.ActionsAllowed
	require.NoError(t, json.Unmarshal([]byte(`{"github_owned_allowed": true, "patterns_allowed": []}`), &strict))
	assert.Empty(t, strict.PatternsAllowed)
	assert.Nil(t, strict.VerifiedAllowed, "an unreported switch must stay absent, not false")
}

func TestActionsAccessLevelDecoding(t *testing.T) {
	var level github.RepositoryActionsAccessLevel
	require.NoError(t, json.Unmarshal([]byte(`{"access_level": "organization"}`), &level))
	require.NotNil(t, level.AccessLevel)
	assert.Equal(t, "organization", *level.AccessLevel)

	var absent github.RepositoryActionsAccessLevel
	require.NoError(t, json.Unmarshal([]byte(`{}`), &absent))
	assert.Nil(t, absent.AccessLevel, "an unreported access level must stay absent, not none")
}

func TestImmutableReleaseSettingsDecoding(t *testing.T) {
	var settings github.ImmutableReleaseSettings
	require.NoError(t, json.Unmarshal([]byte(`{"enforced_repositories": "selected"}`), &settings))
	require.NotNil(t, settings.EnforcedRepositories)
	assert.Equal(t, "selected", *settings.EnforcedRepositories)

	var absent github.ImmutableReleaseSettings
	require.NoError(t, json.Unmarshal([]byte(`{}`), &absent))
	assert.Nil(t, absent.EnforcedRepositories, "an unreported scope must stay absent, not none")
}

// A Dependabot secret carries no value, only the metadata below. The
// timestamps are modelled by value, so an omitted one decodes to the zero time
// and has to be nulled before it reaches a field.
func TestDependabotSecretDecoding(t *testing.T) {
	var secret github.Secret
	require.NoError(t, json.Unmarshal([]byte(`{
		"name": "NPM_TOKEN",
		"created_at": "2026-01-02T03:04:05Z",
		"updated_at": "2026-02-03T04:05:06Z",
		"visibility": "selected",
		"selected_repositories_url": "https://api.github.com/orgs/o/dependabot/secrets/NPM_TOKEN/repositories"
	}`), &secret))

	assert.Equal(t, "NPM_TOKEN", secret.Name)
	assert.Equal(t, "selected", secret.Visibility)
	require.NotNil(t, githubTimeValue(secret.CreatedAt))
	assert.Equal(t, 2026, githubTimeValue(secret.CreatedAt).Year())

	var bare github.Secret
	require.NoError(t, json.Unmarshal([]byte(`{"name": "NPM_TOKEN"}`), &bare))
	assert.Nil(t, githubTimeValue(bare.CreatedAt), "an omitted timestamp must not become year 1")
	assert.Nil(t, githubTimeValue(bare.UpdatedAt), "an omitted timestamp must not become year 1")
}

func TestDependabotSecretIDCarriesItsStore(t *testing.T) {
	// The same secret name in two repositories, and in a repository and its
	// organization, must not share a cache key.
	repoA := dependabotSecretID(scopeRepository, "acme", "alpha", "NPM_TOKEN")
	repoB := dependabotSecretID(scopeRepository, "acme", "beta", "NPM_TOKEN")
	org := dependabotSecretID(scopeOrganization, "acme", "", "NPM_TOKEN")

	assert.NotEqual(t, repoA, repoB)
	assert.NotEqual(t, repoA, org)
	assert.Equal(t, repoA, dependabotSecretID(scopeRepository, "acme", "alpha", "NPM_TOKEN"))
}

// ---------- pagination ----------

func TestNextPage(t *testing.T) {
	tests := []struct {
		name    string
		current int
		resp    *github.Response
		want    int
	}{
		{name: "nil response ends the walk", current: 0, resp: nil, want: 0},
		{name: "no next page", current: 3, resp: &github.Response{NextPage: 0}, want: 0},
		{name: "first page advances", current: 0, resp: &github.Response{NextPage: 2}, want: 2},
		{name: "later page advances", current: 4, resp: &github.Response{NextPage: 5}, want: 5},
		{name: "repeated page ends the walk", current: 4, resp: &github.Response{NextPage: 4}, want: 0},
		{name: "backwards page ends the walk", current: 4, resp: &github.Response{NextPage: 2}, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, nextPage(tc.current, tc.resp))
		})
	}
}

func gpgKeyPage(ids ...int) string {
	entries := make([]string, 0, len(ids))
	for _, id := range ids {
		entries = append(entries, fmt.Sprintf(`{"id": %d, "key_id": "KEY%d"}`, id, id))
	}
	out := "["
	for i, e := range entries {
		if i > 0 {
			out += ","
		}
		out += e
	}
	return out + "]"
}

// Reading only the first page of a key listing reports a member who holds a
// signing key as holding none, which is exactly the answer a signed-commits
// audit would act on.
func TestCollectPagesWalksEveryPage(t *testing.T) {
	var pagesSeen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		pagesSeen = append(pagesSeen, page)
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/api/v3/users/o/gpg_keys?per_page=100&page=2>; rel="next"`, serverURL(r)))
			fmt.Fprint(w, gpgKeyPage(1, 2))
		case "2":
			w.Header().Set("Link", fmt.Sprintf(`<%s/api/v3/users/o/gpg_keys?per_page=100&page=3>; rel="next"`, serverURL(r)))
			fmt.Fprint(w, gpgKeyPage(3, 4))
		case "3":
			fmt.Fprint(w, gpgKeyPage(5))
		default:
			t.Fatalf("unexpected page %q", page)
		}
	}))
	defer server.Close()

	client := newTestGithubClient(t, server)
	keys, err := collectPages(func(opts *github.ListOptions) ([]*github.GPGKey, *github.Response, error) {
		return client.Users.ListGPGKeys(context.Background(), "o", opts)
	})
	require.NoError(t, err)

	require.Len(t, keys, 5, "every page must be collected, not just the first")
	assert.Equal(t, []string{"", "2", "3"}, pagesSeen)
}

// A server whose next link points back at the page just read would otherwise
// re-read it until the process runs out of memory.
func TestCollectPagesStopsOnRepeatedPage(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", fmt.Sprintf(`<%s/api/v3/users/o/gpg_keys?per_page=100&page=2>; rel="next"`, serverURL(r)))
		fmt.Fprint(w, gpgKeyPage(1))
	}))
	defer server.Close()

	client := newTestGithubClient(t, server)
	keys, err := collectPages(func(opts *github.ListOptions) ([]*github.GPGKey, *github.Response, error) {
		return client.Users.ListGPGKeys(context.Background(), "o", opts)
	})
	require.NoError(t, err)

	assert.Equal(t, 2, calls, "a repeated page must end the walk instead of looping")
	assert.Len(t, keys, 2)
}

// A failed page has to surface as a failure. Returning what was gathered so far
// would report a truncated list as complete.
func TestCollectPagesPropagatesError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"message": "boom"}`)
	}))
	defer server.Close()

	client := newTestGithubClient(t, server)
	_, err := collectPages(func(opts *github.ListOptions) ([]*github.GPGKey, *github.Response, error) {
		return client.Users.ListGPGKeys(context.Background(), "o", opts)
	})
	require.Error(t, err)
	assert.False(t, githubForbidden(err), "a server error is not a permission refusal")
	assert.False(t, githubNotAvailable(err), "a server error is not an absent feature")
}

// ---------- allowlist rendering ----------

// When allowedActions is "selected" the allowlist is the whole of the control,
// so its absence and its emptiness must not render the same way: no allowlist
// in force is null, while an allowlist that permits nothing is an empty list.
func TestAllowlistPatterns(t *testing.T) {
	var absent plugin.TValue[[]any]
	got, err := allowlistPatterns(nil, &absent)
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, absent.State,
		"no allowlist in force must render null, not an empty allowlist")

	var permissive plugin.TValue[[]any]
	got, err = allowlistPatterns(&github.ActionsAllowed{PatternsAllowed: []string{"*/*"}}, &permissive)
	require.NoError(t, err)
	assert.Equal(t, []any{"*/*"}, got)
	assert.Zero(t, permissive.State, "a real allowlist must not be marked null")

	var strict plugin.TValue[[]any]
	got, err = allowlistPatterns(&github.ActionsAllowed{PatternsAllowed: []string{}}, &strict)
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Zero(t, strict.State, "an empty allowlist is a real answer, not an unread one")
}

func TestAllowlistBool(t *testing.T) {
	var unreported plugin.TValue[bool]
	got, err := allowlistBool(nil, &unreported)
	require.NoError(t, err)
	assert.False(t, got)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, unreported.State,
		"an unreported switch must render null; a fabricated false passes a check nobody answered")

	var on plugin.TValue[bool]
	got, err = allowlistBool(github.Ptr(true), &on)
	require.NoError(t, err)
	assert.True(t, got)
	assert.Zero(t, on.State)

	var off plugin.TValue[bool]
	got, err = allowlistBool(github.Ptr(false), &off)
	require.NoError(t, err)
	assert.False(t, got)
	assert.Zero(t, off.State, "a reported false is a real answer, not an unread one")
}

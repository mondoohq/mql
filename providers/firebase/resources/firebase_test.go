// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The project config comes in two shapes. Both have to land the same fields,
// and anonymous sign-in has to be recognised whatever its case, because it
// is the value an "anonymous auth is off" check turns on.
func TestParseAuthConfig(t *testing.T) {
	t.Run("v1 shape", func(t *testing.T) {
		cfg, err := parseAuthConfig([]byte(`{
			"authorizedDomains": ["localhost", "app.example.test"],
			"emailPrivacyConfig": {"enableImprovedEmailPrivacy": true},
			"signInConfig": {"allowedMethods": ["password", "google.com", "ANONYMOUS"]}
		}`))
		require.NoError(t, err)
		assert.Equal(t, []string{"password", "google.com", "ANONYMOUS"}, cfg.signInProviders)
		assert.True(t, cfg.anonymousAuthEnabled)
		assert.Equal(t, []string{"localhost", "app.example.test"}, cfg.authorizedDomains)
		assert.True(t, cfg.emailEnumerationProtection)
	})

	t.Run("legacy shape", func(t *testing.T) {
		cfg, err := parseAuthConfig([]byte(`{
			"authorizedDomains": ["localhost"],
			"idpConfig": [{"provider": "password"}, {"provider": "facebook.com"}, {"noProvider": true}]
		}`))
		require.NoError(t, err)
		assert.Equal(t, []string{"password", "facebook.com"}, cfg.signInProviders)
		assert.False(t, cfg.anonymousAuthEnabled)
		assert.False(t, cfg.emailEnumerationProtection, "absent emailPrivacyConfig reads as unprotected")
	})

	t.Run("v1 wins over legacy when both are present", func(t *testing.T) {
		cfg, err := parseAuthConfig([]byte(`{
			"signInConfig": {"allowedMethods": ["password"]},
			"idpConfig": [{"provider": "google.com"}]
		}`))
		require.NoError(t, err)
		assert.Equal(t, []string{"password"}, cfg.signInProviders)
	})

	t.Run("empty object", func(t *testing.T) {
		cfg, err := parseAuthConfig([]byte(`{}`))
		require.NoError(t, err)
		assert.Empty(t, cfg.signInProviders)
		assert.Empty(t, cfg.authorizedDomains)
		assert.False(t, cfg.anonymousAuthEnabled)
		assert.False(t, cfg.emailEnumerationProtection)
	})

	t.Run("non-JSON is an error", func(t *testing.T) {
		_, err := parseAuthConfig([]byte(`<html>`))
		assert.Error(t, err)
	})

	t.Run("wrong types are ignored", func(t *testing.T) {
		cfg, err := parseAuthConfig([]byte(`{
			"authorizedDomains": "localhost",
			"emailPrivacyConfig": {"enableImprovedEmailPrivacy": "yes"},
			"signInConfig": {"allowedMethods": [1, "password"]}
		}`))
		require.NoError(t, err)
		assert.Empty(t, cfg.authorizedDomains)
		assert.False(t, cfg.emailEnumerationProtection)
		assert.Equal(t, []string{"password"}, cfg.signInProviders)
	})
}

// A createAuthUri answer that names whether the address is registered is the
// leak itself, so it must read as unprotected whatever the status. Only a 200
// that withholds the field is protection. Everything else fails closed.
func TestEmailEnumerationProtected(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"registered false disclosed", http.StatusOK, `{"registered": false, "sessionId": "x"}`, false},
		{"registered true disclosed", http.StatusOK, `{"registered": true}`, false},
		{"withheld on 200", http.StatusOK, `{"sessionId": "x"}`, true},
		{"withheld on 400 is not proof", http.StatusBadRequest, `{"error": {"message": "INVALID_IDENTIFIER"}}`, false},
		{"empty body", http.StatusOK, ``, false},
		{"non-JSON", http.StatusOK, `<html>`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, emailEnumerationProtected(tc.status, []byte(tc.body)))
		})
	}
}

// The probe must hit the createAuthUri endpoint with the key and classify the
// answer; a transport failure reads as unprotected.
func TestProbeEmailEnumerationProtection(t *testing.T) {
	serve := func(t *testing.T, status int, body string) *httptest.Server {
		t.Helper()
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/v1/accounts:createAuthUri", r.URL.Path)
			assert.Equal(t, "k1", r.URL.Query().Get("key"))
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
	}

	t.Run("protected", func(t *testing.T) {
		srv := serve(t, http.StatusOK, `{"sessionId": "x"}`)
		defer srv.Close()
		assert.True(t, probeEmailEnumerationProtection(srv.Client(), srv.URL, "k1"))
	})

	t.Run("disclosing", func(t *testing.T) {
		srv := serve(t, http.StatusOK, `{"registered": false}`)
		defer srv.Close()
		assert.False(t, probeEmailEnumerationProtection(srv.Client(), srv.URL, "k1"))
	})

	t.Run("unreachable", func(t *testing.T) {
		srv := serve(t, http.StatusOK, `{}`)
		srv.Close()
		assert.False(t, probeEmailEnumerationProtection(srv.Client(), srv.URL, "k1"))
	})
}

// Document names carry the collection as their sixth segment. Duplicates
// collapse, order of first sight is kept, and a malformed name is skipped
// rather than producing an empty or wrong id.
func TestCollectionIDsFromDocuments(t *testing.T) {
	ids := collectionIDsFromDocuments([]byte(`{"documents": [
		{"name": "projects/p/databases/(default)/documents/users/u1"},
		{"name": "projects/p/databases/(default)/documents/users/u2"},
		{"name": "projects/p/databases/(default)/documents/orders/o1/items/i1"},
		{"name": "projects/p/databases/(default)/documents"},
		{"name": "projects/p/databases/(default)/documents//x"},
		{"noName": true}
	]}`))
	assert.Equal(t, []string{"users", "orders"}, ids)

	assert.Nil(t, collectionIDsFromDocuments([]byte(`{}`)), "no documents key")
	assert.Nil(t, collectionIDsFromDocuments([]byte(`{"documents": []}`)), "empty page")
	assert.Nil(t, collectionIDsFromDocuments([]byte(`not json`)))
}

// listCollectionIds disclosing an empty list still means the structure is
// readable; only a missing key means nothing was disclosed.
func TestListedCollectionIDs(t *testing.T) {
	ids, ok := listedCollectionIDs([]byte(`{"collectionIds": ["users", "orders", 3]}`))
	assert.True(t, ok)
	assert.Equal(t, []string{"users", "orders"}, ids)

	ids, ok = listedCollectionIDs([]byte(`{"collectionIds": []}`))
	assert.True(t, ok, "an empty list is still a disclosure")
	assert.Empty(t, ids)

	_, ok = listedCollectionIDs([]byte(`{"error": {"code": 403}}`))
	assert.False(t, ok)

	_, ok = listedCollectionIDs([]byte(`<html>`))
	assert.False(t, ok)
}

func TestMergeUnique(t *testing.T) {
	assert.Equal(t, []string{"users", "orders", "audit"}, mergeUnique([]string{"users", "orders"}, []string{"orders", "audit", "users"}))
	assert.Equal(t, []string{"a"}, mergeUnique(nil, []string{"a", "a"}))
	assert.Empty(t, mergeUnique(nil, nil))
}

// A src is resolved the way a browser would; a wrong join here checks the
// map of a URL that does not exist and reports the bundle as safe.
func TestResolveScriptURL(t *testing.T) {
	const page = "https://app.example.test"
	cases := map[string]string{
		"//cdn.example.test/lib.js":       "https://cdn.example.test/lib.js",
		"/static/js/main.abc.js":          page + "/static/js/main.abc.js",
		"static/js/main.abc.js":           page + "/static/js/main.abc.js",
		"https://other.example.test/x.js": "https://other.example.test/x.js",
		"http://other.example.test/x.js":  "http://other.example.test/x.js",
	}
	for src, want := range cases {
		assert.Equal(t, want, resolveScriptURL(src, page), src)
	}
}

func TestIsExternalScript(t *testing.T) {
	assert.True(t, isExternalScript("https://www.gstatic.com/firebasejs/10.0.0/firebase-app.js"))
	assert.True(t, isExternalScript("https://www.googletagmanager.com/gtag/js?id=G-1"))
	assert.False(t, isExternalScript("https://app.example.test/static/js/main.js"))
}

// Hosting configured as a single-page app answers every path with the app
// shell, so a 200 for main.js.map is only a leak when the body is a map.
func TestLooksLikeSourceMap(t *testing.T) {
	assert.True(t, looksLikeSourceMap([]byte(`{"version":3,"sources":["src/App.tsx"],"mappings":"AAAA"}`)))
	assert.True(t, looksLikeSourceMap([]byte(`{"version":3,"mappings":"AAAA"`)), "a truncated peek still shows the key")
	assert.False(t, looksLikeSourceMap([]byte(`<!doctype html><html><head><title>App</title></head></html>`)))
	assert.False(t, looksLikeSourceMap(nil))
}

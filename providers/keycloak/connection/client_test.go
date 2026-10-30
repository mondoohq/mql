// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantBase string
		wantHost string
		wantErr  bool
	}{
		{name: "plain host", raw: "https://keycloak.example.com", wantBase: "https://keycloak.example.com", wantHost: "keycloak.example.com"},
		{name: "trailing slash", raw: "https://keycloak.example.com/", wantBase: "https://keycloak.example.com", wantHost: "keycloak.example.com"},
		{name: "context path", raw: "https://keycloak.example.com/auth/", wantBase: "https://keycloak.example.com/auth", wantHost: "keycloak.example.com"},
		{name: "port", raw: "http://localhost:8080", wantBase: "http://localhost:8080", wantHost: "localhost:8080"},
		{name: "surrounding space", raw: "  https://kc.example.com  ", wantBase: "https://kc.example.com", wantHost: "kc.example.com"},
		{name: "no scheme", raw: "keycloak.example.com", wantErr: true},
		{name: "wrong scheme", raw: "ldap://keycloak.example.com", wantErr: true},
		{name: "empty", raw: "   ", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base, host, err := NormalizeBaseURL(tc.raw)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantBase, base)
			assert.Equal(t, tc.wantHost, host)
		})
	}
}

func TestGrantForm(t *testing.T) {
	t.Run("password grant defaults to admin-cli", func(t *testing.T) {
		form, err := grantForm("", "", "admin", "secret")
		require.NoError(t, err)
		assert.Equal(t, "password", form.Get("grant_type"))
		assert.Equal(t, "admin-cli", form.Get("client_id"))
		assert.Equal(t, "admin", form.Get("username"))
		assert.Equal(t, "secret", form.Get("password"))
		assert.Empty(t, form.Get("client_secret"))
	})

	t.Run("password grant keeps a confidential client secret", func(t *testing.T) {
		form, err := grantForm("scanner", "topsecret", "admin", "pw")
		require.NoError(t, err)
		assert.Equal(t, "password", form.Get("grant_type"))
		assert.Equal(t, "scanner", form.Get("client_id"))
		assert.Equal(t, "topsecret", form.Get("client_secret"))
	})

	t.Run("client credentials grant", func(t *testing.T) {
		form, err := grantForm("scanner", "topsecret", "", "")
		require.NoError(t, err)
		assert.Equal(t, "client_credentials", form.Get("grant_type"))
		assert.Equal(t, "scanner", form.Get("client_id"))
		assert.Empty(t, form.Get("username"))
	})

	t.Run("a user without a password is rejected", func(t *testing.T) {
		_, err := grantForm("", "", "admin", "")
		require.Error(t, err)
	})

	t.Run("a client secret without a client id is rejected", func(t *testing.T) {
		_, err := grantForm("", "topsecret", "", "")
		require.Error(t, err)
	})

	t.Run("no credentials at all is rejected", func(t *testing.T) {
		_, err := grantForm("", "", "", "")
		require.Error(t, err)
	})
}

func TestDefaultAuthRealmFor(t *testing.T) {
	assert.Equal(t, "master", defaultAuthRealmFor("password", "production"))
	assert.Equal(t, "master", defaultAuthRealmFor("client_credentials", ""))
	assert.Equal(t, "production", defaultAuthRealmFor("client_credentials", "production"))
}

func TestAdminPath(t *testing.T) {
	assert.Equal(t, "/admin/realms/master", AdminPath("master"))
	assert.Equal(t, "/admin/realms/master/clients", AdminPath("master", "clients"))
	// A realm or an alias can carry a character that would otherwise be read
	// as path structure, so every segment is escaped.
	assert.Equal(t, "/admin/realms/my%2Frealm/groups/a%20b", AdminPath("my/realm", "groups", "a b"))
}

func TestErrorClassifiers(t *testing.T) {
	assert.True(t, IsForbidden(&APIError{StatusCode: http.StatusForbidden}))
	assert.True(t, IsForbidden(&APIError{StatusCode: http.StatusUnauthorized}))
	assert.False(t, IsForbidden(&APIError{StatusCode: http.StatusNotFound}))
	assert.False(t, IsForbidden(&APIError{StatusCode: http.StatusInternalServerError}))
	// A transport failure must not be read as a permission problem, otherwise
	// a network blip degrades a field to null and an audit passes on data that
	// was never read.
	assert.False(t, IsForbidden(errors.New("connection refused")))

	assert.True(t, IsNotFound(&APIError{StatusCode: http.StatusNotFound}))
	assert.False(t, IsNotFound(&APIError{StatusCode: http.StatusForbidden}))
	assert.False(t, IsNotFound(errors.New("connection refused")))

	// The classifiers must see through a wrapped error.
	wrapped := fmt.Errorf("reading clients: %w", &APIError{StatusCode: http.StatusForbidden})
	assert.True(t, IsForbidden(wrapped))
}

func TestAPIErrorMessage(t *testing.T) {
	withMessage := &APIError{StatusCode: 403, Path: "/admin/realms", Message: "forbidden"}
	assert.Equal(t, "keycloak API /admin/realms: 403 (forbidden)", withMessage.Error())

	bare := &APIError{StatusCode: 500, Path: "/admin/realms"}
	assert.Equal(t, "keycloak API /admin/realms: 500", bare.Error())
}

func TestNewAPIError(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "errorMessage wins", body: `{"errorMessage":"unknown_error","error":"generic"}`, want: "unknown_error"},
		{name: "error_description", body: `{"error_description":"missing scope"}`, want: "missing scope"},
		{name: "bare error", body: `{"error":"HTTP 403 Forbidden"}`, want: "HTTP 403 Forbidden"},
		{name: "html body", body: `<html>gateway</html>`, want: ""},
		{name: "empty body", body: ``, want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := newAPIError("/admin/realms", 403, []byte(tc.body))
			assert.Equal(t, 403, err.StatusCode)
			assert.Equal(t, tc.want, err.Message)
		})
	}
}

// testConnection builds a connection against a test server, with a token
// source that already holds a token so the tests drive only the admin API.
func testConnection(t *testing.T, srv *httptest.Server) *KeycloakConnection {
	t.Helper()

	conf := &inventory.Config{
		Type:    "keycloak",
		Options: map[string]string{"url": srv.URL, "username": "admin"},
		Credentials: []*vault.Credential{
			vault.NewPasswordCredential("admin", "pw"),
		},
	}

	conn, err := NewKeycloakConnection(1, &inventory.Asset{}, conf)
	require.NoError(t, err)
	conn.client = srv.Client()
	conn.tokens.client = srv.Client()
	return conn
}

func TestGetPagedWalksEveryPage(t *testing.T) {
	type record struct {
		ID string `json:"id"`
	}

	var requested []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			writeToken(t, w, "token-1", 300, "", 0)
			return
		}

		requested = append(requested, r.URL.Query().Get("first"))
		first, _ := strconv.Atoi(r.URL.Query().Get("first"))

		// Two full pages, then a short one that ends the walk.
		batch := []record{}
		switch first {
		case 0, 100:
			for i := range pageSize {
				batch = append(batch, record{ID: strconv.Itoa(first + i)})
			}
		case 200:
			batch = append(batch, record{ID: "200"})
		}
		require.NoError(t, json.NewEncoder(w).Encode(batch))
	}))
	defer srv.Close()

	conn := testConnection(t, srv)

	records, err := GetPaged[record](context.Background(), conn, "/admin/realms/master/users", nil)
	require.NoError(t, err)
	assert.Len(t, records, 201)
	assert.Equal(t, []string{"0", "100", "200"}, requested)
	assert.Equal(t, "200", records[200].ID)
}

func TestGetPagedStopsOnARepeatedPage(t *testing.T) {
	type record struct {
		ID string `json:"id"`
	}

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			writeToken(t, w, "token-1", 300, "", 0)
			return
		}

		calls++
		// An endpoint that ignores first answers every request with page one.
		batch := make([]record, 0, pageSize)
		for i := range pageSize {
			batch = append(batch, record{ID: strconv.Itoa(i)})
		}
		require.NoError(t, json.NewEncoder(w).Encode(batch))
	}))
	defer srv.Close()

	conn := testConnection(t, srv)

	records, err := GetPaged[record](context.Background(), conn, "/admin/realms/master/users", nil)
	require.NoError(t, err)
	// The duplicate page is dropped, so the records are not multiplied by the
	// page cap.
	assert.Len(t, records, pageSize)
	assert.Equal(t, 2, calls)
}

func TestGetPagedKeepsCallerQuery(t *testing.T) {
	type record struct {
		ID string `json:"id"`
	}

	var seen url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			writeToken(t, w, "token-1", 300, "", 0)
			return
		}
		seen = r.URL.Query()
		require.NoError(t, json.NewEncoder(w).Encode([]record{}))
	}))
	defer srv.Close()

	conn := testConnection(t, srv)

	query := url.Values{"briefRepresentation": []string{"false"}}
	_, err := GetPaged[record](context.Background(), conn, "/admin/realms/master/clients", query)
	require.NoError(t, err)

	assert.Equal(t, "false", seen.Get("briefRepresentation"))
	assert.Equal(t, strconv.Itoa(pageSize), seen.Get("max"))
	// The caller's values must not be mutated, since the same map is reused
	// across calls.
	assert.Empty(t, query.Get("max"))
	assert.Empty(t, query.Get("first"))
}

func TestGetRetriesOnceAfterAnExpiredToken(t *testing.T) {
	tokens := 0
	attempts := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			tokens++
			writeToken(t, w, "token-"+strconv.Itoa(tokens), 300, "", 0)
			return
		}

		attempts++
		// The server rejects the first token, as it does after a session is
		// revoked while the cache still holds the token.
		if r.Header.Get("Authorization") == "Bearer token-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"realm": "master"}))
	}))
	defer srv.Close()

	conn := testConnection(t, srv)

	var out map[string]string
	require.NoError(t, conn.Get(context.Background(), "/admin/realms/master", nil, &out))
	assert.Equal(t, "master", out["realm"])
	assert.Equal(t, 2, attempts)
	assert.Equal(t, 2, tokens)
}

func TestGetReportsAPersistent401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			writeToken(t, w, "token", 300, "", 0)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"HTTP 401 Unauthorized"}`))
	}))
	defer srv.Close()

	conn := testConnection(t, srv)

	err := conn.Get(context.Background(), "/admin/realms/master", nil, nil)
	require.Error(t, err)
	assert.True(t, IsForbidden(err))
}

func TestGetReportsAForbiddenResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			writeToken(t, w, "token", 300, "", 0)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"unknown_error"}`))
	}))
	defer srv.Close()

	conn := testConnection(t, srv)

	err := conn.Get(context.Background(), "/admin/realms/master/users", nil, nil)
	require.Error(t, err)
	assert.True(t, IsForbidden(err))

	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, "unknown_error", apiErr.Message)
}

func TestRealmFilterPrefersTheDiscoveredRealm(t *testing.T) {
	conn := &KeycloakConnection{Conf: &inventory.Config{Options: map[string]string{
		"realm":     "flag-realm",
		"realmName": "discovered-realm",
	}}}
	assert.Equal(t, "discovered-realm", conn.RealmFilter())

	conn = &KeycloakConnection{Conf: &inventory.Config{Options: map[string]string{"realm": "flag-realm"}}}
	assert.Equal(t, "flag-realm", conn.RealmFilter())

	conn = &KeycloakConnection{Conf: &inventory.Config{}}
	assert.Empty(t, conn.RealmFilter())
}

func TestNewKeycloakConnectionRequiresAUrl(t *testing.T) {
	t.Setenv("KEYCLOAK_URL", "")
	_, err := NewKeycloakConnection(1, &inventory.Asset{}, &inventory.Config{Type: "keycloak"})
	require.Error(t, err)
}

func TestNewKeycloakConnectionSeparatesTheCredentials(t *testing.T) {
	t.Setenv("KEYCLOAK_PASSWORD", "")
	t.Setenv("KEYCLOAK_CLIENT_SECRET", "")

	conf := &inventory.Config{
		Type:    "keycloak",
		Options: map[string]string{"url": "https://kc.example.com", "client-id": "scanner"},
		Credentials: []*vault.Credential{
			// A credential with a user name is the admin password, one
			// without is the client secret.
			vault.NewPasswordCredential("admin", "user-password"),
			vault.NewPasswordCredential("", "client-secret"),
		},
	}

	conn, err := NewKeycloakConnection(1, &inventory.Asset{}, conf)
	require.NoError(t, err)
	assert.Equal(t, "password", conn.tokens.grant.Get("grant_type"))
	assert.Equal(t, "admin", conn.tokens.grant.Get("username"))
	assert.Equal(t, "user-password", conn.tokens.grant.Get("password"))
	assert.Equal(t, "client-secret", conn.tokens.grant.Get("client_secret"))
	assert.Equal(t, "https://kc.example.com/realms/master/protocol/openid-connect/token", conn.tokens.tokenURL)
}

func TestNewKeycloakConnectionUsesTheScannedRealmForAServiceAccount(t *testing.T) {
	t.Setenv("KEYCLOAK_PASSWORD", "")

	conf := &inventory.Config{
		Type:    "keycloak",
		Options: map[string]string{"url": "https://kc.example.com", "client-id": "scanner", "realm": "production"},
		Credentials: []*vault.Credential{
			vault.NewPasswordCredential("", "client-secret"),
		},
	}

	conn, err := NewKeycloakConnection(1, &inventory.Asset{}, conf)
	require.NoError(t, err)
	assert.Equal(t, "client_credentials", conn.tokens.grant.Get("grant_type"))
	assert.Equal(t, "https://kc.example.com/realms/production/protocol/openid-connect/token", conn.tokens.tokenURL)
}

func TestNewKeycloakConnectionHonorsTheAuthRealm(t *testing.T) {
	t.Setenv("KEYCLOAK_PASSWORD", "")

	conf := &inventory.Config{
		Type: "keycloak",
		Options: map[string]string{
			"url": "https://kc.example.com", "client-id": "scanner",
			"realm": "production", "auth-realm": "master",
		},
		Credentials: []*vault.Credential{vault.NewPasswordCredential("", "client-secret")},
	}

	conn, err := NewKeycloakConnection(1, &inventory.Asset{}, conf)
	require.NoError(t, err)
	assert.Equal(t, "https://kc.example.com/realms/master/protocol/openid-connect/token", conn.tokens.tokenURL)
}

func TestFullRepresentationIsAFreshCopy(t *testing.T) {
	first := FullRepresentation()
	assert.Equal(t, "false", first.Get("briefRepresentation"))

	// Each caller must get its own map, since GetPaged and the callers add
	// their own keys to it.
	first.Set("max", "1")
	assert.Empty(t, FullRepresentation().Get("max"))
}

func TestAuthRealmIsReportedForACarriedOverScope(t *testing.T) {
	t.Setenv("KEYCLOAK_PASSWORD", "")

	// An unscoped service account root authenticates against master. A realm
	// discovered from it must keep that realm, otherwise it would ask its own
	// realm for a token and fail.
	root := &inventory.Config{
		Type:        "keycloak",
		Options:     map[string]string{"url": "https://kc.example.com", "client-id": "scanner"},
		Credentials: []*vault.Credential{vault.NewPasswordCredential("", "client-secret")},
	}
	conn, err := NewKeycloakConnection(1, &inventory.Asset{}, root)
	require.NoError(t, err)
	assert.Equal(t, "master", conn.AuthRealm())

	child := &inventory.Config{
		Type: "keycloak",
		Options: map[string]string{
			"url": "https://kc.example.com", "client-id": "scanner",
			"realmName": "production", "auth-realm": conn.AuthRealm(),
		},
		Credentials: []*vault.Credential{vault.NewPasswordCredential("", "client-secret")},
	}
	childConn, err := NewKeycloakConnection(2, &inventory.Asset{}, child)
	require.NoError(t, err)
	assert.Equal(t, "production", childConn.RealmFilter())
	assert.Equal(t, "master", childConn.AuthRealm())
	assert.Equal(t, "https://kc.example.com/realms/master/protocol/openid-connect/token", childConn.tokens.tokenURL)
}

func TestNewKeycloakRealmIdentifierEscapesItsSegments(t *testing.T) {
	assert.Equal(t,
		PlatformIdKeycloakRealm+"kc.example.com/realm/production",
		NewKeycloakRealmIdentifier("kc.example.com", "production"))

	// A realm name may carry a slash. Without escaping it would read as a
	// deeper path, so two different realms could share one identifier.
	assert.Equal(t,
		PlatformIdKeycloakRealm+"kc.example.com/realm/my%2Frealm",
		NewKeycloakRealmIdentifier("kc.example.com", "my/realm"))

	assert.NotEqual(t,
		NewKeycloakRealmIdentifier("kc.example.com", "my/realm"),
		NewKeycloakRealmIdentifier("kc.example.com/realm/my", "realm"))
}

func TestGetPagedKeepsEveryRecordFromANonPagingEndpoint(t *testing.T) {
	type record struct {
		ID string `json:"id"`
	}

	// The authentication flow and component endpoints answer with the whole
	// list and ignore first and max. The walk must return every record once,
	// not truncate at the page size and not repeat the body.
	const total = 250

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
			writeToken(t, w, "token", 300, "", 0)
			return
		}

		calls++
		batch := make([]record, 0, total)
		for i := range total {
			batch = append(batch, record{ID: strconv.Itoa(i)})
		}
		require.NoError(t, json.NewEncoder(w).Encode(batch))
	}))
	defer srv.Close()

	conn := testConnection(t, srv)

	records, err := GetPaged[record](context.Background(), conn, "/admin/realms/master/authentication/flows", nil)
	require.NoError(t, err)
	assert.Len(t, records, total)
	assert.Equal(t, "0", records[0].ID)
	assert.Equal(t, strconv.Itoa(total-1), records[total-1].ID)
	// One request for the body, one that repeats it and ends the walk.
	assert.Equal(t, 2, calls)
}

func TestCACertificateReadsThePemDirectly(t *testing.T) {
	t.Setenv("KEYCLOAK_CA_CERT", "")

	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	conf := &inventory.Config{Options: map[string]string{OptionCACert: pem}}

	got, err := CACertificate(conf)
	require.NoError(t, err)
	assert.Equal(t, pem, string(got))
}

func TestCACertificateReadsAPath(t *testing.T) {
	t.Setenv("KEYCLOAK_CA_CERT", "")

	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, []byte(pem), 0o600))

	conf := &inventory.Config{Options: map[string]string{OptionCACert: path}}
	got, err := CACertificate(conf)
	require.NoError(t, err)
	assert.Equal(t, pem, string(got))
}

func TestCACertificateIsAbsentByDefault(t *testing.T) {
	t.Setenv("KEYCLOAK_CA_CERT", "")

	got, err := CACertificate(nil)
	require.NoError(t, err)
	assert.Empty(t, got)

	got, err = CACertificate(&inventory.Config{})
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestCACertificateReportsAnUnreadablePath(t *testing.T) {
	t.Setenv("KEYCLOAK_CA_CERT", "")

	conf := &inventory.Config{Options: map[string]string{OptionCACert: "/no/such/ca.pem"}}
	_, err := CACertificate(conf)
	require.Error(t, err)
}

func TestNewHTTPClientWithoutACertificateKeepsTheDefaultTransport(t *testing.T) {
	t.Setenv("KEYCLOAK_CA_CERT", "")

	client, err := newHTTPClient(&inventory.Config{})
	require.NoError(t, err)
	// No custom transport means the system roots apply and the certificate is
	// verified.
	assert.Nil(t, client.Transport)
	assert.Equal(t, requestTimeout, client.Timeout)
}

func TestNewHTTPClientTrustsTheNamedAuthority(t *testing.T) {
	t.Setenv("KEYCLOAK_CA_CERT", "")

	// A real self-signed certificate, so the pool genuinely accepts it.
	pem := selfSignedPEM(t)
	conf := &inventory.Config{Options: map[string]string{OptionCACert: string(pem)}}

	client, err := newHTTPClient(conf)
	require.NoError(t, err)

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, transport.TLSClientConfig)
	// Verification stays on. The authority is added, not bypassed.
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
	assert.NotNil(t, transport.TLSClientConfig.RootCAs)
	assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
}

func TestNewHTTPClientRejectsAGarbageCertificate(t *testing.T) {
	t.Setenv("KEYCLOAK_CA_CERT", "")

	conf := &inventory.Config{Options: map[string]string{OptionCACert: "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----"}}
	_, err := newHTTPClient(conf)
	require.Error(t, err)
}

// selfSignedPEM builds a throwaway certificate authority for the trust tests.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "keycloak-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestIncludeGlobals(t *testing.T) {
	// The profiles endpoint takes one spelling.
	profiles := IncludeGlobals(IncludeGlobalProfilesParam)
	assert.Equal(t, "true", profiles.Get(IncludeGlobalProfilesParam))
	assert.Len(t, profiles, 1)

	// The policies endpoint has used two spellings across versions. Both are
	// sent, since Keycloak ignores a parameter it does not know and the
	// alternative is silently dropping the built-in policies.
	policies := IncludeGlobals(IncludeGlobalPoliciesParam, IncludeGlobalClientPoliciesParam)
	assert.Equal(t, "true", policies.Get(IncludeGlobalPoliciesParam))
	assert.Equal(t, "true", policies.Get(IncludeGlobalClientPoliciesParam))
	assert.Len(t, policies, 2)

	// The two endpoints must not share a spelling, which is the bug this
	// replaced.
	assert.NotEqual(t, IncludeGlobalProfilesParam, IncludeGlobalPoliciesParam)

	// Each call returns its own map, since GetPaged and callers add keys.
	first := IncludeGlobals(IncludeGlobalProfilesParam)
	first.Set("max", "1")
	assert.Empty(t, IncludeGlobals(IncludeGlobalProfilesParam).Get("max"))

	assert.Empty(t, IncludeGlobals())
}

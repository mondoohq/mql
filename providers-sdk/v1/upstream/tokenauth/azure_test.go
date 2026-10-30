// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tokenauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// testResource is the app registration Azure mints the token for.
	testResource = "api://mondoo-wif"
	// testExchangeAudience is the Mondoo scope MRN. Azure cannot mint a token for it.
	testExchangeAudience = "//captain.api.mondoo.app/spaces/test-space"
	// testCloudShellURL stands in for the fixed Cloud Shell endpoint.
	testCloudShellURL = "http://localhost:50342/oauth2/token"
)

// clearAzureEnv isolates a test from the developer's own managed identity vars.
func clearAzureEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{envTokenAudience, envClientID, envIdentityEndpoint, envIdentityHeader} {
		t.Setenv(key, "")
	}
}

// capturedRequest is a copy of what a request type actually put on the wire. The
// handler's *http.Request must not escape the handler, so every field is copied.
type capturedRequest struct {
	method string
	url    url.URL
	header http.Header
	body   string
}

// query returns the request's query string parameters.
func (c capturedRequest) query() url.Values {
	return c.url.Query()
}

// form parses the request body as a form submission.
func (c capturedRequest) form(t *testing.T) url.Values {
	t.Helper()
	form, err := url.ParseQuery(c.body)
	require.NoError(t, err)
	return form
}

// tokenServer serves an access token and records the request it answered. The
// returned func hands back the recorded request, synchronized against the
// handler goroutine that wrote it.
func tokenServer(t *testing.T, token string) (*httptest.Server, func() capturedRequest) {
	t.Helper()
	var mu sync.Mutex
	var got *capturedRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		mu.Lock()
		got = &capturedRequest{method: r.Method, url: *r.URL, header: r.Header.Clone(), body: string(body)}
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + token + `"}`))
	}))
	t.Cleanup(server.Close)
	return server, func() capturedRequest {
		mu.Lock()
		defer mu.Unlock()
		require.NotNil(t, got, "server was never called")
		return *got
	}
}

func failingServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestAzureTokenRequests checks which endpoints get registered, in what order,
// and with which parameters — without any network access.
func TestAzureTokenRequests(t *testing.T) {
	t.Run("app service first, then cloud shell", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envIdentityEndpoint, "http://localhost:12345/msi/token")
		t.Setenv(envIdentityHeader, "secret-header")
		t.Setenv(envClientID, "client-123")
		t.Setenv(envTokenAudience, testResource)

		reqs, err := azureTokenRequests(testExchangeAudience, testCloudShellURL)
		require.NoError(t, err)
		require.Len(t, reqs, 2)

		// App Service mints for the app registration named by the env var.
		assert.Equal(t, appServiceTokenRequest{
			endpoint: "http://localhost:12345/msi/token",
			header:   "secret-header",
			resource: testResource,
			clientID: "client-123",
		}, reqs[0])

		// Cloud Shell mints for the exchange audience, and reads no env vars.
		assert.Equal(t, cloudShellTokenRequest{
			endpoint: testCloudShellURL,
			resource: testExchangeAudience,
		}, reqs[1])
	})

	// An empty client id falls back to the system-assigned identity.
	t.Run("app service without client id", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envIdentityEndpoint, "http://localhost:12345/msi/token")
		t.Setenv(envIdentityHeader, "secret-header")
		t.Setenv(envTokenAudience, testResource)

		reqs, err := azureTokenRequests(testExchangeAudience, testCloudShellURL)
		require.NoError(t, err)
		require.Len(t, reqs, 2)
		assert.Empty(t, reqs[0].(appServiceTokenRequest).clientID)
	})

	t.Run("no identity endpoint: cloud shell only", func(t *testing.T) {
		clearAzureEnv(t)

		reqs, err := azureTokenRequests(testExchangeAudience, testCloudShellURL)
		require.NoError(t, err)
		require.Len(t, reqs, 1)
		assert.Equal(t, cloudShellTokenRequest{
			endpoint: testCloudShellURL,
			resource: testExchangeAudience,
		}, reqs[0])
	})

	// Unset, App Service falls back to the passed audience — which a working Azure
	// exchange sets to the same app registration URI, so the operator sets it once.
	t.Run("app service resource falls back to the passed audience", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envIdentityEndpoint, "http://localhost:12345/msi/token")
		t.Setenv(envIdentityHeader, "secret-header")

		reqs, err := azureTokenRequests(testResource, testCloudShellURL)
		require.NoError(t, err)
		require.Len(t, reqs, 2)
		assert.Equal(t, testResource, reqs[0].(appServiceTokenRequest).resource)
	})

	// MONDOO_WIF_AUDIENCE overrides the passed audience when the two must differ.
	t.Run("app service env audience overrides the passed audience", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envIdentityEndpoint, "http://localhost:12345/msi/token")
		t.Setenv(envIdentityHeader, "secret-header")
		t.Setenv(envTokenAudience, "api://override")

		reqs, err := azureTokenRequests(testResource, testCloudShellURL)
		require.NoError(t, err)
		require.Len(t, reqs, 2)
		assert.Equal(t, "api://override", reqs[0].(appServiceTokenRequest).resource)
	})

	// MONDOO_WIF_AUDIENCE is for App Service alone. Cloud Shell has no app
	// registration to target and must keep minting for the exchange audience.
	t.Run("cloud shell ignores the env audience", func(t *testing.T) {
		clearAzureEnv(t)
		t.Setenv(envTokenAudience, testResource)
		t.Setenv(envClientID, "client-123")

		reqs, err := azureTokenRequests(testExchangeAudience, testCloudShellURL)
		require.NoError(t, err)
		require.Len(t, reqs, 1)
		assert.Equal(t, testExchangeAudience, reqs[0].(cloudShellTokenRequest).resource)
	})
}

// TestAzureTokenRequestsAppServiceRequiresIdentityHeader guards the SSRF secret.
// Sending an empty X-IDENTITY-HEADER earns a bodiless 401 that names nothing, so
// the missing variable has to be named here instead.
func TestAzureTokenRequestsAppServiceRequiresIdentityHeader(t *testing.T) {
	clearAzureEnv(t)
	t.Setenv(envIdentityEndpoint, "http://localhost:12345/msi/token")
	t.Setenv(envTokenAudience, testResource)

	_, err := azureTokenRequests(testExchangeAudience, testCloudShellURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), envIdentityHeader)

	// It must not silently degrade to Cloud Shell, which serves a different
	// environment and would fail with an error naming the wrong endpoint.
	assert.NotContains(t, err.Error(), "cloud shell")
}

// TestAzureTokenRequestsNamesTheInjectedVariableFirst pins the order of the two
// checks. When both are unset, IDENTITY_HEADER is the one to report: Azure injects
// it, so its absence means the environment is not the one IDENTITY_ENDPOINT
// implies — which subsumes any misconfiguration of the variables we define.
func TestAzureTokenRequestsNamesTheInjectedVariableFirst(t *testing.T) {
	clearAzureEnv(t)
	t.Setenv(envIdentityEndpoint, "http://localhost:12345/msi/token")

	_, err := azureTokenRequests(testExchangeAudience, testCloudShellURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), envIdentityHeader)
	assert.NotContains(t, err.Error(), envTokenAudience)
}

// TestAzureTokenRequestsAppServiceRequiresAResource guards the one case the
// fallback cannot rescue: no env audience and no passed audience leaves App
// Service nothing to request, which Azure answers with an opaque 400.
func TestAzureTokenRequestsAppServiceRequiresAResource(t *testing.T) {
	clearAzureEnv(t)
	t.Setenv(envIdentityEndpoint, "http://localhost:12345/msi/token")
	t.Setenv(envIdentityHeader, "secret-header")

	// Empty passed audience, and MONDOO_WIF_AUDIENCE unset: nothing to fall back to.
	_, err := azureTokenRequests("", testCloudShellURL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), envTokenAudience)

	// It must not silently degrade to Cloud Shell, which serves a different
	// environment and would fail with an error naming the wrong endpoint.
	assert.NotContains(t, err.Error(), "cloud shell")
}

// TestAzureTokenRequestsAlwaysTriesCloudShell pins backwards compatibility: the
// pre-App-Service code always POSTed to the Cloud Shell endpoint, even with an
// empty resource, so Cloud Shell must be registered unconditionally — never gated
// on the audience being present.
func TestAzureTokenRequestsAlwaysTriesCloudShell(t *testing.T) {
	clearAzureEnv(t)

	// No endpoint, and an empty audience: the old code still sent this request.
	reqs, err := azureTokenRequests("", testCloudShellURL)
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	assert.Equal(t, cloudShellTokenRequest{
		endpoint: testCloudShellURL,
		resource: "",
	}, reqs[0])
}

// TestAppServiceTokenRequest pins the App Service wire format: a GET with the
// resource in the query and the injected secret in X-IDENTITY-HEADER.
func TestAppServiceTokenRequest(t *testing.T) {
	t.Run("with a user-assigned identity", func(t *testing.T) {
		server, captured := tokenServer(t, "eyJfake.appservice.token")

		req := appServiceTokenRequest{
			endpoint: server.URL,
			header:   "hdr-secret",
			resource: testResource,
			clientID: "client-abc",
		}
		token, err := req.RequestToken(context.Background(), server.Client())
		require.NoError(t, err)
		assert.Equal(t, "eyJfake.appservice.token", token)

		got := captured()
		assert.Equal(t, http.MethodGet, got.method)
		assert.Equal(t, "hdr-secret", got.header.Get("X-IDENTITY-HEADER"))
		q := got.query()
		assert.Equal(t, appServiceAPIVersion, q.Get("api-version"))
		assert.Equal(t, testResource, q.Get("resource"))
		assert.Equal(t, "client-abc", q.Get("client_id"))
	})

	// No client_id at all, rather than an empty one, which Azure rejects.
	t.Run("with the system-assigned identity", func(t *testing.T) {
		server, captured := tokenServer(t, "eyJfake.appservice.token")

		req := appServiceTokenRequest{endpoint: server.URL, header: "hdr-secret", resource: testResource}
		_, err := req.RequestToken(context.Background(), server.Client())
		require.NoError(t, err)

		assert.False(t, captured().query().Has("client_id"))
	})

	// The label must name the endpoint and resource, and never the secret.
	t.Run("label", func(t *testing.T) {
		withID := appServiceTokenRequest{endpoint: "http://msi", header: "hdr-secret", resource: testResource, clientID: "client-abc"}
		assert.Equal(t, "app service (http://msi, resource=api://mondoo-wif, client_id=client-abc)", withID.String())
		assert.NotContains(t, withID.String(), "hdr-secret")

		systemAssigned := appServiceTokenRequest{endpoint: "http://msi", header: "hdr-secret", resource: testResource}
		assert.Equal(t, "app service (http://msi, resource=api://mondoo-wif, system-assigned identity)", systemAssigned.String())
	})
}

// TestCloudShellTokenRequest pins the Cloud Shell wire format: a form-encoded
// POST with no client_id and no api-version.
func TestCloudShellTokenRequest(t *testing.T) {
	server, captured := tokenServer(t, "eyJcloudshell.token")

	req := cloudShellTokenRequest{endpoint: server.URL, resource: testExchangeAudience}
	token, err := req.RequestToken(context.Background(), server.Client())
	require.NoError(t, err)
	assert.Equal(t, "eyJcloudshell.token", token)

	got := captured()
	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "true", got.header.Get("Metadata"))
	assert.Equal(t, "application/x-www-form-urlencoded", got.header.Get("Content-Type"))

	form := got.form(t)
	assert.Equal(t, testExchangeAudience, form.Get("resource"))
	assert.False(t, form.Has("client_id"))
	assert.False(t, form.Has("api-version"))

	assert.Equal(t, "cloud shell ("+server.URL+", resource="+testExchangeAudience+")", req.String())
}

// TestCloudShellRequestMatchesLegacyWireFormat pins the Cloud Shell request to
// the exact request this provider sent before App Service support was added, so
// an existing Cloud Shell user cannot be broken by a refactor here.
func TestCloudShellRequestMatchesLegacyWireFormat(t *testing.T) {
	// The endpoint the old code hardcoded.
	assert.Equal(t, "http://localhost:50342/oauth2/token", cloudShellTokenURL)

	server, captured := tokenServer(t, "eyJcloudshell.token")

	// No identity endpoint: the environment the old code always assumed. The
	// resource is the audience the caller passed, exactly as before.
	clearAzureEnv(t)

	reqs, err := azureTokenRequests(testExchangeAudience, server.URL+"/oauth2/token")
	require.NoError(t, err)
	require.Len(t, reqs, 1)
	_, err = reqs[0].RequestToken(context.Background(), server.Client())
	require.NoError(t, err)
	got := captured()

	// Verbatim reconstruction of the pre-PR implementation.
	legacyData := make(url.Values)
	legacyData.Set("resource", testExchangeAudience)
	legacy, err := http.NewRequestWithContext(
		context.Background(), "POST", server.URL+"/oauth2/token", strings.NewReader(legacyData.Encode()))
	require.NoError(t, err)
	legacy.Header.Add("Metadata", "true")
	legacy.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	assert.Equal(t, legacy.Method, got.method)
	assert.Equal(t, legacy.URL.Path, got.url.Path)
	assert.Equal(t, legacy.URL.RawQuery, got.url.RawQuery)
	for _, header := range []string{"Metadata", "Content-Type"} {
		assert.Equal(t, legacy.Header.Get(header), got.header.Get(header), header)
	}

	legacyBody, err := io.ReadAll(legacy.Body)
	require.NoError(t, err)
	assert.Equal(t, string(legacyBody), got.body)
}

// TestAzureTokenProvider_GetToken_AppService covers Function Apps and Container
// Apps jobs, which both expose IDENTITY_ENDPOINT and IDENTITY_HEADER.
func TestAzureTokenProvider_GetToken_AppService(t *testing.T) {
	server, captured := tokenServer(t, "eyJfake.appservice.token")

	clearAzureEnv(t)
	t.Setenv(envIdentityEndpoint, server.URL)
	t.Setenv(envIdentityHeader, "hdr-secret")
	t.Setenv(envClientID, "client-abc")
	t.Setenv(envTokenAudience, testResource)

	p := &AzureTokenProvider{}
	token, err := p.GetToken(context.Background(), testExchangeAudience)
	require.NoError(t, err)
	assert.Equal(t, "eyJfake.appservice.token", token)

	// resource comes from the env var, not the exchange audience (an MRN).
	assert.Equal(t, testResource, captured().query().Get("resource"))
}

// TestAzureTokenProvider_GetToken_CloudShell guards the pre-IMDS localhost:50342
// endpoint, which Cloud Shell still serves today.
func TestAzureTokenProvider_GetToken_CloudShell(t *testing.T) {
	server, captured := tokenServer(t, "eyJcloudshell.token")

	clearAzureEnv(t)
	// Set, and ignored: Cloud Shell mints for the exchange audience.
	t.Setenv(envTokenAudience, testResource)

	p := &AzureTokenProvider{cloudShellURL: server.URL}
	token, err := p.GetToken(context.Background(), testExchangeAudience)
	require.NoError(t, err)
	assert.Equal(t, "eyJcloudshell.token", token)

	assert.Equal(t, testExchangeAudience, captured().form(t).Get("resource"))
}

// TestAzureTokenProvider_GetToken_Fallback verifies the try-until-success behavior.
func TestAzureTokenProvider_GetToken_Fallback(t *testing.T) {
	cloudShell, _ := tokenServer(t, "eyJfallback.cloudshell.token")

	clearAzureEnv(t)
	t.Setenv(envIdentityEndpoint, failingServer(t, http.StatusInternalServerError).URL)
	t.Setenv(envIdentityHeader, "hdr-secret")
	t.Setenv(envTokenAudience, testResource)

	p := &AzureTokenProvider{cloudShellURL: cloudShell.URL}
	token, err := p.GetToken(context.Background(), testExchangeAudience)
	require.NoError(t, err)
	assert.Equal(t, "eyJfallback.cloudshell.token", token)
}

// TestAzureTokenProvider_GetToken_AllFail verifies the aggregated error names
// every endpoint that was tried.
func TestAzureTokenProvider_GetToken_AllFail(t *testing.T) {
	clearAzureEnv(t)
	t.Setenv(envIdentityEndpoint, failingServer(t, http.StatusForbidden).URL)
	t.Setenv(envIdentityHeader, "hdr-secret")
	t.Setenv(envTokenAudience, testResource)

	p := &AzureTokenProvider{cloudShellURL: failingServer(t, http.StatusNotFound).URL}
	_, err := p.GetToken(context.Background(), testExchangeAudience)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed on all endpoints")
	assert.Contains(t, err.Error(), "app service")
	assert.Contains(t, err.Error(), "cloud shell")
	assert.NotContains(t, err.Error(), "hdr-secret")
}

// TestRequestAzureTokenSurfacesErrorBody pins the diagnostic: a non-OK response
// must carry Azure's explanation, otherwise a 400 is unactionable.
func TestRequestAzureTokenSurfacesErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"AADSTS500011: resource principal not found"}`))
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	_, err = requestAzureToken(server.Client(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
	assert.Contains(t, err.Error(), "AADSTS500011")
}

// TestRequestAzureTokenRejectsEmptyToken guards against a 200 with no token,
// which would otherwise be handed to the exchange as an empty credential.
func TestRequestAzureTokenRejectsEmptyToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	require.NoError(t, err)

	_, err = requestAzureToken(server.Client(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty access_token")
}

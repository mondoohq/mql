// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func testConnection(t *testing.T, host string, opts ...func(*inventory.Config)) *OllamaConnection {
	t.Helper()
	conf := &inventory.Config{Options: map[string]string{HostOption: host}}
	for _, opt := range opts {
		opt(conf)
	}
	conn, err := NewOllamaConnection(1, &inventory.Asset{}, conf)
	require.NoError(t, err)
	return conn
}

func TestTLS(t *testing.T) {
	assert.False(t, testConnection(t, "http://10.0.0.5:11434").TLS())
	assert.True(t, testConnection(t, "https://ollama.example.com").TLS())
	assert.True(t, testConnection(t, "HTTPS://ollama.example.com").TLS(), "the scheme is compared case-insensitively")
}

func TestIsLocal(t *testing.T) {
	local := []string{
		"http://localhost:11434",
		"http://LOCALHOST:11434",
		"http://127.0.0.1:11434",
		"http://127.0.0.53:11434",
		"http://[::1]:11434",
		"http://ollama.localhost:11434",
	}
	for _, host := range local {
		assert.True(t, testConnection(t, host).IsLocal(), host)
	}

	remote := []string{
		"http://0.0.0.0:11434",
		"http://10.0.0.5:11434",
		"https://ollama.example.com",
		"http://[2001:db8::1]:11434",
	}
	for _, host := range remote {
		assert.False(t, testConnection(t, host).IsLocal(), host)
	}
}

func TestAnonymousStatusSendsNoToken(t *testing.T) {
	var gotAuth string
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	conn := testConnection(t, srv.URL, func(conf *inventory.Config) {
		conf.Options[TokenOption] = "super-secret-token"
	})

	code, err := conn.AnonymousStatus(t.Context())
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Empty(t, gotAuth, "the probe must not carry the configured API token")
	assert.Equal(t, "/api/tags", gotPath, "the probe must use a read-only endpoint")
}

func TestAnonymousStatusUnauthenticatedInstance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	code, err := testConnection(t, srv.URL).AnonymousStatus(t.Context())
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
}

func TestVersionIsFetchedOnce(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"version":"0.12.6"}`))
	}))
	defer srv.Close()

	conn := testConnection(t, srv.URL)
	for range 3 {
		version, err := conn.Version(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "0.12.6", version)
	}
	assert.Equal(t, 1, calls, "asset detection and the version field share a single call")
}

func TestAnonymousWriteStatusCannotMutate(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotAuth   string
		gotBody   []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	conn := testConnection(t, srv.URL, func(c *inventory.Config) {
		c.Options[TokenOption] = "a-token-the-probe-must-not-send"
	})

	code, err := conn.AnonymousWriteStatus(t.Context())
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, code)

	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/create", gotPath,
		"the probe must go to the creation endpoint, never to delete or pull")
	assert.Empty(t, gotAuth, "the probe must be unauthenticated or it proves nothing")

	// The body is what makes the probe safe: it cannot be decoded, so no model
	// name, file, or digest can be read out of it.
	var decoded any
	assert.Error(t, json.Unmarshal(gotBody, &decoded),
		"the probe body must not be valid JSON, or the server could act on it")
	assert.NotContains(t, string(gotBody), "model",
		"the probe body must not name a model under any key")
}

func TestAnonymousWriteStatusGatedInstance(t *testing.T) {
	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	code, err := testConnection(t, srv.URL).AnonymousWriteStatus(t.Context())
	require.NoError(t, err)
	assert.True(t, reached)
	assert.Equal(t, http.StatusUnauthorized, code)
}

func TestAnonymousWriteStatusUnreachableHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	_, err := testConnection(t, url).AnonymousWriteStatus(t.Context())
	assert.Error(t, err, "a transport failure must surface, never read as writes being open")
}

// corsHandler answers a preflight the way gin-contrib/cors v1.7.2 does, which
// is the middleware Ollama v0.34.0 pins and configures in
// server/routes.go GenerateRoutes. Its applyCors aborts an origin it does not
// allow with a bare 403 carrying no cross-origin headers at all, and answers
// one it does allow with 204 plus the preflight header set, naming the request
// origin unless every origin is allowed, in which case it names `*`.
func corsHandler(allow func(origin string) bool, allowOrigin func(origin string) string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" || !allow(origin) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
		w.Header().Set("Access-Control-Allow-Origin", allowOrigin(origin))
		w.WriteHeader(http.StatusNoContent)
	}
}

func allowAny(string) bool { return true }

func TestCORSWildcardInstance(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		corsHandler(allowAny, func(string) string { return "*" })(w, r)
	}))
	defer srv.Close()

	obs, err := testConnection(t, srv.URL).CORS(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "*", obs.AllowOrigin, "OLLAMA_ORIGINS=* names every origin")
	assert.True(t, obs.Observed)
	assert.Equal(t, 1, calls, "an answer for the unrelated origin settles it; the control is not needed")
}

func TestCORSEchoesAnUnrelatedOrigin(t *testing.T) {
	// A wildcard pattern such as `https://*` matches the unrelated origin and
	// gin-contrib/cors echoes it back rather than naming `*`. That is the same
	// exposure and must read the same way.
	srv := httptest.NewServer(corsHandler(
		func(origin string) bool { return strings.HasPrefix(origin, "https://") },
		func(origin string) string { return origin },
	))
	defer srv.Close()

	obs, err := testConnection(t, srv.URL).CORS(t.Context())
	require.NoError(t, err)
	assert.Equal(t, obs.ProbeOrigin, obs.AllowOrigin)
	assert.True(t, obs.Observed)
}

func TestCORSRestrictedInstance(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		corsHandler(
			func(origin string) bool { return strings.HasPrefix(origin, "app://") },
			func(origin string) string { return origin },
		)(w, r)
	}))
	defer srv.Close()

	obs, err := testConnection(t, srv.URL).CORS(t.Context())
	require.NoError(t, err)
	assert.Empty(t, obs.AllowOrigin, "a stock instance allows the unrelated origin nothing")
	assert.True(t, obs.Observed,
		"the control origin is answered with cross-origin headers, so the refusal is a refusal and not silence")
	assert.Equal(t, 2, calls)
}

func TestCORSInstanceWithoutCrossOriginHandling(t *testing.T) {
	// Nothing on this instance looks at Origin, so its answer says nothing
	// about cross-origin access in either direction.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	obs, err := testConnection(t, srv.URL).CORS(t.Context())
	require.NoError(t, err)
	assert.Empty(t, obs.AllowOrigin)
	assert.False(t, obs.Observed, "silence must not be reported as a refusal")
}

func TestCORSProbeShape(t *testing.T) {
	var (
		gotMethod string
		gotOrigin string
		gotAuth   string
		gotACRM   string
		gotBody   []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotOrigin = r.Header.Get("Origin")
		gotAuth = r.Header.Get("Authorization")
		gotACRM = r.Header.Get("Access-Control-Request-Method")
		gotBody, _ = io.ReadAll(r.Body)
		corsHandler(allowAny, func(string) string { return "*" })(w, r)
	}))
	defer srv.Close()

	conn := testConnection(t, srv.URL, func(c *inventory.Config) {
		c.Options[TokenOption] = "a-token-the-probe-must-not-send"
	})

	obs, err := conn.CORS(t.Context())
	require.NoError(t, err)

	assert.Equal(t, http.MethodOptions, gotMethod, "a preflight reaches no handler and so changes nothing")
	assert.Empty(t, gotBody, "a preflight carries no body")
	assert.Equal(t, http.MethodPost, gotACRM, "without this header the request is not a preflight")
	assert.Empty(t, gotAuth, "a preflight is answered before credentials are read, so sending one only risks leaking it")
	assert.Equal(t, obs.ProbeOrigin, gotOrigin)
	assert.True(t, strings.HasSuffix(gotOrigin, ".example.com"),
		"the probe origin must be a reserved name that resolves to nothing an operator owns")
}

func TestCORSProbeOriginDiffersEveryRun(t *testing.T) {
	srv := httptest.NewServer(corsHandler(allowAny, func(string) string { return "*" }))
	defer srv.Close()

	conn := testConnection(t, srv.URL)
	first, err := conn.CORS(t.Context())
	require.NoError(t, err)
	second, err := conn.CORS(t.Context())
	require.NoError(t, err)

	assert.NotEqual(t, first.ProbeOrigin, second.ProbeOrigin,
		"a fixed probe origin could be added to an allowlist and read as a clean result")
}

// hostCheckHandler answers the way allowedHostsMiddleware does in ollama
// v0.34.0 server/routes.go: a host name that is neither an IP the instance
// recognizes nor a local TLD gets a bare 403, anything else reaches the
// handler. The probe's reserved name is neither, so it is refused.
func hostCheckHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.Host, ".example.com") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(body))
	}
}

func TestForeignHostStatusProtectedInstance(t *testing.T) {
	srv := httptest.NewServer(hostCheckHandler(`{"models":[]}`))
	defer srv.Close()

	obs, err := testConnection(t, srv.URL).ForeignHostStatus(t.Context())
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, obs.ControlStatus)
	assert.Equal(t, http.StatusForbidden, obs.ForeignStatus)
	assert.True(t, strings.HasSuffix(obs.ForeignHost, ".example.com"),
		"the claimed host must be a reserved name, and must not end in a suffix ollama treats as local")
}

func TestForeignHostStatusUnprotectedInstance(t *testing.T) {
	var gotHosts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHosts = append(gotHosts, r.Host)
		_, _ = w.Write([]byte(`{"models":[]}`))
	}))
	defer srv.Close()

	obs, err := testConnection(t, srv.URL).ForeignHostStatus(t.Context())
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, obs.ControlStatus)
	assert.Equal(t, http.StatusOK, obs.ForeignStatus)

	require.Len(t, gotHosts, 2)
	assert.Equal(t, srv.Listener.Addr().String(), gotHosts[0], "the control must claim the instance's own host name")
	assert.Equal(t, obs.ForeignHost, gotHosts[1])
}

func TestForeignHostStatusCarriesTheConfiguredToken(t *testing.T) {
	// The question is whether the host name alone decides the answer, so the
	// pair must be authenticated the way an ordinary call is. An unauthenticated
	// pair on a gated instance would be refused for the wrong reason.
	var gotAuth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"models":[]}`))
	}))
	defer srv.Close()

	conn := testConnection(t, srv.URL, func(c *inventory.Config) {
		c.Options[TokenOption] = "configured-token"
	})
	_, err := conn.ForeignHostStatus(t.Context())
	require.NoError(t, err)

	assert.Equal(t, []string{"Bearer configured-token", "Bearer configured-token"}, gotAuth)
}

func TestForeignHostStatusUnreachableHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	_, err := testConnection(t, url).ForeignHostStatus(t.Context())
	assert.Error(t, err, "a transport failure must surface, never read as the host check being absent")
}

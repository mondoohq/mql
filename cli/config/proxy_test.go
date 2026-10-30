// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/utils/sysproxy"
)

// clearProxyEnv gives a test a proxy-free environment and a fresh viper, so
// the machine running the tests cannot leak its own settings in.
func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{EnvAPIProxy, sysproxy.EnvSystemProxy, "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
	viper.Reset()
	t.Cleanup(viper.Reset)
}

func resolve(t *testing.T, fn func(*http.Request) (*url.URL, error), target string) string {
	t.Helper()
	require.NotNil(t, fn, "a nil selector would mean direct connections for every request")
	u, err := url.Parse(target)
	require.NoError(t, err)
	p, err := fn(&http.Request{URL: u})
	require.NoError(t, err)
	if p == nil {
		return ""
	}
	return p.String()
}

func TestProxyFuncPrecedence(t *testing.T) {
	const target = "https://us.api.mondoo.com/ping"

	t.Run("config file proxy overrides the environment", func(t *testing.T) {
		clearProxyEnv(t)
		t.Setenv("HTTPS_PROXY", "http://env-proxy:3128")
		viper.Set("api_proxy", "http://config-proxy:3128")

		fn, err := ProxyFunc()
		require.NoError(t, err)
		assert.Equal(t, "http://config-proxy:3128", resolve(t, fn, target))
	})

	t.Run("config file proxy overrides NO_PROXY", func(t *testing.T) {
		clearProxyEnv(t)
		t.Setenv("NO_PROXY", "*")
		viper.Set("api_proxy", "http://config-proxy:3128")

		fn, err := ProxyFunc()
		require.NoError(t, err)
		assert.Equal(t, "http://config-proxy:3128", resolve(t, fn, target), "an explicit api_proxy is unconditional")
	})

	t.Run("parsed config struct is honored when viper has nothing", func(t *testing.T) {
		clearProxyEnv(t)
		t.Setenv("HTTPS_PROXY", "http://env-proxy:3128")
		opts := &CommonOpts{APIProxy: "http://struct-proxy:3128"}

		fn, err := opts.ProxyFunc()
		require.NoError(t, err)
		assert.Equal(t, "http://struct-proxy:3128", resolve(t, fn, target))
	})

	t.Run("MONDOO_API_PROXY overrides the config file", func(t *testing.T) {
		clearProxyEnv(t)
		t.Setenv(EnvAPIProxy, "http://env-api-proxy:3128")
		viper.Set("api_proxy", "http://config-proxy:3128")

		fn, err := ProxyFunc()
		require.NoError(t, err)
		assert.Equal(t, "http://env-api-proxy:3128", resolve(t, fn, target))
	})

	t.Run("a proxy without a scheme is taken as http", func(t *testing.T) {
		clearProxyEnv(t)
		viper.Set("api_proxy", "proxy.corp:3128")

		fn, err := ProxyFunc()
		require.NoError(t, err)
		assert.Equal(t, "http://proxy.corp:3128", resolve(t, fn, target))
	})

	t.Run("a broken api_proxy is an error", func(t *testing.T) {
		clearProxyEnv(t)
		viper.Set("api_proxy", "ftp://proxy.corp:21")

		_, err := ProxyFunc()
		require.Error(t, err)
		_, err = NewHttpClient()
		require.Error(t, err)
	})

	t.Run("environment applies without an api_proxy, with NO_PROXY", func(t *testing.T) {
		clearProxyEnv(t)
		t.Setenv("HTTPS_PROXY", "http://env-proxy:3128")
		t.Setenv("NO_PROXY", "us.api.mondoo.com")

		fn, err := ProxyFunc()
		require.NoError(t, err)
		assert.Equal(t, "", resolve(t, fn, target))
		assert.Equal(t, "http://env-proxy:3128", resolve(t, fn, "https://releases.mondoo.com/x"))
	})

	t.Run("system proxy disabled falls back to the environment", func(t *testing.T) {
		clearProxyEnv(t)
		t.Setenv("HTTPS_PROXY", "http://env-proxy:3128")
		viper.Set(KeySystemProxy, false)

		fn, err := ProxyFunc()
		require.NoError(t, err)
		assert.Equal(t, "http://env-proxy:3128", resolve(t, fn, target))
	})

	t.Run("nothing configured connects directly", func(t *testing.T) {
		clearProxyEnv(t)
		viper.Set(KeySystemProxy, false) // keep the machine's own settings out of it

		fn, err := ProxyFunc()
		require.NoError(t, err)
		assert.Equal(t, "", resolve(t, fn, target))
	})
}

func TestSystemProxyEnabled(t *testing.T) {
	clearProxyEnv(t)
	assert.True(t, SystemProxyEnabled(), "on by default")

	viper.Set(KeySystemProxy, false)
	assert.False(t, SystemProxyEnabled(), "config file turns it off")

	t.Setenv(sysproxy.EnvSystemProxy, "true")
	assert.True(t, SystemProxyEnabled(), "environment wins over the config file")

	t.Setenv(sysproxy.EnvSystemProxy, "")
	viper.Reset()
	off := false
	assert.False(t, systemProxyEnabled(&off), "a parsed struct counts when viper has nothing")
	on := true
	assert.True(t, systemProxyEnabled(&on))
}

func TestEffectiveProxy(t *testing.T) {
	const target = "https://us.api.mondoo.com"

	t.Run("config", func(t *testing.T) {
		clearProxyEnv(t)
		t.Setenv("HTTPS_PROXY", "http://env-proxy:3128")
		opts := &CommonOpts{APIProxy: "http://user:secret@config-proxy:3128"}
		p, source, err := opts.EffectiveProxy(target)
		require.NoError(t, err)
		assert.Equal(t, ProxySourceConfig, source)
		assert.Equal(t, "http://user:xxxxx@config-proxy:3128", p.Redacted())
	})

	t.Run("environment", func(t *testing.T) {
		clearProxyEnv(t)
		t.Setenv("HTTPS_PROXY", "http://env-proxy:3128")
		p, source, err := (&CommonOpts{}).EffectiveProxy(target)
		require.NoError(t, err)
		assert.Equal(t, ProxySourceEnvironment, source)
		assert.Equal(t, "http://env-proxy:3128", p.String())
	})

	t.Run("direct", func(t *testing.T) {
		clearProxyEnv(t)
		viper.Set(KeySystemProxy, false)
		p, source, err := (&CommonOpts{}).EffectiveProxy(target)
		require.NoError(t, err)
		assert.Equal(t, ProxySourceNone, source)
		assert.Nil(t, p)
	})
}

func TestProviderEnvironment(t *testing.T) {
	t.Run("opt-out is passed on", func(t *testing.T) {
		clearProxyEnv(t)
		viper.Set(KeySystemProxy, false)
		assert.Equal(t, []string{sysproxy.EnvSystemProxy + "=false"}, ProviderEnvironment())
	})

	t.Run("an environment proxy is inherited, not re-exported", func(t *testing.T) {
		clearProxyEnv(t)
		t.Setenv("HTTPS_PROXY", "http://env-proxy:3128")
		assert.Empty(t, ProviderEnvironment())
	})
}

func TestUpstreamApiEndpoint(t *testing.T) {
	clearProxyEnv(t)
	assert.Equal(t, defaultAPIendpoint, UpstreamApiEndpoint())
	viper.Set("api_endpoint", "https://eu.api.mondoo.com")
	assert.Equal(t, "https://eu.api.mondoo.com", UpstreamApiEndpoint())
}

func TestGetAPIProxyStaysCompatible(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://env-proxy:3128")
	p, err := GetAPIProxy()
	require.NoError(t, err)
	assert.Equal(t, "http://env-proxy:3128", p.String(), "the deprecated helper still falls back to HTTPS_PROXY")

	viper.Set("api_proxy", "http://config-proxy:3128")
	p, err = GetAPIProxy()
	require.NoError(t, err)
	assert.Equal(t, "http://config-proxy:3128", p.String())

	t.Setenv(EnvAPIProxy, "")
	viper.Reset()
	t.Setenv("HTTPS_PROXY", "")
	p, err = (&CommonOpts{APIProxy: "struct-proxy:3128"}).GetAPIProxy()
	require.NoError(t, err)
	assert.Equal(t, "http://struct-proxy:3128", p.String())
}

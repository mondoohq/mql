// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/viper"
	rangerUtils "go.mondoo.com/mql/utils/ranger"
	"go.mondoo.com/mql/utils/sysproxy"
	"go.mondoo.com/ranger-rpc"
)

// Proxy selection for Mondoo Platform traffic: API calls, provider and binary
// downloads, result uploads. Precedence, highest first:
//
//  1. --api-proxy, or MONDOO_API_PROXY
//  2. api_proxy in the config file
//  3. HTTPS_PROXY / HTTP_PROXY with NO_PROXY, as Go reads them
//  4. the operating system's proxy settings, unless system_proxy is false
//     (on Windows: Internet Settings with a manual proxy, a setup script or
//     auto-detection, then the WinHTTP default set with netsh)
//  5. a direct connection
//
// A proxy in the config file therefore overrides anything the environment or
// the operating system says. system_proxy: false leaves steps 1 to 3 in place
// and only stops the operating system's settings from being read, which is
// how every version before system proxy support behaved.

// KeySystemProxy is the config key, and through viper's env binding the
// MONDOO_SYSTEM_PROXY variable, that turns off reading the operating system's
// proxy settings. Unset means on.
const KeySystemProxy = "system_proxy"

// EnvAPIProxy is the environment variable that sets the proxy for Mondoo
// Platform traffic ahead of the config file, on par with --api-proxy.
const EnvAPIProxy = "MONDOO_API_PROXY"

// ProxySource says where the proxy for a destination came from.
type ProxySource string

const (
	// ProxySourceNone is a direct connection.
	ProxySourceNone ProxySource = ""
	// ProxySourceConfig is --api-proxy, MONDOO_API_PROXY or api_proxy in the config file.
	ProxySourceConfig ProxySource = "api_proxy"
	// ProxySourceEnvironment is HTTPS_PROXY or HTTP_PROXY.
	ProxySourceEnvironment ProxySource = "environment"
	// ProxySourceSystem is the operating system's proxy settings.
	ProxySourceSystem ProxySource = "system"
)

// explicitAPIProxy returns the proxy configured for Mondoo Platform traffic
// (steps 1 and 2 above), or nil when there is none. configured is the config
// file value from a parsed CommonOpts; viper already carries it once it has
// loaded the file, so it only matters for callers that unmarshalled the config
// some other way.
func explicitAPIProxy(configured string) (*url.URL, error) {
	if proxy := os.Getenv(EnvAPIProxy); proxy != "" {
		return sysproxy.ParseProxyURL(proxy)
	}
	if proxy := viper.GetString("api_proxy"); proxy != "" {
		return sysproxy.ParseProxyURL(proxy)
	}
	if configured != "" {
		return sysproxy.ParseProxyURL(configured)
	}
	return nil, nil
}

// SystemProxyEnabled reports whether the operating system's proxy settings may
// be consulted: MONDOO_SYSTEM_PROXY first, then system_proxy in the config,
// and on when neither says anything.
func SystemProxyEnabled() bool {
	return systemProxyEnabled(nil)
}

// systemProxyEnabled is SystemProxyEnabled with the parsed config value as the
// last word before the default, for a CommonOpts that did not come from viper.
func systemProxyEnabled(configured *bool) bool {
	if v := os.Getenv(sysproxy.EnvSystemProxy); v != "" {
		return sysproxy.ParseEnabled(v)
	}
	if viper.IsSet(KeySystemProxy) {
		return viper.GetBool(KeySystemProxy)
	}
	if configured != nil {
		return *configured
	}
	return true
}

// ProxyFunc returns the proxy selector for Mondoo Platform traffic, following
// the precedence documented at the top of this file. It reads viper and the
// environment, so it works before the config file is unmarshalled into a
// CommonOpts; prefer CommonOpts.ProxyFunc once one is at hand.
func ProxyFunc() (func(*http.Request) (*url.URL, error), error) {
	return proxyFunc("", nil)
}

// ProxyFunc is the proxy selector for Mondoo Platform traffic with this
// configuration. See the precedence at the top of this file.
func (c *CommonOpts) ProxyFunc() (func(*http.Request) (*url.URL, error), error) {
	return proxyFunc(c.APIProxy, c.SystemProxy)
}

func proxyFunc(configured string, systemProxy *bool) (func(*http.Request) (*url.URL, error), error) {
	explicit, err := explicitAPIProxy(configured)
	if err != nil {
		return nil, err
	}
	if explicit != nil {
		return http.ProxyURL(explicit), nil
	}
	if !systemProxyEnabled(systemProxy) {
		return sysproxy.EnvironmentProxyFunc(), nil
	}
	return sysproxy.ProxyFunc(), nil
}

// NewHttpClient returns ranger's default HTTP client with ProxyFunc installed,
// for code that runs before the config file is parsed (login, provider
// downloads). Use CommonOpts.GetHttpClient once the config is loaded.
func NewHttpClient() (*http.Client, error) {
	proxy, err := ProxyFunc()
	if err != nil {
		return nil, err
	}
	return ranger.NewHttpClient(rangerUtils.WithProxyFunc(proxy)), nil
}

// GetHttpClient returns ranger's default HTTP client with this configuration's
// proxy selection installed.
func (c *CommonOpts) GetHttpClient() (*http.Client, error) {
	proxy, err := c.ProxyFunc()
	if err != nil {
		return nil, err
	}
	return ranger.NewHttpClient(rangerUtils.WithProxyFunc(proxy)), nil
}

// EffectiveProxy reports the proxy that Mondoo Platform traffic to target goes
// through and where that choice came from, for diagnostics such as the status
// command. A nil proxy with ProxySourceNone is a direct connection.
func (c *CommonOpts) EffectiveProxy(target string) (*url.URL, ProxySource, error) {
	explicit, err := explicitAPIProxy(c.APIProxy)
	if err != nil {
		return nil, ProxySourceNone, err
	}
	if explicit != nil {
		return explicit, ProxySourceConfig, nil
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, ProxySourceNone, err
	}
	selectProxy, err := c.ProxyFunc()
	if err != nil {
		return nil, ProxySourceNone, err
	}
	proxy, err := selectProxy(&http.Request{URL: u})
	if err != nil || proxy == nil {
		return nil, ProxySourceNone, err
	}
	if sysproxy.EnvironmentConfigured() {
		return proxy, ProxySourceEnvironment, nil
	}
	return proxy, ProxySourceSystem, nil
}

// UpstreamApiEndpoint returns the configured Mondoo API endpoint (flag,
// environment, config file) or the default, without a parsed CommonOpts.
func UpstreamApiEndpoint() string {
	if endpoint := viper.GetString("api_endpoint"); endpoint != "" {
		return endpoint
	}
	return defaultAPIendpoint
}

// ProviderEnvironment returns environment assignments for a provider
// subprocess so it makes the same proxy decisions as this process. The cloud
// SDKs inside providers read only HTTP_PROXY, HTTPS_PROXY and NO_PROXY, so a
// proxy found in the operating system's settings travels that way, and a
// system_proxy: false opt-out travels as MONDOO_SYSTEM_PROXY=false so the
// provider's own platform client honors it. api_proxy is not exported: it is
// scoped to Mondoo Platform traffic and reaches providers through the
// upstream config instead. Variables the parent already has are never
// overridden.
func ProviderEnvironment() []string {
	if !SystemProxyEnabled() {
		return []string{sysproxy.EnvSystemProxy + "=false"}
	}
	endpoint, err := url.Parse(UpstreamApiEndpoint())
	if err != nil {
		endpoint = nil
	}
	return sysproxy.Environment(endpoint)
}

// GetAPIProxy returns the proxy configured explicitly for Mondoo Platform
// traffic, or HTTPS_PROXY when there is none. It predates system proxy
// support and returns one fixed URL, so it cannot report a per-destination
// choice and never sees the operating system's settings.
//
// Deprecated: use ProxyFunc or NewHttpClient, which apply every source.
func GetAPIProxy() (*url.URL, error) {
	proxy, err := explicitAPIProxy("")
	if err != nil || proxy != nil {
		return proxy, err
	}
	if proxy, ok := os.LookupEnv("HTTPS_PROXY"); ok && proxy != "" {
		return url.Parse(proxy)
	}
	return nil, nil
}

// GetAPIProxy is GetAPIProxy with the config file value as a last fallback.
//
// Deprecated: use ProxyFunc or GetHttpClient, which apply every source.
func (c *CommonOpts) GetAPIProxy() (*url.URL, error) {
	proxy, err := GetAPIProxy()
	if err != nil || proxy != nil {
		return proxy, err
	}
	if c.APIProxy != "" {
		return sysproxy.ParseProxyURL(c.APIProxy)
	}
	return nil, nil
}

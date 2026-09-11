// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ranger

import (
	"net/http"
	"net/url"

	"go.mondoo.com/ranger-rpc"
)

// WithProxyFunc is a ranger.HttpClientOption that installs proxy as the
// per-request proxy selector of the client's transport, replacing ranger's
// default of http.ProxyFromEnvironment. A nil proxy means direct connections.
// ranger.WithProxy takes a single fixed URL; this is for selectors such as
// sysproxy.ProxyFunc that decide per destination.
func WithProxyFunc(proxy func(*http.Request) (*url.URL, error)) ranger.HttpClientOption {
	return func(c *http.Client) {
		if t, ok := c.Transport.(*http.Transport); ok {
			t.Proxy = proxy
		}
	}
}

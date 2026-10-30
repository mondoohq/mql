// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/network/connection"
	"go.mondoo.com/mql/providers/network/resources"
	"go.mondoo.com/mql/utils/syncx"
)

// TestResource_HttpGetTargetScheme verifies which endpoint http.get derives from
// the connection when no URL is given: a bare `host <domain>` (no scheme, no
// port) now resolves to HTTPS, matching the tls resource, so both policies
// inspect the same endpoint. An explicit non-TLS port still resolves to HTTP.
func TestResource_HttpGetTargetScheme(t *testing.T) {
	testCases := []struct {
		name       string
		host       string
		port       int32
		wantPrefix string
	}{
		{"bare domain defaults to https", "mondoo.com", 0, "https://mondoo.com"},
		{"explicit 443 is https", "mondoo.com", 443, "https://mondoo.com"},
		{"explicit http port stays http", "mondoo.com", 80, "http://mondoo.com"},
		{"non-standard port stays http", "mondoo.com", 8080, "http://mondoo.com:8080"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
			conf := &inventory.Config{Host: tc.host, Port: tc.port}
			runtime.Connection = connection.NewHostConnection(1, &inventory.Asset{}, conf)

			// Building the resource derives the target URL from the connection
			// (initHttpGet) without performing the request, so the id carries the
			// endpoint http.get would hit.
			get, err := resources.NewResource(runtime, "http.get", map[string]*llx.RawData{})
			require.NoError(t, err)
			require.Truef(t, strings.HasPrefix(get.MqlID(), tc.wantPrefix),
				"http.get id = %q, want prefix %q", get.MqlID(), tc.wantPrefix)
		})
	}
}

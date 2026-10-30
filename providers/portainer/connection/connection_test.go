// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAddress(t *testing.T) {
	cases := []struct {
		name       string
		address    string
		wantHost   string
		wantScheme string
		wantBase   string
		wantErr    bool
	}{
		{"bare host defaults to https and /api", "portainer.example.com", "portainer.example.com", "https", "/api", false},
		{"explicit http scheme is kept", "http://portainer.example.com", "portainer.example.com", "http", "/api", false},
		{"explicit port is preserved", "https://portainer.example.com:9443", "portainer.example.com:9443", "https", "/api", false},
		{"bare host:port defaults scheme and keeps port", "portainer.example.com:9443", "portainer.example.com:9443", "https", "/api", false},
		{"reverse-proxy prefix gets /api appended", "https://portainer.example.com/prefix", "portainer.example.com", "https", "/prefix/api", false},
		{"trailing slash keeps the default base path", "https://portainer.example.com/", "portainer.example.com", "https", "/api", false},
		{"surrounding whitespace is trimmed", "  https://portainer.example.com  ", "portainer.example.com", "https", "/api", false},
		{"bare host with whitespace still defaults scheme", "  portainer.example.com  ", "portainer.example.com", "https", "/api", false},
		{"empty address is an error", "", "", "", "", true},
		{"whitespace-only address is an error", "   ", "", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, scheme, base, err := parseAddress(tc.address)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantHost, host, "host")
			assert.Equal(t, tc.wantScheme, scheme, "scheme")
			assert.Equal(t, tc.wantBase, base, "basePath")
		})
	}
}

func TestAuthenticationMethod(t *testing.T) {
	cases := map[int64]string{1: "internal", 2: "ldap", 3: "oauth", 0: "unknown", 99: "unknown"}
	for in, want := range cases {
		assert.Equalf(t, want, AuthenticationMethod(in), "AuthenticationMethod(%d)", in)
	}
}

func TestUserRole(t *testing.T) {
	cases := map[int64]string{1: "administrator", 2: "standard", 0: "unknown", 99: "unknown"}
	for in, want := range cases {
		assert.Equalf(t, want, UserRole(in), "UserRole(%d)", in)
	}
}

func TestMembershipRole(t *testing.T) {
	cases := map[int64]string{1: "leader", 2: "member", 0: "unknown", 99: "unknown"}
	for in, want := range cases {
		assert.Equalf(t, want, MembershipRole(in), "MembershipRole(%d)", in)
	}
}

// TestEnvironmentStatus covers all four states Portainer declares for an
// endpoint. 3 and 4 are only reachable on cloud-provisioned environments, and
// mapping them to "unknown" used to hide error-state environments from any
// audit that filtered on "down".
func TestEnvironmentStatus(t *testing.T) {
	cases := map[int64]string{
		1:  "up",
		2:  "down",
		3:  "provisioning",
		4:  "error",
		0:  "unknown",
		5:  "unknown",
		99: "unknown",
	}
	for in, want := range cases {
		assert.Equalf(t, want, EnvironmentStatus(in), "EnvironmentStatus(%d)", in)
	}
}

func TestAccessPolicyRole(t *testing.T) {
	cases := map[int64]string{
		1:  "environment_administrator",
		2:  "helpdesk_user",
		3:  "standard_user",
		4:  "readonly_user",
		5:  "operator_user",
		0:  "unknown",
		6:  "unknown",
		-1: "unknown",
	}
	for in, want := range cases {
		assert.Equalf(t, want, AccessPolicyRole(in), "AccessPolicyRole(%d)", in)
	}
}

func TestEdgeStackDeploymentType(t *testing.T) {
	cases := map[int64]string{0: "compose", 1: "kubernetes", 2: "unknown", 99: "unknown"}
	for in, want := range cases {
		assert.Equalf(t, want, EdgeStackDeploymentType(in), "EdgeStackDeploymentType(%d)", in)
	}
}

// TestInstanceKey pins the platform-id fallback: without it, every instance
// that reports no instance id would share the platform id ".../instance/" and
// collapse onto a single asset.
func TestInstanceKey(t *testing.T) {
	cases := []struct {
		name       string
		instanceID string
		hostname   string
		want       string
	}{
		{"instance id wins", "inst-1", "portainer.example.com", "inst-1"},
		{"falls back to hostname", "", "portainer.example.com", "portainer.example.com"},
		{"falls back to a constant", "", "", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := &PortainerConnection{instanceID: tc.instanceID, hostname: tc.hostname}
			assert.Equal(t, tc.want, conn.InstanceKey())
		})
	}
}

func TestPlatformIDs(t *testing.T) {
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/portainer/instance/inst-1",
		NewInstancePlatformID("inst-1"))
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/portainer/instance/inst-1/environment/7",
		NewEnvironmentPlatformID("inst-1", 7))

	// two instances without an id must not collide once the key falls back
	a := &PortainerConnection{hostname: "a.example.com"}
	b := &PortainerConnection{hostname: "b.example.com"}
	assert.NotEqual(t,
		NewInstancePlatformID(a.InstanceKey()),
		NewInstancePlatformID(b.InstanceKey()))
}

func TestNewAPIRuntimeTLS(t *testing.T) {
	t.Run("verifies certificates by default", func(t *testing.T) {
		rt := newAPIRuntime("portainer.invalid", "https", "/api", "ptr_token", false)

		tr, ok := rt.Transport.(*http.Transport)
		require.True(t, ok, "expected the default http transport")
		if tr.TLSClientConfig != nil {
			assert.False(t, tr.TLSClientConfig.InsecureSkipVerify,
				"certificate verification must stay on without --insecure")
		}
	})

	t.Run("skips verification only when asked, keeping the transport defaults", func(t *testing.T) {
		rt := newAPIRuntime("portainer.invalid", "https", "/api", "ptr_token", true)

		tr, ok := rt.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, tr.TLSClientConfig)
		assert.True(t, tr.TLSClientConfig.InsecureSkipVerify)

		// the clone must keep what http.DefaultTransport carries, or an
		// instance behind a proxy becomes unreachable on this path alone
		def := http.DefaultTransport.(*http.Transport)
		assert.NotNil(t, tr.Proxy, "proxy from the environment must survive")
		assert.Equal(t, def.TLSHandshakeTimeout, tr.TLSHandshakeTimeout)
		assert.Equal(t, def.IdleConnTimeout, tr.IdleConnTimeout)
		assert.Equal(t, def.MaxIdleConns, tr.MaxIdleConns)
		if def.TLSClientConfig != nil {
			assert.False(t, def.TLSClientConfig.InsecureSkipVerify,
				"the shared default transport must not be mutated")
		}
	})
}

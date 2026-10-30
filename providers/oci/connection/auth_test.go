// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"slices"
	"testing"
)

// TestUsesPrincipalAuth pins which --auth-method values route to a keyless
// principal provider and which fall through to the API-key path. Getting this
// backwards would either ignore an explicitly requested instance principal or
// send an ordinary API-key connection down the principal path.
func TestUsesPrincipalAuth(t *testing.T) {
	cases := []struct {
		method string
		want   bool
	}{
		{"", false},
		{authMethodAPIKey, false},
		{authMethodInstancePrincipal, true},
		{authMethodResourcePrincipal, true},
		{authMethodWorkloadIdentity, true},
		{authMethodSecurityToken, true},
	}
	for _, c := range cases {
		if got := usesPrincipalAuth(c.method); got != c.want {
			t.Errorf("usesPrincipalAuth(%q) = %v, want %v", c.method, got, c.want)
		}
	}
}

// TestSupportedAuthMethodsCoverEveryBranch keeps the CLI allowlist and the
// provider switch from drifting: a method accepted by ParseCLI but unhandled by
// principalConfigProvider would fail at connect with "unsupported OCI
// auth-method" after the flag had already been validated.
func TestSupportedAuthMethodsCoverEveryBranch(t *testing.T) {
	for _, method := range SupportedAuthMethods {
		if method == authMethodAPIKey {
			continue // handled by the config-file / raw-credential paths
		}
		if !usesPrincipalAuth(method) {
			t.Errorf("%q is advertised but does not route to a principal provider", method)
		}
	}

	if !slices.Contains(SupportedAuthMethods, authMethodAPIKey) {
		t.Error("api-key must stay in the advertised list; it is the default")
	}
}

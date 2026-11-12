// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// A resource's default fields are computed whenever the resource is printed,
// including in the result of a failing check that never read them. On
// microsoft.user.authenticationMethods every field but registrationDetails
// reads the user's own methods (one Graph call per user), so a default such as
// count turned a check on the tenant-wide registration report into a per-user
// fetch of every member's methods.
func TestUserAuthenticationMethodsHasNoPerUserDefaults(t *testing.T) {
	src, err := os.ReadFile("ms365.lr")
	require.NoError(t, err)

	decl := regexp.MustCompile(`(?m)^private microsoft\.user\.authenticationMethods\b([^{\n]*)\{`).FindSubmatch(src)
	require.NotNil(t, decl, "microsoft.user.authenticationMethods not found in ms365.lr")
	require.NotContains(t, string(decl[1]), "@defaults",
		"a default field on microsoft.user.authenticationMethods is computed whenever it is printed and fetches the methods of every user printed")
}

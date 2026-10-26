// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package upstream

import (
	"strings"

	"go.mondoo.com/mql"
)

// UserAgent returns the User-Agent mql sends on GraphQL calls:
// "mql/<version>", followed by " (provider <name>)" if a provider is given.
// The leading "mql/" is relied on by the server to classify traffic. In a
// provider plugin the version is the one stamped into that provider binary
// (the mql release it was built from), or the dev version for unstamped builds.
func UserAgent(provider string) string {
	ua := "mql/" + strings.TrimPrefix(mql.GetVersion(), "v")
	if provider != "" {
		ua += " (provider " + provider + ")"
	}
	return ua
}

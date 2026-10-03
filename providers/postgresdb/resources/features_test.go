// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// withStructuredErrors turns the StructuredErrors feature on or off for one
// test, the way a Connect request carrying the scan's features does.
func withStructuredErrors(t *testing.T, on bool) {
	t.Helper()
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })
	if on {
		plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
	} else {
		plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)}))
	}
}

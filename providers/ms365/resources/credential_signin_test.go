// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"testing"
	"time"

	"github.com/microsoft/kiota-abstractions-go/authentication"
	beta "github.com/microsoftgraph/msgraph-beta-sdk-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func credentialBetaClient(t *testing.T, f *fakeGraph) *beta.GraphServiceClient {
	adapter, err := beta.NewGraphRequestAdapter(&authentication.AnonymousAuthenticationProvider{})
	require.NoError(t, err)
	adapter.SetBaseUrl(f.srv.URL + "/beta")
	return beta.NewGraphServiceClient(adapter)
}

func TestFetchCredentialSignIns(t *testing.T) {
	// Synthetic: two pages of the beta report; the row shape follows the
	// Graph appCredentialSignInActivity resource. One key signed in to two
	// resources, so it has two rows.
	f := newFakeGraph(t, map[string]fakeRoute{
		"/beta/reports/appCredentialSignInActivities": {status: 200, body: `{
			"@odata.nextLink": "{{base}}/reports/appCredentialSignInActivities/page2",
			"value": [
				{"id": "r1", "keyId": "AAAA-KEY", "keyType": "clientSecret", "resourceId": "res-1",
				 "signInActivity": {"lastSignInDateTime": "2026-10-01T09:00:00Z"}},
				{"id": "r2", "keyId": "bbbb-key", "keyType": "certificate",
				 "signInActivity": {"lastSignInDateTime": null}},
				{"id": "r3", "keyType": "clientSecret",
				 "signInActivity": {"lastSignInDateTime": "2026-10-02T09:00:00Z"}}
			]}`},
		"/reports/appCredentialSignInActivities/page2": {status: 200, body: `{
			"value": [
				{"id": "r4", "keyId": "aaaa-key", "keyType": "clientSecret", "resourceId": "res-2",
				 "signInActivity": {"lastSignInDateTime": "2026-11-15T12:30:00Z"}}
			]}`},
	})

	got, err := fetchCredentialSignIns(context.Background(), credentialBetaClient(t, f))
	require.NoError(t, err)
	assert.Equal(t, map[string]time.Time{
		"aaaa-key": time.Date(2026, 11, 15, 12, 30, 0, 0, time.UTC),
	}, utcTimes(got), "the latest row per key wins across pages; rows without a key or a time are skipped")
}

func TestFetchCredentialSignInsRefused(t *testing.T) {
	// Synthetic: Graph answers 403 for a tenant without Entra ID P1/P2.
	f := newFakeGraph(t, map[string]fakeRoute{
		"/beta/reports/appCredentialSignInActivities": {status: 403, body: `{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant","message":"premium license required"}}`},
	})
	_, err := fetchCredentialSignIns(context.Background(), credentialBetaClient(t, f))
	assert.Error(t, err, "a refusal is an error, never an empty report that reads as 'never used'")
}

func utcTimes(m map[string]time.Time) map[string]time.Time {
	res := make(map[string]time.Time, len(m))
	for k, v := range m {
		res[k] = v.UTC()
	}
	return res
}

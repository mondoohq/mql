// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"testing"
	"time"

	"github.com/microsoft/kiota-abstractions-go/authentication"
	beta "github.com/microsoftgraph/msgraph-beta-sdk-go"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func betaClientFor(t *testing.T, f *fakeGraph) *beta.GraphServiceClient {
	adapter, err := beta.NewGraphRequestAdapter(&authentication.AnonymousAuthenticationProvider{})
	require.NoError(t, err)
	adapter.SetBaseUrl(f.srv.URL + "/beta")
	return beta.NewGraphServiceClient(adapter)
}

func TestFetchServicePrincipalSignInActivities(t *testing.T) {
	// Synthetic: two pages of the beta report; the row shape follows the
	// Graph servicePrincipalSignInActivity resource.
	f := newFakeGraph(t, map[string]fakeRoute{
		"/beta/reports/servicePrincipalSignInActivities": {status: 200, body: `{
			"@odata.nextLink": "{{base}}/reports/servicePrincipalSignInActivities/page2",
			"value": [
				{"id": "r-1", "appId": "AAAA-1111",
				 "lastSignInActivity": {"lastSignInDateTime": "2026-11-01T10:00:00Z"},
				 "applicationAuthenticationClientSignInActivity": {"lastSignInDateTime": "2026-11-01T10:00:00Z"},
				 "delegatedClientSignInActivity": {"lastSignInDateTime": null}},
				{"id": "r-x"}
			]}`},
		"/reports/servicePrincipalSignInActivities/page2": {status: 200, body: `{
			"value": [
				{"id": "r-2", "appId": "bbbb-2222",
				 "lastSignInActivity": {"lastSignInDateTime": "2026-06-30T08:15:00Z"},
				 "delegatedResourceSignInActivity": {"lastSignInDateTime": "2026-06-30T08:15:00Z"}}
			]}`},
	})

	got, err := fetchServicePrincipalSignInActivities(context.Background(), betaClientFor(t, f))
	require.NoError(t, err)
	require.Len(t, got, 2, "both pages are read and a row without an appId is skipped")

	a := got["aaaa-1111"]
	require.NotNil(t, a, "rows are keyed by lower-cased appId")
	assert.Equal(t, time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC), lastSignInOf(a, betamodels.ServicePrincipalSignInActivityable.GetLastSignInActivity).UTC())
	assert.Equal(t, time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC), lastSignInOf(a, betamodels.ServicePrincipalSignInActivityable.GetApplicationAuthenticationClientSignInActivity).UTC())
	assert.Nil(t, lastSignInOf(a, betamodels.ServicePrincipalSignInActivityable.GetDelegatedClientSignInActivity), "a category with a null time is null")
	assert.Nil(t, lastSignInOf(a, betamodels.ServicePrincipalSignInActivityable.GetDelegatedResourceSignInActivity), "an absent category is null")

	b := got["bbbb-2222"]
	require.NotNil(t, b)
	assert.Equal(t, time.Date(2026, 6, 30, 8, 15, 0, 0, time.UTC), lastSignInOf(b, betamodels.ServicePrincipalSignInActivityable.GetDelegatedResourceSignInActivity).UTC())

	assert.Nil(t, lastSignInOf(nil, betamodels.ServicePrincipalSignInActivityable.GetLastSignInActivity), "an application without a row is null")
}

func TestFetchServicePrincipalSignInActivitiesRefused(t *testing.T) {
	// Synthetic: Graph answers 403 for a tenant without Entra ID P1/P2 or
	// without AuditLog.Read.All.
	f := newFakeGraph(t, map[string]fakeRoute{
		"/beta/reports/servicePrincipalSignInActivities": {status: 403, body: `{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant","message":"Neither tenant is B2C or tenant doesn't have premium license"}}`},
	})
	_, err := fetchServicePrincipalSignInActivities(context.Background(), betaClientFor(t, f))
	assert.Error(t, err, "a refusal is an error, never an empty report that reads as 'never signed in'")
}

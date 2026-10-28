// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/microsoft/kiota-abstractions-go/serialization"
	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

const (
	testTenantID = "2919c383-55f1-4d5b-9d3e-352998c3fd2b"
	skuE5        = "c42b9cae-ea4f-4ab7-9717-81576235ccac"
	skuTeamsFree = "16ddbbfc-09ea-4de2-b1d7-312db6112d70"
)

func decodeGraph[T any](t *testing.T, raw string, factory serialization.ParsableFactory) T {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(raw))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(factory)
	require.NoError(t, err)
	return parsed.(T)
}

func testSubscribedSku(t *testing.T, skuID, partNumber string) models.SubscribedSkuable {
	return decodeGraph[models.SubscribedSkuable](t, `{
		"id": "`+testTenantID+`_`+skuID+`",
		"skuId": "`+skuID+`",
		"skuPartNumber": "`+partNumber+`",
		"appliesTo": "User",
		"capabilityStatus": "Enabled",
		"consumedUnits": 2,
		"prepaidUnits": {"enabled": 25, "suspended": 0, "warning": 0, "lockedOut": 0},
		"servicePlans": [
			{"servicePlanId": "4828c8ec-dc2e-4779-b502-87ac9ce28ab7", "servicePlanName": "TEAMS1", "provisioningStatus": "Success", "appliesTo": "User"}
		]
	}`, models.CreateSubscribedSkuFromDiscriminatorValue)
}

func testLicenseDetails(t *testing.T, status string) models.LicenseDetailsable {
	return decodeGraph[models.LicenseDetailsable](t, `{
		"id": "g8MZKfFVW02dPjUpmMP9K66cK8RP6rdKlxeBV2I1zKw",
		"skuId": "`+skuE5+`",
		"skuPartNumber": "DEVELOPERPACK_E5",
		"servicePlans": [
			{"servicePlanId": "4828c8ec-dc2e-4779-b502-87ac9ce28ab7", "servicePlanName": "TEAMS1", "provisioningStatus": "`+status+`", "appliesTo": "User"}
		]
	}`, models.CreateLicenseDetailsFromDiscriminatorValue)
}

// licenseTestEnv is a runtime whose microsoft resource has the tenant's SKUs
// and the given users' Graph licenseDetails already loaded, so nothing calls
// Graph.
func licenseTestEnv(t *testing.T, skus []models.SubscribedSkuable, skuErr error, live map[string]models.LicenseDetailsable) (*plugin.Runtime, *mqlMicrosoft) {
	t.Helper()
	runtime := plugin.NewRuntime(nil, nil, false, CreateResource, NewResource, GetData, SetData, nil)
	res, err := CreateResource(runtime, "microsoft", map[string]*llx.RawData{})
	require.NoError(t, err)
	ms := res.(*mqlMicrosoft)
	ms.subscribedSkus.once.Do(func() {
		ms.subscribedSkus.setSkus(skus)
		ms.subscribedSkus.err = skuErr
	})
	ms.userLicenseDetails.byUser = map[string]*userLicenseDetails{}
	for userID, d := range live {
		entry := &userLicenseDetails{}
		entry.once.Do(func() { entry.bySku = map[string]models.LicenseDetailsable{skuE5: d} })
		ms.userLicenseDetails.byUser[userID] = entry
	}
	return runtime, ms
}

func testUser(t *testing.T, runtime *plugin.Runtime, userID string, skuIDs ...string) *mqlMicrosoftUser {
	t.Helper()
	assigned := []any{}
	for _, skuID := range skuIDs {
		lic, err := CreateResource(runtime, "microsoft.user.assignedLicense", map[string]*llx.RawData{
			"__id":          llx.StringData(userAssignedLicenseID(userID, skuID)),
			"skuId":         llx.StringData(skuID),
			"disabledPlans": llx.ArrayData([]any{}, types.String),
		})
		require.NoError(t, err)
		assigned = append(assigned, lic)
	}
	u, err := CreateResource(runtime, "microsoft.user", map[string]*llx.RawData{
		"__id":             llx.StringData(userID),
		"id":               llx.StringData(userID),
		"assignedLicenses": llx.ArrayData(assigned, types.ResourceLike),
	})
	require.NoError(t, err)
	return u.(*mqlMicrosoftUser)
}

// Graph names a user's licenseDetails entry after the tenant and the SKU. The
// first case is an id Graph returned; the second was computed independently.
func TestGraphLicenseDetailID(t *testing.T) {
	tests := []struct {
		tenantID string
		want     string
	}{
		{testTenantID, "g8MZKfFVW02dPjUpmMP9K66cK8RP6rdKlxeBV2I1zKw"},
		{"00112233-4455-6677-8899-aabbccddeeff", "MyIRAFVEd2aImaq7zN3u_66cK8RP6rdKlxeBV2I1zKw"},
	}
	for _, tc := range tests {
		sku := decodeGraph[models.SubscribedSkuable](t, `{"id": "`+tc.tenantID+`_`+skuE5+`", "skuId": "`+skuE5+`"}`, models.CreateSubscribedSkuFromDiscriminatorValue)
		got, err := graphLicenseDetailID(sku)
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}

	_, err := graphLicenseDetailID(decodeGraph[models.SubscribedSkuable](t, `{"id": "not-a-tenant", "skuId": "`+skuE5+`"}`, models.CreateSubscribedSkuFromDiscriminatorValue))
	assert.Error(t, err)
}

// licenseDetails comes from assignedLicenses and the tenant's SKUs, without a
// Graph call per user. An assigned SKU the tenant does not hold is left out,
// as Graph leaves it out of licenseDetails.
func TestUserLicenseDetailsFromAssignedLicenses(t *testing.T) {
	runtime, _ := licenseTestEnv(t, []models.SubscribedSkuable{testSubscribedSku(t, skuE5, "DEVELOPERPACK_E5")}, nil, nil)
	user := testUser(t, runtime, "alice", skuE5, skuTeamsFree)

	details, err := user.licenseDetails()
	require.NoError(t, err)
	require.Len(t, details, 1)
	d := details[0].(*mqlMicrosoftUserLicenseDetail)
	assert.Equal(t, skuE5, d.SkuId.Data)
	assert.Equal(t, "DEVELOPERPACK_E5", d.SkuPartNumber.Data)
	assert.Equal(t, "g8MZKfFVW02dPjUpmMP9K66cK8RP6rdKlxeBV2I1zKw", d.Id.Data)
}

// Graph returns the same licenseDetail id to every user holding a SKU. Two
// users on one SKU whose service plans differ must each keep their own plans.
func TestUserLicenseDetailKeepsPerUserServicePlans(t *testing.T) {
	runtime, _ := licenseTestEnv(t, []models.SubscribedSkuable{testSubscribedSku(t, skuE5, "DEVELOPERPACK_E5")}, nil,
		map[string]models.LicenseDetailsable{
			"alice": testLicenseDetails(t, "Success"),
			"bob":   testLicenseDetails(t, "PendingInput"),
		})

	planStatus := func(userID string) (string, *mqlMicrosoftUserLicenseDetail) {
		details, err := testUser(t, runtime, userID, skuE5).licenseDetails()
		require.NoError(t, err)
		require.Len(t, details, 1)
		d := details[0].(*mqlMicrosoftUserLicenseDetail)
		plans, err := d.servicePlans()
		require.NoError(t, err)
		require.Len(t, plans, 1)
		return plans[0].(*mqlMicrosoftUserLicenseDetailServicePlanInfo).ProvisioningStatus.Data, d
	}
	aliceStatus, alice := planStatus("alice")
	bobStatus, bob := planStatus("bob")
	assert.Equal(t, "Success", aliceStatus)
	assert.Equal(t, "PendingInput", bobStatus)

	// the Graph id stays visible as the id field
	assert.Equal(t, alice.Id.Data, bob.Id.Data)
	assert.NotEqual(t, alice.MqlID(), bob.MqlID())
}

// A failed SKU listing must surface on licenseDetails. An empty list would
// read as "no licenses" and pass checks such as CIS 1.1.4 without data.
func TestUserLicenseDetailsSurfacesSkuError(t *testing.T) {
	runtime, _ := licenseTestEnv(t, nil, errors.New("403 Forbidden"), nil)
	_, err := testUser(t, runtime, "alice", skuE5).licenseDetails()
	assert.EqualError(t, err, "403 Forbidden")
}

func TestTenantSubscribedSku(t *testing.T) {
	runtime, _ := licenseTestEnv(t, nil, nil, nil)
	sku, err := newMqlMicrosoftTenantSubscribedSku(runtime, testSubscribedSku(t, skuE5, "DEVELOPERPACK_E5"))
	require.NoError(t, err)
	assert.Equal(t, "DEVELOPERPACK_E5", sku.SkuPartNumber.Data)
	assert.Equal(t, int64(2), sku.ConsumedUnits.Data)
	assert.Equal(t, int64(25), sku.PrepaidUnits.Data.(map[string]any)["enabled"])
	require.Len(t, sku.ServicePlans.Data, 1)
	assert.Equal(t, "TEAMS1", sku.ServicePlans.Data[0].(map[string]any)["servicePlanName"])
}

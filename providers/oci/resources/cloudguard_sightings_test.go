// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/cloudguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Impacted-resource and endpoint identifiers are only unique inside one
// sighting. Two sightings naming the same compromised host would collide, and
// CreateResource answers a repeated id with the cached first instance - so the
// second sighting would report the first one's timestamps and "when was this
// host touched" would get a wrong answer with nothing to indicate it.
func TestOciCloudGuardSightingChildIDSeparatesSightings(t *testing.T) {
	a := ociCloudGuardSightingChildID("ocid1.cloudguardsighting.oc1..a", "resource-1")
	b := ociCloudGuardSightingChildID("ocid1.cloudguardsighting.oc1..b", "resource-1")

	assert.NotEqual(t, a, b)
	assert.Equal(t, "ocid1.cloudguardsighting.oc1..a/resource-1", a)
}

func TestOciCloudGuardSightingChildIDSeparatesRecordsInOneSighting(t *testing.T) {
	sighting := "ocid1.cloudguardsighting.oc1..a"

	assert.NotEqual(t,
		ociCloudGuardSightingChildID(sighting, "resource-1"),
		ociCloudGuardSightingChildID(sighting, "resource-2"),
	)
}

// Payload shaped after the ListSightings response. The score is a pointer on a
// field the API marks mandatory, so a payload omitting it has to stay nil
// rather than becoming zero: zero is the lowest possible grade and would rank
// an unscored sighting below every real one.
func TestOciCloudGuardSightingSummaryDecode(t *testing.T) {
	var sighting cloudguard.SightingSummary
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "ocid1.cloudguardsighting.oc1..aaaa",
		"compartmentId": "ocid1.compartment.oc1..bbbb",
		"detectorRuleId": "IMPOSSIBLE_TRAVEL",
		"classificationStatus": "NOT_CLASSIFIED",
		"sightingType": "SUSPICIOUS_LOGIN",
		"sightingTypeDisplayName": "Suspicious login",
		"tacticName": "Initial Access",
		"techniqueName": "Valid Accounts",
		"sightingScore": 7,
		"severity": "HIGH",
		"confidence": "MEDIUM",
		"problemId": "ocid1.cloudguardproblem.oc1..cccc",
		"actorPrincipalId": "ocid1.user.oc1..dddd",
		"actorPrincipalName": "svc-deploy",
		"actorPrincipalType": "USER",
		"regions": ["us-ashburn-1", "us-phoenix-1"],
		"timeFirstDetected": "2026-08-01T10:00:00.000Z",
		"timeLastDetected": "2026-08-02T11:30:00.000Z"
	}`), &sighting))

	assert.Equal(t, cloudguard.ClassificationStatusNotClassified, sighting.ClassificationStatus)
	assert.Equal(t, cloudguard.SeverityHigh, sighting.Severity)
	assert.Equal(t, cloudguard.ConfidenceMedium, sighting.Confidence)
	assert.Equal(t, "svc-deploy", stringValue(sighting.ActorPrincipalName))
	assert.Equal(t, "ocid1.cloudguardproblem.oc1..cccc", stringValue(sighting.ProblemId))
	assert.Equal(t, []string{"us-ashburn-1", "us-phoenix-1"}, sighting.Regions)
	require.NotNil(t, sighting.SightingScore)
	assert.Equal(t, int64(7), *intPtrToInt64(sighting.SightingScore))
	require.NotNil(t, sighting.TimeLastDetected)
	assert.Nil(t, sighting.TimeFirstOccurred)
}

func TestOciCloudGuardSightingSummaryDecodeWithoutScore(t *testing.T) {
	var sighting cloudguard.SightingSummary
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "ocid1.cloudguardsighting.oc1..aaaa",
		"compartmentId": "ocid1.compartment.oc1..bbbb",
		"severity": "LOW"
	}`), &sighting))

	assert.Nil(t, sighting.SightingScore)
	assert.Nil(t, intPtrToInt64(sighting.SightingScore))
	assert.Nil(t, sighting.ProblemId)
}

// Coordinates are optional, and 0,0 is a real point in the Gulf of Guinea, so
// an address the service could not place must stay nil and read as null rather
// than being mapped to a coastline nobody was near.
func TestOciCloudGuardSightingEndpointDecodeWithoutCoordinates(t *testing.T) {
	var endpoint cloudguard.SightingEndpointSummary
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "endpoint-1",
		"sightingId": "ocid1.cloudguardsighting.oc1..aaaa",
		"ipAddress": "203.0.113.9",
		"ipAddressType": "EXTERNAL",
		"timeLastDetected": "2026-08-02T11:30:00.000Z"
	}`), &endpoint))

	assert.Equal(t, "203.0.113.9", stringValue(endpoint.IpAddress))
	assert.Nil(t, endpoint.Latitude)
	assert.Nil(t, endpoint.Longitude)
	assert.Empty(t, endpoint.Regions)
	assert.Empty(t, endpoint.Services)
}

func TestOciCloudGuardSightingEndpointDecode(t *testing.T) {
	var endpoint cloudguard.SightingEndpointSummary
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "endpoint-1",
		"sightingId": "ocid1.cloudguardsighting.oc1..aaaa",
		"ipAddress": "203.0.113.9",
		"ipAddressType": "EXTERNAL",
		"ipClassificationType": "MALICIOUS",
		"country": "Sealand",
		"latitude": 51.894,
		"longitude": 1.4797,
		"asnNumber": "64496",
		"regions": ["us-ashburn-1"],
		"services": ["IDENTITY"],
		"timeLastDetected": "2026-08-02T11:30:00.000Z"
	}`), &endpoint))

	assert.Equal(t, "MALICIOUS", stringValue(endpoint.IpClassificationType))
	assert.Equal(t, "64496", stringValue(endpoint.AsnNumber))
	require.NotNil(t, endpoint.Latitude)
	assert.InDelta(t, 51.894, *endpoint.Latitude, 0.0001)
	assert.Equal(t, []string{"IDENTITY"}, endpoint.Services)
}

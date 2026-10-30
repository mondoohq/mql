// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// Payloads follow the response examples in the Graph v1.0 reference for
// riskyServicePrincipal and servicePrincipalRiskDetection, decoded through the
// SDK's own discriminator factories.

const riskyServicePrincipalJSON = `{
  "@odata.type": "#microsoft.graph.riskyServicePrincipal",
  "id": "9089a539-a539-9089-39a5-899039a58990",
  "isEnabled": false,
  "isProcessing": true,
  "riskLastUpdatedDateTime": "2021-08-14T13:06:51.0451374Z",
  "riskLevel": "high",
  "riskState": "confirmedCompromised",
  "riskDetail": "hidden",
  "displayName": "Contoso App",
  "appId": "b55552fe-a272-4b56-990b-95038d917878",
  "servicePrincipalType": "Application"
}`

const servicePrincipalRiskDetectionJSON = `{
  "@odata.type": "#microsoft.graph.servicePrincipalRiskDetection",
  "id": "2856d6e87c5c3a74021ff70291fa68107570c150d8dc145bdea5",
  "requestId": "6b2a7b6e-1f0c-4b4b-8a0e-2a1d3c4e5f60",
  "correlationId": "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
  "riskEventType": "investigationsThreatIntelligence",
  "riskState": "atRisk",
  "riskLevel": "medium",
  "riskDetail": "none",
  "source": "IdentityProtection",
  "detectionTimingType": "offline",
  "activity": "servicePrincipal",
  "tokenIssuerType": "AzureAD",
  "ipAddress": "203.0.113.7",
  "location": {"city": "Seattle", "state": "Washington", "countryOrRegion": "US"},
  "activityDateTime": "2021-10-26T00:00:00Z",
  "detectedDateTime": "2021-10-27T00:00:00Z",
  "lastUpdatedDateTime": "2021-10-28T16:28:17Z",
  "servicePrincipalId": "99b8d28b-11ae-4e84-9bef-0e767e286abc",
  "servicePrincipalDisplayName": "Contoso App",
  "appId": "0b1b38ac-a572-491d-a9db-b07197643457",
  "keyIds": ["9d9fea30-d8e3-481b-b57c-0ef569a989e5", "1a2b3c4d-0000-4000-8000-000000000001"],
  "additionalInfo": "[{\"Key\":\"alertUrl\",\"Value\":null}]"
}`

// The detection the docs show for an offline threat-intelligence hit carries
// no sign-in context at all.
const servicePrincipalRiskDetectionSparseJSON = `{
  "@odata.type": "#microsoft.graph.servicePrincipalRiskDetection",
  "id": "sparse-1",
  "requestId": null,
  "ipAddress": null,
  "location": null,
  "riskEventType": "investigationsThreatIntelligence"
}`

func decodeRiskyServicePrincipal(t *testing.T, payload string) models.RiskyServicePrincipalable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateRiskyServicePrincipalFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.RiskyServicePrincipalable)
}

func decodeServicePrincipalRiskDetection(t *testing.T, payload string) models.ServicePrincipalRiskDetectionable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateServicePrincipalRiskDetectionFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.ServicePrincipalRiskDetectionable)
}

func TestRiskyServicePrincipalArgs(t *testing.T) {
	args := riskyServicePrincipalArgs(decodeRiskyServicePrincipal(t, riskyServicePrincipalJSON))

	assert.Equal(t, "9089a539-a539-9089-39a5-899039a58990", rawString(t, args, "__id"))
	assert.Equal(t, "9089a539-a539-9089-39a5-899039a58990", rawString(t, args, "id"))
	assert.Equal(t, "b55552fe-a272-4b56-990b-95038d917878", rawString(t, args, "appId"))
	assert.Equal(t, "Contoso App", rawString(t, args, "displayName"))
	assert.Equal(t, "Application", rawString(t, args, "servicePrincipalType"))
	assert.Equal(t, "high", rawString(t, args, "riskLevel"))
	assert.Equal(t, "confirmedCompromised", rawString(t, args, "riskState"))
	assert.Equal(t, "hidden", rawString(t, args, "riskDetail"))
	// Both booleans are set opposite to their zero value so a dropped or
	// swapped mapping shows up.
	assert.Equal(t, false, args["isEnabled"].Value)
	assert.Equal(t, true, args["isProcessing"].Value)
	ts, ok := args["riskLastUpdatedDateTime"].Value.(*time.Time)
	require.True(t, ok)
	assert.Equal(t, time.Date(2021, 8, 14, 13, 6, 51, 45137400, time.UTC), ts.UTC())
}

func TestServicePrincipalRiskDetectionArgs(t *testing.T) {
	args := servicePrincipalRiskDetectionArgs(decodeServicePrincipalRiskDetection(t, servicePrincipalRiskDetectionJSON))

	want := map[string]string{
		"__id":                        "2856d6e87c5c3a74021ff70291fa68107570c150d8dc145bdea5",
		"id":                          "2856d6e87c5c3a74021ff70291fa68107570c150d8dc145bdea5",
		"requestId":                   "6b2a7b6e-1f0c-4b4b-8a0e-2a1d3c4e5f60",
		"correlationId":               "1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
		"riskEventType":               "investigationsThreatIntelligence",
		"riskState":                   "atRisk",
		"riskLevel":                   "medium",
		"riskDetail":                  "none",
		"source":                      "IdentityProtection",
		"detectionTimingType":         "offline",
		"activity":                    "servicePrincipal",
		"tokenIssuerType":             "AzureAD",
		"ipAddress":                   "203.0.113.7",
		"city":                        "Seattle",
		"state":                       "Washington",
		"countryOrRegion":             "US",
		"servicePrincipalDisplayName": "Contoso App",
		"additionalInfo":              `[{"Key":"alertUrl","Value":null}]`,
	}
	for k, v := range want {
		assert.Equal(t, v, rawString(t, args, k), k)
	}
	assert.Equal(t, []any{"9d9fea30-d8e3-481b-b57c-0ef569a989e5", "1a2b3c4d-0000-4000-8000-000000000001"}, args["keyIds"].Value)
	assertStringList(t, args["keyIds"])

	for k, want := range map[string]time.Time{
		"activityDateTime":    time.Date(2021, 10, 26, 0, 0, 0, 0, time.UTC),
		"detectedDateTime":    time.Date(2021, 10, 27, 0, 0, 0, 0, time.UTC),
		"lastUpdatedDateTime": time.Date(2021, 10, 28, 16, 28, 17, 0, time.UTC),
	} {
		ts, ok := args[k].Value.(*time.Time)
		require.True(t, ok, k)
		assert.Equal(t, want, ts.UTC(), k)
	}
}

// Absent sign-in context must read as null and an empty key list, never as
// an empty string or a zero time.
func TestServicePrincipalRiskDetectionArgsSparse(t *testing.T) {
	args := servicePrincipalRiskDetectionArgs(decodeServicePrincipalRiskDetection(t, servicePrincipalRiskDetectionSparseJSON))

	for _, k := range []string{"ipAddress", "requestId", "city", "state", "countryOrRegion", "riskLevel", "tokenIssuerType"} {
		assert.Nil(t, args[k].Value, k)
	}
	for _, k := range []string{"activityDateTime", "detectedDateTime", "lastUpdatedDateTime"} {
		assert.Nil(t, args[k].Value, k)
	}
	assert.Equal(t, []any{}, args["keyIds"].Value)
	assertStringList(t, args["keyIds"])
}

func graphStatusErr(status int, code, msg string) *odataerrors.ODataError {
	payload := odataerrors.NewMainError()
	payload.SetCode(&code)
	payload.SetMessage(&msg)
	err := odataerrors.NewODataError()
	err.SetErrorEscaped(payload)
	err.ResponseStatusCode = status
	return err
}

func TestClassifyWorkloadIdentityProtectionError(t *testing.T) {
	// The message Graph returned live for a token without the scope.
	missingScope := graphStatusErr(403, "Forbidden", "You cannot perform the requested operation, required scopes are missing in the token.")
	notLicensed := graphStatusErr(403, "Forbidden", "Your tenant is not licensed for this feature.")

	t.Run("missing scope is Forbidden with the permission", func(t *testing.T) {
		err := classifyWorkloadIdentityProtectionError(missingScope, permIdentityRiskyServicePrincipalReadAll)
		assert.True(t, errors.Is(err, llx.ErrForbidden))
		var e *llx.Error
		require.True(t, errors.As(err, &e))
		assert.Equal(t, []string{permIdentityRiskyServicePrincipalReadAll}, e.Permissions)
		assert.Contains(t, err.Error(), "required scopes are missing")
	})
	t.Run("missing license is NotApplicable", func(t *testing.T) {
		err := classifyWorkloadIdentityProtectionError(notLicensed, permIdentityRiskyServicePrincipalReadAll)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(err))
	})
	t.Run("wrapped 403 is still classified", func(t *testing.T) {
		err := classifyWorkloadIdentityProtectionError(fmt.Errorf("paging: %w", missingScope), permIdentityRiskEventReadAll)
		assert.True(t, errors.Is(err, llx.ErrForbidden))
	})
	t.Run("non-403 Graph error is unclassified", func(t *testing.T) {
		err := classifyWorkloadIdentityProtectionError(graphStatusErr(400, "BadRequest", "Invalid filter clause"), permIdentityRiskEventReadAll)
		require.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(err))
	})
	t.Run("transport error is unclassified", func(t *testing.T) {
		err := classifyWorkloadIdentityProtectionError(&net.OpError{Op: "dial", Err: errors.New("connection refused")}, permIdentityRiskEventReadAll)
		require.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(err))
	})
	t.Run("nil", func(t *testing.T) {
		assert.NoError(t, classifyWorkloadIdentityProtectionError(nil, permIdentityRiskEventReadAll))
	})
}

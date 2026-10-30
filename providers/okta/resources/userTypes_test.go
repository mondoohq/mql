// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecodeOktaUserType pins the AdditionalProperties round-trip. The SDK
// declares only `id` on UserType and drops everything else into an untyped map;
// if its MarshalJSON ever stopped writing that map back out, every field but
// `id` would silently come back empty rather than failing.
func TestDecodeOktaUserType(t *testing.T) {
	t.Parallel()
	wire := `{
		"id": "oty1",
		"name": "contractor",
		"displayName": "Contractor",
		"description": "External contractors",
		"default": false,
		"createdBy": "00u1",
		"lastUpdatedBy": "00u2",
		"created": "2026-01-02T03:04:05.000Z",
		"lastUpdated": "2026-02-03T04:05:06.000Z"
	}`

	var src okta.UserType
	require.NoError(t, json.Unmarshal([]byte(wire), &src))
	require.Equal(t, "oty1", src.GetId())

	entry, err := decodeOktaUserType(&src)
	require.NoError(t, err)

	assert.Equal(t, "oty1", entry.Id)
	assert.Equal(t, "contractor", entry.Name)
	assert.Equal(t, "Contractor", entry.DisplayName)
	assert.Equal(t, "External contractors", entry.Description)
	assert.False(t, entry.Default)
	assert.Equal(t, "00u1", entry.CreatedBy)
	assert.Equal(t, "00u2", entry.LastUpdatedBy)
	require.NotNil(t, entry.Created)
	assert.Equal(t, 2026, entry.Created.Year())
	require.NotNil(t, entry.LastUpdated)
	assert.Equal(t, 2026, entry.LastUpdated.Year())
}

// TestDecodeOktaUserTypeDefaultType covers the built-in type, whose `default`
// is true and which carries no description.
func TestDecodeOktaUserTypeDefaultType(t *testing.T) {
	t.Parallel()
	var src okta.UserType
	require.NoError(t, json.Unmarshal(
		[]byte(`{"id":"oty0","name":"user","displayName":"User","default":true}`), &src))

	entry, err := decodeOktaUserType(&src)
	require.NoError(t, err)
	assert.True(t, entry.Default)
	assert.Empty(t, entry.Description)
	assert.Nil(t, entry.Created)
}

func TestOktaProfileMappingSides(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name                             string
		sourceType, sourceID, targetType string
		targetID                         string
		wantApplication, wantUserType    string
	}{
		{
			name:       "app to okta user",
			sourceType: "appuser", sourceID: "app1",
			targetType: "user", targetID: "oty1",
			wantApplication: "app1", wantUserType: "oty1",
		},
		{
			name:       "okta user to app",
			sourceType: "user", sourceID: "oty1",
			targetType: "appuser", targetID: "app1",
			wantApplication: "app1", wantUserType: "oty1",
		},
		{
			name:       "missing app side",
			sourceType: "user", sourceID: "oty1",
			targetType: "appuser", targetID: "",
			wantApplication: "", wantUserType: "oty1",
		},
		{
			name:       "both empty",
			sourceType: "", sourceID: "",
			targetType: "", targetID: "",
			wantApplication: "", wantUserType: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app, userType := oktaProfileMappingSides(tc.sourceType, tc.sourceID, tc.targetType, tc.targetID)
			assert.Equal(t, tc.wantApplication, app, "application id")
			assert.Equal(t, tc.wantUserType, userType, "user type id")
		})
	}
}

func TestIsOktaFeatureUnavailable(t *testing.T) {
	t.Parallel()
	err := assert.AnError

	tests := []struct {
		name   string
		resp   *okta.APIResponse
		err    error
		expect bool
	}{
		{"forbidden", apiResponse(http.StatusForbidden), err, true},
		{"not found", apiResponse(http.StatusNotFound), err, true},
		{"gone", apiResponse(http.StatusGone), err, true},
		{"unauthorized is a real failure", apiResponse(http.StatusUnauthorized), err, false},
		{"server error is a real failure", apiResponse(http.StatusInternalServerError), err, false},
		{"rate limited is a real failure", apiResponse(http.StatusTooManyRequests), err, false},
		{"no error", apiResponse(http.StatusNotFound), nil, false},
		{"no response", nil, err, false},
		// The SDK hands back a non-nil *APIResponse wrapping a nil
		// *http.Response whenever the request produced no response at all.
		// StatusCode is promoted from that embed, so this case panicked.
		{"response with no http response", &okta.APIResponse{}, err, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expect, isOktaFeatureUnavailable(tc.resp, tc.err))
		})
	}
}

func apiResponse(status int) *okta.APIResponse {
	return &okta.APIResponse{Response: &http.Response{StatusCode: status}}
}

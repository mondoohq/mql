// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	cs "github.com/codesphere-cloud/cs-go/api/openapi_client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: the API's path to workspace map; no live Codesphere account was
// available.
func TestDomainRoutes(t *testing.T) {
	routes := domainRoutes(map[string][]int{"/z": {3}, "/": {1, 2}, "/api": {4}})
	require.Len(t, routes, 3)
	assert.Equal(t, "/", routes[0].path)
	assert.Equal(t, []int{1, 2}, routes[0].workspaceIDs)
	assert.Equal(t, "/api", routes[1].path)
	assert.Equal(t, "/z", routes[2].path)

	assert.Empty(t, domainRoutes(nil))
}

// Synthetic: domains shaped per the API schema, decoded by the vendor client.
func TestCustomDomainArgs(t *testing.T) {
	var d cs.DomainsGetDomain200Response
	require.NoError(t, json.Unmarshal([]byte(`{
		"teamId": 12, "dataCenterId": 2, "name": "app.example.com",
		"workspaces": {"/": [101]},
		"certificateRequestStatus": {"issued": false, "reason": "CAA record forbids issuance"},
		"dnsEntries": {"a": "203.0.113.10", "cname": "12.dc2.example.net", "txt": "cs-verify=abc"},
		"domainVerificationStatus": {"verified": true, "reason": null},
		"customConfig": {"maxBodySizeMb": 50, "useRegex": true},
		"restricted": true
	}`), &d))
	args := customDomainArgs(&d)
	assert.Equal(t, "12/app.example.com", args["__id"].Value)
	assert.Equal(t, true, args["verified"].Value)
	assert.Nil(t, args["verificationReason"].Value)
	assert.Equal(t, false, args["certificateIssued"].Value)
	assert.Equal(t, "CAA record forbids issuance", args["certificateReason"].Value)
	assert.Equal(t, true, args["restricted"].Value)
	assert.Equal(t, "203.0.113.10", args["aRecord"].Value)
	assert.Equal(t, "12.dc2.example.net", args["cname"].Value)
	assert.Equal(t, float64(50), args["maxBodySizeMb"].Value)
	assert.Nil(t, args["maxConnectionTimeoutSeconds"].Value, "an unset limit is null, not zero")
	assert.Equal(t, true, args["useRegex"].Value)

	var plain cs.DomainsGetDomain200Response
	require.NoError(t, json.Unmarshal([]byte(`{
		"teamId": 12, "dataCenterId": 2, "name": "plain.example.com", "workspaces": {},
		"certificateRequestStatus": {"issued": true, "reason": null},
		"dnsEntries": {"a": "203.0.113.10", "cname": "c", "txt": "t"},
		"domainVerificationStatus": {"verified": false, "reason": "TXT record missing"}
	}`), &plain))
	args = customDomainArgs(&plain)
	assert.Nil(t, args["maxBodySizeMb"].Value)
	assert.Nil(t, args["useRegex"].Value)
	assert.Nil(t, args["restricted"].Value)
	assert.Equal(t, "TXT record missing", args["verificationReason"].Value)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// armError builds the error azcore hands a caller for a real ARM failure
// response, so the classifier is tested against the payload shape rather than
// against a hand-set ErrorCode field. The code and subcode are read out of the
// body exactly as they are in production.
func armError(status int, body string) error {
	reqURL, err := url.Parse("https://management.azure.com/subscriptions/sub/resourceGroups/rg")
	if err != nil {
		panic(err)
	}
	resp := &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    &http.Request{Method: http.MethodGet, URL: reqURL},
	}
	return runtime.NewResponseError(resp)
}

func asResponseError(t *testing.T, err error) *azcore.ResponseError {
	t.Helper()
	var respErr *azcore.ResponseError
	require.ErrorAs(t, err, &respErr)
	return respErr
}

// Every body below was captured from a live subscription. They are the whole
// reason the 400 handling is an allowlist rather than a status check: three of
// them mean "there is nothing here" and three mean "ask again" or "you asked
// wrong", and only the status code is the same.
const (
	// A cluster that is not a private-link private cluster -- the default shape.
	bodyAksNotPrivateLink = `{
  "code": "BadRequest",
  "details": null,
  "message": "Cluster my-cluster is not a private link service based private cluster.",
  "subcode": "ClusterIsNotAPrivateLinkCluster"
}`
	// Every SQL server has a master database, and master never supports LTR.
	bodySqlLtrUnsupported = `{"error":{"code":"LongTermRetentionPolicyNotSupported","message":"Long Term Retention is not supported : Not supported for master."}}`
	// A subscription without Defender's standard tier.
	bodyDefenderNoBundle = `{"error":{"code":"Subscription with no standard pricing bundle","message":"Regulatory compliance is not supported for subscription 'sub' as it has no standard pricing bundle"}}`

	// A Kusto cluster mid-provision. Retrying succeeds, so swallowing this
	// would report "no databases" for a cluster that has them.
	bodyKustoStillCreating = `{"error":{"code":"BadRequest","message":"Cannot fetch databases while resource is in state 'Creating'."}}`
	// An API Management service mid-activation. Same story.
	bodyApimActivating = `{"error":{"code":"InvalidOperation","message":"API Management service is activating"}}`
	// A request we got wrong. Must stay an error, or the bug hides as an
	// authoritative empty result.
	bodyBadApiVersion = `{"error":{"code":"InvalidApiVersionParameter","message":"The api-version '1999-01-01' is invalid."}}`
)

// The defect: isAzureNotConfigured matched 404 and 403 only, so a resource
// provider that reports an absent feature with a 400 failed the whole
// collection instead of one field. A public AKS cluster took the entire cluster
// list down with it.
func TestIsAzureNotConfiguredAcceptsTheAbsence400s(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"aks cluster is not a private link cluster", bodyAksNotPrivateLink},
		{"sql long-term retention not supported", bodySqlLtrUnsupported},
		{"defender has no standard pricing bundle", bodyDefenderNoBundle},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, isAzureNotConfigured(armError(http.StatusBadRequest, tc.body)))
		})
	}
}

// The other half of the fix, and the reason it is not simply "400 counts too":
// a 400 also carries transient state and our own bad requests. Degrading either
// to an empty collection reports an authoritative "nothing here" for a resource
// that has something.
func TestIsAzureNotConfiguredRejectsTransientAndCallerErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"kusto cluster still provisioning", http.StatusBadRequest, bodyKustoStillCreating},
		{"api management still activating", http.StatusBadRequest, bodyApimActivating},
		{"our api version is wrong", http.StatusBadRequest, bodyBadApiVersion},
		{"a 400 with no body at all", http.StatusBadRequest, ""},
		{"a 409 conflict on unsettled state", http.StatusConflict, `{"error":{"code":"RequestConflict","message":"provisioning state is not terminal"}}`},
		{"throttled", http.StatusTooManyRequests, `{"error":{"code":"TooManyRequests","message":"slow down"}}`},
		{"server error", http.StatusInternalServerError, `{"error":{"code":"InternalServerError","message":"boom"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, isAzureNotConfigured(armError(tc.status, tc.body)))
		})
	}
}

// A generic BadRequest code is only accepted with its subcode, so the same code
// without it -- which is what a caller error looks like -- must not match.
func TestBadRequestNeedsItsSubcode(t *testing.T) {
	withSubcode := armError(http.StatusBadRequest, bodyAksNotPrivateLink)
	require.True(t, isAzureNotConfigured(withSubcode))

	withoutSubcode := armError(http.StatusBadRequest,
		`{"code":"BadRequest","message":"Something else was wrong with the request."}`)
	assert.False(t, isAzureNotConfigured(withoutSubcode))

	wrongSubcode := armError(http.StatusBadRequest,
		`{"code":"BadRequest","message":"nope","subcode":"SomethingElseEntirely"}`)
	assert.False(t, isAzureNotConfigured(wrongSubcode))
}

func TestAzureFeatureNotApplicable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		code    string
		subcode string
		want    bool
	}{
		{"aks", http.StatusBadRequest, "BadRequest", "ClusterIsNotAPrivateLinkCluster", true},
		// ARM ids and error codes both vary in casing depending on the API.
		{"casing is ignored", http.StatusBadRequest, "badrequest", "clusterisnotaprivatelinkcluster", true},
		{"whitespace is trimmed", http.StatusBadRequest, " BadRequest ", " ClusterIsNotAPrivateLinkCluster ", true},
		{"a code that needs no subcode", http.StatusBadRequest, "LongTermRetentionPolicyNotSupported", "", true},
		{"a subcode on such a code is ignored", http.StatusBadRequest, "LongTermRetentionPolicyNotSupported", "Whatever", true},
		{"a code with spaces in it", http.StatusBadRequest, "Subscription with no standard pricing bundle", "", true},

		{"generic code without its subcode", http.StatusBadRequest, "BadRequest", "", false},
		{"unknown code", http.StatusBadRequest, "SomethingNew", "", false},
		{"empty code", http.StatusBadRequest, "", "", false},
		// The status gate matters on its own: an allowlisted code arriving with
		// a different status is a different situation than the one measured.
		{"right code, wrong status", http.StatusConflict, "LongTermRetentionPolicyNotSupported", "", false},
		{"404 goes through the status check, not here", http.StatusNotFound, "ResourceNotFound", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, azureFeatureNotApplicable(tc.status, tc.code, tc.subcode))
		})
	}
}

func TestAzureErrorSubcode(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"bare envelope", bodyAksNotPrivateLink, "ClusterIsNotAPrivateLinkCluster"},
		{"wrapped envelope", `{"error":{"code":"BadRequest","subcode":"Wrapped"}}`, "Wrapped"},
		{"no subcode", bodySqlLtrUnsupported, ""},
		{"empty body", "", ""},
		{"not json", "<html>gateway timeout</html>", ""},
		{"subcode is not a string", `{"code":"BadRequest","subcode":42}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := armError(http.StatusBadRequest, tc.body)
			respErr := asResponseError(t, err)
			assert.Equal(t, tc.want, azureErrorSubcode(respErr))
		})
	}

	assert.Empty(t, azureErrorSubcode(nil), "a nil error has no subcode")
}

// azcore builds the error by reading the body, and the classifier reads it again
// to get the subcode. Pin that the second read works -- if azcore ever stopped
// caching the payload, the subcode would silently read empty and every AKS
// cluster would start failing again.
func TestSubcodeSurvivesAzcoreConsumingTheBody(t *testing.T) {
	err := armError(http.StatusBadRequest, bodyAksNotPrivateLink)
	respErr := asResponseError(t, err)

	require.Equal(t, "BadRequest", respErr.ErrorCode, "azcore read the code out of the body")
	for i := range 3 {
		assert.Equal(t, "ClusterIsNotAPrivateLinkCluster", azureErrorSubcode(respErr),
			"read %d must still see the body", i+1)
	}
}

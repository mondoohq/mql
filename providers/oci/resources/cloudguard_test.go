// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/cloudguard"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ociTestServiceError is a stand-in for the SDK's service error. The SDK's own
// type is unexported behind common.IsServiceError, which matches on this
// interface, so implementing it is the only way to build one in a test.
type ociTestServiceError struct {
	status int
	code   string
	msg    string
}

func (e ociTestServiceError) Error() string           { return e.msg }
func (e ociTestServiceError) GetHTTPStatusCode() int  { return e.status }
func (e ociTestServiceError) GetMessage() string      { return e.msg }
func (e ociTestServiceError) GetCode() string         { return e.code }
func (e ociTestServiceError) GetOpcRequestID() string { return "test-request-id" }

func TestOciCloudGuardNotSubscribed(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			// The regression this guards. A tenancy that never onboarded Cloud
			// Guard answers every call this way, and it is the most common state
			// to query, so it has to read as "off" rather than as a failure.
			name: "not subscribed",
			err: ociTestServiceError{
				status: http.StatusNotFound,
				code:   "NotAuthorizedOrNotFound",
				msg:    "Cloudguard subscription is not available",
			},
			want: true,
		},
		{
			// Must NOT be swallowed: an under-scoped token would otherwise be
			// reported as a clean "Cloud Guard is disabled".
			name: "authorization failure",
			err: ociTestServiceError{
				status: http.StatusForbidden,
				code:   "NotAuthorizedOrNotFound",
				msg:    "not authorized",
			},
			want: false,
		},
		{
			name: "bad credentials",
			err:  ociTestServiceError{status: http.StatusUnauthorized, code: "NotAuthenticated", msg: "bad key"},
			want: false,
		},
		{
			name: "throttled",
			err:  ociTestServiceError{status: http.StatusTooManyRequests, code: "TooManyRequests", msg: "slow down"},
			want: false,
		},
		{
			name: "malformed request",
			err:  ociTestServiceError{status: http.StatusBadRequest, code: "InvalidParameter", msg: "bad params"},
			want: false,
		},
		{"transport error", errors.New("connection refused"), false},
		{"no error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociCloudGuardNotSubscribed(tt.err))
		})
	}
}

func TestOciReferentGone(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "service 404",
			err:  ociTestServiceError{status: http.StatusNotFound, code: "BucketNotFound", msg: "gone"},
			want: true,
		},
		{
			// An ONS topic is resolved by scanning the listing, not by a GET, so
			// its absence arrives as a sentinel with no HTTP status attached.
			// Before this was recognised, one connector pointing at a deleted
			// topic failed the whole connector listing.
			name: "ons topic sentinel",
			err:  fmt.Errorf("%w: %s", errOciOnsTopicNotFound, "ocid1.onstopic.oc1.phx.example"),
			want: true,
		},
		{"bare sentinel", errOciOnsTopicNotFound, true},
		{
			name: "authorization failure is not absence",
			err:  ociTestServiceError{status: http.StatusForbidden, code: "NotAuthorizedOrNotFound", msg: "denied"},
			want: false,
		},
		{"unrelated error", errors.New("connection refused"), false},
		{"no error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociReferentGone(tt.err))
		})
	}
}

// TestOciListSecurityZonesAsksTheGivenCompartment pins the request that lists
// security zones. ListSecurityZones answers only for the compartment it is
// given, and isRequiredSecurityZonesInSubtree does not widen that, so a single
// call at the tenancy root found no zone attached to a child compartment.
func TestOciListSecurityZonesAsksTheGivenCompartment(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items": [{"id": "ocid1.securityzone..z1", "displayName": "zone",
			"compartmentId": "ocid1.compartment..child", "isInheritanceAfterDeleteEnabled": false}]}`))
	}))
	t.Cleanup(srv.Close)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy..t", "ocid1.user..u", "us-ashburn-1",
		"aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99", string(keyPEM), nil)
	client, err := cloudguard.NewCloudGuardClientWithConfigurationProvider(provider)
	require.NoError(t, err)
	client.Host = srv.URL

	zones, err := ociListSecurityZones(context.Background(), &client, "ocid1.compartment..child")
	require.NoError(t, err)
	require.Len(t, zones, 1)
	assert.Equal(t, "ocid1.compartment..child", *zones[0].CompartmentId)
	require.NotNil(t, zones[0].IsInheritanceAfterDeleteEnabled)
	assert.False(t, *zones[0].IsInheritanceAfterDeleteEnabled)
	require.Len(t, queries, 1)
	assert.Contains(t, queries[0], "compartmentId=ocid1.compartment..child")
	assert.NotContains(t, queries[0], "isRequiredSecurityZonesInSubtree")
}

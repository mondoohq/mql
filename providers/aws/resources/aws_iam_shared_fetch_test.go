// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Each pair below has a deprecated dict field and the typed replacement this
// branch added, and both used to paginate the same API on their own. A query
// touching both then cost two walks of ListServerCertificates per account and
// two of ListMFADevices per user. The tests seed the memo and leave the
// resource without a runtime, so an accessor that went back to the API
// dereferences a nil connection and fails rather than quietly costing a call.

func TestIamServerCertificateFetchIsMemoized(t *testing.T) {
	arn := "arn:aws:iam::123456789012:server-certificate/web"
	a := &mqlAwsIam{}
	a.serverCertsCache = []iamtypes.ServerCertificateMetadata{{Arn: &arn}}
	a.serverCertsFetched.Store(true)

	require.NotPanics(t, func() {
		got, err := a.fetchServerCertificates()
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, arn, *got[0].Arn)
	}, "a seeded memo must answer without reaching for the connection")
}

func TestIamServerCertificatesReadTheMemo(t *testing.T) {
	arn := "arn:aws:iam::123456789012:server-certificate/web"
	name := "web"
	expiry := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	a := &mqlAwsIam{}
	a.serverCertsCache = []iamtypes.ServerCertificateMetadata{
		{Arn: &arn, ServerCertificateName: &name, Expiration: &expiry},
	}
	a.serverCertsFetched.Store(true)

	var dicts []any
	require.NotPanics(t, func() {
		var err error
		dicts, err = a.serverCertificates()
		require.NoError(t, err)
	}, "the deprecated dict must answer from the shared fetch")
	require.Len(t, dicts, 1)
	assert.Equal(t, name, dicts[0].(map[string]any)["ServerCertificateName"])
}

// With the memo seeded empty the typed accessor has nothing to build, so it
// returns without a runtime. A version that re-paginated would panic here.
func TestIamTlsCertificatesReadTheMemo(t *testing.T) {
	a := &mqlAwsIam{}
	a.serverCertsFetched.Store(true)

	require.NotPanics(t, func() {
		got, err := a.tlsCertificates()
		require.NoError(t, err)
		assert.Empty(t, got)
	}, "the typed replacement must answer from the shared fetch")
}

func TestIamUserMfaDeviceFetchIsMemoized(t *testing.T) {
	serial := "arn:aws:iam::123456789012:mfa/alice"
	a := &mqlAwsIamUser{}
	a.mfaDevicesCache = []iamtypes.MFADevice{{SerialNumber: &serial}}
	a.mfaDevicesFetched.Store(true)

	require.NotPanics(t, func() {
		got, err := a.fetchMfaDevices()
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, serial, *got[0].SerialNumber)
	}, "a seeded memo must answer without reaching for the connection")
}

func TestIamUserMfaDevicesReadTheMemo(t *testing.T) {
	serial := "arn:aws:iam::123456789012:mfa/alice"
	user := "alice"
	a := &mqlAwsIamUser{}
	a.mfaDevicesCache = []iamtypes.MFADevice{{SerialNumber: &serial, UserName: &user}}
	a.mfaDevicesFetched.Store(true)

	var dicts []any
	require.NotPanics(t, func() {
		var err error
		dicts, err = a.mfaDevices()
		require.NoError(t, err)
	}, "the deprecated dict must answer from the shared fetch")
	require.Len(t, dicts, 1)
	assert.Equal(t, serial, dicts[0].(map[string]any)["SerialNumber"])
}

func TestIamUserAssignedMfaDevicesReadTheMemo(t *testing.T) {
	a := &mqlAwsIamUser{}
	a.mfaDevicesFetched.Store(true)

	require.NotPanics(t, func() {
		got, err := a.assignedMfaDevices()
		require.NoError(t, err)
		assert.Empty(t, got)
	}, "the typed replacement must answer from the shared fetch")
}

// A user with no MFA device reads as an empty list, never as null: "this user
// has no second factor" is the answer a console-MFA check is looking for, and
// a null would make the check inconclusive instead.
func TestIamUserMfaDevicesEmptyIsNotNull(t *testing.T) {
	a := &mqlAwsIamUser{}
	a.mfaDevicesFetched.Store(true)

	got, err := a.mfaDevices()
	require.NoError(t, err)
	assert.NotNil(t, got)
	assert.Empty(t, got)
}

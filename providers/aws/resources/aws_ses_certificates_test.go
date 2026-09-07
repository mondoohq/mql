// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sesv2_types "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// During a rotation an identity carries two associations for one address: the
// outgoing certificate DEPROVISIONING alongside the incoming one
// PROVISIONING. A key built from the address alone collapses them, so
// CreateResource returns the cached first association for the second, and one
// of the two certificates is never reported at all.
func TestSesIdentityCertificateCacheID_Distinct(t *testing.T) {
	const identity = "arn:aws:ses:us-east-1:666666666666:identity/example.com"

	outgoing := sesIdentityCertificateCacheID(identity, "sales@example.com", "arn:aws:acm:us-east-1:666666666666:certificate/old")
	incoming := sesIdentityCertificateCacheID(identity, "sales@example.com", "arn:aws:acm:us-east-1:666666666666:certificate/new")
	assert.NotEqual(t, outgoing, incoming, "a rotation's two certificates for one address must not collide")

	otherAddress := sesIdentityCertificateCacheID(identity, "support@example.com", "arn:aws:acm:us-east-1:666666666666:certificate/old")
	assert.NotEqual(t, outgoing, otherAddress)

	otherIdentity := sesIdentityCertificateCacheID(
		"arn:aws:ses:us-east-1:666666666666:identity/other.example",
		"sales@example.com", "arn:aws:acm:us-east-1:666666666666:certificate/old")
	assert.NotEqual(t, outgoing, otherIdentity)
}

// Every field on IdentityCertificate is optional on the wire. An absent expiry
// must stay null: decoding it into a zero time.Time would report 1 January
// year 1 as a real expiry date, which any "expires within N days" check reads
// as long expired.
func TestSesCertificateArgs_AbsentValuesStayNull(t *testing.T) {
	expiry := time.Date(2027, 3, 14, 0, 0, 0, 0, time.UTC)

	present := sesCertificateArgs("arn:aws:ses:us-east-1:666666666666:identity/example.com", sesv2_types.IdentityCertificate{
		CertificateArn:        aws.String("arn:aws:acm:us-east-1:666666666666:certificate/abc"),
		CertificateExpiryTime: &expiry,
		FromAddress:           aws.String("sales@example.com"),
		Status:                sesv2_types.IdentityCertificateStatusActive,
	})

	assert.Equal(t, "ACTIVE", present["status"].Value)
	assert.Equal(t, "sales@example.com", present["fromAddress"].Value)
	assert.Equal(t, "arn:aws:acm:us-east-1:666666666666:certificate/abc", present["arn"].Value)
	gotExpiry, ok := present["certificateExpiryTime"].Value.(*time.Time)
	require.True(t, ok)
	require.NotNil(t, gotExpiry)
	assert.Equal(t, expiry, *gotExpiry)

	absent := sesCertificateArgs("arn:aws:ses:us-east-1:666666666666:identity/example.com", sesv2_types.IdentityCertificate{
		Status: sesv2_types.IdentityCertificateStatusFailed,
	})

	assert.Nil(t, absent["certificateExpiryTime"].Value, "an absent expiry must read null, not the zero time")
	assert.Nil(t, absent["arn"].Value, "an absent certificate ARN must read null, not an empty string")
	assert.Nil(t, absent["fromAddress"].Value)
	// A FAILED association is exactly the case an audit is looking for, so the
	// status has to survive even when everything else is absent.
	assert.Equal(t, "FAILED", absent["status"].Value)
}

// The states that mean "this address is not signing" have to stay
// distinguishable from ACTIVE. Any normalization that folded them together,
// or that mapped an unset status onto a default, would let an audit for
// "every certificate is ACTIVE" pass on an identity whose certificate failed.
func TestSesCertificateArgs_StatusIsReportedVerbatim(t *testing.T) {
	const identity = "arn:aws:ses:us-east-1:666666666666:identity/example.com"

	cases := map[sesv2_types.IdentityCertificateStatus]string{
		sesv2_types.IdentityCertificateStatusActive:         "ACTIVE",
		sesv2_types.IdentityCertificateStatusFailed:         "FAILED",
		sesv2_types.IdentityCertificateStatusInactive:       "INACTIVE",
		sesv2_types.IdentityCertificateStatusProvisioning:   "PROVISIONING",
		sesv2_types.IdentityCertificateStatusDeprovisioning: "DEPROVISIONING",
	}
	for status, want := range cases {
		args := sesCertificateArgs(identity, sesv2_types.IdentityCertificate{Status: status})
		assert.Equal(t, want, args["status"].Value)
	}

	// An association SES returns with no status must not silently read ACTIVE.
	unset := sesCertificateArgs(identity, sesv2_types.IdentityCertificate{})
	assert.Equal(t, "", unset["status"].Value)
}

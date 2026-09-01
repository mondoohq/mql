// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers/network/resources/tlsshake"
)

func TestRevocationFields(t *testing.T) {
	cert := &x509.Certificate{Signature: []byte("signature")}
	key := string(cert.Signature)

	t.Run("a certificate that was checked and is not revoked", func(t *testing.T) {
		isRevoked, revokedAt, checked := revocationFields(
			map[string]*tlsshake.Revocation{key: nil}, cert)

		assert.Equal(t, llx.BoolFalse, isRevoked)
		assert.Equal(t, llx.BoolTrue, checked)
		// Nothing was revoked, so there is no revocation time to report. This
		// used to be the zero time, which renders as a duration rather than as
		// the absence of a date.
		assert.Equal(t, llx.NilData, revokedAt)
	})

	t.Run("a certificate that was checked and is revoked", func(t *testing.T) {
		at := time.Date(2026, 7, 14, 21, 1, 28, 0, time.UTC)
		isRevoked, revokedAt, checked := revocationFields(
			map[string]*tlsshake.Revocation{key: {At: at}}, cert)

		assert.Equal(t, llx.BoolTrue, isRevoked)
		assert.Equal(t, llx.BoolTrue, checked)
		assert.Equal(t, llx.TimeData(at), revokedAt)
	})

	t.Run("a certificate whose revocation status could not be determined", func(t *testing.T) {
		// No entry in the map. Reporting false here is what made a revoked
		// certificate whose issuer has retired OCSP read as good, and left
		// revokedAt at the zero time.
		isRevoked, revokedAt, checked := revocationFields(
			map[string]*tlsshake.Revocation{}, cert)

		assert.Equal(t, llx.NilData, isRevoked)
		assert.Equal(t, llx.NilData, revokedAt)
		assert.Equal(t, llx.BoolFalse, checked)
	})
}

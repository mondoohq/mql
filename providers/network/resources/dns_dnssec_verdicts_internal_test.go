// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/network/resources/dnsshake"
)

func TestDnssecVerdicts(t *testing.T) {
	t.Run("reports the verdicts when the resolver honored DNSSEC", func(t *testing.T) {
		signed, verified, chain, current := dnssecVerdicts(&dnsshake.DnssecValidation{
			DnssecOk:              true,
			Signatures:            []dnsshake.DnssecSignature{{TypeCovered: "A"}},
			SignaturesVerified:    true,
			ChainOfTrustValidated: true,
		}, true)

		assert.Equal(t, llx.BoolTrue, signed)
		assert.Equal(t, llx.BoolTrue, verified)
		assert.Equal(t, llx.BoolTrue, chain)
		assert.Equal(t, llx.BoolTrue, current)
	})

	t.Run("reports an unsigned zone as unsigned", func(t *testing.T) {
		// The resolver did return DNSSEC records, so an answer with no signature
		// really is evidence that the zone is not signed.
		signed, verified, chain, current := dnssecVerdicts(&dnsshake.DnssecValidation{
			DnssecOk:   true,
			Signatures: []dnsshake.DnssecSignature{},
		}, false)

		assert.Equal(t, llx.BoolFalse, signed)
		assert.Equal(t, llx.BoolFalse, verified)
		assert.Equal(t, llx.BoolFalse, chain)
		assert.Equal(t, llx.BoolFalse, current)
	})

	t.Run("reports nothing about the zone when the resolver stripped DNSSEC", func(t *testing.T) {
		// A resolver that did not honor the DNSSEC OK bit answers without
		// signatures whether or not the zone is signed, so an unsigned-looking
		// answer says nothing. Reporting false here is what made a signed zone
		// read as unsigned.
		signed, verified, chain, current := dnssecVerdicts(&dnsshake.DnssecValidation{
			DnssecOk:   false,
			Signatures: []dnsshake.DnssecSignature{},
		}, false)

		assert.Equal(t, llx.NilData, signed)
		assert.Equal(t, llx.NilData, verified)
		assert.Equal(t, llx.NilData, chain)
		assert.Equal(t, llx.NilData, current)
	})
}

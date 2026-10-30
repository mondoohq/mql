// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/network/resources/tlsshake"
)

// certs with neither an OCSP responder nor a CRL cannot be determined, so these
// exercise the map handling without reaching the network.
func uncheckableChain() []*x509.Certificate {
	return []*x509.Certificate{
		{Signature: []byte("leaf")},
		{Signature: []byte("intermediate")},
		{Signature: []byte("root")},
	}
}

func TestWithChainRevocations(t *testing.T) {
	t.Run("does not write through to the tester's map", func(t *testing.T) {
		// The tester owns this map and other fields read it, so writing to it
		// here would publish this chain's findings onto an unrelated one.
		known := map[string]*tlsshake.Revocation{}
		res := withChainRevocations(known, uncheckableChain())

		assert.Empty(t, known)
		assert.NotSame(t, &known, &res)
	})

	t.Run("keeps what the tester already determined", func(t *testing.T) {
		at := time.Date(2026, 7, 14, 21, 1, 28, 0, time.UTC)
		known := map[string]*tlsshake.Revocation{
			"leaf":         {At: at},
			"intermediate": nil,
		}

		res := withChainRevocations(known, uncheckableChain())

		require.Contains(t, res, "leaf")
		require.NotNil(t, res["leaf"])
		assert.Equal(t, at, res["leaf"].At)

		// A nil value is a determination too, not an absence, so it must not be
		// mistaken for something still to check.
		require.Contains(t, res, "intermediate")
		assert.Nil(t, res["intermediate"])
	})

	t.Run("adds nothing when nothing can be determined", func(t *testing.T) {
		res := withChainRevocations(map[string]*tlsshake.Revocation{}, uncheckableChain())
		assert.Empty(t, res, "an undeterminable certificate must stay absent, not become 'not revoked'")
	})

	t.Run("never checks the last certificate in the chain", func(t *testing.T) {
		// It is a trust anchor: there is no issuer below it, and its revocation
		// is not a question its own chain can answer.
		res := withChainRevocations(map[string]*tlsshake.Revocation{"root": nil}, uncheckableChain())
		assert.Contains(t, res, "root", "a value already known is still carried through")

		res = withChainRevocations(map[string]*tlsshake.Revocation{}, uncheckableChain())
		assert.NotContains(t, res, "root")
	})

	t.Run("handles a chain with a single certificate", func(t *testing.T) {
		res := withChainRevocations(map[string]*tlsshake.Revocation{}, uncheckableChain()[:1])
		assert.Empty(t, res)
	})

	t.Run("handles an empty chain", func(t *testing.T) {
		res := withChainRevocations(map[string]*tlsshake.Revocation{}, nil)
		assert.Empty(t, res)
	})
}

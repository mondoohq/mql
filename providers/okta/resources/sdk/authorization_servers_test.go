// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJsonWebKeyDecode verifies the full JWK shape decodes from the
// credentials/keys response — in particular the fields that the generated
// AuthorizationServerJsonWebKey model drops (created, lastUpdated, expiresAt,
// key_ops, x5c, x5t, x5t#S256). This is the backward-compat guarantee for the
// okta.authorizationServer.key resource.
func TestJsonWebKeyDecode(t *testing.T) {
	const payload = `[{
		"kid": "k1",
		"status": "ACTIVE",
		"alg": "RS256",
		"kty": "RSA",
		"use": "sig",
		"key_ops": ["sign", "verify"],
		"created": "2024-01-01T00:00:00.000Z",
		"lastUpdated": "2024-02-01T00:00:00.000Z",
		"expiresAt": "2025-01-01T00:00:00.000Z",
		"x5c": ["MIIcert"],
		"x5t": "thumbprint",
		"x5t#S256": "thumbprint256",
		"n": "modulus",
		"e": "AQAB"
	}]`

	var keys []*JsonWebKey
	require.NoError(t, json.Unmarshal([]byte(payload), &keys))
	require.Len(t, keys, 1)

	k := keys[0]
	assert.Equal(t, "k1", k.Kid)
	assert.Equal(t, "ACTIVE", k.Status)
	assert.Equal(t, "RS256", k.Alg)
	assert.Equal(t, "RSA", k.Kty)
	assert.Equal(t, "sig", k.Use)
	assert.Equal(t, []string{"sign", "verify"}, k.KeyOps)
	require.NotNil(t, k.Created)
	require.NotNil(t, k.LastUpdated)
	require.NotNil(t, k.ExpiresAt)
	assert.Equal(t, 2025, k.ExpiresAt.Year())
	assert.Equal(t, []string{"MIIcert"}, k.X5c)
	assert.Equal(t, "thumbprint", k.X5t)
	assert.Equal(t, "thumbprint256", k.X5tS256) // verifies the `x5t#S256` json tag
	assert.Equal(t, "modulus", k.N)
	assert.Equal(t, "AQAB", k.E)
}

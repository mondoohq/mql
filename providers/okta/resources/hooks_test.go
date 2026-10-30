// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseInlineHookChannel(t *testing.T) {
	// Shape matches json.Marshal(entry.Channel): the channel object itself,
	// not a wrapper containing it.
	channelJSON := []byte(`{
		"type": "HTTP",
		"version": "1.0.0",
		"config": {
			"uri": "https://hook.example.com/okta",
			"method": "POST",
			"authScheme": {"type": "HEADER", "key": "Authorization"}
		}
	}`)

	channelType, uri, authScheme, err := parseInlineHookChannel(channelJSON)
	require.NoError(t, err)
	assert.Equal(t, "HTTP", channelType)
	assert.Equal(t, "https://hook.example.com/okta", uri)
	assert.Equal(t, "HEADER", authScheme["type"])
	assert.Equal(t, "Authorization", authScheme["key"])
}

func TestParseInlineHookChannel_Empty(t *testing.T) {
	channelType, uri, authScheme, err := parseInlineHookChannel([]byte(`{"type":"HTTP"}`))
	require.NoError(t, err)
	assert.Equal(t, "HTTP", channelType)
	assert.Equal(t, "", uri)
	assert.Nil(t, authScheme)
}

func TestOktaHookKeyPublicKey(t *testing.T) {
	jwk := map[string]any{"kty": "RSA", "kid": "k1", "use": "sig", "e": "AQAB"}

	// Okta's actual shape: the JWK nested under a publicKey wrapper (which the
	// SDK's *JsonWebKey typing pushes into AdditionalProperties).
	wrapped := map[string]any{"publicKey": jwk}
	assert.Equal(t, jwk, oktaHookKeyPublicKey(wrapped))

	// Already-flat JWK: returned unchanged.
	assert.Equal(t, jwk, oktaHookKeyPublicKey(jwk))

	// Non-map payloads pass through.
	assert.Nil(t, oktaHookKeyPublicKey(nil))
	assert.Equal(t, "x", oktaHookKeyPublicKey("x"))
}

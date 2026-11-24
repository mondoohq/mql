// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: a whoami-v2 answer shaped after the Hub OpenAPI document; no live
// account was checked.
func TestWhoAmIDecodeOrgSecurityAndExpiry(t *testing.T) {
	data := []byte(`{
		"type":"user","id":"u1","name":"alice","fullname":"Alice","avatarUrl":"a","isPro":false,
		"auth":{"type":"access_token","expiresAt":"2027-01-01T00:00:00.000Z",
			"accessToken":{"displayName":"ci","role":"read","createdAt":"2026-01-01T00:00:00.000Z"}},
		"orgs":[
			{"type":"org","id":"o1","name":"acme","fullname":"Acme","avatarUrl":"x","plan":"enterprise",
			 "securityRestrictions":["mfa","sso"]},
			{"type":"org","id":"o2","name":"free","fullname":"Free","avatarUrl":"y","securityRestrictions":[]},
			{"type":"org","id":"o3","name":"quiet","fullname":"Quiet","avatarUrl":"z"}
		]}`)

	var u User
	require.NoError(t, json.Unmarshal(data, &u))
	assert.Equal(t, "2027-01-01T00:00:00.000Z", u.Auth.ExpiresAt)
	require.Len(t, u.Orgs, 3)

	assert.Equal(t, "enterprise", u.Orgs[0].Plan)
	require.NotNil(t, u.Orgs[0].SecurityRestrictions)
	assert.Equal(t, []string{"mfa", "sso"}, *u.Orgs[0].SecurityRestrictions)

	// A reported empty list stays apart from one the Hub left out.
	assert.Empty(t, u.Orgs[1].Plan)
	require.NotNil(t, u.Orgs[1].SecurityRestrictions)
	assert.Empty(t, *u.Orgs[1].SecurityRestrictions)
	assert.Nil(t, u.Orgs[2].SecurityRestrictions)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: a trusted publisher shaped after GET .../settings/trusted-publishers
// in the Hub OpenAPI document; no live account was checked.
func TestTrustedPublisherDecode(t *testing.T) {
	data := []byte(`[
		{"_id":"aaaaaaaaaaaaaaaaaaaaaaaa","issuerUrl":"https://token.actions.githubusercontent.com",
		 "claims":{"repository":{"kind":"eq","value":"acme/app"},"ref":{"kind":"prefix","value":"refs/heads/"}},
		 "configuredBy":{"_id":"bbbbbbbbbbbbbbbbbbbbbbbb","avatarUrl":"a","fullname":"Alice","name":"alice",
		   "isHf":false,"isHfAdmin":false,"isMod":false,"type":"user","isPro":false},
		 "createdAt":"2026-01-01T00:00:00.000Z","lastUsedAt":"2026-02-01T00:00:00.000Z",
		 "capabilities":["inference-api"],"permissions":["repo.content.write"]},
		{"_id":"cccccccccccccccccccccccc","issuerUrl":"https://gitlab.com","claims":{},"createdAt":"2026-01-01T00:00:00.000Z"}
	]`)

	var pubs []TrustedPublisher
	require.NoError(t, json.Unmarshal(data, &pubs))
	require.Len(t, pubs, 2)

	a := pubs[0]
	assert.Equal(t, "https://token.actions.githubusercontent.com", a.IssuerURL)
	assert.Equal(t, map[string]any{"kind": "prefix", "value": "refs/heads/"}, a.Claims["ref"])
	require.NotNil(t, a.ConfiguredBy)
	assert.Equal(t, "alice", a.ConfiguredBy.Name)
	assert.Equal(t, "2026-02-01T00:00:00.000Z", a.LastUsedAt)
	assert.Equal(t, []string{"inference-api"}, a.Capabilities)
	assert.Equal(t, []string{"repo.content.write"}, a.Permissions)

	b := pubs[1]
	assert.Nil(t, b.ConfiguredBy)
	assert.Empty(t, b.LastUsedAt)
	assert.Nil(t, b.Permissions)
}

// Synthetic: access requests shaped after GET .../user-access-request/{status}
// in the Hub OpenAPI document; no live account was checked.
func TestAccessRequestDecode(t *testing.T) {
	data := []byte(`[
		{"requestId":"aaaaaaaaaaaaaaaaaaaaaaaa","status":"accepted","timestamp":"2026-01-01T00:00:00.000Z",
		 "reviewedAt":"2026-01-02T00:00:00.000Z",
		 "user":{"_id":"bbbbbbbbbbbbbbbbbbbbbbbb","avatarUrl":"a","fullname":"Alice","isPro":false,"user":"alice",
		   "type":"user","verifiedOrgNames":[],"email":"alice@example.com"},
		 "grantedBy":{"_id":"cccccccccccccccccccccccc","avatarUrl":"b","fullname":"Bob","isPro":false,"user":"bob","type":"user"},
		 "fields":{"reason":"research"}},
		{"requestId":"dddddddddddddddddddddddd","status":"accepted","timestamp":"2026-01-01T00:00:00.000Z","grantedBy":{}},
		{"requestId":"eeeeeeeeeeeeeeeeeeeeeeee","status":"pending","timestamp":"2026-01-03T00:00:00.000Z"}
	]`)

	var reqs []AccessRequest
	require.NoError(t, json.Unmarshal(data, &reqs))
	require.Len(t, reqs, 3)

	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaa", reqs[0].RequestID)
	require.NotNil(t, reqs[0].User)
	assert.Equal(t, "alice", reqs[0].User.User)
	require.NotNil(t, reqs[0].GrantedBy)
	assert.Equal(t, "bob", reqs[0].GrantedBy.User)
	assert.Equal(t, "2026-01-01T00:00:00.000Z", reqs[0].Timestamp)
	assert.Equal(t, "2026-01-02T00:00:00.000Z", reqs[0].ReviewedAt)

	// The spec allows an empty grantedBy object; it names nobody.
	assert.Nil(t, reqs[1].User)
	require.NotNil(t, reqs[1].GrantedBy)
	assert.Empty(t, reqs[1].GrantedBy.User)

	assert.Equal(t, "pending", reqs[2].Status)
	assert.Nil(t, reqs[2].GrantedBy)
	assert.Empty(t, reqs[2].ReviewedAt)
}

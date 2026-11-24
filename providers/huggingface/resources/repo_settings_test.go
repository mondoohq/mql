// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	hfmodels "go.mondoo.com/mql/providers/huggingface/internal/huggingface-hub-go/models"
)

// Synthetic: trusted publishers shaped after GET .../settings/trusted-publishers
// in the Hub OpenAPI document; no live account was checked.
func TestTrustedPublisherArgs(t *testing.T) {
	p := hfmodels.TrustedPublisher{
		ID: "p1", IssuerURL: "https://token.actions.githubusercontent.com",
		Claims:       map[string]any{"repository": map[string]any{"kind": "eq", "value": "acme/app"}},
		ConfiguredBy: &hfmodels.HubAccount{Name: "alice"},
		CreatedAt:    "2026-01-01T00:00:00.000Z",
		LastUsedAt:   "2026-02-01T00:00:00.000Z",
		Permissions:  []string{"repo.content.write"},
	}
	args := trustedPublisherArgs(hfmodels.RepoTypeModel, "acme/llm", p)
	assert.Equal(t, "https://token.actions.githubusercontent.com", args["issuerUrl"].Value)
	assert.Equal(t, "alice", args["configuredBy"].Value)
	assert.Equal(t, []any{"repo.content.write"}, args["permissions"].Value)
	assert.Equal(t, new(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)), args["lastUsedAt"].Value)
	assert.Equal(t, p.Claims, args["claims"].Value)

	// The same publisher id under another repository is another record.
	other := trustedPublisherArgs(hfmodels.RepoTypeDataset, "acme/llm", p)
	assert.NotEqual(t, args["__id"].Value, other["__id"].Value)

	bare := trustedPublisherArgs(hfmodels.RepoTypeSpace, "acme/app", hfmodels.TrustedPublisher{ID: "p2"})
	assert.Nil(t, bare["configuredBy"].Value)
	assert.Nil(t, bare["lastUsedAt"].Value)
	assert.Nil(t, bare["claims"].Value)
}

// Synthetic: access requests shaped after GET .../user-access-request/{status}
// in the Hub OpenAPI document; no live account was checked.
func TestAccessRequestArgs(t *testing.T) {
	req := hfmodels.AccessRequest{
		RequestID: "r1", Status: "accepted",
		User:       &hfmodels.AccessRequestUser{User: "alice"},
		GrantedBy:  &hfmodels.AccessRequestUser{User: "bob"},
		Timestamp:  "2026-01-01T00:00:00.000Z",
		ReviewedAt: "2026-01-02T00:00:00.000Z",
	}
	args := accessRequestArgs(hfmodels.RepoTypeModel, "acme/llm", req)
	assert.Equal(t, "alice", args["user"].Value)
	assert.Equal(t, "bob", args["grantedBy"].Value)
	assert.Equal(t, "accepted", args["status"].Value)
	assert.Equal(t, new(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), args["requestedAt"].Value)
	assert.Equal(t, new(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)), args["reviewedAt"].Value)

	// A hidden requester profile and an empty grantor object both stay null.
	hidden := accessRequestArgs(hfmodels.RepoTypeModel, "acme/llm", hfmodels.AccessRequest{
		RequestID: "r2", Status: "accepted", GrantedBy: &hfmodels.AccessRequestUser{},
	})
	assert.Nil(t, hidden["user"].Value)
	assert.Nil(t, hidden["grantedBy"].Value)
	assert.Nil(t, hidden["reviewedAt"].Value)

	assert.NotEqual(t, args["__id"].Value, accessRequestArgs(hfmodels.RepoTypeDataset, "acme/llm", req)["__id"].Value)
}

// Synthetic: an ungated repository; no live account was checked. It has no
// requests to review, so the list is empty without any request being made
// (the nil runtime would panic on one).
func TestFetchAccessRequestsUngated(t *testing.T) {
	res, err := fetchAccessRequests(nil, hfmodels.RepoTypeModel, "acme/llm", false)
	require.NoError(t, err)
	assert.Empty(t, res)
}

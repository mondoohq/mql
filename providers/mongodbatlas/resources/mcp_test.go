// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

func TestMcpUnavailable(t *testing.T) {
	// The stakes: when this returns true the accessor renders null, and when it
	// returns false the error propagates. What it must never do is let a
	// transport failure through as "feature not enabled", because the caller
	// turns that into a null field and an audit passes on data never read.
	tests := []struct {
		name string
		resp *http.Response
		want bool
	}{
		{"nil response is a transport error, not a feature answer", nil, false},
		{"403 means the credential cannot read MCP", &http.Response{StatusCode: http.StatusForbidden}, true},
		{"401 means the credential cannot read MCP", &http.Response{StatusCode: http.StatusUnauthorized}, true},
		{"404 means Remote MCP is not enabled", &http.Response{StatusCode: http.StatusNotFound}, true},
		{"200 is not an unavailable answer", &http.Response{StatusCode: http.StatusOK}, false},
		{"500 is a server fault the caller must see", &http.Response{StatusCode: http.StatusInternalServerError}, false},
		{"429 is throttling the caller must see", &http.Response{StatusCode: http.StatusTooManyRequests}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mcpUnavailable(tc.resp))
		})
	}
}

func TestServiceAccountAccessEntryMapsMcpIpAccessList(t *testing.T) {
	// The MCP configuration reuses the service account access list shape. If a
	// tag drifts, the source restriction reads as empty, which is exactly the
	// finding the field exists to report.
	created := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	lastUsed := time.Date(2026, 4, 2, 9, 30, 0, 0, time.UTC)

	got := serviceAccountAccessEntry(admin.ServiceAccountIPAccessListEntry{
		CidrBlock:       admin.PtrString("10.0.0.0/8"),
		IpAddress:       admin.PtrString("10.1.2.3"),
		CreatedAt:       &created,
		LastUsedAt:      &lastUsed,
		LastUsedAddress: admin.PtrString("10.1.2.3"),
		RequestCount:    admin.PtrInt(42),
	})

	assert.Equal(t, "10.0.0.0/8", got.cidrBlock)
	assert.Equal(t, "10.1.2.3", got.ipAddress)
	assert.Equal(t, "10.1.2.3", got.lastUsedAddress)
	assert.Equal(t, int64(42), got.requestCount)
	assert.Equal(t, &created, got.created)
	assert.Equal(t, &lastUsed, got.lastUsed)
}

func TestServiceAccountAccessEntryHandlesAbsentValues(t *testing.T) {
	// An entry restricted by CIDR carries no ipAddress and has never been used.
	// Those must stay empty and null rather than becoming a zero timestamp,
	// which would report 1 January year 1 as a real last-used date.
	got := serviceAccountAccessEntry(admin.ServiceAccountIPAccessListEntry{
		CidrBlock: admin.PtrString("192.168.0.0/16"),
	})

	assert.Equal(t, "192.168.0.0/16", got.cidrBlock)
	assert.Empty(t, got.ipAddress)
	assert.Zero(t, got.requestCount)
	assert.Nil(t, got.created)
	assert.Nil(t, got.lastUsed)
}

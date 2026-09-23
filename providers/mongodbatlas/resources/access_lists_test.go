// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

func TestApiKeyAccessEntry(t *testing.T) {
	created := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	lastUsed := time.Date(2026, 8, 10, 14, 30, 0, 0, time.UTC)

	got := apiKeyAccessEntry(admin.UserAccessListResponse{
		CidrBlock:       admin.PtrString("10.0.0.0/24"),
		IpAddress:       admin.PtrString("10.0.0.1"),
		Created:         &created,
		Count:           admin.PtrInt(42),
		LastUsed:        &lastUsed,
		LastUsedAddress: admin.PtrString("10.0.0.7"),
	})

	assert.Equal(t, "10.0.0.0/24", got.cidrBlock)
	assert.Equal(t, "10.0.0.1", got.ipAddress)
	require.NotNil(t, got.created)
	assert.Equal(t, created, *got.created)
	// The API key endpoint names the usage counter `count`; mistyping it here
	// would silently report every entry as never used.
	assert.Equal(t, int64(42), got.requestCount)
	require.NotNil(t, got.lastUsed)
	assert.Equal(t, lastUsed, *got.lastUsed)
	assert.Equal(t, "10.0.0.7", got.lastUsedAddress)
}

func TestApiKeyAccessEntryUnused(t *testing.T) {
	// An entry that has never authenticated reports no last-used time. It must
	// stay null rather than becoming the zero time, which would render as a
	// real date in year 1 and read as "used long ago".
	got := apiKeyAccessEntry(admin.UserAccessListResponse{
		CidrBlock: admin.PtrString("192.168.1.0/24"),
	})

	assert.Equal(t, "192.168.1.0/24", got.cidrBlock)
	assert.Empty(t, got.ipAddress)
	assert.Nil(t, got.created, "an absent creation time stays null")
	assert.Zero(t, got.requestCount)
	assert.Nil(t, got.lastUsed, "an unused entry reports no last-used time")
	assert.Empty(t, got.lastUsedAddress)
}

func TestServiceAccountAccessEntry(t *testing.T) {
	created := time.Date(2026, 1, 15, 8, 0, 0, 0, time.UTC)
	lastUsed := time.Date(2026, 8, 11, 11, 45, 0, 0, time.UTC)

	got := serviceAccountAccessEntry(admin.ServiceAccountIPAccessListEntry{
		CidrBlock:       admin.PtrString("172.16.0.0/16"),
		IpAddress:       admin.PtrString("172.16.4.9"),
		CreatedAt:       &created,
		RequestCount:    admin.PtrInt(7),
		LastUsedAt:      &lastUsed,
		LastUsedAddress: admin.PtrString("172.16.4.9"),
	})

	assert.Equal(t, "172.16.0.0/16", got.cidrBlock)
	assert.Equal(t, "172.16.4.9", got.ipAddress)
	require.NotNil(t, got.created)
	assert.Equal(t, created, *got.created)
	// The service account endpoint names the same counter `requestCount` and
	// the timestamps `createdAt`/`lastUsedAt`. Both shapes must normalize to
	// the identical resource fields or a query cannot span both credentials.
	assert.Equal(t, int64(7), got.requestCount)
	require.NotNil(t, got.lastUsed)
	assert.Equal(t, lastUsed, *got.lastUsed)
	assert.Equal(t, "172.16.4.9", got.lastUsedAddress)
}

func TestServiceAccountAccessEntryUnused(t *testing.T) {
	got := serviceAccountAccessEntry(admin.ServiceAccountIPAccessListEntry{
		IpAddress: admin.PtrString("203.0.113.5"),
	})

	assert.Empty(t, got.cidrBlock)
	assert.Equal(t, "203.0.113.5", got.ipAddress)
	assert.Nil(t, got.created)
	assert.Zero(t, got.requestCount)
	assert.Nil(t, got.lastUsed)
}

func TestAccessListEntryID(t *testing.T) {
	tests := []struct {
		name  string
		entry apiAccessListEntry
		want  string
	}{
		{
			name:  "cidr block keys the entry",
			entry: apiAccessListEntry{cidrBlock: "10.0.0.0/24", ipAddress: "10.0.0.1"},
			want:  "mongodbatlas.apiAccessListEntry/apiKey/abc123/10.0.0.0/24",
		},
		{
			name:  "address is the fallback when no cidr is reported",
			entry: apiAccessListEntry{ipAddress: "203.0.113.5"},
			want:  "mongodbatlas.apiAccessListEntry/apiKey/abc123/203.0.113.5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, accessListEntryID("apiKey/abc123", tt.entry))
		})
	}
}

func TestAccessListEntryIDIsParentScoped(t *testing.T) {
	// The same CIDR may be allowed for several credentials. The parent segment
	// keeps those distinct, so one entry does not alias another in the cache.
	entry := apiAccessListEntry{cidrBlock: "10.0.0.0/24"}

	key := accessListEntryID("apiKey/abc123", entry)
	other := accessListEntryID("serviceAccount/mdb_sa_id_xyz", entry)

	assert.NotEqual(t, key, other)
}

func TestLabelMap(t *testing.T) {
	assert.Equal(t, map[string]any{}, labelMap(nil))
	assert.Equal(t, map[string]any{}, labelMap([]admin.ComponentLabel{}))

	assert.Equal(t, map[string]any{"team": "payments", "tier": "prod"}, labelMap([]admin.ComponentLabel{
		{Key: admin.PtrString("team"), Value: admin.PtrString("payments")},
		{Key: admin.PtrString("tier"), Value: admin.PtrString("prod")},
	}))

	assert.Equal(t, map[string]any{"team": "platform"}, labelMap([]admin.ComponentLabel{
		{Key: admin.PtrString("team"), Value: admin.PtrString("payments")},
		{Key: admin.PtrString("team"), Value: admin.PtrString("platform")},
	}), "a later label wins on a duplicate key")

	assert.Equal(t, map[string]any{"": ""}, labelMap([]admin.ComponentLabel{{}}),
		"labels are pointer fields, so an absent key or value must not panic")
}

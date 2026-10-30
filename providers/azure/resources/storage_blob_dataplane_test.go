// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	storage "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestBlobServiceDataPlaneSettings(t *testing.T) {
	t.Run("absent blob properties report null, not a clean bill of health", func(t *testing.T) {
		args := blobServiceDataPlaneSettings(nil).rawData()
		assert.Equal(t, llx.NilData, args["changeFeedEnabled"])
		assert.Equal(t, llx.NilData, args["restorePolicyEnabled"])
		assert.Equal(t, llx.NilData, args["lastAccessTimeTrackingEnabled"])
		assert.Equal(t, llx.NilData, args["defaultServiceVersion"])
		assert.Equal(t, []any{}, args["corsAllowedOrigins"].Value)
	})

	t.Run("present properties with every sub-block omitted mean the features are off", func(t *testing.T) {
		args := blobServiceDataPlaneSettings(&storage.BlobServicePropertiesProperties{}).rawData()
		assert.Equal(t, false, args["changeFeedEnabled"].Value)
		assert.Equal(t, false, args["restorePolicyEnabled"].Value)
		assert.Equal(t, false, args["lastAccessTimeTrackingEnabled"].Value)
		// No retention to report while the features are off.
		assert.Equal(t, llx.NilData, args["changeFeedRetentionInDays"])
		assert.Equal(t, llx.NilData, args["restorePolicyDays"])
		assert.Equal(t, llx.NilData, args["restorePolicyMinRestoreTime"])
	})

	t.Run("a wildcard cors origin is collected across rules", func(t *testing.T) {
		star := "*"
		site := "https://app.example.com"
		blank := ""
		props := &storage.BlobServicePropertiesProperties{
			Cors: &storage.CorsRules{CorsRules: []*storage.CorsRule{
				nil,
				{AllowedOrigins: []*string{&site, nil, &blank}},
				{AllowedOrigins: []*string{&star}},
			}},
		}
		args := blobServiceDataPlaneSettings(props).rawData()
		assert.Equal(t, []any{site, star}, args["corsAllowedOrigins"].Value)
	})

	t.Run("change feed enabled with a retention window", func(t *testing.T) {
		yes := true
		days := int32(90)
		props := &storage.BlobServicePropertiesProperties{
			ChangeFeed: &storage.ChangeFeed{Enabled: &yes, RetentionInDays: &days},
		}
		args := blobServiceDataPlaneSettings(props).rawData()
		assert.Equal(t, true, args["changeFeedEnabled"].Value)
		assert.Equal(t, int64(90), args["changeFeedRetentionInDays"].Value)
	})

	t.Run("change feed enabled with no retention window stays null, meaning kept forever", func(t *testing.T) {
		yes := true
		props := &storage.BlobServicePropertiesProperties{
			ChangeFeed: &storage.ChangeFeed{Enabled: &yes},
		}
		args := blobServiceDataPlaneSettings(props).rawData()
		assert.Equal(t, true, args["changeFeedEnabled"].Value)
		assert.Equal(t, llx.NilData, args["changeFeedRetentionInDays"])
	})

	t.Run("a disabled change feed does not carry a stale retention value", func(t *testing.T) {
		no := false
		days := int32(7)
		props := &storage.BlobServicePropertiesProperties{
			ChangeFeed: &storage.ChangeFeed{Enabled: &no, RetentionInDays: &days},
		}
		args := blobServiceDataPlaneSettings(props).rawData()
		assert.Equal(t, false, args["changeFeedEnabled"].Value)
		assert.Equal(t, llx.NilData, args["changeFeedRetentionInDays"])
	})

	t.Run("point in time restore", func(t *testing.T) {
		yes := true
		days := int32(6)
		minRestore := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
		version := "2021-04-10"
		props := &storage.BlobServicePropertiesProperties{
			RestorePolicy:         &storage.RestorePolicyProperties{Enabled: &yes, Days: &days, MinRestoreTime: &minRestore},
			DefaultServiceVersion: &version,
		}
		args := blobServiceDataPlaneSettings(props).rawData()
		assert.Equal(t, true, args["restorePolicyEnabled"].Value)
		assert.Equal(t, int64(6), args["restorePolicyDays"].Value)
		require.NotEqual(t, llx.NilData, args["restorePolicyMinRestoreTime"])
		assert.Equal(t, "2021-04-10", args["defaultServiceVersion"].Value)
	})

	t.Run("a disabled restore policy leaves the timestamp null rather than the zero time", func(t *testing.T) {
		no := false
		zero := time.Time{}
		props := &storage.BlobServicePropertiesProperties{
			RestorePolicy: &storage.RestorePolicyProperties{Enabled: &no, MinRestoreTime: &zero},
		}
		args := blobServiceDataPlaneSettings(props).rawData()
		assert.Equal(t, llx.NilData, args["restorePolicyMinRestoreTime"])
	})

	t.Run("last access time tracking", func(t *testing.T) {
		yes := true
		props := &storage.BlobServicePropertiesProperties{
			LastAccessTimeTrackingPolicy: &storage.LastAccessTimeTrackingPolicy{Enable: &yes},
		}
		args := blobServiceDataPlaneSettings(props).rawData()
		assert.Equal(t, true, args["lastAccessTimeTrackingEnabled"].Value)
	})
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package recording

import (
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestLoadRecording(t *testing.T) {
	record, err := LoadRecordingFile("testdata/recording.json")
	assert.NoError(t, err)
	assert.NotNil(t, record)
}

// TestSaveWhileAddingData reproduces the data race that crashes a parallel scan:
// a shared recording is saved (which finalizes every asset by iterating its
// `resources` map) while another goroutine is still fetching data for that asset
// via AddData (which writes to the same map). Without synchronization this panics
// with "index out of range" in finalize() or "concurrent map ... write", and the
// race detector flags it. See providers-sdk/v1/recording/asset_recording.go.
func TestSaveWhileAddingData(t *testing.T) {
	r := newTestRecording(t, "test-asset-race", []string{"pid-race"}, 1)
	r.doNotSave = true // exercise finalize() without touching the filesystem
	lookup := llx.AssetRecordingLookup{Mrn: "test-asset-race"}

	const iterations = 20000
	var wg sync.WaitGroup

	// Writer 1: keeps inserting distinct resources, growing asset.resources.
	// This races finalize()'s iteration of that map.
	wg.Go(func() {
		for i := range iterations {
			r.AddData(llx.AddDataReq{
				ConnectionID:      1,
				Resource:          "aws.ec2.instance",
				ResourceID:        strconv.Itoa(i),
				RequestResourceId: strconv.Itoa(i),
				Field:             "name",
				Data:              llx.StringData("instance"),
			})
		}
	})

	// Writer 2: repeatedly writes fields on a single "hot" resource, mutating
	// its Fields map. This races the reader goroutine's Fields access.
	wg.Go(func() {
		for i := range iterations {
			r.AddData(llx.AddDataReq{
				ConnectionID:      1,
				Resource:          "aws.ec2.instance",
				ResourceID:        "hot",
				RequestResourceId: "hot",
				Field:             strconv.Itoa(i % 64),
				Data:              llx.StringData("v"),
			})
		}
	})

	// Reader: finalizes the recording repeatedly, iterating the resources map.
	wg.Go(func() {
		for range iterations / 10 {
			assert.NoError(t, r.Save())
		}
	})

	// Reader: exercises the data-read paths, which access Resource.Fields while
	// Writer 2 mutates it. GetResource must hand back a safe snapshot.
	wg.Go(func() {
		for i := range iterations {
			r.GetData(lookup, "aws.ec2.instance", "hot", strconv.Itoa(i%64))
			if fields, ok := r.GetResource(lookup, "aws.ec2.instance", "hot"); ok {
				for range fields { // iterate the returned map; must be a safe snapshot
				}
			}
		}
	})

	wg.Wait()
}

// newTestRecording creates a fresh recording and ensures an asset with the given
// MRN, platform IDs, and connection ID.
func newTestRecording(t *testing.T, mrn string, platformIds []string, connID uint32) *recording {
	t.Helper()
	r := &recording{
		Assets: []*Asset{},
	}
	r.refreshCache()

	asset := &inventory.Asset{
		Mrn:         mrn,
		PlatformIds: platformIds,
		Platform:    &inventory.Platform{},
	}
	conf := &inventory.Config{
		Type: "local",
		Id:   connID,
	}
	r.EnsureAsset(asset, "provider", connID, conf)
	return r
}

func TestAddAndGetData(t *testing.T) {
	t.Run("adds data for existing asset", func(t *testing.T) {
		r := newTestRecording(t, "test-asset-1", []string{"pid-1"}, 1)

		// Add data for a new resource
		req := llx.AddDataReq{
			ConnectionID:      1,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-12345",
			RequestResourceId: "i-12345",
			Field:             "name",
			Data:              llx.StringData("test-instance"),
		}
		r.AddData(req)

		// Verify the resource was created
		resourceKey := "aws.ec2.instance\x1ei-12345"
		res, exists := r.Assets[0].resources[resourceKey]
		assert.True(t, exists)
		assert.Equal(t, "aws.ec2.instance", res.Resource)
		assert.Equal(t, "i-12345", res.ID)
		assert.NotNil(t, res.Fields["name"])
		assert.Equal(t, "test-instance", res.Fields["name"].Value)

		// Verify GetData retrieves the field correctly
		data, ok := r.GetData(llx.AssetRecordingLookup{ConnectionId: 1}, "aws.ec2.instance", "i-12345", "name")
		assert.True(t, ok)
		assert.Equal(t, "test-instance", data.Value)

		// Verify GetData retrieves the resource id when the field is empty
		data, ok = r.GetData(llx.AssetRecordingLookup{ConnectionId: 1}, "aws.ec2.instance", "i-12345", "")
		assert.True(t, ok)
		assert.Equal(t, "i-12345", data.Value)
	})

	t.Run("adds data to existing resource", func(t *testing.T) {
		r := newTestRecording(t, "test-asset-2", []string{"pid-2"}, 2)

		// Add initial field
		req1 := llx.AddDataReq{
			ConnectionID:      2,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-67890",
			RequestResourceId: "i-67890",
			Field:             "name",
			Data:              llx.StringData("instance-1"),
		}
		r.AddData(req1)

		// Add another field to the same resource
		req2 := llx.AddDataReq{
			ConnectionID:      2,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-67890",
			RequestResourceId: "i-67890",
			Field:             "state",
			Data:              llx.StringData("running"),
		}
		r.AddData(req2)

		// Verify both fields exist
		resourceKey := "aws.ec2.instance\x1ei-67890"
		res, exists := r.Assets[0].resources[resourceKey]
		assert.True(t, exists)
		assert.Equal(t, 2, len(res.Fields))
		assert.Equal(t, "instance-1", res.Fields["name"].Value)
		assert.Equal(t, "running", res.Fields["state"].Value)

		// Verify GetData retrieves both fields correctly
		nameData, ok := r.GetData(llx.AssetRecordingLookup{ConnectionId: 2}, "aws.ec2.instance", "i-67890", "name")
		assert.True(t, ok)
		assert.Equal(t, "instance-1", nameData.Value)

		stateData, ok := r.GetData(llx.AssetRecordingLookup{ConnectionId: 2}, "aws.ec2.instance", "i-67890", "state")
		assert.True(t, ok)
		assert.Equal(t, "running", stateData.Value)
	})

	t.Run("adds request resource id to the lookup map when the request and response resource ids differ", func(t *testing.T) {
		r := newTestRecording(t, "test-asset-3", []string{"pid-3"}, 3)

		// Add data where the request ID differs from the actual ID
		req := llx.AddDataReq{
			ConnectionID:      3,
			Resource:          "aws.ec2.instance",
			ResourceID:        "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
			RequestResourceId: "",
			Field:             "name",
			Data:              llx.StringData("test-instance"),
		}
		r.AddData(req)

		lookupKey := "aws.ec2.instance\x1e"
		actualID, exists := r.Assets[0].IdsLookup[lookupKey]
		assert.True(t, exists)
		assert.Equal(t, "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", actualID)

		data, ok := r.GetData(llx.AssetRecordingLookup{ConnectionId: 3}, "aws.ec2.instance", "", "name")
		assert.True(t, ok)
		assert.Equal(t, "test-instance", data.Value)
	})

	t.Run("does not add the resource id to the lookup map when both ids are equal", func(t *testing.T) {
		r := newTestRecording(t, "test-asset-4", []string{"pid-4"}, 4)

		req := llx.AddDataReq{
			ConnectionID:      4,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-xyz789",
			RequestResourceId: "i-xyz789",
			Field:             "name",
			Data:              llx.StringData("same-id-instance"),
		}
		r.AddData(req)

		// Verify IdsLookup was not updated
		_, exists := r.Assets[0].IdsLookup["i-xyz789"]
		assert.False(t, exists)
		assert.Equal(t, 0, len(r.Assets[0].IdsLookup))

		// Verify GetData retrieves the data using the resource ID
		data, ok := r.GetData(llx.AssetRecordingLookup{ConnectionId: 4}, "aws.ec2.instance", "i-xyz789", "name")
		assert.True(t, ok)
		assert.Equal(t, "same-id-instance", data.Value)
	})

	t.Run("ignores data when connection id not found", func(t *testing.T) {
		r := newTestRecording(t, "test-asset-5", []string{"pid-5"}, 5)

		// Add data for a non-existent connection
		req := llx.AddDataReq{
			ConnectionID:      999,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-should-not-exist",
			RequestResourceId: "i-should-not-exist",
			Field:             "name",
			Data:              llx.StringData("ghost-instance"),
		}
		r.AddData(req)

		// Verify no resource was created
		assert.Equal(t, 0, len(r.Assets[0].resources))

		// Verify GetData returns false for non-existent connection
		data, ok := r.GetData(llx.AssetRecordingLookup{ConnectionId: 999}, "aws.ec2.instance", "i-should-not-exist", "name")
		assert.False(t, ok)
		assert.Nil(t, data)
	})

	t.Run("adds data without a field", func(t *testing.T) {
		r := newTestRecording(t, "test-asset-6", []string{"pid-6"}, 6)

		req := llx.AddDataReq{
			ConnectionID:      6,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-field-test",
			RequestResourceId: "i-field-test",
			Field:             "",
			Data:              nil,
		}
		r.AddData(req)

		// Verify resource exists but has no fields
		resourceKey := "aws.ec2.instance\x1ei-field-test"
		res, exists := r.Assets[0].resources[resourceKey]
		assert.True(t, exists)
		assert.Equal(t, "aws.ec2.instance", res.Resource)
		assert.Equal(t, "i-field-test", res.ID)
		assert.Equal(t, 0, len(res.Fields))

		// Verify GetData with empty field returns the resource id
		data, ok := r.GetData(llx.AssetRecordingLookup{ConnectionId: 6}, "aws.ec2.instance", "i-field-test", "")
		assert.True(t, ok)
		assert.Equal(t, "i-field-test", data.Value)

		// Verify GetData for "id" field returns false when the field was never stored.
		// The recording must not conflate the resource identifier (resolvedID) with a
		// user-defined "id" field, since they may have different types.
		data, ok = r.GetData(llx.AssetRecordingLookup{ConnectionId: 6}, "aws.ec2.instance", "i-field-test", "id")
		assert.False(t, ok)
		assert.Nil(t, data)
	})

	t.Run("overwrites field data when added multiple times", func(t *testing.T) {
		r := newTestRecording(t, "test-asset-7", []string{"pid-7"}, 7)

		// Add initial field value
		req1 := llx.AddDataReq{
			ConnectionID:      7,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-overwrite",
			RequestResourceId: "i-overwrite",
			Field:             "state",
			Data:              llx.StringData("pending"),
		}
		r.AddData(req1)

		// Verify initial value via GetData
		data, ok := r.GetData(llx.AssetRecordingLookup{ConnectionId: 7}, "aws.ec2.instance", "i-overwrite", "state")
		assert.True(t, ok)
		assert.Equal(t, "pending", data.Value)

		// Overwrite the same field
		req2 := llx.AddDataReq{
			ConnectionID:      7,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-overwrite",
			RequestResourceId: "i-overwrite",
			Field:             "state",
			Data:              llx.StringData("running"),
		}
		r.AddData(req2)

		// Verify the field was overwritten
		resourceKey := "aws.ec2.instance\x1ei-overwrite"
		res, exists := r.Assets[0].resources[resourceKey]
		assert.True(t, exists)
		assert.Equal(t, 1, len(res.Fields))
		assert.Equal(t, "running", res.Fields["state"].Value)

		// Verify GetData retrieves the updated value
		data, ok = r.GetData(llx.AssetRecordingLookup{ConnectionId: 7}, "aws.ec2.instance", "i-overwrite", "state")
		assert.True(t, ok)
		assert.Equal(t, "running", data.Value)
	})

	t.Run("add multiple resources for the same asset", func(t *testing.T) {
		r := newTestRecording(t, "test-asset-8", []string{"pid-8"}, 8)

		// Add multiple resources
		req1 := llx.AddDataReq{
			ConnectionID:      8,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-multi-1",
			RequestResourceId: "i-multi-1",
			Field:             "name",
			Data:              llx.StringData("instance-1"),
		}
		r.AddData(req1)

		req2 := llx.AddDataReq{
			ConnectionID:      8,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-multi-2",
			RequestResourceId: "i-multi-2",
			Field:             "name",
			Data:              llx.StringData("instance-2"),
		}
		r.AddData(req2)

		req3 := llx.AddDataReq{
			ConnectionID:      8,
			Resource:          "aws.s3.bucket",
			ResourceID:        "bucket-1",
			RequestResourceId: "bucket-1",
			Field:             "name",
			Data:              llx.StringData("my-bucket"),
		}
		r.AddData(req3)

		// Verify all resources exist
		assert.Equal(t, 3, len(r.Assets[0].resources))

		res1, exists := r.Assets[0].resources["aws.ec2.instance\x1ei-multi-1"]
		assert.True(t, exists)
		assert.Equal(t, "instance-1", res1.Fields["name"].Value)

		res2, exists := r.Assets[0].resources["aws.ec2.instance\x1ei-multi-2"]
		assert.True(t, exists)
		assert.Equal(t, "instance-2", res2.Fields["name"].Value)

		res3, exists := r.Assets[0].resources["aws.s3.bucket\x1ebucket-1"]
		assert.True(t, exists)
		assert.Equal(t, "my-bucket", res3.Fields["name"].Value)

		// Verify GetData retrieves all resources correctly
		data1, ok := r.GetData(llx.AssetRecordingLookup{ConnectionId: 8}, "aws.ec2.instance", "i-multi-1", "name")
		assert.True(t, ok)
		assert.Equal(t, "instance-1", data1.Value)

		data2, ok := r.GetData(llx.AssetRecordingLookup{ConnectionId: 8}, "aws.ec2.instance", "i-multi-2", "name")
		assert.True(t, ok)
		assert.Equal(t, "instance-2", data2.Value)

		data3, ok := r.GetData(llx.AssetRecordingLookup{ConnectionId: 8}, "aws.s3.bucket", "bucket-1", "name")
		assert.True(t, ok)
		assert.Equal(t, "my-bucket", data3.Value)
	})
}

func TestGetDataLookupTypes(t *testing.T) {
	setup := func(t *testing.T) *recording {
		t.Helper()
		r := newTestRecording(t, "test-mrn", []string{"pid-1", "pid-2"}, 10)

		req := llx.AddDataReq{
			ConnectionID:      10,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-lookup",
			RequestResourceId: "i-lookup",
			Field:             "name",
			Data:              llx.StringData("lookup-instance"),
		}
		r.AddData(req)

		return r
	}

	t.Run("GetData by MRN", func(t *testing.T) {
		r := setup(t)
		data, ok := r.GetData(llx.AssetRecordingLookup{Mrn: "test-mrn"}, "aws.ec2.instance", "i-lookup", "name")
		assert.True(t, ok)
		assert.Equal(t, "lookup-instance", data.Value)
	})

	t.Run("GetData by platform ID", func(t *testing.T) {
		r := setup(t)
		data, ok := r.GetData(llx.AssetRecordingLookup{PlatformIds: []string{"pid-1"}}, "aws.ec2.instance", "i-lookup", "name")
		assert.True(t, ok)
		assert.Equal(t, "lookup-instance", data.Value)
	})

	t.Run("GetData by second platform ID", func(t *testing.T) {
		r := setup(t)
		data, ok := r.GetData(llx.AssetRecordingLookup{PlatformIds: []string{"pid-2"}}, "aws.ec2.instance", "i-lookup", "name")
		assert.True(t, ok)
		assert.Equal(t, "lookup-instance", data.Value)
	})

	t.Run("GetData by connection ID", func(t *testing.T) {
		r := setup(t)
		data, ok := r.GetData(llx.AssetRecordingLookup{ConnectionId: 10}, "aws.ec2.instance", "i-lookup", "name")
		assert.True(t, ok)
		assert.Equal(t, "lookup-instance", data.Value)
	})

	t.Run("GetData prefers MRN over platform IDs and connection ID", func(t *testing.T) {
		r := setup(t)
		// All three are set but MRN should be used
		data, ok := r.GetData(llx.AssetRecordingLookup{
			Mrn:          "test-mrn",
			PlatformIds:  []string{"pid-1"},
			ConnectionId: 10,
		}, "aws.ec2.instance", "i-lookup", "name")
		assert.True(t, ok)
		assert.Equal(t, "lookup-instance", data.Value)
	})

	t.Run("GetData falls back to platform ID when MRN not found", func(t *testing.T) {
		r := setup(t)
		data, ok := r.GetData(llx.AssetRecordingLookup{
			Mrn:         "nonexistent-mrn",
			PlatformIds: []string{"pid-1"},
		}, "aws.ec2.instance", "i-lookup", "name")
		assert.True(t, ok)
		assert.Equal(t, "lookup-instance", data.Value)
	})

	t.Run("GetData falls back to connection ID when MRN and platform IDs not found", func(t *testing.T) {
		r := setup(t)
		data, ok := r.GetData(llx.AssetRecordingLookup{
			Mrn:          "nonexistent-mrn",
			PlatformIds:  []string{"nonexistent-pid"},
			ConnectionId: 10,
		}, "aws.ec2.instance", "i-lookup", "name")
		assert.True(t, ok)
		assert.Equal(t, "lookup-instance", data.Value)
	})

	t.Run("GetData returns false when nothing matches", func(t *testing.T) {
		r := setup(t)
		data, ok := r.GetData(llx.AssetRecordingLookup{
			Mrn:          "nonexistent-mrn",
			PlatformIds:  []string{"nonexistent-pid"},
			ConnectionId: 999,
		}, "aws.ec2.instance", "i-lookup", "name")
		assert.False(t, ok)
		assert.Nil(t, data)
	})
}

func TestGetAssetData(t *testing.T) {
	t.Run("returns false when asset MRN not found", func(t *testing.T) {
		r := newTestRecording(t, "test-mrn", []string{"pid-1"}, 1)

		data, ok := r.GetAssetData("nonexistent-mrn")
		assert.False(t, ok)
		assert.Nil(t, data)
	})

	t.Run("returns asset data with resource recordings", func(t *testing.T) {
		r := newTestRecording(t, "test-mrn", []string{"pid-1"}, 1)

		// Add a resource with fields
		req := llx.AddDataReq{
			ConnectionID:      1,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-12345",
			RequestResourceId: "i-12345",
			Field:             "name",
			Data:              llx.StringData("test-instance"),
		}
		r.AddData(req)

		data, ok := r.GetAssetData("test-mrn")
		assert.True(t, ok)

		// Verify the resource recording exists
		resourceKey := "aws.ec2.instance\x1ei-12345"
		rec, exists := data[resourceKey]
		assert.True(t, exists)
		assert.Equal(t, "aws.ec2.instance", rec.Resource)
		assert.Equal(t, "i-12345", rec.Id)
		assert.Equal(t, "test-instance", string(rec.Fields["name"].Data.Value))
	})

	t.Run("includes asset metadata", func(t *testing.T) {
		r := newTestRecording(t, "test-mrn", []string{"pid-1"}, 1)

		data, ok := r.GetAssetData("test-mrn")
		assert.True(t, ok)

		// Verify asset metadata is included
		assetKey := "asset\x1e"
		rec, exists := data[assetKey]
		assert.True(t, exists)
		assert.Equal(t, "asset", rec.Resource)
		assert.Equal(t, "", rec.Id)
		// ensureAssetMetadata populates platform from asset.Name (empty in test setup)
		// and ids from asset.PlatformIds
		assert.Equal(t, "", string(rec.Fields["platform"].Data.Value))
		assert.Equal(t, 1, len(rec.Fields["ids"].Data.Array))
		assert.Equal(t, "pid-1", string(rec.Fields["ids"].Data.Array[0].Value))
	})

	t.Run("includes IdsLookup entries as internal lookup resources", func(t *testing.T) {
		r := newTestRecording(t, "test-mrn", []string{"pid-1"}, 1)

		// Add data where request ID differs from actual ID to create a lookup entry
		req := llx.AddDataReq{
			ConnectionID:      1,
			Resource:          "aws.ec2.instance",
			ResourceID:        "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
			RequestResourceId: "", // Empty request ID creates a lookup entry
			Field:             "name",
			Data:              llx.StringData("test-instance"),
		}
		r.AddData(req)

		data, ok := r.GetAssetData("test-mrn")
		assert.True(t, ok)

		// Verify the lookup entry is stored as an internal lookup resource
		lookupKey := "mql/internal-lookup-id\x1eaws.ec2.instance\x1e"
		rec, exists := data[lookupKey]
		assert.True(t, exists, "internal lookup resource should exist")
		assert.Equal(t, "mql/internal-lookup-id", rec.Resource)
		assert.Equal(t, "aws.ec2.instance\x1e", rec.Id)
		assert.Equal(t, "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", string(rec.Fields["value"].Data.Value))
	})

	t.Run("returns multiple resources for the same asset", func(t *testing.T) {
		r := newTestRecording(t, "test-mrn", []string{"pid-1"}, 1)

		// Add multiple resources
		r.AddData(llx.AddDataReq{
			ConnectionID:      1,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-1",
			RequestResourceId: "i-1",
			Field:             "name",
			Data:              llx.StringData("instance-1"),
		})
		r.AddData(llx.AddDataReq{
			ConnectionID:      1,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-2",
			RequestResourceId: "i-2",
			Field:             "name",
			Data:              llx.StringData("instance-2"),
		})
		r.AddData(llx.AddDataReq{
			ConnectionID:      1,
			Resource:          "aws.s3.bucket",
			ResourceID:        "my-bucket",
			RequestResourceId: "my-bucket",
			Field:             "name",
			Data:              llx.StringData("bucket-name"),
		})

		data, ok := r.GetAssetData("test-mrn")
		assert.True(t, ok)

		// Verify all resources are included (3 resources + 1 asset metadata)
		assert.Equal(t, 4, len(data))

		rec1, exists := data["aws.ec2.instance\x1ei-1"]
		assert.True(t, exists)
		assert.Equal(t, "instance-1", string(rec1.Fields["name"].Data.Value))

		rec2, exists := data["aws.ec2.instance\x1ei-2"]
		assert.True(t, exists)
		assert.Equal(t, "instance-2", string(rec2.Fields["name"].Data.Value))

		rec3, exists := data["aws.s3.bucket\x1emy-bucket"]
		assert.True(t, exists)
		assert.Equal(t, "bucket-name", string(rec3.Fields["name"].Data.Value))
	})

	t.Run("converts multiple fields per resource", func(t *testing.T) {
		r := newTestRecording(t, "test-mrn", []string{"pid-1"}, 1)

		// Add multiple fields to the same resource
		r.AddData(llx.AddDataReq{
			ConnectionID:      1,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-multi",
			RequestResourceId: "i-multi",
			Field:             "name",
			Data:              llx.StringData("my-instance"),
		})
		r.AddData(llx.AddDataReq{
			ConnectionID:      1,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-multi",
			RequestResourceId: "i-multi",
			Field:             "state",
			Data:              llx.StringData("running"),
		})

		data, ok := r.GetAssetData("test-mrn")
		assert.True(t, ok)

		rec, exists := data["aws.ec2.instance\x1ei-multi"]
		assert.True(t, exists)
		assert.Equal(t, 2, len(rec.Fields))
		assert.Equal(t, "my-instance", string(rec.Fields["name"].Data.Value))
		assert.Equal(t, "running", string(rec.Fields["state"].Data.Value))
	})
}

func TestGetResourceLookupTypes(t *testing.T) {
	setup := func(t *testing.T) *recording {
		t.Helper()
		r := newTestRecording(t, "test-mrn", []string{"pid-1"}, 10)

		req := llx.AddDataReq{
			ConnectionID:      10,
			Resource:          "aws.ec2.instance",
			ResourceID:        "i-res",
			RequestResourceId: "i-res",
			Field:             "state",
			Data:              llx.StringData("running"),
		}
		r.AddData(req)

		return r
	}

	t.Run("GetResource by MRN", func(t *testing.T) {
		r := setup(t)
		fields, ok := r.GetResource(llx.AssetRecordingLookup{Mrn: "test-mrn"}, "aws.ec2.instance", "i-res")
		assert.True(t, ok)
		assert.Equal(t, "running", fields["state"].Value)
	})

	t.Run("GetResource by platform ID", func(t *testing.T) {
		r := setup(t)
		fields, ok := r.GetResource(llx.AssetRecordingLookup{PlatformIds: []string{"pid-1"}}, "aws.ec2.instance", "i-res")
		assert.True(t, ok)
		assert.Equal(t, "running", fields["state"].Value)
	})

	t.Run("GetResource by connection ID", func(t *testing.T) {
		r := setup(t)
		fields, ok := r.GetResource(llx.AssetRecordingLookup{ConnectionId: 10}, "aws.ec2.instance", "i-res")
		assert.True(t, ok)
		assert.Equal(t, "running", fields["state"].Value)
	})

	t.Run("GetResource returns false when nothing matches", func(t *testing.T) {
		r := setup(t)
		fields, ok := r.GetResource(llx.AssetRecordingLookup{Mrn: "nonexistent"}, "aws.ec2.instance", "i-res")
		assert.False(t, ok)
		assert.Nil(t, fields)
	})
}

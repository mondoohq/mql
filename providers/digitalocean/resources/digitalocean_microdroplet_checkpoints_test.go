// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestMicroDropletCheckpointArgs_Decode(t *testing.T) {
	raw := `{
		"id": "cp-1",
		"microvm_id": "md-1",
		"microvm_name": "api",
		"name": "before-upgrade",
		"region": "nyc3",
		"size": {"cpu": 2, "memory": 4096, "disk": 50},
		"status": "CHECKPOINT_AVAILABLE",
		"memory_bytes": 1073741824,
		"disk_bytes": 2147483648,
		"created_at": "2026-05-01T10:00:00Z"
	}`
	var cp godo.MicroVMCheckpoint
	require.NoError(t, json.Unmarshal([]byte(raw), &cp))
	args, err := microDropletCheckpointArgs(&cp)
	require.NoError(t, err)

	assert.Equal(t, "digitalocean.microDroplet.checkpoint/cp-1", args["__id"].Value)
	assert.Equal(t, "before-upgrade", args["name"].Value)
	assert.Equal(t, "nyc3", args["region"].Value)
	assert.Equal(t, "CHECKPOINT_AVAILABLE", args["status"].Value)
	assert.Equal(t, "api", args["microDropletName"].Value)
	assert.Equal(t, int64(1073741824), args["memoryBytes"].Value)
	assert.Equal(t, int64(2147483648), args["diskBytes"].Value)
	assert.Equal(t, int64(2), args["vcpus"].Value)
	assert.Equal(t, int64(4096), args["memoryMib"].Value)
	assert.Equal(t, int64(50), args["diskGb"].Value)
	assert.NotNil(t, args["createdAt"].Value)
}

func TestMicroDropletCheckpointArgs_NoSize(t *testing.T) {
	// godo documents that a checkpoint may record no size.
	args, err := microDropletCheckpointArgs(&godo.MicroVMCheckpoint{ID: "cp-2"})
	require.NoError(t, err)
	assert.Nil(t, args["vcpus"].Value)
	assert.Nil(t, args["memoryMib"].Value)
	assert.Nil(t, args["diskGb"].Value)
	assert.Nil(t, args["createdAt"].Value)

	_, err = microDropletCheckpointArgs(&godo.MicroVMCheckpoint{})
	require.Error(t, err)
}

func TestListMicroVMCheckpoints_Paginates(t *testing.T) {
	var pages []string
	var client *godo.Client
	client = newTestGodoClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/microvms/checkpoints", r.URL.Path)
		// The account-wide list must not be narrowed to one instance.
		assert.Empty(t, r.URL.Query().Get("microvm_id"))
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "", "1":
			fmt.Fprintf(w, `{"checkpoints":[{"id":"cp-1"},{"id":"cp-2"}],"links":{"pages":{"next":"%sv2/microvms/checkpoints?page=2","last":"%sv2/microvms/checkpoints?page=2"}},"meta":{"total":3}}`, client.BaseURL, client.BaseURL)
		case "2":
			fmt.Fprintf(w, `{"checkpoints":[{"id":"cp-3"}],"links":{"pages":{"prev":"%sv2/microvms/checkpoints?page=1","first":"%sv2/microvms/checkpoints?page=1"}},"meta":{"total":3}}`, client.BaseURL, client.BaseURL)
		default:
			t.Fatalf("unexpected page %q", page)
		}
	})
	checkpoints, err := listMicroVMCheckpoints(context.Background(), client.MicroVMs)
	require.NoError(t, err)
	require.Len(t, checkpoints, 3)
	assert.Equal(t, "cp-3", checkpoints[2].ID)
	assert.Equal(t, 2, len(pages))
}

func newTestCheckpoint(id, microVMID string) *mqlDigitaloceanMicroDropletCheckpoint {
	cp := &mqlDigitaloceanMicroDropletCheckpoint{Id: plugin.TValue[string]{Data: id, State: plugin.StateIsSet}}
	cp.microVMID = microVMID
	return cp
}

func TestCheckpointsOf(t *testing.T) {
	a1 := newTestCheckpoint("cp-1", "md-a")
	b1 := newTestCheckpoint("cp-2", "md-b")
	a2 := newTestCheckpoint("cp-3", "md-a")
	orphan := newTestCheckpoint("cp-4", "")
	all := []any{a1, b1, a2, orphan}

	assert.Equal(t, []any{a1, a2}, checkpointsOf(all, "md-a"))
	assert.Equal(t, []any{b1}, checkpointsOf(all, "md-b"))
	assert.Equal(t, []any{}, checkpointsOf(all, "md-c"))
	// An instance with no id must not collect the checkpoints that record no source.
	assert.Equal(t, []any{}, checkpointsOf(all, ""))
}

func TestFindMicroDroplet(t *testing.T) {
	mk := func(id string) *mqlDigitaloceanMicroDroplet {
		return &mqlDigitaloceanMicroDroplet{Id: plugin.TValue[string]{Data: id, State: plugin.StateIsSet}}
	}
	a, b := mk("md-a"), mk("md-b")
	instances := []any{a, b}
	assert.Same(t, b, findMicroDroplet(instances, "md-b"))
	// A checkpoint whose instance was deleted finds nothing.
	assert.Nil(t, findMicroDroplet(instances, "md-gone"))
}

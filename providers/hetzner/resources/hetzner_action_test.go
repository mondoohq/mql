// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionResourceDicts(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, []any{}, actionResourceDicts(nil))
	})

	t.Run("renders id and type", func(t *testing.T) {
		got := actionResourceDicts([]*hcloud.ActionResource{
			{ID: 42, Type: hcloud.ActionResourceTypeServer},
			{ID: 7, Type: hcloud.ActionResourceTypeVolume},
		})
		assert.Equal(t, []any{
			map[string]any{"id": int64(42), "type": "server"},
			map[string]any{"id": int64(7), "type": "volume"},
		}, got)
	})

	// The dict-to-primitive converter only accepts int64. An int would fail
	// serialization at query time, long after this code ran.
	t.Run("ids are int64", func(t *testing.T) {
		got := actionResourceDicts([]*hcloud.ActionResource{{ID: 1, Type: hcloud.ActionResourceTypeZone}})
		require.Len(t, got, 1)
		entry := got[0].(map[string]any)
		_, ok := entry["id"].(int64)
		assert.True(t, ok, "id must be int64, got %T", entry["id"])
	})

	t.Run("skips nil entries", func(t *testing.T) {
		got := actionResourceDicts([]*hcloud.ActionResource{
			nil,
			{ID: 5, Type: hcloud.ActionResourceTypeFirewall},
		})
		assert.Equal(t, []any{map[string]any{"id": int64(5), "type": "firewall"}}, got)
	})
}

func TestActionsFrom(t *testing.T) {
	// A resource whose action endpoint 404s no longer exists, which is the
	// same "nothing to list" answer paginate gives a missing collection.
	t.Run("not found is an empty history", func(t *testing.T) {
		got, err := actionsFrom(nil, func() ([]*hcloud.Action, error) {
			return nil, hcloud.Error{Code: hcloud.ErrorCodeNotFound}
		})
		require.NoError(t, err)
		assert.Equal(t, []any{}, got)
	})

	// A denial establishes nothing about what was done to the resource.
	// Reporting it as an empty history would assert an audit trail that was
	// never read, and every check over it would pass.
	t.Run("denial propagates", func(t *testing.T) {
		_, err := actionsFrom(nil, func() ([]*hcloud.Action, error) {
			return nil, hcloud.Error{Code: hcloud.ErrorCodeForbidden}
		})
		assert.Error(t, err)
	})

	t.Run("transport error propagates", func(t *testing.T) {
		_, err := actionsFrom(nil, func() ([]*hcloud.Action, error) {
			return nil, errors.New("connection reset")
		})
		assert.Error(t, err)
	})

	t.Run("no actions is an empty list", func(t *testing.T) {
		got, err := actionsFrom(nil, func() ([]*hcloud.Action, error) {
			return nil, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []any{}, got)
	})
}

// The per-resource action clients are the only ones that still work:
// GET /actions has required an explicit ID list since 2025-01-30 and
// ActionClient.All is deprecated for that reason. This pins that every
// resource we expose an actions() accessor for really does carry one.
func TestPerResourceActionClientsExist(t *testing.T) {
	c := hcloud.NewClient(hcloud.WithToken("test"))

	assert.NotNil(t, c.Server.Action)
	assert.NotNil(t, c.Firewall.Action)
	assert.NotNil(t, c.LoadBalancer.Action)
	assert.NotNil(t, c.Volume.Action)
	assert.NotNil(t, c.Certificate.Action)
	assert.NotNil(t, c.Network.Action)
	assert.NotNil(t, c.PrimaryIP.Action)
	assert.NotNil(t, c.FloatingIP.Action)
	assert.NotNil(t, c.Image.Action)
	assert.NotNil(t, c.Zone.Action)
	assert.NotNil(t, c.StorageBox.Action)
}

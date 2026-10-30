// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/discovery"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func assetErr(name, msg string) *discovery.AssetWithError {
	return &discovery.AssetWithError{
		Asset: &inventory.Asset{Name: name},
		Err:   errors.New(msg),
	}
}

func TestNoUsableAssetsError(t *testing.T) {
	tests := []struct {
		name        string
		connected   int
		assetErrors []*discovery.AssetWithError
		expectErr   bool
		contains    []string
	}{
		{
			// the reported case: the only asset failed, the query loop had
			// nothing to iterate, and the command exited 0
			name:        "single asset failed",
			connected:   0,
			assetErrors: []*discovery.AssetWithError{assetErr("prod-db", "no authentication method defined")},
			expectErr:   true,
			contains:    []string{"could not connect to asset prod-db", "no authentication method defined"},
		},
		{
			name:      "every asset failed",
			connected: 0,
			assetErrors: []*discovery.AssetWithError{
				assetErr("web-1", "connection refused"),
				assetErr("web-2", "connection refused"),
			},
			expectErr: true,
			contains:  []string{"any of the 2 assets", "first failure on web-1", "connection refused"},
		},
		{
			// a root asset that fails before it is named still has to produce a
			// readable message rather than a dangling "asset "
			name:        "failed asset has no name",
			connected:   0,
			assetErrors: []*discovery.AssetWithError{assetErr("", "unable to create runtime")},
			expectErr:   true,
			contains:    []string{"<unnamed asset>", "unable to create runtime"},
		},
		{
			// partial failure stays non-fatal: assets that connected were
			// queried, and --exit-1-on-failure governs query result failures
			name:        "some assets connected despite failures",
			connected:   2,
			assetErrors: []*discovery.AssetWithError{assetErr("web-3", "connection refused")},
			expectErr:   false,
		},
		{
			name:      "everything connected",
			connected: 3,
			expectErr: false,
		},
		{
			// no assets and no errors is not a failure, e.g. a discovery filter
			// that legitimately matched nothing
			name:      "nothing to do",
			connected: 0,
			expectErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := noUsableAssetsError(test.connected, test.assetErrors)
			if !test.expectErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			for _, want := range test.contains {
				assert.Contains(t, err.Error(), want)
			}
		})
	}
}

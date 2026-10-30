// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package statutil

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// The stat scripts print the access time before the modification time.
// ModTime must come from the modification time; the fixtures were captured
// from a file whose access time was set months after its modification time.
func TestStatModTimeIsNotAccessTime(t *testing.T) {
	tests := []struct {
		fixture string
		mtime   int64
	}{
		// access time 1790755200
		{"./testdata/debian9.toml", 1768471200},
		// access time 1790780400
		{"./testdata/darwin.toml", 1768500000},
	}
	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			path, err := filepath.Abs(tc.fixture)
			require.NoError(t, err)
			p, err := mock.New(0, &inventory.Asset{}, mock.WithPath(path))
			require.NoError(t, err)

			fi, err := New(p).Stat("/tmp/mtime-probe")
			require.NoError(t, err)
			assert.Equal(t, time.Unix(tc.mtime, 0), fi.ModTime())
			assert.Equal(t, int64(3), fi.Size())
		})
	}
}

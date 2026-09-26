// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package platformid

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestMacOSMachineId(t *testing.T) {
	filepath, _ := filepath.Abs("./testdata/osx_test.toml")
	provider, err := mock.New(0, &inventory.Asset{}, mock.WithPath(filepath))
	require.NoError(t, err)

	lid := MacOSIdProvider{connection: provider}
	id, err := lid.ID()
	require.NoError(t, err)

	assert.Equal(t, "5c09e2c7-07f2-5bee-be82-7cb70688e55c", id, "machine id is properly detected")
}

func TestMacOSMachineIdNonZeroExit(t *testing.T) {
	filepath, _ := filepath.Abs("./testdata/osx_nonzero_exit.toml")
	provider, err := mock.New(0, &inventory.Asset{}, mock.WithPath(filepath))
	require.NoError(t, err)

	lid := MacOSIdProvider{connection: provider}
	id, err := lid.ID()

	// a non-zero ioreg exit must surface as an error, not a silent empty id
	// that callers would mistake for a valid (blank) machine id
	require.Error(t, err)
	assert.Empty(t, id)
}

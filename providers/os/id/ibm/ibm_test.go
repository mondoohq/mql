// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ibm_test

import (
	"testing"

	subject "go.mondoo.com/mql/providers/os/id/ibm"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
)

func TestDetectLinuxInstance(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/instance_linux.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	identifier, name, relatedIdentifiers := subject.Detect(conn, platform)

	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/ibm/compute/v1/accounts/bbb1e1386b1c419f929ecf7499b20ab6/location/us-east-2/instances/0767_596409db-cb61-4d33-9550-6b86b503ed12",
		identifier,
	)
	assert.Equal(t, "salim-test", name)
	require.Len(t, relatedIdentifiers, 1)
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/ibm/compute/v1/accounts/bbb1e1386b1c419f929ecf7499b20ab6",
		relatedIdentifiers[0],
	)
}

func TestDetectAIXInstance(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/instance_unix_aix.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	identifier, name, relatedIdentifiers := subject.Detect(conn, platform)

	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/ibm/compute/v1/accounts/bbb1e1386b1c419f929ecf7499b20ab6/location/us-east-2/instances/0767_596409db-cb61-4d33-9550-6b86b503ed12",
		identifier,
	)
	assert.Equal(t, "salim-test", name)
	require.Len(t, relatedIdentifiers, 1)
	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/ibm/compute/v1/accounts/bbb1e1386b1c419f929ecf7499b20ab6",
		relatedIdentifiers[0],
	)
}

func TestDetectInstanceWithoutMetadataService(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/instance_no_metadata.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	// If the metadata service in the IBM cloud instance is not turned on, we can't detect much

	identifier, name, relatedIdentifiers := subject.Detect(conn, platform)
	assert.Empty(t, identifier)
	assert.Empty(t, name)
	require.Empty(t, relatedIdentifiers)
}

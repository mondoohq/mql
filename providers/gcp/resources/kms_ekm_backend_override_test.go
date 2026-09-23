// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func ekmConn(path string) *mqlGcpProjectKmsServiceEkmConnection {
	return &mqlGcpProjectKmsServiceEkmConnection{
		ResourcePath: plugin.TValue[string]{Data: path, State: plugin.StateIsSet},
		Name:         plugin.TValue[string]{Data: parseResourceName(path), State: plugin.StateIsSet},
	}
}

func TestEkmConnectionByResourcePath(t *testing.T) {
	euConn := ekmConn("projects/example-project/locations/europe-west1/ekmConnections/ekm-a")
	usConn := ekmConn("projects/example-project/locations/us-east1/ekmConnections/ekm-a")
	conns := []any{euConn, usConn}

	t.Run("matches the full resource path, not the short name", func(t *testing.T) {
		got := ekmConnectionByResourcePath(conns, "projects/example-project/locations/us-east1/ekmConnections/ekm-a")
		assert.Same(t, usConn, got)
	})

	t.Run("no match returns nil", func(t *testing.T) {
		assert.Nil(t, ekmConnectionByResourcePath(conns, "projects/example-project/locations/us-east1/ekmConnections/ekm-b"))
	})

	t.Run("a connection in another project does not match", func(t *testing.T) {
		assert.Nil(t, ekmConnectionByResourcePath(conns, "projects/other-project/locations/us-east1/ekmConnections/ekm-a"))
	})

	t.Run("empty list returns nil", func(t *testing.T) {
		assert.Nil(t, ekmConnectionByResourcePath(nil, "projects/example-project/locations/us-east1/ekmConnections/ekm-a"))
	})
}

func TestEkmConnectionBackendOverrideUnsetIsNull(t *testing.T) {
	opts := &mqlGcpProjectKmsServiceKeyringCryptokeyVersionExternalProtectionLevelOptions{}

	got, err := opts.ekmConnectionBackendOverride()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, opts.EkmConnectionBackendOverride.State)
}

func TestEkmConnectionBackendOverrideRejectsPathWithoutProject(t *testing.T) {
	opts := &mqlGcpProjectKmsServiceKeyringCryptokeyVersionExternalProtectionLevelOptions{}
	opts.cacheEkmConnectionBackendOverride = "locations/us-east1/ekmConnections/ekm-a"

	got, err := opts.ekmConnectionBackendOverride()
	assert.Error(t, err)
	assert.Nil(t, got)
}

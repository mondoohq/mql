// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection_test

import (
	"bytes"
	"os"
	"testing"

	"go.mondoo.com/mql/providers/gcp/connection"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGcloudConfig(t *testing.T) {
	data, err := os.ReadFile("./testdata/gcloud_config.json")
	require.NoError(t, err)

	config, err := connection.ParseGcloudConfig(bytes.NewReader(data))
	require.NoError(t, err)

	assert.Equal(t, "mondoo-abc-12345", config.Configuration.Properties.Core.Project)
}

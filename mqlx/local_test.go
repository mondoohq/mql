// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlx_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlx"
)

// TestConnectLocalE2E connects to the real local OS through installed
// providers. It is opt-in because it spawns provider subprocesses, which is
// not suitable for unit-test environments.
func TestConnectLocalE2E(t *testing.T) {
	if os.Getenv("MQLX_E2E") == "" {
		t.Skip("set MQLX_E2E=1 to run the end-to-end local connection test")
	}

	ctx := context.Background()
	env, err := mqlx.NewEnv()
	require.NoError(t, err)
	defer env.Close()

	conn, err := env.ConnectLocal(ctx)
	require.NoError(t, err)
	defer conn.Close()

	res, err := conn.Query(ctx, "asset { name platform version }")
	require.NoError(t, err)
	require.NoError(t, res.Err())

	m, ok := res.Value().(map[string]any)
	require.True(t, ok, "expected map, got %T", res.Value())
	assert.NotEmpty(t, m["platform"])

	var info struct {
		Name     string `mql:"name"`
		Platform string `mql:"platform"`
		Version  string `mql:"version"`
	}
	require.NoError(t, res.Decode(&info))
	assert.NotEmpty(t, info.Platform)
	t.Logf("connected to %s: platform=%s version=%s", info.Name, info.Platform, info.Version)
}

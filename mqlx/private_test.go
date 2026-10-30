// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlx_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlx"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/providers-sdk/v1/testutils/mockprovider"
)

// privateEnv registers the mockprovider as a caller-supplied private,
// in-process provider. Its resources (muser, mgroup, ...) have fields that are
// computed in Go and resolved only when an expression reads them — the case
// expression mode's eager value-to-dict mapping cannot express.
func privateEnv(t *testing.T) *mqlx.Env {
	t.Helper()
	schema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "mockprovider"})
	env, err := mqlx.NewEnv(
		mqlx.WithFeatures(testutils.Features),
		mqlx.WithPrivateProvider(mockprovider.Config, schema, mockprovider.Init()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { env.Close() })
	return env
}

func TestPrivateProviderResource(t *testing.T) {
	env := privateEnv(t)
	ctx := context.Background()

	t.Run("scalar field", func(t *testing.T) {
		res, err := env.MustCompile(`muser(name: "bob").name`).Eval(ctx)
		require.NoError(t, err)
		require.NoError(t, res.Err())
		assert.Equal(t, "bob", res.Value())
	})

	t.Run("lazily computed resource field", func(t *testing.T) {
		// muser.group is resolved on read: its Go resolver creates the
		// mgroup resource only when the expression accesses it.
		res, err := env.MustCompile(`muser(name: "bob").group.name`).Eval(ctx)
		require.NoError(t, err)
		require.NoError(t, res.Err())
		assert.Equal(t, "group one", res.Value())
	})

	t.Run("computed dict field", func(t *testing.T) {
		res, err := env.MustCompile(`muser(name: "bob").dict["string"]`).Eval(ctx)
		require.NoError(t, err)
		require.NoError(t, res.Err())
		assert.Equal(t, "hello world", res.Value())
	})

	t.Run("field error surfaces", func(t *testing.T) {
		res, err := env.MustCompile(`muser(name: "bob").error`).Eval(ctx)
		require.NoError(t, err)
		require.Error(t, res.Err())
		assert.Contains(t, res.Err().Error(), "error from the mockprovider")
	})

	t.Run("decode block into struct", func(t *testing.T) {
		res, err := env.MustCompile(`muser(name: "bob") { name group { name } }`).Eval(ctx)
		require.NoError(t, err)
		require.NoError(t, res.Err())

		var out struct {
			Name  string `mql:"name"`
			Group struct {
				Name string `mql:"name"`
			} `mql:"group"`
		}
		require.NoError(t, res.Decode(&out))
		assert.Equal(t, "bob", out.Name)
		assert.Equal(t, "group one", out.Group.Name)
	})
}

func TestPrivateProviderValidation(t *testing.T) {
	_, err := mqlx.NewEnv(mqlx.WithPrivateProvider(mockprovider.Config, nil, mockprovider.Init()))
	require.ErrorContains(t, err, "no schema provided")

	schema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "mockprovider"})
	_, err = mqlx.NewEnv(mqlx.WithPrivateProvider(mockprovider.Config, schema, nil))
	require.ErrorContains(t, err, "no plugin provided")
}

// TestAssetPrimitive exercises the native `asset` primitive end-to-end through a
// real (in-process) provider: compile -> serialize (asset2result) -> wire ->
// deserialize (passet2raw) -> return to caller. muser.running returns an asset
// value anchored on the muser resource. The anchor is not introspectable from
// MQL (no field accessors); only the value and nil comparisons are exposed.
// See ADR 030.
func TestAssetPrimitive(t *testing.T) {
	env := privateEnv(t)
	ctx := context.Background()

	t.Run("running returns an asset value carrying the anchor", func(t *testing.T) {
		res, err := env.MustCompile(`muser(name: "bob").running`).Eval(ctx)
		require.NoError(t, err)
		require.NoError(t, res.Err())
		av, ok := res.Value().(*llx.AssetValue)
		require.True(t, ok, "expected *llx.AssetValue, got %T", res.Value())
		require.NotNil(t, av)
		assert.Equal(t, "muser", av.ResourceType)
		assert.NotEmpty(t, av.ResourceId)
	})

	t.Run("running is not null", func(t *testing.T) {
		res, err := env.MustCompile(`muser(name: "bob").running != null`).Eval(ctx)
		require.NoError(t, err)
		require.NoError(t, res.Err())
		assert.Equal(t, true, res.Value())
	})
}

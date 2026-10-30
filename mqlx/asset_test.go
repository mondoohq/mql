// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlx_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlx"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

// Asset-mode tests run against a recorded Linux asset; no real connection is
// made. The runtime is wrapped via WrapRuntime, the escape hatch for callers
// that manage runtimes themselves.
var (
	mockConnOnce sync.Once
	mockEnv      *mqlx.Env
	mockConn     *mqlx.Conn
)

func testConn(t *testing.T) (*mqlx.Env, *mqlx.Conn) {
	t.Helper()
	mockConnOnce.Do(func() {
		var err error
		mockEnv, err = mqlx.NewEnv(mqlx.WithFeatures(testutils.Features))
		if err != nil {
			panic(err.Error())
		}
		mockConn = mockEnv.WrapRuntime(testutils.LinuxMock())
	})
	return mockEnv, mockConn
}

func TestAssetValues(t *testing.T) {
	_, conn := testConn(t)
	ctx := context.Background()

	tests := []struct {
		query string
		want  any
	}{
		{"asset.platform", "arch"},
		{"asset { platform version }", map[string]any{
			"platform": "arch",
			"version":  "rolling",
		}},
		{"users { name uid }", []any{
			map[string]any{"name": "root", "uid": int64(0)},
			map[string]any{"name": "bin", "uid": int64(1)},
			map[string]any{"name": "chris", "uid": int64(1000)},
			map[string]any{"name": "christopher", "uid": int64(1001)},
		}},
	}

	for _, tc := range tests {
		t.Run(tc.query, func(t *testing.T) {
			res, err := conn.Query(ctx, tc.query)
			require.NoError(t, err)
			require.NoError(t, res.Err())
			assert.Equal(t, tc.want, res.Value())
		})
	}
}

func TestAssetMultiValue(t *testing.T) {
	_, conn := testConn(t)

	res, err := conn.Query(context.Background(), "asset.platform\nasset.version")
	require.NoError(t, err)
	require.NoError(t, res.Err())

	m, ok := res.Value().(map[string]any)
	require.True(t, ok, "expected map, got %T", res.Value())
	assert.Equal(t, "arch", m["asset.platform"])
	assert.Equal(t, "rolling", m["asset.version"])
}

func TestAssetCompileOnceEvalMany(t *testing.T) {
	env, conn := testConn(t)

	q, err := env.Compile("users.where(uid >= props.min) { name }",
		mqlx.WithProps(map[string]any{"min": 0}))
	require.NoError(t, err)

	res, err := q.EvalOn(context.Background(), conn,
		mqlx.WithPropValues(map[string]any{"min": 1000}))
	require.NoError(t, err)
	require.NoError(t, res.Err())

	list, ok := res.Value().([]any)
	require.True(t, ok)
	assert.Len(t, list, 2)
}

func TestAssetDecode(t *testing.T) {
	_, conn := testConn(t)

	res, err := conn.Query(context.Background(), "users { name uid }")
	require.NoError(t, err)
	require.NoError(t, res.Err())

	type user struct {
		Name string `mql:"name"`
		UID  int64  `mql:"uid"`
	}
	var users []user
	require.NoError(t, res.Decode(&users))

	require.Len(t, users, 4)
	assert.Equal(t, user{Name: "root", UID: 0}, users[0])
	assert.Equal(t, user{Name: "christopher", UID: 1001}, users[3])
}

func TestAssetValueError(t *testing.T) {
	_, conn := testConn(t)

	query := "x = parse.json(content: '{\"arr\": []}').params\nx['arr'][0]"
	res, err := conn.Query(context.Background(), query)
	require.NoError(t, err)

	assert.Nil(t, res.Value())
	require.Error(t, res.Err())
	assert.Contains(t, res.Err().Error(), "array index out of bound")
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlx_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlx"
)

// exprEnv is shared across expression-mode tests: expression mode needs no
// providers, no asset, and no provider subprocess.
var (
	exprEnvOnce sync.Once
	exprEnv     *mqlx.Env
)

func testEnv(t *testing.T) *mqlx.Env {
	t.Helper()
	exprEnvOnce.Do(func() {
		var err error
		exprEnv, err = mqlx.NewEnv()
		if err != nil {
			panic(err.Error())
		}
	})
	return exprEnv
}

func TestExprValues(t *testing.T) {
	env := testEnv(t)
	ctx := context.Background()

	tests := []struct {
		query string
		want  any
	}{
		{"1 + 2", int64(3)},
		{"'hello world'.contains('world')", true},
		{"'MQL'.downcase", "mql"},
		{"semver('1.2.3') < semver('1.10.0')", true},
		{"[1, 2, 3].where(_ > 1).length", int64(2)},
		{"{'a': 1, 'b': 2}['b']", int64(2)},
		{"'joe@example.com' == regex.email", true},
		{"if (1 > 2) { return 'a' } return 'b'", "b"},
	}

	for _, tc := range tests {
		t.Run(tc.query, func(t *testing.T) {
			q, err := env.Compile(tc.query)
			require.NoError(t, err)

			res, err := q.Eval(ctx)
			require.NoError(t, err)
			require.NoError(t, res.Err())
			assert.Equal(t, tc.want, res.Value())
		})
	}
}

func TestExprTime(t *testing.T) {
	env := testEnv(t)

	res, err := env.MustCompile("time.now").Eval(context.Background())
	require.NoError(t, err)
	require.NoError(t, res.Err())

	now, ok := res.Value().(*time.Time)
	require.True(t, ok, "expected *time.Time, got %T", res.Value())
	assert.WithinDuration(t, time.Now(), *now, time.Minute)
}

func TestExprProps(t *testing.T) {
	env := testEnv(t)
	ctx := context.Background()

	t.Run("defaults and overrides", func(t *testing.T) {
		q, err := env.Compile("props.a + props.b",
			mqlx.WithProps(map[string]any{"a": 2, "b": 3}))
		require.NoError(t, err)

		res, err := q.Eval(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(5), res.Value())

		res, err = q.Eval(ctx, mqlx.WithPropValues(map[string]any{"a": 40}))
		require.NoError(t, err)
		assert.Equal(t, int64(43), res.Value())
	})

	t.Run("dict props with dot access", func(t *testing.T) {
		q, err := env.Compile("props.event.process.binary.contains('/tmp')",
			mqlx.WithProps(map[string]any{"event": map[string]any{}}))
		require.NoError(t, err)

		event := map[string]any{
			"process": map[string]any{"binary": "/tmp/evil"},
		}
		res, err := q.Eval(ctx, mqlx.WithPropValues(map[string]any{"event": event}))
		require.NoError(t, err)
		require.NoError(t, res.Err())
		assert.Equal(t, true, res.Value())
	})

	t.Run("undeclared override", func(t *testing.T) {
		q, err := env.Compile("props.a", mqlx.WithProps(map[string]any{"a": 1}))
		require.NoError(t, err)

		_, err = q.Eval(ctx, mqlx.WithPropValues(map[string]any{"b": 2}))
		require.ErrorContains(t, err, "'b' was not declared")
	})

	t.Run("type mismatch", func(t *testing.T) {
		q, err := env.Compile("props.a", mqlx.WithProps(map[string]any{"a": 1}))
		require.NoError(t, err)

		_, err = q.Eval(ctx, mqlx.WithPropValues(map[string]any{"a": "nope"}))
		require.ErrorContains(t, err, "must be of type")
	})
}

func TestExprMultiValue(t *testing.T) {
	env := testEnv(t)

	res, err := env.MustCompile("1 + 2\n'a' + 'b'").Eval(context.Background())
	require.NoError(t, err)
	require.NoError(t, res.Err())

	m, ok := res.Value().(map[string]any)
	require.True(t, ok, "expected map, got %T", res.Value())
	require.Len(t, m, 2)
	// Operator entrypoints label as the operator; identical labels are
	// disambiguated by numbering.
	assert.Equal(t, int64(3), m["+"])
	assert.Equal(t, "ab", m["+ (2)"])
}

func TestExprAssignmentOnly(t *testing.T) {
	env := testEnv(t)

	res, err := env.MustCompile("a = 1").Eval(context.Background())
	require.NoError(t, err)
	assert.Nil(t, res.Value())
}

func TestCompileError(t *testing.T) {
	env := testEnv(t)

	_, err := env.Compile("not_a_resource.field")
	require.Error(t, err)

	var cerr *mqlx.CompileError
	require.True(t, errors.As(err, &cerr))
	assert.Equal(t, "not_a_resource.field", cerr.Source)
}

func TestEvalCancelledContext(t *testing.T) {
	env := testEnv(t)
	q := env.MustCompile("1 + 2")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := q.Eval(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestQueryConcurrentEval(t *testing.T) {
	env := testEnv(t)
	q, err := env.Compile("props.n * 2", mqlx.WithProps(map[string]any{"n": 0}))
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(n int64) {
			defer wg.Done()
			res, err := q.Eval(context.Background(),
				mqlx.WithPropValues(map[string]any{"n": n}))
			assert.NoError(t, err)
			assert.Equal(t, n*2, res.Value())
		}(int64(i))
	}
	wg.Wait()
}

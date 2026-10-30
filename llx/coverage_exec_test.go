// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/types"
)

// partialRuntime answers one field as a provider converted to partial results
// would (ADR 046 §8): the recorded value, plus a partition it could not read.
type partialRuntime struct {
	llx.Runtime
	resource string
	field    string
	gap      *llx.Error
}

func (r *partialRuntime) WatchAndUpdate(resource llx.Resource, field string, watcherUID string, callback func(res any, err error)) error {
	if resource.MqlName() != r.resource || field != r.field {
		return r.Runtime.WatchAndUpdate(resource, field, watcherUID, callback)
	}
	return r.Runtime.WatchAndUpdate(resource, field, watcherUID, func(res any, err error) {
		if err == nil {
			err = llx.Partial(r.gap)
		}
		callback(res, err)
	})
}

func TestCoverageGapsPropagateToEverythingComputedFromThem(t *testing.T) {
	gap := llx.Forbidden(errors.New("AccessDenied"),
		llx.WithScope(llx.ErrorScope_ERROR_SCOPE_PARTITION, "eu-west-1"),
		llx.WithPermissions("ec2:DescribeAddresses"))
	runtime := &partialRuntime{
		Runtime:  testutils.LinuxMock(),
		resource: "users",
		field:    "list",
		gap:      gap,
	}

	run := func(t *testing.T, query string) *llx.RawData {
		t.Helper()
		bundle, err := mqlc.Compile(query, nil, mqlc.NewConfig(runtime.Schema(), mql.Features{}))
		require.NoError(t, err)
		results := resultsOf(t, runtime, bundle)
		require.Len(t, results, 1)
		return results[0].Data
	}

	for _, query := range []string{
		"users.list",
		"users.list.length",
		"users.list.where(name == 'root')",
		"users.list.all(uid >= 0)",
		"users.list.where(name == 'root').length == 1",
		"users.list { name }",
		"users { name }",
	} {
		t.Run(query, func(t *testing.T) {
			data := run(t, query)
			require.NoError(t, data.Error, "a partial input does not fail the result")
			require.Len(t, data.CoverageGaps, 1)
			assert.True(t, errors.Is(data.CoverageGaps[0], llx.ErrForbidden))
			assert.Equal(t, "eu-west-1", data.CoverageGaps[0].ScopeID)
		})
	}

	t.Run("an empty-looking result still says what it could not read", func(t *testing.T) {
		data := run(t, "users.list.where(name == 'nobody-has-this-name')")
		assert.Equal(t, []any{}, data.Value)
		assert.Len(t, data.CoverageGaps, 1)
	})

	t.Run("the value is the one that was read", func(t *testing.T) {
		assert.Equal(t, int64(1), run(t, "users.list.where(name == 'root').length").Value)
	})

	t.Run("a result not computed from the partial field carries nothing", func(t *testing.T) {
		data := run(t, "sshd.config.ciphers")
		require.NoError(t, data.Error)
		assert.Empty(t, data.CoverageGaps)
	})

	t.Run("delivery does not write gaps into the shared field value", func(t *testing.T) {
		// Two queries in one bundle: the gaps of the second must not leak
		// onto the first through a value both read from the cache.
		bundle, err := mqlc.Compile("users.list.length\nsshd.config.ciphers.length", nil,
			mqlc.NewConfig(runtime.Schema(), mql.Features{}))
		require.NoError(t, err)
		results := resultsOf(t, runtime, bundle)
		require.Len(t, results, 2)
		assert.Len(t, results[0].Data.CoverageGaps, 1)
		assert.Empty(t, results[1].Data.CoverageGaps)
	})
}

// A gap on a field read inside a block reaches the block's result: the gap is
// in what each block run read, not in the value the block was called on.
func TestCoverageGapsInsideBlocksReachTheBlockResult(t *testing.T) {
	gap := llx.Unavailable(errors.New("connection refused"),
		llx.WithScope(llx.ErrorScope_ERROR_SCOPE_PARTITION, "europe-west1"))

	for _, tc := range []struct{ resource, field, query string }{
		{"sshd.config", "ciphers", "sshd.config { ciphers }"},
		{"user", "name", "users.list { name }"},
		{"user", "name", "users.list.where(name == 'root')"},
		{"user", "name", "users.all(name != '')"},
	} {
		t.Run(tc.query, func(t *testing.T) {
			runtime := &partialRuntime{Runtime: testutils.LinuxMock(), resource: tc.resource, field: tc.field, gap: gap}
			bundle, err := mqlc.Compile(tc.query, nil, mqlc.NewConfig(runtime.Schema(), mql.Features{}))
			require.NoError(t, err)
			results := resultsOf(t, runtime, bundle)
			require.Len(t, results, 1)
			require.NoError(t, results[0].Data.Error)
			require.Len(t, results[0].Data.CoverageGaps, 1, "one partition, deduplicated across every block run")
			assert.Equal(t, "europe-west1", results[0].Data.CoverageGaps[0].ScopeID)
		})
	}
}

// A gap reaches the wire result that cnspec and the server read, and comes
// back from it unchanged.
func TestCoverageGapsSurviveTheResultRoundTrip(t *testing.T) {
	gap := llx.TooManyRequests(errors.New("Throttling"),
		llx.WithScope(llx.ErrorScope_ERROR_SCOPE_PARTITION, "us-east-1"))
	raw := &llx.RawResult{
		CodeID: "abc",
		Data:   (&llx.RawData{Type: types.Array(types.String), Value: []any{"a"}}).WithCoverageGaps([]*llx.Error{gap}),
	}

	res := raw.Result()
	assert.Empty(t, res.Error, "a gap is not an error")
	require.Len(t, res.CoverageGaps, 1)
	assert.Equal(t, "Throttling", res.CoverageGaps[0].Error)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS, res.CoverageGaps[0].Detail.Kind)

	back := res.RawResultV2()
	require.NoError(t, back.Data.Error)
	assert.Equal(t, []any{"a"}, back.Data.Value)
	require.Len(t, back.Data.CoverageGaps, 1)
	assert.Equal(t, "Throttling", back.Data.CoverageGaps[0].Error())
	assert.Equal(t, "us-east-1", back.Data.CoverageGaps[0].ScopeID)
	assert.True(t, errors.Is(back.Data.CoverageGaps[0], llx.ErrTooManyRequests))
}

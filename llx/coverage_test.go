// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/types"
)

func TestPartial(t *testing.T) {
	t.Run("nothing to report is nil", func(t *testing.T) {
		assert.NoError(t, Partial())
		assert.NoError(t, Partial(nil, nil))
	})

	t.Run("carries its gaps through a wrap", func(t *testing.T) {
		err := fmt.Errorf("listing: %w", Partial(Forbidden(errors.New("AccessDenied"))))
		gaps, ok := CoverageGapsOf(err)
		require.True(t, ok)
		require.Len(t, gaps, 1)
		assert.Equal(t, ErrorKind_ERROR_KIND_FORBIDDEN, gaps[0].Kind)
	})

	t.Run("a plain error is not a partial", func(t *testing.T) {
		_, ok := CoverageGapsOf(Forbidden(errors.New("AccessDenied")))
		assert.False(t, ok)
		_, ok = CoverageGapsOf(nil)
		assert.False(t, ok)
	})

	t.Run("an unclassified error stays unclassified", func(t *testing.T) {
		gaps, _ := CoverageGapsOf(Partial(errors.New("boom")))
		require.Len(t, gaps, 1)
		assert.Equal(t, ErrorKind_ERROR_KIND_UNSPECIFIED, gaps[0].Kind)
		assert.Equal(t, "boom", gaps[0].Error())
	})
}

func TestUnionCoverageGaps(t *testing.T) {
	denied := func(region string, perms ...string) *Error {
		return Forbidden(errors.New("AccessDenied in "+region),
			WithScope(ErrorScope_ERROR_SCOPE_PARTITION, region), WithPermissions(perms...))
	}

	t.Run("deduplicates on kind, scope, scope id and permissions", func(t *testing.T) {
		res := UnionCoverageGaps(
			[]*Error{denied("eu-west-1", "ec2:DescribeAddresses")},
			[]*Error{denied("eu-west-1", "ec2:DescribeAddresses"), denied("us-east-1", "ec2:DescribeAddresses")},
		)
		require.Len(t, res, 2)
		assert.Equal(t, "eu-west-1", res[0].ScopeID)
		assert.Equal(t, "us-east-1", res[1].ScopeID)
	})

	t.Run("permission order does not make a new gap", func(t *testing.T) {
		res := UnionCoverageGaps([]*Error{denied("eu-west-1", "a", "b"), denied("eu-west-1", "b", "a")})
		assert.Len(t, res, 1)
	})

	t.Run("a different kind in the same partition is a different gap", func(t *testing.T) {
		throttled := TooManyRequests(errors.New("Throttling"), WithScope(ErrorScope_ERROR_SCOPE_PARTITION, "eu-west-1"))
		res := UnionCoverageGaps([]*Error{denied("eu-west-1"), throttled})
		assert.Len(t, res, 2)
	})

	t.Run("no gaps is nil", func(t *testing.T) {
		assert.Nil(t, UnionCoverageGaps(nil, []*Error{}))
	})
}

func TestWithCoverageGapsNeverWritesThrough(t *testing.T) {
	gap := Forbidden(errors.New("AccessDenied"))

	// NilData is shared by every null in the process; a gap written onto it
	// would show up on all of them.
	res := NilData.WithCoverageGaps([]*Error{gap})
	assert.Len(t, res.CoverageGaps, 1)
	assert.Empty(t, NilData.CoverageGaps)
	assert.NotSame(t, NilData, res)

	assert.Same(t, NilData, NilData.WithCoverageGaps(nil), "nothing to add returns the value itself")
}

func TestCoverageGapKeepsItsPartitionWhenUnclassified(t *testing.T) {
	// ErrorDetailOf drops an unclassified error's detail; a gap must not, since
	// the partition is what says which region to look at.
	gap := NewError(ErrorKind_ERROR_KIND_UNSPECIFIED, errors.New("internal error"),
		WithScope(ErrorScope_ERROR_SCOPE_PARTITION, "eu-west-1"))
	raw := (&RawData{Type: types.Array(types.String), Value: []any{}}).WithCoverageGaps([]*Error{gap})

	back := raw.Result().RawData()
	require.Len(t, back.CoverageGaps, 1)
	assert.Equal(t, "eu-west-1", back.CoverageGaps[0].ScopeID)
	assert.Equal(t, "internal error", back.CoverageGaps[0].Error())
}

func TestCoverageGapsJSONfield(t *testing.T) {
	bundle := &CodeBundle{Labels: &Labels{Labels: map[string]string{"abc": "aws.ec2.eips"}}}

	t.Run("a complete result writes nothing", func(t *testing.T) {
		assert.Nil(t, (&RawData{Type: types.Int, Value: int64(1)}).CoverageGapsJSONfield("abc", bundle))
		var r *RawData
		assert.Nil(t, r.CoverageGapsJSONfield("abc", bundle))
	})

	t.Run("gaps are keyed by the value's label", func(t *testing.T) {
		r := &RawData{Type: types.Array(types.String), CoverageGaps: []*Error{
			Forbidden(errors.New("AccessDenied"),
				WithScope(ErrorScope_ERROR_SCOPE_PARTITION, "eu-west-1"),
				WithPermissions("ec2:DescribeVolumes", "ec2:DescribeAddresses")),
			TooManyRequests(nil, WithRetryAfter(1500*time.Millisecond)),
			{err: errors.New("boom")},
		}}
		got := r.CoverageGapsJSONfield("abc", bundle)
		assert.JSONEq(t, `{"aws.ec2.eips":[
			{"kind":"forbidden","scope":"partition","scopeId":"eu-west-1","permissions":["ec2:DescribeAddresses","ec2:DescribeVolumes"],"error":"AccessDenied"},
			{"kind":"too_many_requests","retryAfterMs":1500},
			{"kind":"unspecified","error":"boom"}
		]}`, "{"+string(got)+"}")
		assert.Equal(t, []string{"ec2:DescribeVolumes", "ec2:DescribeAddresses"}, r.CoverageGaps[0].Permissions,
			"rendering must not reorder the shared gap")
	})
}

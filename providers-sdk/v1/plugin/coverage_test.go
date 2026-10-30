// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// ADR 046 §8: an accessor returns res, llx.Partial(errs...). The field is set,
// not null, the data is kept, and the wire carries coverage_gaps, not error.

func deniedIn(region string) error {
	return llx.Forbidden(errors.New("AccessDenied"),
		llx.WithScope(llx.ErrorScope_ERROR_SCOPE_PARTITION, region),
		llx.WithPermissions("ec2:DescribeAddresses"))
}

func TestGetOrComputeKeepsThePartialValue(t *testing.T) {
	var cached TValue[[]any]
	res := GetOrCompute(&cached, func() ([]any, error) {
		return []any{"eip-1", "eip-2"}, llx.Partial(deniedIn("eu-west-1"))
	})

	assert.True(t, res.IsSet())
	assert.False(t, res.IsNull(), "a partial field is not a null")
	assert.NoError(t, res.Error, "code that checks a sibling's Error must still see the data")
	assert.Equal(t, []any{"eip-1", "eip-2"}, res.Data)
	require.Len(t, res.CoverageGaps, 1)
	assert.Equal(t, "eu-west-1", res.CoverageGaps[0].ScopeID)

	// Cached: the compute function is not asked again.
	again := GetOrCompute(&cached, func() ([]any, error) {
		t.Fatal("recomputed a cached partial field")
		return nil, nil
	})
	assert.Equal(t, res.Data, again.Data)
	assert.Len(t, again.CoverageGaps, 1)
}

func TestGetOrComputeRecognizesAWrappedPartial(t *testing.T) {
	var cached TValue[[]any]
	res := GetOrCompute(&cached, func() ([]any, error) {
		return []any{"a"}, fmt.Errorf("listing addresses: %w", llx.Partial(deniedIn("eu-west-1")))
	})
	assert.NoError(t, res.Error)
	assert.Len(t, res.CoverageGaps, 1)
}

func TestGetOrComputeWithNoGapsIsComplete(t *testing.T) {
	// llx.Partial() with nothing to report is nil, so a loop returns it
	// unconditionally and a complete result looks exactly as it always did.
	var cached TValue[[]any]
	res := GetOrCompute(&cached, func() ([]any, error) {
		return []any{"a"}, llx.Partial(nil, nil)
	})
	assert.NoError(t, res.Error)
	assert.Nil(t, res.CoverageGaps)
	assert.Nil(t, res.ToDataRes(types.Array(types.String)).CoverageGaps)
}

func TestGetOrComputeStillFailsOnAPlainError(t *testing.T) {
	var cached TValue[[]any]
	res := GetOrCompute(&cached, func() ([]any, error) {
		return []any{"a"}, deniedIn("eu-west-1")
	})
	assert.True(t, res.IsNull())
	assert.Error(t, res.Error)
	assert.Nil(t, res.CoverageGaps)
}

func TestPartialFieldOnTheWire(t *testing.T) {
	var cached TValue[[]any]
	res := GetOrCompute(&cached, func() ([]any, error) {
		return []any{"eip-1"}, llx.Partial(deniedIn("eu-west-1"), deniedIn("ap-south-1"))
	})

	dataRes := res.ToDataRes(types.Array(types.String))
	assert.Empty(t, dataRes.Error)
	assert.Nil(t, dataRes.ErrorDetail)
	require.Len(t, dataRes.CoverageGaps, 2)
	assert.Equal(t, "AccessDenied", dataRes.CoverageGaps[0].Error)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, dataRes.CoverageGaps[0].Detail.Kind)
	assert.Equal(t, "eu-west-1", dataRes.CoverageGaps[0].Detail.ScopeId)
	assert.Equal(t, "ap-south-1", dataRes.CoverageGaps[1].Detail.ScopeId)
	assert.Equal(t, []string{"ec2:DescribeAddresses"}, dataRes.CoverageGaps[0].Detail.Permissions)

	raw := dataRes.Data.RawData()
	assert.Equal(t, []any{"eip-1"}, raw.Value)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:fix inline
func strp(s string) *string { return new(s) }

// TestParseEcsTime covers the ECS timestamp parser, which must accept both the
// minute-precision form Alibaba Cloud commonly returns (2017-12-10T04:04Z) and
// full RFC3339, and return nil for nil/empty/unparseable input.
func TestParseEcsTime(t *testing.T) {
	t.Run("nil pointer returns nil", func(t *testing.T) {
		assert.Nil(t, parseEcsTime(nil))
	})
	t.Run("empty string returns nil", func(t *testing.T) {
		assert.Nil(t, parseEcsTime(new("")))
	})
	t.Run("minute-precision UTC parses", func(t *testing.T) {
		got := parseEcsTime(new("2017-12-10T04:04Z"))
		require.NotNil(t, got)
		assert.Equal(t, 2017, got.Year())
		assert.Equal(t, 4, got.Minute())
		assert.Equal(t, 0, got.Second())
	})
	t.Run("full RFC3339 parses", func(t *testing.T) {
		got := parseEcsTime(new("2017-12-10T04:04:30Z"))
		require.NotNil(t, got)
		assert.Equal(t, 30, got.Second())
	})
	t.Run("unparseable string returns nil (not a zero time)", func(t *testing.T) {
		assert.Nil(t, parseEcsTime(new("not-a-time")))
	})
}

// TestMongodbParseTime covers the MongoDB parser's extra layouts, including the
// date-only and seconds-with-Z variants ApsaraDB emits.
func TestMongodbParseTime(t *testing.T) {
	cases := map[string]bool{ // input -> should-parse
		"":                     false,
		"garbage":              false,
		"2021-11-25T16:00Z":    true, // minute precision
		"2021-11-25T16:00:05Z": true, // seconds
		"2021-11-25":           true, // date only
	}
	for in, shouldParse := range cases {
		var arg *string
		if in != "" {
			arg = new(in)
		}
		got := mongodbParseTime(arg)
		if shouldParse {
			assert.NotNilf(t, got, "expected %q to parse", in)
		} else {
			assert.Nilf(t, got, "expected %q to yield nil", in)
		}
	}
	assert.Nil(t, mongodbParseTime(nil))
}

// TestVpcAclTotalCount covers the *string TotalCount parser that drives
// DescribeNetworkAcls pagination termination: a valid number returns its value,
// and nil/empty/non-numeric return -1 (the sentinel the loop treats as "stop").
func TestVpcAclTotalCount(t *testing.T) {
	assert.Equal(t, int64(42), vpcAclTotalCount(new("42")))
	assert.Equal(t, int64(0), vpcAclTotalCount(new("0")))
	assert.Equal(t, int64(-1), vpcAclTotalCount(nil))
	assert.Equal(t, int64(-1), vpcAclTotalCount(new("")))
	assert.Equal(t, int64(-1), vpcAclTotalCount(new("not-a-number")))
}

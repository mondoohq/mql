// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseSlsProjectArn covers the ActionTrail SLS project ARN parser, which
// feeds the trail -> log.project typed reference. A parsing bug would silently
// break that cross-reference.
func TestParseSlsProjectArn(t *testing.T) {
	t.Run("well-formed arn", func(t *testing.T) {
		region, project := parseSlsProjectArn("acs:log:cn-hangzhou:1234567890:project/my-audit-logs")
		assert.Equal(t, "cn-hangzhou", region)
		assert.Equal(t, "my-audit-logs", project)
	})
	t.Run("empty string yields empties", func(t *testing.T) {
		region, project := parseSlsProjectArn("")
		assert.Equal(t, "", region)
		assert.Equal(t, "", project)
	})
	t.Run("non-log service yields empties", func(t *testing.T) {
		region, project := parseSlsProjectArn("acs:oss:cn-hangzhou:1234567890:project/x")
		assert.Equal(t, "", region)
		assert.Equal(t, "", project)
	})
	t.Run("missing project resource keeps region, empty project", func(t *testing.T) {
		region, project := parseSlsProjectArn("acs:log:cn-beijing:1234567890:dashboard/d1")
		assert.Equal(t, "cn-beijing", region)
		assert.Equal(t, "", project)
	})
	t.Run("too few segments yields empties", func(t *testing.T) {
		region, project := parseSlsProjectArn("acs:log:cn-hangzhou")
		assert.Equal(t, "", region)
		assert.Equal(t, "", project)
	})
}

// TestSlsEpochTime covers the SLS logstore timestamp conversion, which the API
// returns as epoch SECONDS. Getting the unit wrong would report timestamps off
// by three orders of magnitude.
func TestSlsEpochTime(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		assert.Nil(t, slsEpochTime(nil))
	})
	t.Run("zero returns nil", func(t *testing.T) {
		z := int32(0)
		assert.Nil(t, slsEpochTime(&z))
	})
	t.Run("epoch seconds convert to UTC", func(t *testing.T) {
		v := int32(1700000000) // 2023-11-14T22:13:20Z
		got := slsEpochTime(&v)
		require.NotNil(t, got)
		assert.Equal(t, 2023, got.Year())
		assert.Equal(t, "UTC", got.Location().String())
	})
}

// TestConfigEpochMillis covers the Cloud Config rule timestamp conversion, which
// the API returns as epoch MILLISECONDS (distinct from SLS's seconds).
func TestConfigEpochMillis(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		assert.Nil(t, configEpochMillis(nil))
	})
	t.Run("zero returns nil", func(t *testing.T) {
		z := int64(0)
		assert.Nil(t, configEpochMillis(&z))
	})
	t.Run("epoch millis convert to UTC", func(t *testing.T) {
		v := int64(1700000000000) // 2023-11-14T22:13:20Z
		got := configEpochMillis(&v)
		require.NotNil(t, got)
		assert.Equal(t, 2023, got.Year())
		assert.Equal(t, "UTC", got.Location().String())
	})
	t.Run("seconds mistaken for millis would be wrong (guards unit)", func(t *testing.T) {
		// 1_700_000_000 interpreted as millis is 1970, proving the unit matters.
		v := int64(1700000000)
		got := configEpochMillis(&v)
		require.NotNil(t, got)
		assert.Equal(t, 1970, got.Year())
	})
}

// TestAlicloudParseTime covers the shared RFC3339 parser used by KMS and
// ActionTrail.
func TestAlicloudParseTime(t *testing.T) {
	assert.Nil(t, alicloudParseTime(nil))
	assert.Nil(t, alicloudParseTime(new("")))
	assert.Nil(t, alicloudParseTime(new("not-a-time")))
	got := alicloudParseTime(new("2026-01-02T15:04:05Z"))
	require.NotNil(t, got)
	assert.Equal(t, 2026, got.Year())
	assert.Equal(t, 5, got.Second())

	// A timezone offset must parse and normalize (12:00+08:00 == 04:00 UTC),
	// not just Z-suffixed UTC.
	off := alicloudParseTime(new("2026-07-20T12:00:00+08:00"))
	require.NotNil(t, off)
	assert.Equal(t, 4, off.UTC().Hour())
}

// TestSlsParseTime covers slsParseTime — the RFC3339 string parser used by SLS
// and the untested twin of alicloudParseTime — including nil/empty/garbage and
// a timezone-offset form (a regression to a Z-only layout would silently drop
// offset-stamped times).
func TestSlsParseTime(t *testing.T) {
	assert.Nil(t, slsParseTime(nil))
	assert.Nil(t, slsParseTime(new("")))
	assert.Nil(t, slsParseTime(new("not-a-time")))

	got := slsParseTime(new("2026-01-02T15:04:05Z"))
	require.NotNil(t, got)
	assert.Equal(t, 2026, got.Year())
	assert.Equal(t, 5, got.Second())

	off := slsParseTime(new("2026-07-20T12:00:00+08:00"))
	require.NotNil(t, off)
	assert.Equal(t, 4, off.UTC().Hour())
}

// TestRmParseTime covers the Resource Management parser, which must accept the
// fractional-second form the API returns.
func TestRmParseTime(t *testing.T) {
	assert.Nil(t, rmParseTime(nil))
	assert.Nil(t, rmParseTime(new("")))
	t.Run("fractional seconds parse", func(t *testing.T) {
		got := rmParseTime(new("2020-11-01T09:00:00.000Z"))
		require.NotNil(t, got)
		assert.Equal(t, 2020, got.Year())
		assert.Equal(t, 9, got.Hour())
	})
	t.Run("plain RFC3339 parses", func(t *testing.T) {
		got := rmParseTime(new("2020-11-01T09:00:00Z"))
		require.NotNil(t, got)
		assert.Equal(t, 2020, got.Year())
	})
}

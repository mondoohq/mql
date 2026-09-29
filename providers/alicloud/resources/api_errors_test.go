// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"
	"time"

	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mondoo.com/mql/llx"
)

// teaErr builds the error shape the Darabonba clients return for a service
// response error.
func teaErr(status int, code string) error {
	return tea.NewSDKError(map[string]any{
		"statusCode": status,
		"code":       code,
		"message":    "refused",
	})
}

func TestClassifyAlicloudError(t *testing.T) {
	const perm = "ram:GetAccountMFAInfo"

	t.Run("403 is forbidden and names the permission", func(t *testing.T) {
		err := classifyAlicloudError(teaErr(403, "NoPermission"), perm)
		assert.ErrorIs(t, err, llx.ErrForbidden)
		var le *llx.Error
		require.True(t, errors.As(err, &le))
		assert.Contains(t, le.Permissions, perm)
	})
	t.Run("401 is unauthenticated", func(t *testing.T) {
		assert.ErrorIs(t, classifyAlicloudError(teaErr(401, "InvalidAccessKeyId"), perm), llx.ErrUnauthenticated)
	})
	t.Run("a service that is not activated is not applicable, whatever the status", func(t *testing.T) {
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE,
			llx.KindOf(classifyAlicloudError(teaErr(403, "Forbidden.NotOpen"), perm)))
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE,
			llx.KindOf(classifyAlicloudError(teaErr(400, "ServiceNotActivated"), perm)))
	})
	t.Run("throttling is too many requests", func(t *testing.T) {
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS,
			llx.KindOf(classifyAlicloudError(teaErr(400, "Throttling.User"), perm)))
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS,
			llx.KindOf(classifyAlicloudError(teaErr(429, ""), perm)))
	})
	t.Run("5xx is unavailable", func(t *testing.T) {
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNAVAILABLE,
			llx.KindOf(classifyAlicloudError(teaErr(503, "ServiceUnavailable"), perm)))
	})
	t.Run("a plain 400 stays unclassified", func(t *testing.T) {
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
			llx.KindOf(classifyAlicloudError(teaErr(400, "InvalidParameter"), perm)))
	})
	t.Run("a transport error is returned unchanged", func(t *testing.T) {
		in := errors.New("dial tcp: connection refused")
		assert.Equal(t, in, classifyAlicloudError(in, perm))
	})
	t.Run("a wrapped SDK error is still classified", func(t *testing.T) {
		wrapped := fmt.Errorf("listing: %w", teaErr(403, "NoPermission"))
		assert.ErrorIs(t, classifyAlicloudError(wrapped, perm), llx.ErrForbidden)
	})
}

func TestAlicloudRegionSkippable(t *testing.T) {
	assert.True(t, alicloudRegionSkippable(teaErr(403, "NoPermission")))
	assert.True(t, alicloudRegionSkippable(teaErr(404, "InvalidRegionId.NotFound")))
	assert.True(t, alicloudRegionSkippable(teaErr(400, "Forbidden.NotOpen")))
	assert.False(t, alicloudRegionSkippable(teaErr(500, "InternalError")), "a server fault must be warned about")
	assert.False(t, alicloudRegionSkippable(errors.New("dial tcp: i/o timeout")))
}

func TestParseAlicloudTime(t *testing.T) {
	cases := map[string]time.Time{
		"2021-09-24T18:00:07Z":      time.Date(2021, 9, 24, 18, 0, 7, 0, time.UTC),
		"2021-09-24T18:00Z":         time.Date(2021, 9, 24, 18, 0, 0, 0, time.UTC),
		"2021-09-24T20:00:07+02:00": time.Date(2021, 9, 24, 18, 0, 7, 0, time.UTC),
		"2021-09-24 18:00:07":       time.Date(2021, 9, 24, 18, 0, 7, 0, time.UTC),
		"2022-11-17":                time.Date(2022, 11, 17, 0, 0, 0, 0, time.UTC),
	}
	for in, want := range cases {
		got := parseAlicloudTime(tea.String(in))
		require.NotNil(t, got, in)
		assert.True(t, want.Equal(*got), "%s parsed as %s", in, got)
	}
	assert.Nil(t, parseAlicloudTime(nil))
	assert.Nil(t, parseAlicloudTime(tea.String("")))
	assert.Nil(t, parseAlicloudTime(tea.String("not a date")), "an unparseable value must stay null, not become year 1")
}

func TestEpochAuto(t *testing.T) {
	want := time.Date(2024, 4, 25, 7, 0, 0, 0, time.UTC)

	ms := want.UnixMilli()
	got := epochAuto(&ms)
	require.NotNil(t, got)
	assert.True(t, want.Equal(*got), "milliseconds read as %s", got)

	secs := want.Unix()
	got = epochAuto(&secs)
	require.NotNil(t, got)
	assert.True(t, want.Equal(*got), "seconds read as %s", got)

	zero := int64(0)
	assert.Nil(t, epochAuto(&zero), "zero must stay null rather than 1970")
	assert.Nil(t, epochAuto(nil))
}

func TestParseJSONLists(t *testing.T) {
	assert.Equal(t, []any{int64(0), int64(1), int64(23)}, parseJSONIntList(tea.String(`["0","1","23"]`)))
	assert.Equal(t, []any{int64(1), int64(7)}, parseJSONIntList(tea.String(`[1,7]`)))
	assert.Equal(t, []any{int64(2)}, parseJSONIntList(tea.String(`["x","2"]`)), "a non-number member is dropped")
	assert.Equal(t, []string{"cn-hangzhou", "cn-beijing"}, parseJSONStringList(tea.String(`["cn-hangzhou", "cn-beijing"]`)))
	assert.Empty(t, parseJSONStringList(tea.String("")))
	assert.Empty(t, parseJSONStringList(tea.String("cn-hangzhou")), "a value that is not a JSON array yields nothing")
	assert.Empty(t, parseJSONStringList(nil))
}

func TestPageDone(t *testing.T) {
	total := int32(250)
	assert.False(t, ecsPageDone(100, 1, 100, &total))
	assert.False(t, ecsPageDone(100, 2, 100, &total))
	assert.True(t, ecsPageDone(50, 3, 100, &total), "a short page ends the walk")
	assert.True(t, ecsPageDone(0, 1, 100, nil), "an empty page ends the walk")
	exact := int32(200)
	assert.True(t, ecsPageDone(100, 2, 100, &exact), "a full last page ends the walk once the total is read")
	assert.False(t, ecsPageDone(100, 1, 100, nil), "without a total a full page asks for the next")

	casTotal := int64(150)
	assert.False(t, casPageDone(100, 1, 100, &casTotal))
	assert.True(t, casPageDone(50, 2, 100, &casTotal))
	assert.True(t, casPageDone(0, 1, 100, nil))
}

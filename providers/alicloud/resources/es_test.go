// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	esclient "github.com/alibabacloud-go/elasticsearch-20170613/v6/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mondoo.com/mql/llx"
)

// TestEsParseTime covers the cluster timestamp parser across the layouts the
// API uses. An unparseable value must stay null rather than becoming the zero
// time, which would report 1 January year 1 as a real creation date.
func TestEsParseTime(t *testing.T) {
	want := time.Date(2026, 8, 15, 12, 30, 0, 0, time.UTC)

	t.Run("nil stays nil", func(t *testing.T) {
		assert.Nil(t, esParseTime(nil))
	})
	t.Run("empty stays nil", func(t *testing.T) {
		assert.Nil(t, esParseTime(tea.String("")))
	})
	t.Run("garbage stays nil", func(t *testing.T) {
		assert.Nil(t, esParseTime(tea.String("not a date")))
	})
	t.Run("epoch milliseconds are not silently accepted", func(t *testing.T) {
		assert.Nil(t, esParseTime(tea.String("1562849679000")))
	})
	t.Run("rfc3339", func(t *testing.T) {
		got := esParseTime(tea.String("2026-08-15T12:30:00Z"))
		require.NotNil(t, got)
		assert.Equal(t, want, got.UTC())
	})
	t.Run("milliseconds layout", func(t *testing.T) {
		got := esParseTime(tea.String("2026-08-15T12:30:00.000Z"))
		require.NotNil(t, got)
		assert.Equal(t, want, got.UTC())
	})
}

// TestEsStrings covers the address-list flattening. A nil or empty entry must be
// dropped rather than surfacing as a blank string, which would read as a
// configured rule in a whitelist.
func TestEsStrings(t *testing.T) {
	assert.Equal(t, []any{}, esStrings(nil))
	assert.Equal(t, []any{}, esStrings([]*string{nil, tea.String("")}))
	assert.Equal(t, []any{"0.0.0.0/0"}, esStrings([]*string{tea.String("0.0.0.0/0"), nil}))
	assert.Equal(t, []any{"10.0.0.0/8", "192.168.0.0/16"},
		esStrings([]*string{tea.String("10.0.0.0/8"), tea.String(""), tea.String("192.168.0.0/16")}))
}

// TestEsRegionUnavailable covers the classifier that decides whether a
// first-page listing error is an ordinary "no Elasticsearch here" or a real
// failure. Getting this wrong in either direction is bad: matching everything
// buries a throttled region in debug output, and matching nothing emits a
// warning per region on every healthy scan.
func TestEsRegionUnavailable(t *testing.T) {
	sdkErr := func(status int) error {
		return &tea.SDKError{StatusCode: tea.Int(status), Code: tea.String("Forbidden")}
	}

	t.Run("403 is an ordinary skip", func(t *testing.T) {
		assert.True(t, esRegionUnavailable(sdkErr(403)))
	})
	t.Run("404 is an ordinary skip", func(t *testing.T) {
		assert.True(t, esRegionUnavailable(sdkErr(404)))
	})
	t.Run("wrapped errors are still matched", func(t *testing.T) {
		assert.True(t, esRegionUnavailable(fmt.Errorf("list instances: %w", sdkErr(403))))
	})
	t.Run("429 throttling is a real failure", func(t *testing.T) {
		assert.False(t, esRegionUnavailable(sdkErr(429)))
	})
	t.Run("500 is a real failure", func(t *testing.T) {
		assert.False(t, esRegionUnavailable(sdkErr(500)))
	})
	t.Run("transport error is a real failure", func(t *testing.T) {
		assert.False(t, esRegionUnavailable(errors.New("dial tcp: i/o timeout")))
	})
	t.Run("SDK error without a status is a real failure", func(t *testing.T) {
		assert.False(t, esRegionUnavailable(&tea.SDKError{Code: tea.String("Throttling")}))
	})
}

// TestEsInternetExposed covers the exposure verdict. Kibana counts on its own:
// the console reads everything the cluster holds, so treating a public console
// as unexposed because the cluster endpoint is private would miss the finding.
func TestEsInternetExposed(t *testing.T) {
	tests := []struct {
		name                 string
		public, kibanaPublic bool
		want                 bool
	}{
		{"both private", false, false, false},
		{"cluster endpoint public", true, false, true},
		{"only kibana public", false, true, true},
		{"both public", true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, esInternetExposed(tt.public, tt.kibanaPublic))
		})
	}
}

// TestEsSnapshotIndices covers the snapshot index list. A setting without a
// list must read null, not an empty list that would claim no index is backed
// up, and blank entries must not surface as index names.
func TestEsSnapshotIndices(t *testing.T) {
	t.Run("nil setting is null", func(t *testing.T) {
		assert.Nil(t, esSnapshotIndices(nil))
	})
	t.Run("absent list is null", func(t *testing.T) {
		assert.Nil(t, esSnapshotIndices(&esclient.DescribeSnapshotSettingResponseBodyResult{Enable: tea.Bool(true)}))
	})
	t.Run("empty list stays empty", func(t *testing.T) {
		assert.Equal(t, []any{}, esSnapshotIndices(&esclient.DescribeSnapshotSettingResponseBodyResult{Indices: []*string{}}))
	})
	t.Run("blank entries dropped", func(t *testing.T) {
		got := esSnapshotIndices(&esclient.DescribeSnapshotSettingResponseBodyResult{
			Indices: []*string{tea.String("logs-*"), nil, tea.String(""), tea.String("orders")},
		})
		assert.Equal(t, []any{"logs-*", "orders"}, got)
	})
}

// TestEsSnapshotSettingDecode checks that the SDK struct tags match the field
// names the API documents, so a renamed tag cannot silently zero a field.
func TestEsSnapshotSettingDecode(t *testing.T) {
	body := `{"RequestId":"r","Result":{"Enable":true,"QuartzRegex":"0 0 01 ? * * *","Indices":["logs-*","orders"]}}`
	var resp esclient.DescribeSnapshotSettingResponseBody
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	require.NotNil(t, resp.Result)
	assert.True(t, tea.BoolValue(resp.Result.Enable))
	assert.Equal(t, "0 0 01 ? * * *", tea.StringValue(resp.Result.QuartzRegex))
	assert.Equal(t, []any{"logs-*", "orders"}, esSnapshotIndices(resp.Result))
}

// TestEsClassifyError covers the refusal classifier on the snapshot call. A
// 403 is Forbidden naming the permission, a 401 is Unauthenticated, and
// anything the target did not refuse stays unclassified.
func TestEsClassifyError(t *testing.T) {
	sdkErr := func(status int) error {
		return &tea.SDKError{StatusCode: tea.Int(status), Code: tea.String("x")}
	}
	const perm = "elasticsearch:DescribeSnapshotSetting"

	t.Run("403 is forbidden with permission", func(t *testing.T) {
		err := esClassifyError(sdkErr(403), perm)
		assert.ErrorIs(t, err, llx.ErrForbidden)
		var le *llx.Error
		require.True(t, errors.As(err, &le))
		assert.Contains(t, le.Permissions, perm)
	})
	t.Run("401 is unauthenticated", func(t *testing.T) {
		assert.ErrorIs(t, esClassifyError(sdkErr(401), perm), llx.ErrUnauthenticated)
	})
	t.Run("500 is unclassified", func(t *testing.T) {
		assert.Equal(t, llx.KindOf(errors.New("x")), llx.KindOf(esClassifyError(sdkErr(500), perm)))
	})
	t.Run("transport error is unclassified", func(t *testing.T) {
		in := errors.New("dial tcp: connection refused")
		assert.Equal(t, in, esClassifyError(in, perm))
	})
}

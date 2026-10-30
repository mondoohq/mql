// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package reporter

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/iox"
)

func TestCodeBundleToJSON_CoverageGaps(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	bundle, err := x.Compile("mondoo.version\nmondoo.build")
	require.NoError(t, err)
	eps := bundle.CodeV2.Entrypoints()
	require.Len(t, eps, 2)
	version := bundle.CodeV2.Checksums[eps[0]]
	build := bundle.CodeV2.Checksums[eps[1]]

	render := func(results map[string]*llx.RawResult) map[string]any {
		var buf bytes.Buffer
		require.NoError(t, CodeBundleToJSON(bundle, results, &iox.IOWriter{Writer: &buf}))
		var got map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &got), buf.String())
		return got
	}

	t.Run("complete results have no gaps key", func(t *testing.T) {
		got := render(map[string]*llx.RawResult{
			version: {CodeID: version, Data: &llx.RawData{Type: types.String, Value: "v14"}},
			build:   {CodeID: build, Data: &llx.RawData{Type: types.String, Value: "1"}},
		})
		assert.Equal(t, map[string]any{"mondoo.version": "v14", "mondoo.build": "1"}, got)
	})

	t.Run("gaps sit beside the values", func(t *testing.T) {
		got := render(map[string]*llx.RawResult{
			version: {CodeID: version, Data: &llx.RawData{
				Type: types.String, Value: "v14",
				CoverageGaps: []*llx.Error{llx.Forbidden(nil,
					llx.WithScope(llx.ErrorScope_ERROR_SCOPE_PARTITION, "eu-west-1"),
					llx.WithPermissions("mondoo:Read"))},
			}},
			build: {CodeID: build, Data: &llx.RawData{Type: types.String, Value: "1"}},
		})
		// The value keeps its shape; the gap is keyed by the value's label.
		assert.Equal(t, "v14", got["mondoo.version"])
		assert.Equal(t, "1", got["mondoo.build"])
		assert.Equal(t, map[string]any{"mondoo.version": []any{map[string]any{
			"kind": "forbidden", "scope": "partition", "scopeId": "eu-west-1",
			"permissions": []any{"mondoo:Read"},
		}}}, got[CoverageGapsKey])
	})
}

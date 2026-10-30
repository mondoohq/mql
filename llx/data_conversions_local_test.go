// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/types"
)

func Test_resolveValue(t *testing.T) {
	t.Run("map", func(t *testing.T) {
		mv := MapPrimitive(map[string]*Primitive{
			"foo": StringPrimitive("bar"),
		}, types.String)

		var b *blockExecutor
		data, _, err := b.resolveValue(mv, 0)
		require.NoError(t, err)
		require.Equal(t, map[string]any{"foo": "bar"}, data.Value)
	})
	t.Run("map with ref value", func(t *testing.T) {
		barRef, _ := StringPrimitive("bar").RefV2()
		mv := MapPrimitive(map[string]*Primitive{
			"foo": RefPrimitiveV2(barRef),
		}, types.Any)

		b := &blockExecutor{
			cache: &cache{
				data: map[uint64]*stepCache{
					barRef: {
						Result: &RawData{
							Type:  types.String,
							Value: "bar",
						},
					},
				},
			},
		}
		data, _, err := b.resolveValue(mv, 0)
		require.NoError(t, err)
		require.Equal(t, map[string]any{"foo": "bar"}, data.Value)
	})
}

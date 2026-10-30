// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

type expressionRuntime struct{ llx.Runtime }

func (*expressionRuntime) Schema() resources.ResourcesSchema {
	return &resources.Schema{Resources: map[string]*resources.ResourceInfo{}}
}

func TestRunWithContextStopsBetweenEntrypoints(t *testing.T) {
	for _, phase := range []string{"before", "callback", "complete"} {
		t.Run(phase, func(t *testing.T) {
			runtime := &expressionRuntime{}
			bundle, err := mqlc.Compile("true\nfalse", nil, mqlc.NewConfig(runtime.Schema(), mql.DefaultFeatures))
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var results []*llx.RawResult
			executor, err := llx.NewExecutorV2(bundle.CodeV2, runtime, nil, func(result *llx.RawResult) {
				results = append(results, result)
				if phase == "callback" {
					cancel()
				}
			})
			require.NoError(t, err)
			if phase == "before" {
				cancel()
			}
			err = executor.RunWithContext(ctx)
			if phase == "complete" {
				require.NoError(t, err)
				require.Len(t, results, 2)
			} else {
				require.ErrorIs(t, err, context.Canceled)
				if phase == "before" {
					require.Empty(t, results)
				} else {
					require.Len(t, results, 1)
				}
			}
		})
	}
}

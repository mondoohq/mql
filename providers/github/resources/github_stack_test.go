// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/google/go-github/v92/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestPullRequestStackFields(t *testing.T) {
	stackKeys := []string{
		"stackId", "stackNumber", "stackSize", "stackPosition",
		"stackBaseBranch", "stackBaseSha",
	}

	t.Run("pull request outside a stack reports null, not zero", func(t *testing.T) {
		fields := pullRequestStackFields(&github.PullRequest{})

		require.Len(t, fields, len(stackKeys))
		for _, k := range stackKeys {
			assert.Equal(t, llx.NilData, fields[k], "%s must be null when the PR is not stacked", k)
		}
	})

	t.Run("stacked pull request reports its position", func(t *testing.T) {
		fields := pullRequestStackFields(&github.PullRequest{
			Stack: &github.PullRequestStack{
				ID:       github.Ptr(int64(4210)),
				Number:   github.Ptr(7),
				Size:     github.Ptr(3),
				Position: github.Ptr(2),
				Base: &github.PullRequestStackBase{
					Ref: "main",
					SHA: "8e1f0c0a4d2b6f9c3a5e7d1b0f2c4a6e8d0b2f4a",
				},
			},
		})

		assert.Equal(t, int64(4210), fields["stackId"].Value)
		assert.Equal(t, int64(7), fields["stackNumber"].Value)
		assert.Equal(t, int64(3), fields["stackSize"].Value)
		assert.Equal(t, int64(2), fields["stackPosition"].Value)
		assert.Equal(t, "main", fields["stackBaseBranch"].Value)
		assert.Equal(t, "8e1f0c0a4d2b6f9c3a5e7d1b0f2c4a6e8d0b2f4a", fields["stackBaseSha"].Value)
	})

	// The bottom of a stack is position 1, so a policy asserting "reviewed in
	// order" must be able to tell position 1 from an unstacked PR. That only
	// works if the unstacked case is null rather than 0.
	t.Run("bottom of the stack is position 1", func(t *testing.T) {
		fields := pullRequestStackFields(&github.PullRequest{
			Stack: &github.PullRequestStack{Position: github.Ptr(1), Size: github.Ptr(2)},
		})

		assert.Equal(t, int64(1), fields["stackPosition"].Value)
		assert.NotEqual(t, llx.NilData, fields["stackPosition"])
	})

	t.Run("missing base leaves only the base fields null", func(t *testing.T) {
		fields := pullRequestStackFields(&github.PullRequest{
			Stack: &github.PullRequestStack{ID: github.Ptr(int64(9)), Size: github.Ptr(2)},
		})

		assert.Equal(t, int64(9), fields["stackId"].Value)
		assert.Equal(t, llx.NilData, fields["stackBaseBranch"])
		assert.Equal(t, llx.NilData, fields["stackBaseSha"])
	})

	// An absent counter inside a present stack must not silently become 0.
	t.Run("absent counters inside a present stack stay null", func(t *testing.T) {
		fields := pullRequestStackFields(&github.PullRequest{
			Stack: &github.PullRequestStack{ID: github.Ptr(int64(11))},
		})

		assert.Nil(t, fields["stackSize"].Value)
		assert.Nil(t, fields["stackPosition"].Value)
	})
}

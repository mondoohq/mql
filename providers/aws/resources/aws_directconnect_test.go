// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkPages(t *testing.T) {
	t.Run("a single page ends the walk", func(t *testing.T) {
		var seen []*string
		err := walkPages(func(nextToken *string) (*string, error) {
			seen = append(seen, nextToken)
			return nil, nil
		})
		require.NoError(t, err)
		require.Len(t, seen, 1)
		assert.Nil(t, seen[0], "the first page is requested with no token")
	})

	t.Run("every page is visited in order", func(t *testing.T) {
		tokens := []*string{aws.String("page2"), aws.String("page3"), nil}
		var seen []string
		call := 0

		err := walkPages(func(nextToken *string) (*string, error) {
			seen = append(seen, aws.ToString(nextToken))
			next := tokens[call]
			call++
			return next, nil
		})

		require.NoError(t, err)
		assert.Equal(t, []string{"", "page2", "page3"}, seen)
	})

	t.Run("an empty token ends the walk", func(t *testing.T) {
		calls := 0
		err := walkPages(func(nextToken *string) (*string, error) {
			calls++
			return aws.String(""), nil
		})
		require.NoError(t, err)
		assert.Equal(t, 1, calls, "an empty token means no more pages, not another page")
	})

	t.Run("a repeated token ends the walk", func(t *testing.T) {
		// A service that echoes back the token it was given would otherwise
		// re-collect the same page forever. The guard has to hold whether or
		// not the caller notices, so the walk must terminate on its own.
		calls := 0
		err := walkPages(func(nextToken *string) (*string, error) {
			calls++
			require.Less(t, calls, 10, "the walk did not terminate on a repeated token")
			return aws.String("stuck"), nil
		})
		require.NoError(t, err)
		assert.Equal(t, 2, calls, "the first page, then the page that repeated its token")
	})

	t.Run("an error stops the walk and propagates", func(t *testing.T) {
		boom := errors.New("throttled")
		calls := 0

		err := walkPages(func(nextToken *string) (*string, error) {
			calls++
			if calls == 2 {
				return nil, boom
			}
			return aws.String("page2"), nil
		})

		require.ErrorIs(t, err, boom)
		assert.Equal(t, 2, calls, "no page is fetched after the failure")
	})
}

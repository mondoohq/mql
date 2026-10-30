// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDelegatedServiceCacheKey(t *testing.T) {
	date := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	t.Run("with date", func(t *testing.T) {
		assert.Equal(t,
			"config.amazonaws.com/"+date.String(),
			delegatedServiceCacheKey("config.amazonaws.com", &date),
		)
	})

	t.Run("nil date does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			assert.Equal(t,
				"config.amazonaws.com",
				delegatedServiceCacheKey("config.amazonaws.com", nil),
			)
		})
	})
}

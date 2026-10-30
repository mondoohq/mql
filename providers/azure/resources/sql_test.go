// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestElasticPoolNameFromID(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		assert.Nil(t, elasticPoolNameFromID(nil))
	})
	t.Run("full ARM id returns last segment", func(t *testing.T) {
		id := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Sql/servers/srv/elasticPools/mypool"
		got := elasticPoolNameFromID(&id)
		assert.NotNil(t, got)
		assert.Equal(t, "mypool", *got)
	})
	t.Run("bare name returns itself", func(t *testing.T) {
		id := "mypool"
		got := elasticPoolNameFromID(&id)
		assert.NotNil(t, got)
		assert.Equal(t, "mypool", *got)
	})
	t.Run("empty string returns empty", func(t *testing.T) {
		id := ""
		got := elasticPoolNameFromID(&id)
		assert.NotNil(t, got)
		assert.Equal(t, "", *got)
	})
	t.Run("trailing slash returns empty last segment", func(t *testing.T) {
		id := "/subscriptions/sub/elasticPools/"
		got := elasticPoolNameFromID(&id)
		assert.NotNil(t, got)
		assert.Equal(t, "", *got)
	})
}

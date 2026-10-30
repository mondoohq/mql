// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEveryPlatformIsCataloged(t *testing.T) {
	for _, s := range SubAssets {
		assert.NotNil(t, PlatformByName(s.Platform), s.Platform)
	}
	assert.NotNil(t, PlatformByName("exoscale-organization"))
}

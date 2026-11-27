// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	memorydb_types "github.com/aws/aws-sdk-go-v2/service/memorydb/types"
	"github.com/stretchr/testify/assert"
)

func TestMemorydbDataTiering(t *testing.T) {
	assert.Equal(t, true, memorydbDataTiering(memorydb_types.DataTieringStatusTrue).Value)
	assert.Equal(t, false, memorydbDataTiering(memorydb_types.DataTieringStatusFalse).Value)
	// Synthetic: an unreported status is null, not false.
	assert.Nil(t, memorydbDataTiering("").Value)
}

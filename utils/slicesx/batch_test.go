// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package slicesx

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBatch(t *testing.T) {
	slice := []string{}
	for i := range 100 {
		slice = append(slice, fmt.Sprintf("item-%d", i))
	}

	batches := Batch(slice, 10)
	assert.Len(t, batches, 10)

	flattenedBatches := []string{}
	for _, batch := range batches {
		flattenedBatches = append(flattenedBatches, batch...)
	}
	assert.Equal(t, slice, flattenedBatches)
}

func TestBatch_Uneven(t *testing.T) {
	slice := []string{}
	for i := range 101 {
		slice = append(slice, fmt.Sprintf("item-%d", i))
	}

	batches := Batch(slice, 10)
	assert.Len(t, batches, 11)

	flattenedBatches := []string{}
	for _, batch := range batches {
		flattenedBatches = append(flattenedBatches, batch...)
	}
	assert.Equal(t, slice, flattenedBatches)
}

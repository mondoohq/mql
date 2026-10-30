// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package stringx_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/utils/stringx"
)

func TestIntersection(t *testing.T) {
	a := []string{"a", "b", "c"}
	b := []string{"b", "c", "d", "f"}

	actual := stringx.Intersection(a, b)
	expected := []string{"b", "c"}
	assert.ElementsMatch(t, actual, expected)
}

func TestIntersectionNoOverlap(t *testing.T) {
	a := []string{"a", "b", "c"}
	b := []string{"d", "f"}

	actual := stringx.Intersection(a, b)
	assert.Empty(t, actual)
}

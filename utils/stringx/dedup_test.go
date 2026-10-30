// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package stringx_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/utils/stringx"
)

func TestDedupStringArray(t *testing.T) {
	arr := []string{"a", "a", "b", "b", "c"}
	assert.ElementsMatch(t, []string{"a", "b", "c"}, stringx.DedupStringArray(arr))
}

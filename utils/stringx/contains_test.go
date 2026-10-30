// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package stringx_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/utils/stringx"
)

func TestContains(t *testing.T) {
	assert.True(t, stringx.Contains([]string{"ab", "aa"}, "ab"))
	assert.False(t, stringx.Contains([]string{"ab", "aa"}, "a"))
	assert.False(t, stringx.Contains([]string{"ab", "aa"}, "bs"))
	assert.True(t, stringx.Contains([]string{"hello", "world"}, "world"))
	assert.True(t, stringx.Contains([]string{"hello", "world"}, "hello"))
	assert.False(t, stringx.Contains([]string{"hello", "world"}, "john"))
}

func TestContainsAnyOf(t *testing.T) {
	assert.True(t, stringx.ContainsAnyOf([]string{"ab", "aa"}, "ab"))
	assert.False(t, stringx.ContainsAnyOf([]string{"ab", "aa"}, "a", "b"))
	assert.False(t, stringx.ContainsAnyOf([]string{"ab", "aa"}, "bs"))
	assert.True(t, stringx.ContainsAnyOf([]string{"hello", "world"}, "", "world"))
	assert.True(t, stringx.ContainsAnyOf([]string{"hello", "world"}, "hello", "world"))
	assert.False(t, stringx.ContainsAnyOf([]string{"hello", "world"}, "john"))
}

func TestRemoveEmpty(t *testing.T) {
	assert.Equal(t, []string{"aa"}, stringx.RemoveEmpty([]string{"", "aa"}))
	assert.Equal(t, []string{"aa"}, stringx.RemoveEmpty([]string{"aa", ""}))
	assert.Equal(t, []string{"aa", "ab"}, stringx.RemoveEmpty([]string{"", "aa", "", "ab", ""}))
}

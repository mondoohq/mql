// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package convert_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	subject "go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

func TestDictToMapStr_Int(t *testing.T) {
	input := map[string]any{
		"one": 1,
		"two": 2,
		"bad": "not-an-int",
	}
	expected := map[string]int{
		"one": 1,
		"two": 2,
	}

	output := subject.DictToTypedMap[int](input)
	assert.Equal(t, expected, output)
}

func TestDictToMapStr_String(t *testing.T) {
	input := map[string]any{
		"a": "hello",
		"b": "world",
		"c": 123, // Should be ignored
	}
	expected := map[string]string{
		"a": "hello",
		"b": "world",
	}

	output := subject.DictToTypedMap[string](input)
	assert.Equal(t, expected, output)
}

func TestDictToMapStr_EmptyInput(t *testing.T) {
	output := subject.DictToTypedMap[int](nil)
	assert.Empty(t, output)
}

func TestDictToMapStr_WrongType(t *testing.T) {
	input := map[string]any{
		"x": []int{1, 2, 3},
		"y": map[string]any{"nested": "value"},
	}
	output := subject.DictToTypedMap[string](input)
	assert.Empty(t, output)
}

func TestDictToMapStr_NonMapInput(t *testing.T) {
	output := subject.DictToTypedMap[int]("not a map")
	assert.Empty(t, output)
}

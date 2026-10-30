// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mapx_test

import (
	"testing"

	subject "go.mondoo.com/mql/utils/mapx"

	"github.com/stretchr/testify/assert"
)

func TestMerge(t *testing.T) {
	t.Run("map[string]int", func(t *testing.T) {
		tests := []struct {
			name     string
			m1, m2   map[string]int
			expected map[string]int
		}{
			{
				name:     "Merge with nil maps",
				m1:       map[string]int{"a": 1},
				m2:       nil,
				expected: map[string]int{"a": 1},
			},
			{
				name:     "Merge with no conflicts",
				m1:       map[string]int{"a": 1, "b": 2},
				m2:       map[string]int{"c": 3, "d": 4},
				expected: map[string]int{"a": 1, "b": 2, "c": 3, "d": 4},
			},
			{
				name:     "Merge with conflicts, prefer first map",
				m1:       map[string]int{"a": 10, "b": 20},
				m2:       map[string]int{"a": 1, "b": 2, "c": 3},
				expected: map[string]int{"a": 10, "b": 20, "c": 3},
			},
			{
				name:     "First map empty",
				m1:       map[string]int{},
				m2:       map[string]int{"x": 100, "y": 200},
				expected: map[string]int{"x": 100, "y": 200},
			},
			{
				name:     "Second map empty",
				m1:       map[string]int{"x": 100, "y": 200},
				m2:       map[string]int{},
				expected: map[string]int{"x": 100, "y": 200},
			},
			{
				name:     "Both maps empty",
				m1:       map[string]int{},
				m2:       map[string]int{},
				expected: map[string]int{},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := subject.Merge(tt.m1, tt.m2)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("map[string]string", func(t *testing.T) {
		tests := []struct {
			name     string
			m1, m2   map[string]string
			expected map[string]string
		}{
			{
				name:     "Merge with nil maps",
				m1:       nil,
				m2:       map[string]string{"a": "coco"},
				expected: map[string]string{"a": "coco"},
			},
			{
				name:     "Merge two non-empty maps with string keys",
				m1:       map[string]string{"a": "apple", "b": "banana"},
				m2:       map[string]string{"b": "BLUEBERRY", "c": "cherry"},
				expected: map[string]string{"a": "apple", "b": "banana", "c": "cherry"},
			},
			{
				name:     "Merge with an empty first map",
				m1:       map[string]string{},
				m2:       map[string]string{"a": "apple", "b": "banana"},
				expected: map[string]string{"a": "apple", "b": "banana"},
			},
			{
				name:     "Merge with an empty second map",
				m1:       map[string]string{"a": "apple", "b": "banana"},
				m2:       map[string]string{},
				expected: map[string]string{"a": "apple", "b": "banana"},
			},
			{
				name:     "Merge two empty maps",
				m1:       map[string]string{},
				m2:       map[string]string{},
				expected: map[string]string{},
			},
			{
				name:     "Merge two nil maps",
				m1:       nil,
				m2:       nil,
				expected: map[string]string{},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.expected, subject.Merge(tt.m1, tt.m2))
			})
		}
	})
}

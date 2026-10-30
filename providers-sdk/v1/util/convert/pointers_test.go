// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package convert_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	subject "go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

func TestPtr(t *testing.T) {
	t.Run("Pointer to int", func(t *testing.T) {
		value := 42
		ptr := new(value)
		assert.NotNil(t, ptr)
		assert.Equal(t, value, *ptr)
	})

	t.Run("Pointer to string", func(t *testing.T) {
		value := "test"
		ptr := new(value)
		assert.NotNil(t, ptr)
		assert.Equal(t, value, *ptr)
	})

	t.Run("Pointer to bool", func(t *testing.T) {
		value := true
		ptr := new(value)
		assert.NotNil(t, ptr)
		assert.Equal(t, value, *ptr)
	})

	t.Run("Pointer to float64", func(t *testing.T) {
		value := 3.14
		ptr := new(value)
		assert.NotNil(t, ptr)
		assert.Equal(t, value, *ptr)
	})

	t.Run("Pointer to struct", func(t *testing.T) {
		type Example struct {
			Field string
		}
		value := Example{Field: "value"}
		ptr := new(value)
		assert.NotNil(t, ptr)
		assert.Equal(t, value, *ptr)
	})

	t.Run("Pointer to slice", func(t *testing.T) {
		value := []int{1, 2, 3}
		ptr := new(value)
		assert.NotNil(t, ptr)
		assert.Equal(t, value, *ptr)
	})

	t.Run("Pointer to nil interface", func(t *testing.T) {
		var value any
		ptr := new(value)
		assert.NotNil(t, ptr)
		assert.Nil(t, *ptr)
	})
}

func TestValue(t *testing.T) {
	type custom struct {
		notempty bool
	}

	tests := []struct {
		name string
		ptr  any
		want any
	}{
		{"Nil int pointer", (*int)(nil), 0},
		{"Non-nil int pointer", new(42), 42},
		{"Nil string pointer", (*string)(nil), ""},
		{"Non-nil string pointer", new("hello"), "hello"},
		{"Nil float64 pointer", (*float64)(nil), 0.0},
		{"Non-nil float64 pointer", new(3.14), 3.14},
		{"Nil bool pointer", (*bool)(nil), false},
		{"Non-nil bool pointer", new(true), true},
		{"Nil custom struct pointer", (*custom)(nil), custom{}},
		{"Non-nil bool pointer", new(custom{true}), custom{true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.want.(type) {
			case int:
				assert.EqualValues(t, tt.want, subject.ToValue[int](tt.ptr.(*int)))
			case string:
				assert.EqualValues(t, tt.want, subject.ToValue[string](tt.ptr.(*string)))
			case float64:
				assert.EqualValues(t, tt.want, subject.ToValue[float64](tt.ptr.(*float64)))
			case bool:
				assert.EqualValues(t, tt.want, subject.ToValue[bool](tt.ptr.(*bool)))
			case custom:
				assert.EqualValues(t, tt.want, subject.ToValue[custom](tt.ptr.(*custom)))
			}
		})
	}
}

func TestToListFromPtrs(t *testing.T) {
	t.Run("list with valid pointers", func(t *testing.T) {
		a, b, c := 1, 2, 3
		ptrs := []*int{&a, &b, &c}
		result := subject.ToListFromPtrs(ptrs)
		assert.Equal(t, []int{1, 2, 3}, result)
	})

	t.Run("list with nil pointer elements", func(t *testing.T) {
		a, b := 10, 20
		ptrs := []*int{&a, nil, &b}
		result := subject.ToListFromPtrs(ptrs)
		assert.Equal(t, []int{10, 0, 20}, result) // `nil` should result in 0
	})

	t.Run("empty list", func(t *testing.T) {
		ptrs := []*int{}
		result := subject.ToListFromPtrs(ptrs)
		assert.Empty(t, result)
	})

	t.Run("nil input slice", func(t *testing.T) {
		var ptrs []*int
		result := subject.ToListFromPtrs(ptrs)
		assert.Nil(t, result)
	})

	t.Run("list of string pointers", func(t *testing.T) {
		a, b := "hello", "world"
		ptrs := []*string{&a, nil, &b}
		result := subject.ToListFromPtrs(ptrs)
		assert.Equal(t, []string{"hello", "", "world"}, result) // Default for string is ""
	})

	t.Run("list of struct pointers", func(t *testing.T) {
		type Person struct {
			Name string
			Age  int
		}
		p1 := Person{Name: "Alice", Age: 30}
		p2 := Person{Name: "Bob", Age: 25}
		ptrs := []*Person{&p1, nil, &p2}
		result := subject.ToListFromPtrs(ptrs)
		assert.Equal(t, []Person{
			{Name: "Alice", Age: 30},
			{},
			{Name: "Bob", Age: 25},
		}, result) // Default for struct is zero value
	})
}

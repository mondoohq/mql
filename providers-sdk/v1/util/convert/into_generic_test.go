// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package convert_test

import (
	"strconv"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/util/convert"

	"github.com/stretchr/testify/assert"
)

func TestInto(t *testing.T) {
	t.Run("Convert int to string", func(t *testing.T) {
		input := []int{1, 2, 3, 4, 5}
		output := convert.Into(input, func(i int) string {
			return strconv.Itoa(i)
		})
		expected := []string{"1", "2", "3", "4", "5"}
		assert.Equal(t, expected, output)
	})

	t.Run("Convert float64 to string", func(t *testing.T) {
		input := []float64{1.1, 2.2, 3.3}
		output := convert.Into(input, func(f float64) string {
			return strconv.FormatFloat(f, 'f', 1, 64)
		})
		expected := []string{"1.1", "2.2", "3.3"}
		assert.Equal(t, expected, output)
	})

	t.Run("Convert struct to string", func(t *testing.T) {
		type Person struct {
			Name string
		}
		input := []Person{{"Alice"}, {"Bob"}, {"Charlie"}}
		output := convert.Into(input, func(p Person) string {
			return p.Name
		})
		expected := []string{"Alice", "Bob", "Charlie"}
		assert.Equal(t, expected, output)
	})

	t.Run("Convert string to int", func(t *testing.T) {
		input := []string{"10", "20", "30"}
		output := convert.Into(input, func(s string) int {
			i, _ := strconv.Atoi(s)
			return i
		})
		expected := []int{10, 20, 30}
		assert.Equal(t, expected, output)
	})

	t.Run("Convert bool to string", func(t *testing.T) {
		input := []bool{true, false, true}
		output := convert.Into(input, func(b bool) string {
			return strconv.FormatBool(b)
		})
		expected := []string{"true", "false", "true"}
		assert.Equal(t, expected, output)
	})

	t.Run("Handle empty slice", func(t *testing.T) {
		input := []int{}
		output := convert.Into(input, func(i int) string {
			return strconv.Itoa(i)
		})
		expected := []string{}
		assert.Equal(t, expected, output)
	})

	t.Run("Handle nil slice", func(t *testing.T) {
		var input []int
		output := convert.Into(input, func(i int) string {
			return strconv.Itoa(i)
		})
		assert.Empty(t, output)
	})

	t.Run("Identity function", func(t *testing.T) {
		input := []string{"apple", "banana", "cherry"}
		output := convert.Into(input, func(s string) string {
			return s
		})
		expected := []string{"apple", "banana", "cherry"}
		assert.Equal(t, expected, output)
	})

	t.Run("Convert complex numbers to string", func(t *testing.T) {
		input := []complex128{1 + 2i, 3 + 4i}
		output := convert.Into(input, func(c complex128) string {
			return strconv.FormatComplex(c, 'f', 1, 128)
		})
		expected := []string{"(1.0+2.0i)", "(3.0+4.0i)"}
		assert.Equal(t, expected, output)
	})

	t.Run("Convert nested struct", func(t *testing.T) {
		type Outer struct {
			Inner struct {
				Value string
			}
		}
		input := []Outer{
			{Inner: struct{ Value string }{"one"}},
			{Inner: struct{ Value string }{"two"}},
		}
		output := convert.Into(input, func(o Outer) string {
			return o.Inner.Value
		})
		expected := []string{"one", "two"}
		assert.Equal(t, expected, output)
	})
}

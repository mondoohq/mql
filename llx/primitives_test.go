// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/types"
)

func init() {
	logger.InitTestEnv()
}

func TestPrimitiveBool(t *testing.T) {
	a := &Primitive{Type: string(types.Bool), Value: bool2bytes(true)}
	b := &Primitive{Type: string(types.Bool), Value: bool2bytes(false)}
	assert.Equal(t, a, BoolPrimitive(true))
	assert.Equal(t, b, BoolPrimitive(false))
}

func TestPrimitiveFloat(t *testing.T) {
	a := &Primitive{Type: string(types.Float), Value: []byte{0x9a, 0x99, 0x99, 0x99, 0x99, 0x99, 0x28, 0x40}}
	assert.Equal(t, a, FloatPrimitive(12.3))
}

func TestPrimitiveInt(t *testing.T) {
	a := &Primitive{Type: string(types.Int), Value: []byte{0xf6, 0x01}}
	assert.Equal(t, a, IntPrimitive(123))
}

func TestPrimitiveString(t *testing.T) {
	a := &Primitive{Type: string(types.String), Value: []byte("hi")}
	assert.Equal(t, a, StringPrimitive("hi"))
}

func TestPrimitiveRegex(t *testing.T) {
	a := &Primitive{Type: string(types.Regex), Value: []byte(".*")}
	assert.Equal(t, a, RegexPrimitive(".*"))
}

func TestPrimitiveTime(t *testing.T) {
	a := &Primitive{Type: string(types.Time), Value: []byte{0x15, 0xcd, 0x5b, 0x07, 0x00, 0x00, 0x00, 0x00, 0x15, 0xcd, 0x5b, 0x07}}
	ut := time.Unix(123456789, 123456789)
	assert.Equal(t, a, TimePrimitive(&ut))

	assert.Equal(t, NilPrimitive, TimePrimitive(nil))
}

func TestPrimitiveArray(t *testing.T) {
	a := &Primitive{Type: string(types.Array(types.Int)), Array: []*Primitive{IntPrimitive(123)}}
	assert.Equal(t, a, ArrayPrimitive([]*Primitive{IntPrimitive(123)}, types.Int))
}

func TestPrimitiveMap(t *testing.T) {
	a := &Primitive{Type: string(types.Map(types.String, types.Int)), Map: map[string]*Primitive{"a": IntPrimitive(123)}}
	assert.Equal(t, a, MapPrimitive(map[string]*Primitive{"a": IntPrimitive(123)}, types.Int))
}

func TestPrimitiveFunction(t *testing.T) {
	a := &Primitive{
		Type:  string(types.Function(0, nil)),
		Value: []byte{0xf6, 0x01},
	}
	assert.Equal(t, a, FunctionPrimitiveV1(123))
}

func TestPrimitiveNil(t *testing.T) {
	t.Run("nil type", func(t *testing.T) {
		p := &Primitive{
			Type: string(types.Nil),
		}
		assert.True(t, p.IsNil())
	})

	t.Run("string without value is an empty string (not nil)", func(t *testing.T) {
		p := &Primitive{
			Type: string(types.String),
		}
		assert.False(t, p.IsNil())
	})

	t.Run("string with value is not nil", func(t *testing.T) {
		p := StringPrimitive("hi")
		assert.False(t, p.IsNil())
	})

	t.Run("map type without value is empty map (not nil)", func(t *testing.T) {
		p := MapPrimitive(nil, types.Int)
		assert.False(t, p.IsNil())
	})

	t.Run("map type with empty value is not nil", func(t *testing.T) {
		p := MapPrimitive(map[string]*Primitive{}, types.Int)
		assert.False(t, p.IsNil())
	})

	t.Run("array type without value is empty array (not nil)", func(t *testing.T) {
		p := ArrayPrimitive(nil, types.Int)
		assert.False(t, p.IsNil())
	})

	t.Run("array type with empty value is not nil", func(t *testing.T) {
		p := ArrayPrimitive([]*Primitive{}, types.Int)
		assert.False(t, p.IsNil())
	})
}

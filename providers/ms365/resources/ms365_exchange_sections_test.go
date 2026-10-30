// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

func TestIsAbsentSection(t *testing.T) {
	var typedNilSlice []any
	var typedNilMap map[string]any
	var boxedTypedNil any = typedNilSlice

	tests := []struct {
		name string
		in   any
		want bool
	}{
		{"untyped nil", nil, true},
		{"typed nil slice", typedNilSlice, true},
		{"typed nil slice boxed in any", boxedTypedNil, true},
		{"typed nil map", typedNilMap, true},
		{"nil pointer", (*ExchangeOnlineReport)(nil), true},
		{"empty but non-nil slice", []any{}, false},
		{"empty but non-nil map", map[string]any{}, false},
		{"populated slice", []any{"x"}, false},
		{"scalar", "value", false},
		{"zero scalar", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isAbsentSection(tc.in))
		})
	}
}

// The whole point: a section that RAN and matched nothing must stay an empty
// list, while a section that never ran must read null.
//
// The converter cannot make that distinction for us -- it returns no error
// either way -- so the caller has to test the report field itself. Marking the
// field set-but-not-null is what turns "never collected" into a confident "none
// found" on the wire.
func TestExchangeNullableListDistinguishesAbsentFromEmpty(t *testing.T) {
	t.Run("absent section reads null", func(t *testing.T) {
		var absent []any
		data, err := convert.JsonToDictSlice(absent)
		assert.NoError(t, err, "an absent section converts without error, which is why it looks legitimate")

		// what the previous code did with that value
		old := plugin.TValue[[]any]{Data: data, State: plugin.StateIsSet, Error: err}
		assert.True(t, old.State&plugin.StateIsNull == 0,
			"the old assignment marked the field set-and-not-null, so it rendered as []")

		v := exchangeNullableList(isAbsentSection(absent), data, err)
		assert.True(t, v.State&plugin.StateIsNull != 0, "must be null")
		assert.True(t, v.State&plugin.StateIsSet != 0, "must also be marked set")
	})

	t.Run("section that ran with no results reads empty", func(t *testing.T) {
		ran := []any{}
		data, err := convert.JsonToDictSlice(ran)
		v := exchangeNullableList(isAbsentSection(ran), data, err)
		assert.True(t, v.State&plugin.StateIsNull == 0, "must NOT be null")
		assert.Empty(t, v.Data)
	})

	t.Run("populated section keeps its data", func(t *testing.T) {
		v := exchangeNullableList(false, []any{"a", "b"}, nil)
		assert.Len(t, v.Data, 2)
		assert.True(t, v.State&plugin.StateIsNull == 0)
	})

	t.Run("conversion error is preserved", func(t *testing.T) {
		boom := errors.New("decode failed")
		v := exchangeNullableList(false, nil, boom)
		assert.Equal(t, boom, v.Error)
	})
}

func TestExchangeNullableDict(t *testing.T) {
	t.Run("absent section reads null", func(t *testing.T) {
		var absent any
		data, err := convert.JsonToDict(absent)
		assert.NoError(t, err, "an absent section converts without error, which is why it looks legitimate")

		old := plugin.TValue[any]{Data: data, State: plugin.StateIsSet, Error: err}
		assert.True(t, old.State&plugin.StateIsNull == 0,
			"the old assignment marked the field set-and-not-null, so it rendered as {}")

		v := exchangeNullableDict(isAbsentSection(absent), data, err)
		assert.True(t, v.State&plugin.StateIsNull != 0)
	})

	t.Run("present section keeps its data", func(t *testing.T) {
		v := exchangeNullableDict(false, map[string]any{"k": "v"}, nil)
		assert.Equal(t, map[string]any{"k": "v"}, v.Data)
		assert.True(t, v.State&plugin.StateIsNull == 0)
	})
}

// A derived bool is the most dangerous of the three: false is a legitimate
// value, so an absent section reporting false is indistinguishable from a real
// answer. unifiedAuditLogIngestionEnabled is exactly that field.
func TestExchangeNullableBool(t *testing.T) {
	t.Run("absent section reads null, not false", func(t *testing.T) {
		v := exchangeNullableBool(true, false, nil)
		assert.True(t, v.State&plugin.StateIsNull != 0,
			"an uncollected section must not report false as fact")
	})

	t.Run("present false is reported", func(t *testing.T) {
		v := exchangeNullableBool(false, false, nil)
		assert.True(t, v.State&plugin.StateIsNull == 0)
		assert.False(t, v.Data)
	})

	t.Run("present true is reported", func(t *testing.T) {
		v := exchangeNullableBool(false, true, nil)
		assert.True(t, v.Data)
	})
}

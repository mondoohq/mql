// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type psItem struct {
	Name  string
	Value *string
}

func TestUnmarshalList(t *testing.T) {
	one := "x"
	cases := []struct {
		name string
		in   string
		want []psItem
	}{
		{"null", "null", []psItem{}},
		{"empty object", "{}", []psItem{}},
		{"empty array", "[]", []psItem{}},
		{"array", `[{"Name":"a"},{"Name":"b"}]`, []psItem{{Name: "a"}, {Name: "b"}}},
		// ConvertTo-Json unrolls a one-element collection into a bare object.
		{"single object", `{"Name":"a"}`, []psItem{{Name: "a"}}},
		{"calculated property wrapper", `{"value":[{"Name":"a"}],"Count":1}`, []psItem{{Name: "a"}}},
		{"wrapper, other casing", `{"Value":[{"Name":"a"},{"Name":"b"}]}`, []psItem{{Name: "a"}, {Name: "b"}}},
		{"empty wrapper", `{"value":null,"Count":0}`, []psItem{}},
		{"wrapper single object", `{"value":{"Name":"a"},"Count":1}`, []psItem{{Name: "a"}}},
		// An element whose own property is called Value is not a wrapper.
		{"element with a Value property", `{"Name":"a","Value":"x"}`, []psItem{{Name: "a", Value: &one}}},
		{"element with a null Value property", `{"Name":"a","Value":null}`, []psItem{{Name: "a"}}},
		// Without a Count, an object whose only property is Value is an element.
		{"element with only a Value property", `{"Value":"x"}`, []psItem{{Value: &one}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := UnmarshalList[psItem]([]byte(c.in))
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestUnmarshalListErrors(t *testing.T) {
	for _, in := range []string{"", " \r\n "} {
		_, err := UnmarshalList[psItem]([]byte(in))
		assert.ErrorIs(t, err, ErrNoOutput, "empty output means the command failed, not an empty list")
	}
	_, err := UnmarshalList[psItem]([]byte(`[{"Name":`))
	assert.Error(t, err)
	_, err = UnmarshalList[psItem]([]byte(`{"Name":1}`))
	assert.Error(t, err, "a type mismatch in the single element is an error, not an empty list")
}

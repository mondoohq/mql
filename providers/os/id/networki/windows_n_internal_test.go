// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networki

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalPowershellObjects(t *testing.T) {
	t.Run("array of objects", func(t *testing.T) {
		list, err := unmarshalPowershellObjects(`[{"InterfaceAlias":"Ethernet0"},{"InterfaceAlias":"Ethernet1"}]`)
		require.NoError(t, err)
		require.Len(t, list, 2)
		assert.Equal(t, "Ethernet0", list[0]["InterfaceAlias"])
		assert.Equal(t, "Ethernet1", list[1]["InterfaceAlias"])
	})

	t.Run("bare object", func(t *testing.T) {
		// ConvertTo-Json drops the array wrapper when the pipeline produced a
		// single item, which is what a one-interface host reports.
		list, err := unmarshalPowershellObjects(`{"InterfaceAlias":"Ethernet0"}`)
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, "Ethernet0", list[0]["InterfaceAlias"])
	})

	t.Run("leading whitespace", func(t *testing.T) {
		list, err := unmarshalPowershellObjects("\r\n    {\r\n  \"InterfaceAlias\": \"Ethernet0\"\r\n}")
		require.NoError(t, err)
		require.Len(t, list, 1)
	})

	t.Run("empty output", func(t *testing.T) {
		_, err := unmarshalPowershellObjects("")
		assert.Error(t, err)
	})

	t.Run("not json", func(t *testing.T) {
		_, err := unmarshalPowershellObjects("Get-NetIPInterface : Access is denied.")
		assert.Error(t, err)
	})

	t.Run("json scalar", func(t *testing.T) {
		_, err := unmarshalPowershellObjects(`"Ethernet0"`)
		assert.Error(t, err)
	})
}

func TestCleanIPString(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{"plain ipv4", "192.168.5.38", "192.168.5.38"},
		{"plain ipv6", "2001:db8::1", "2001:db8::1"},
		{"ipconfig preferred suffix", "192.168.5.38(Preferred)", "192.168.5.38"},
		{"link-local with zone index", "fe80::869:1f7d:a331:f3e1%4", "fe80::869:1f7d:a331:f3e1"},
		{"isatap with zone index", "fe80::5efe:172.17.2.72%6", "fe80::5efe:172.17.2.72"},
		{"zone index and preferred suffix", "fe80::bc2b:599c:b679:ca2d%5(Preferred)", "fe80::bc2b:599c:b679:ca2d"},
		{"surrounding whitespace", "  192.168.5.38  ", "192.168.5.38"},
		{"empty", "", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, cleanIPString(test.ip))
		})
	}
}

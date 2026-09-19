// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package domainlist

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseInventory(t *testing.T) {
	f, err := os.Open("./testdata/input.txt")
	assert.Nil(t, err)
	defer f.Close()

	obj, err := Parse(f)
	require.NoError(t, err)
	assert.Equal(t, obj.Hosts, []string{"example.com:443", "my-example.com:4443", "sub.example.com:8443", "my-example.com:8443", "anotherdomain.com"})

	out := obj.ToV1Inventory()
	assert.Equal(t, 5, len(out.Spec.Assets))
	assert.Equal(t, "example.com:443", out.Spec.Assets[0].Name)
	assert.Equal(t, "example.com", out.Spec.Assets[0].Connections[0].Host)
	assert.Equal(t, int32(443), out.Spec.Assets[0].Connections[0].Port)
	assert.Equal(t, "host", out.Spec.Assets[0].Connections[0].Type)

	// a domainlist line is a target, not a name its author chose. Leaving it
	// unmarked is what lets a provider replace `example.com:443` with the
	// normalized name it computes after connecting.
	assert.False(t, out.Spec.Assets[0].NameOverride)
}

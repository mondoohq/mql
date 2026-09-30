// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networkinterface_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/networkinterface"
)

func TestParseNetAdapterSingleObject(t *testing.T) {
	h := &networkinterface.WindowsInterfaceHandler{}
	list, err := h.ParseNetAdapter(strings.NewReader(`{"Name":"Ethernet","ifIndex":6,"InterfaceType":6,"Status":"Up","MacAddress":"0A-1B-2C-3D-4E-5F"}`))
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "Ethernet", list[0].Name)
	assert.Equal(t, 6, list[0].IfIndex)

	list, err = h.ParseNetAdapter(strings.NewReader("null"))
	require.NoError(t, err)
	assert.Empty(t, list)
}

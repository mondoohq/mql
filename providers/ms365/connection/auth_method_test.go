// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// TestNewMs365Connection_InvalidAuthMethod asserts that an unusable auth-method
// is reported before anything reaches the network. NewMs365Connection signs in
// and then probes the Graph API to validate the connection, so the parse has to
// come first for the failure to be about the option rather than about
// connectivity — and so this test can run offline.
func TestNewMs365Connection_InvalidAuthMethod(t *testing.T) {
	_, err := NewMs365Connection(0, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			OptionTenantID:   "tid",
			OptionClientID:   "cid",
			OptionAuthMethod: "service-principal",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "service-principal")
}

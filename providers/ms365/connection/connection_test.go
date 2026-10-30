// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build debugtest
// +build debugtest

package connection

import (
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"os"
	"testing"
)

func TestMs365(t *testing.T) {
	cred := &vault.Credential{
		Type:           vault.CredentialType_pkcs12,
		PrivateKeyPath: "/Users/chris/tmph5uvp4s4.pem",
	}

	data, err := os.ReadFile(cred.PrivateKeyPath)
	require.NoError(t, err)
	cred.Secret = data

	conn, err := NewMs365Connection(0, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{
			OptionTenantID: "<tenant_id>",
			OptionClientID: "<client_id>",
		},
		Credentials: []*vault.Credential{cred},
	})
	require.NoError(t, err)
	require.NotNil(t, conn)

}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build debugtest
// +build debugtest

package winrm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func TestWinrmConnection(t *testing.T) {
	cred := &vault.Credential{
		Type:     vault.CredentialType_password,
		User:     "administrator",
		Password: "<your_pwd>",
	}
	cred.PreProcess()

	conn, err := NewConnection(0, &inventory.Config{
		Type:        shared.Type_Winrm.String(),
		Host:        "192.168.1.111",
		Credentials: []*vault.Credential{cred},
		Insecure:    true,
	}, nil)
	require.NoError(t, err)
	assert.NotNil(t, conn)

}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build debugtest
// +build debugtest

package connection

import (
	"context"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestSlackProvider(t *testing.T) {

	cred := &vault.Credential{
		Type:     vault.CredentialType_password,
		Password: "<slack-token>",
	}
	cred.PreProcess()

	conn, err := NewSlackConnection(1, &inventory.Asset{}, &inventory.Config{
		Type:        "slack",
		Credentials: []*vault.Credential{cred},
	})
	require.NoError(t, err)

	client := conn.Client()
	ctx := context.Background()
	users, err := client.GetUsersContext(ctx, slack.GetUsersOptionLimit(999))
	require.NoError(t, err)
	require.NotNil(t, users)
}

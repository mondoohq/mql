// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build debugtest
// +build debugtest

package gcpsecretmanager

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestGcpSecretmanager(t *testing.T) {
	projectID := "mondoo-dev-262313"
	v := New(projectID)
	ctx := context.Background()

	key := "mondoo-test-secret-key"
	cred := &vault.Secret{
		Key:    key,
		Secret: []byte("super-secret"),
	}

	id, err := v.Set(ctx, cred)
	require.NoError(t, err)

	newCred, err := v.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, cred, newCred)
}

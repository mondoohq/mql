// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package multivault

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers-sdk/v1/vault/inmemory"
)

func TestMultiVault(t *testing.T) {
	secret1 := &vault.Secret{
		Key:  "secret1",
		Data: []byte("password"),
	}
	secret2 := &vault.Secret{
		Key:  "secret2",
		Data: []byte("password2"),
	}
	secret3 := &vault.Secret{
		Key:  "secret3",
		Data: []byte("password3"),
	}

	ctx := context.Background()
	var err error

	v1 := inmemory.New()
	_, err = v1.Set(ctx, secret1)
	require.NoError(t, err)

	v2 := inmemory.New()
	_, err = v2.Set(ctx, secret2)
	require.NoError(t, err)

	m := New(v1, v2)

	var sec *vault.Secret
	sec, err = m.Get(ctx, &vault.SecretID{
		Key: secret1.Key,
	})
	require.NoError(t, err)
	assert.Equal(t, secret1, sec)

	sec, err = m.Get(ctx, &vault.SecretID{
		Key: secret2.Key,
	})
	require.NoError(t, err)
	assert.Equal(t, secret2, sec)

	_, err = m.Get(ctx, &vault.SecretID{
		Key: secret3.Key,
	})
	require.Error(t, err)
}

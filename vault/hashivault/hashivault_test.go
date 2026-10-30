// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build debugtest
// +build debugtest

package hashivault

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestHashiVault(t *testing.T) {
	endpoint := "http://127.0.0.1:8200"
	token := "secretgoeshere"

	// store secret
	c, err := client(endpoint, token)
	require.NoError(t, err)
	ctx := context.Background()

	key := "test-key"
	fields := map[string]string{
		"key":  "value",
		"key2": "value2",
	}
	v := New(endpoint, token)
	id, err := set(v, c, key, fields)
	require.NoError(t, err)

	// get secret
	newCred, err := v.Get(ctx, id)
	require.NoError(t, err)

	jsonSecret := make(map[string]string)
	err = json.Unmarshal(newCred.Data, &jsonSecret)
	require.NoError(t, err)

	assert.Equal(t, jsonSecret, fields)
}

func client(endpoint string, token string) (*api.Client, error) {
	c, err := api.NewClient(&api.Config{
		Address: endpoint,
	})
	if err != nil {
		return nil, err
	}
	if token != "" {
		c.SetToken(token)
	}
	return c, nil
}

func set(v *Vault, c *api.Client, key string, fields map[string]string) (*vault.SecretID, error) {
	err := validKey(key)
	if err != nil {
		return nil, err
	}

	// convert creds fields to vault struct
	// TODO: we could store labels as part of the content fields, may not look as nice
	// see https://github.com/hashicorp/vault/issues/7905
	data := map[string]any{}
	for k, v := range fields {
		data[k] = v
	}

	// encapsulate data into v2 secrets api
	secretData := map[string]any{
		"data": data,
	}

	// store secret
	_, err = c.Logical().Write(v.secretPath(key), secretData)
	if err != nil {
		return nil, err
	}

	return &vault.SecretID{Key: key}, nil
}

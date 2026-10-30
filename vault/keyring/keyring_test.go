// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package keyring

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestEncryptedFile(t *testing.T) {
	v := NewEncryptedFile("./testdata", "mondoo", "superpassword")
	ctx := context.Background()

	credSecret := map[string]string{
		"key":  "value",
		"key2": "value2",
	}
	credBytes, err := json.Marshal(credSecret)
	require.NoError(t, err)

	key := "mondoo-test-secret-key"
	cred := &vault.Secret{
		Key:   key,
		Label: "mondoo: " + key,
		Data:  credBytes,
	}

	id, err := v.Set(ctx, cred)
	require.NoError(t, err)

	// create a new instance to test file reading
	v2 := NewEncryptedFile("./testdata", "mondoo", "superpassword")

	newCred, err := v2.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, key, newCred.Key)
	assert.Equal(t, cred.Label, newCred.Label)
	assert.Equal(t, cred.Data, newCred.Data)
}

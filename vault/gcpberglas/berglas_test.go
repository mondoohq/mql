// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gcpberglas

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestGcpBerglas(t *testing.T) {
	t.Skip("Skip test as it requires actual GCP project and bucket")

	// replace with actual values to test this
	projectID := "project-id-here"
	bucketName := " bucket-name"
	v := New(projectID)
	ctx := context.Background()

	cred := &vault.Secret{
		Data: []byte("my-secret-data"),
		Key:  fmt.Sprintf("storage/%s/foo", bucketName),
	}
	_, err := v.Set(ctx, cred)
	require.NoError(t, err)
	get, err := v.Get(ctx, &vault.SecretID{Key: cred.Key})
	require.NoError(t, err)
	assert.Equal(t, cred.Data, get.Data)

	cred.Data = []byte("my-even-more-secret-data")
	_, err = v.Set(ctx, cred)
	require.NoError(t, err)
	get, err = v.Get(ctx, &vault.SecretID{Key: cred.Key})
	require.NoError(t, err)
	assert.Equal(t, cred.Data, get.Data)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build debugtest
// +build debugtest

package awsparameterstore

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestAwsParameterStore(t *testing.T) {
	os.Setenv("AWS_PROFILE", "mondoo-dev")
	os.Setenv("AWS_REGION", "us-east-1")
	cfg, err := config.LoadDefaultAWSConfig()
	require.NoError(t, err)
	v := New(cfg)
	ctx := context.Background()

	key := "mondoo-test-secret-key"
	cred := &vault.Credential{
		Key: key,
		Fields: map[string]string{
			"key":  "value1",
			"key2": "value2",
		},
	}

	id, err := v.Set(ctx, cred)
	require.NoError(t, err)

	newCred, err := v.Get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, cred, newCred)
}

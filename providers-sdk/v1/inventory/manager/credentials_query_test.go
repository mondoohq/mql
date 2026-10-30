// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package manager_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/inventory/manager"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

var runtime llx.Runtime

func init() {
	runtime = testutils.LinuxMock()
}

func TestSecretKeySimple(t *testing.T) {
	query := `{ type: 'ssh_agent' }`
	runner, err := manager.NewCredentialQueryRunner(query, runtime)
	require.NoError(t, err)
	cred, err := runner.Run(&inventory.Asset{})
	require.NoError(t, err)
	assert.Equal(t, vault.CredentialType_ssh_agent, cred.Type)
}

func TestSecretKeyIfReturn(t *testing.T) {
	query := `
		if (props.labels['key'] == 'value') {
			return {type: 'password', secret_id: 'theonekey'}
		}
		return {type: 'private_key', secret_id: 'otherkey'}
	`

	runner, err := manager.NewCredentialQueryRunner(query, runtime)
	require.NoError(t, err)

	cred, err := runner.Run(&inventory.Asset{
		Labels: map[string]string{
			"key": "value",
		},
	})
	require.NoError(t, err)

	assert.Equal(t, vault.CredentialType_password, cred.Type)
	assert.Equal(t, "theonekey", cred.SecretId)
}

func TestSecretKeyIfConditionalReturn(t *testing.T) {
	query := `
		if (props.labels['Name'] == 'ssh') { 
	       return { user: 'ec2-user', type: 'private_key', secret_id: 'arn:aws:secretsmanager:us-east-2:172746783610:secret:vj/secret-lHvP9r'}
        }
        return { secret_id: '' }"
	`

	runner, err := manager.NewCredentialQueryRunner(query, runtime)
	require.NoError(t, err)

	// check with provided label
	cred, err := runner.Run(&inventory.Asset{
		Labels: map[string]string{
			"Name": "ssh",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, vault.CredentialType_private_key, cred.Type)
	assert.Equal(t, "arn:aws:secretsmanager:us-east-2:172746783610:secret:vj/secret-lHvP9r", cred.SecretId)

	// check without a label
	cred, err = runner.Run(&inventory.Asset{
		Labels: map[string]string{},
	})
	require.NoError(t, err)
	assert.Equal(t, vault.CredentialType_undefined, cred.Type)
	assert.Equal(t, "", cred.SecretId)
}

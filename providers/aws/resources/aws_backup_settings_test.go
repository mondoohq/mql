// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackupGlobalSettingBool(t *testing.T) {
	settings := map[string]string{
		"isCrossAccountBackupEnabled": "true",
		"isMpaEnabled":                "false",
		"isBroken":                    "maybe",
	}
	got := backupGlobalSettingBool(settings, "isCrossAccountBackupEnabled")
	require.NotNil(t, got)
	assert.True(t, *got)
	got = backupGlobalSettingBool(settings, "isMpaEnabled")
	require.NotNil(t, got)
	assert.False(t, *got)
	assert.Nil(t, backupGlobalSettingBool(settings, "isDelegatedAdministratorEnabled"), "an absent setting is null, not false")
	assert.Nil(t, backupGlobalSettingBool(settings, "isBroken"))
}

func TestBackupVaultAccountFromArn(t *testing.T) {
	assert.Equal(t, "210987654321", backupVaultAccountFromArn("arn:aws:backup:us-east-1:210987654321:backup-vault:lag-vault"))
	assert.Empty(t, backupVaultAccountFromArn("lag-vault"))
}

func TestBackupVaultArgsCarryVaultTypeAndState(t *testing.T) {
	args := backupVaultArgs(&backup.DescribeBackupVaultOutput{
		BackupVaultArn:    aws.String("arn:aws:backup:us-east-1:123456789012:backup-vault:restore"),
		BackupVaultName:   aws.String("restore"),
		VaultType:         backuptypes.VaultTypeRestoreAccessBackupVault,
		VaultState:        backuptypes.VaultStateAvailable,
		EncryptionKeyType: backuptypes.EncryptionKeyTypeAwsOwnedKmsKey,
	}, "us-east-1")
	assert.Equal(t, "RESTORE_ACCESS_BACKUP_VAULT", args["vaultType"].Value)
	assert.Equal(t, "AVAILABLE", args["vaultState"].Value)
	assert.Equal(t, "AWS_OWNED_KMS_KEY", args["encryptionKeyType"].Value)

	empty := backupVaultArgs(&backup.DescribeBackupVaultOutput{}, "us-east-1")
	assert.Nil(t, empty["vaultType"].Value, "an unreported vault type is null")
}

func TestBackupVaultSourceVaultFromSeededDetail(t *testing.T) {
	rt := testRuntime()
	v := &mqlAwsBackupVault{MqlRuntime: rt, Name: setString("plain"), Region: setString("us-east-1")}
	v.detail = &backup.DescribeBackupVaultOutput{MpaApprovalTeamArn: aws.String("arn:aws:mpa:us-east-1:123456789012:approval-team/t1")}
	v.detailFetched = true

	src, err := v.sourceBackupVault()
	require.NoError(t, err)
	assert.Nil(t, src)
	assert.True(t, v.SourceBackupVault.IsNull(), "a vault without a source reads null")

	team, err := v.mpaApprovalTeamArn()
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:mpa:us-east-1:123456789012:approval-team/t1", team)
	_, err = v.mpaSessionArn()
	require.NoError(t, err)
	assert.True(t, v.MpaSessionArn.IsNull())
}

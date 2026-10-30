// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestIsEncryptedBackup(t *testing.T) {
	for stmt, want := range map[string]bool{
		"BACKUP INTO 'nodelocal://1/b1' WITH OPTIONS (encryption_passphrase = '*****', detached)":           true,
		"BACKUP INTO 's3://bucket/x' WITH OPTIONS (KMS = 'aws:///arn:aws:kms:us-east-1:1:key/2', detached)": true,
		"BACKUP INTO 'nodelocal://1/b2' WITH OPTIONS (detached)":                                            false,
		"BACKUP INTO 'nodelocal://1/kms_backups' WITH OPTIONS (detached)":                                   false,
	} {
		if got := isEncryptedBackup(stmt); got != want {
			t.Errorf("isEncryptedBackup(%q) = %v, want %v", stmt, got, want)
		}
	}
}

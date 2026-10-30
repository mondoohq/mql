// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gcpberglas

import (
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func init() {
	vault.Register(vault.VaultType_GCPBerglas, func(cfg *vault.VaultConfiguration) (vault.Vault, error) {
		projectID := cfg.Options["project-id"]
		kmsKeyID := cfg.Options["kms-key-id"]
		bucketName := cfg.Options["bucket-name"]
		opts := []Option{}
		if kmsKeyID != "" {
			opts = append(opts, WithKmsKey(kmsKeyID))
		}
		if bucketName != "" {
			opts = append(opts, WithBucket(bucketName))
		}
		return New(projectID, opts...), nil
	})
}

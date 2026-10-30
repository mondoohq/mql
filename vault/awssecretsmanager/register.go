// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awssecretsmanager

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func init() {
	vault.Register(vault.VaultType_AWSSecretsManager, func(cfg *vault.VaultConfiguration) (vault.Vault, error) {
		// TODO: do we really want to load it from the env?
		awsCfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, errors.Wrap(err, "cannot not determine aws environment")
		}
		return New(awsCfg), nil
	})
}

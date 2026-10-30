// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awssecretsmanager

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

type Option func(*Vault)

func New(cfg aws.Config, opts ...Option) *Vault {
	v := &Vault{
		cfg: cfg.Copy(),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

func WithKmsKey(kmsKeyID string) Option {
	return func(v *Vault) {
		v.kmsKeyID = kmsKeyID
	}
}

type Vault struct {
	cfg      aws.Config
	kmsKeyID string
}

func (v *Vault) About(context.Context, *vault.Empty) (*vault.VaultInfo, error) {
	return &vault.VaultInfo{Name: "AWS Secrets Manager"}, nil
}

func (v *Vault) Get(ctx context.Context, id *vault.SecretID) (*vault.Secret, error) {
	// create the client
	parsedArn, err := arn.Parse(id.Key)
	if err != nil {
		return nil, err
	}
	cfg := v.cfg.Copy()
	cfg.Region = parsedArn.Region
	c := secretsmanager.NewFromConfig(cfg)

	// retrieve secret
	log.Debug().Str("secret-id", id.Key).Msg("getting cred from aws secrets manager")
	out, err := c.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &id.Key,
	})
	if err != nil {
		log.Debug().Err(err).Str("secret-id", id.Key).Msg("could not retrieve secret from aws secret manager")
		return nil, vault.NotFoundError
	}

	// NOTE: we cannot use out.SecretBinary since it is not guaranteed to be set
	var data []byte
	if out.SecretString != nil {
		data = []byte(*out.SecretString)
	} else {
		data = out.SecretBinary
	}

	return &vault.Secret{
		Key:  id.Key,
		Data: data,
		// we do not know the encoding here, but the default is binary
		Encoding: vault.SecretEncoding_encoding_binary,
	}, nil
}

func (v *Vault) Set(ctx context.Context, cred *vault.Secret) (*vault.SecretID, error) {
	var kmsKeyID *string
	if len(v.kmsKeyID) > 0 {
		kmsKeyID = &v.kmsKeyID
	}

	c := secretsmanager.NewFromConfig(v.cfg)
	o, err := c.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         &cred.Key,
		SecretBinary: cred.Data,
		KmsKeyId:     kmsKeyID,
	})
	if err != nil {
		if _, ok := errors.AsType[*types.ResourceExistsException](err); ok {
			return v.updateSecret(ctx, cred)
		}

		return nil, err
	}

	return &vault.SecretID{Key: *o.ARN}, err
}

func (v *Vault) Delete(ctx context.Context, id *vault.SecretID) (*vault.Empty, error) {
	return nil, vault.NotImplementedError
}

func (v *Vault) updateSecret(ctx context.Context, cred *vault.Secret) (*vault.SecretID, error) {
	var kmsKeyID *string
	if len(v.kmsKeyID) > 0 {
		kmsKeyID = &v.kmsKeyID
	}

	c := secretsmanager.NewFromConfig(v.cfg)
	o, err := c.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{
		SecretBinary: cred.Data,
		KmsKeyId:     kmsKeyID,
	})
	if err != nil {
		return nil, err
	}

	return &vault.SecretID{Key: *o.ARN}, err
}

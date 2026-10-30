// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsparameterstore

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

var notImplemented = errors.New("not implemented") //nolint:unused

// https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html
// https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameter.html
func New(cfg aws.Config) *Vault {
	return &Vault{
		cfg: cfg,
	}
}

type Vault struct {
	cfg aws.Config
}

func (v *Vault) About(context.Context, *vault.Empty) (*vault.VaultInfo, error) {
	return &vault.VaultInfo{Name: "AWS Parameter Store"}, nil
}

// arn:aws:ssm:us-east-2:123456789012:parameter/prod-*
func (v *Vault) Get(ctx context.Context, id *vault.SecretID) (*vault.Secret, error) {
	// create the client
	parsedArn, err := arn.Parse(id.Key)
	if err != nil {
		return nil, err
	}
	cfg := v.cfg.Copy()
	cfg.Region = parsedArn.Region
	c := ssm.NewFromConfig(cfg)

	name := strings.TrimPrefix(parsedArn.Resource, "parameter/")
	// retrieve secret
	out, err := c.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return nil, vault.NotFoundError
	}

	var data []byte
	if out != nil && out.Parameter != nil {
		v := *out.Parameter.Value
		data = []byte(v)
	}

	return &vault.Secret{
		Key:  id.Key,
		Data: data,
		// we do not know the encoding here, but the default is binary
		Encoding: vault.SecretEncoding_encoding_binary,
	}, nil
}

func (v *Vault) Set(ctx context.Context, cred *vault.Secret) (*vault.SecretID, error) {
	return nil, errors.New("not implemented")
}

func (v *Vault) Delete(ctx context.Context, id *vault.SecretID) (*vault.Empty, error) {
	return nil, vault.NotImplementedError
}

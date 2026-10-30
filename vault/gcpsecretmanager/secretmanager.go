// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gcpsecretmanager

import (
	"context"
	"errors"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/utils/multierr"
)

// https://cloud.google.com/security/products/secret-manager
// https://docs.cloud.google.com/secret-manager/docs/reference/libraries#client-libraries-install-go
func New(projectID string) *Vault {
	return &Vault{
		projectID: projectID,
	}
}

type Vault struct {
	projectID string
}

func (v *Vault) About(context.Context, *vault.Empty) (*vault.VaultInfo, error) {
	return &vault.VaultInfo{Name: "GCP Secret Manager: " + v.projectID}, nil
}

// Dial gets a Vault client.
func (v *Vault) client(ctx context.Context) (*secretmanager.Client, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, multierr.Wrap(err, "failed to setup gcp secret manager client")
	}
	return client, nil
}

// we need to remove the leading // from mrns, this should not be done here, therefore we just throw an error
func validKey(key string) error {
	if strings.HasPrefix(key, "/") {
		return errors.New("leading / are not allowed")
	}
	return nil
}

// gcp does not support / in strings which we heavily use
// 😤 secret names can only contain english letters (A-Z), numbers (0-9), dashes (-), and underscores (_)
// therefore we cannot use url encode and we need to fallback to an unsafe mechanism where we may
// run into issues of two keys matching the same value, lets not maintain a mapping table for now
// since we do not allow "list" a one-way transformation is okay for now
func gcpKeyID(key string) string {
	gcpKey := strings.ReplaceAll(key, "/", "-")
	gcpKey = strings.ReplaceAll(gcpKey, ".", "-")
	return gcpKey
}

func (v *Vault) Get(ctx context.Context, id *vault.SecretID) (*vault.Secret, error) {
	err := validKey(id.Key)
	if err != nil {
		return nil, err
	}

	c, err := v.client(ctx)
	if err != nil {
		return nil, err
	}

	// retrieve secret metadata
	result, err := c.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", v.projectID, gcpKeyID(id.Key)),
	})
	if err != nil {
		return nil, vault.NotFoundError
	}

	return &vault.Secret{
		Key:  id.Key,
		Data: result.Payload.Data,
	}, nil
}

func (v *Vault) Set(ctx context.Context, cred *vault.Secret) (*vault.SecretID, error) {
	return nil, errors.New("not implemented")
}

func (v *Vault) Delete(ctx context.Context, id *vault.SecretID) (*vault.Empty, error) {
	return nil, vault.NotImplementedError
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gcpberglas

import (
	"context"
	"errors"
	"fmt"
	"strings"

	berglas "github.com/GoogleCloudPlatform/berglas/v2/pkg/berglas"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/utils/multierr"
)

type storageType string

type Option func(*Vault)

const cloudStorage storageType = "storage"

// https://github.com/GoogleCloudPlatform/berglas
func New(projectID string, opts ...Option) *Vault {
	v := &Vault{projectID: projectID}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

func WithBucket(bucket string) Option {
	return func(v *Vault) {
		v.bucket = bucket
		v.storageType = cloudStorage
	}
}

func WithKmsKey(kmsKeyID string) Option {
	return func(v *Vault) {
		v.kmsKeyID = kmsKeyID
	}
}

type berglasStorageInfo struct {
	bucket string
	object string
}

type Vault struct {
	projectID   string
	storageType storageType
	kmsKeyID    string
	bucket      string
}

func (v *Vault) About(context.Context, *vault.Empty) (*vault.VaultInfo, error) {
	return &vault.VaultInfo{Name: "GCP Berglas: " + v.projectID}, nil
}

func (v *Vault) client(ctx context.Context) (*berglas.Client, error) {
	client, err := berglas.New(ctx)
	if err != nil {
		return nil, multierr.Wrap(err, "failed to setup gcp berglas client")
	}
	return client, nil
}

// expected berglas key format: {storage}/{bucketName}/{objectName}
func getBerglasStorageInfo(key string) (berglasStorageInfo, error) {
	split := strings.Split(key, "/")
	if len(split) != 3 {
		return berglasStorageInfo{}, errors.New("invalid berglas key provided")
	}
	// we omit storage for now, as berglas secrets manager is not yet supported
	// however, the key contains the type as to not break any existing keys if we add support in the future
	return berglasStorageInfo{
		bucket: split[1],
		object: split[2],
	}, nil
}

func (v *Vault) assembleBerglasKeyId(key string) (string, error) {
	if v.storageType == cloudStorage {
		return fmt.Sprintf("%s/%s/%s", v.storageType, v.bucket, key), nil
	}
	return "", errors.New("invalid berglas storage type")
}

func (v *Vault) Get(ctx context.Context, id *vault.SecretID) (*vault.Secret, error) {
	c, err := v.client(ctx)
	if err != nil {
		return nil, err
	}

	berglasReadInfo, err := getBerglasStorageInfo(id.Key)
	if err != nil {
		return nil, err
	}

	result, err := c.Read(ctx, &berglas.StorageReadRequest{
		Bucket: berglasReadInfo.bucket,
		Object: berglasReadInfo.object,
	})
	if err != nil {
		return nil, vault.NotFoundError
	}

	return &vault.Secret{
		Key:  id.Key,
		Data: result.Plaintext,
		// we do not know the encoding here, but the default is binary
		Encoding: vault.SecretEncoding_encoding_binary,
	}, nil
}

func (v *Vault) Delete(ctx context.Context, id *vault.SecretID) (*vault.Empty, error) {
	c, err := v.client(ctx)
	if err != nil {
		return nil, err
	}

	berglasInfo, err := getBerglasStorageInfo(id.Key)
	if err != nil {
		return nil, err
	}

	err = c.Delete(ctx, &berglas.StorageDeleteRequest{
		Bucket: berglasInfo.bucket,
		Object: berglasInfo.object,
	})
	if err != nil {
		return nil, err
	}

	return &vault.Empty{}, nil
}

func (v *Vault) Set(ctx context.Context, cred *vault.Secret) (*vault.SecretID, error) {
	if len(v.kmsKeyID) == 0 {
		return nil, errors.New("specified KMS key id is empty")
	}

	if len(v.storageType) == 0 {
		return nil, errors.New("cannot create vault secret without a storage type")
	}

	if len(v.bucket) == 0 && v.storageType == cloudStorage {
		return nil, errors.New("specified bucket name is empty")
	}

	c, err := v.client(ctx)
	if err != nil {
		return nil, err
	}

	// assemble the berglas key that will be used to get this secret
	// it uses the storage type and the passed in key to build a key
	key, err := v.assembleBerglasKeyId(cred.Key)
	if err != nil {
		return nil, err
	}

	_, err = c.Update(ctx, &berglas.StorageUpdateRequest{
		Bucket:          v.bucket,
		Object:          cred.Key,
		Plaintext:       cred.Data,
		Key:             v.kmsKeyID,
		CreateIfMissing: true,
	})
	if err != nil {
		return nil, err
	}
	return &vault.SecretID{
		Key: key,
	}, nil
}

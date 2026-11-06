// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	datasynctypes "github.com/aws/aws-sdk-go-v2/service/datasync/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocationTypeFromUri(t *testing.T) {
	// Synthetic: URI shapes from the DataSync API reference; no target showed these.
	assert.Equal(t, "azure-blob", locationTypeFromUri("azure-blob://acct.blob.core.windows.net/container/"))
	assert.Equal(t, "object-storage", locationTypeFromUri("object-storage://storage.googleapis.com/bucket/"))
	assert.Equal(t, "", locationTypeFromUri("not-a-uri"))
}

func TestDatasyncSecretArn(t *testing.T) {
	// Synthetic: a location carries one secret config; each is read.
	assert.Equal(t, "managed", datasyncSecretArn(&datasynctypes.ManagedSecretConfig{SecretArn: aws.String("managed")}, nil, nil))
	assert.Equal(t, "cmk", datasyncSecretArn(nil, &datasynctypes.CmkSecretConfig{SecretArn: aws.String("cmk")}, nil))
	assert.Equal(t, "custom", datasyncSecretArn(nil, nil, &datasynctypes.CustomSecretConfig{SecretArn: aws.String("custom")}))
	// Synthetic: an empty config (KMS key only, secret not yet created) is no secret.
	assert.Equal(t, "", datasyncSecretArn(&datasynctypes.ManagedSecretConfig{}, &datasynctypes.CmkSecretConfig{KmsKeyArn: aws.String("k")}, nil))
	assert.Equal(t, "", datasyncSecretArn(nil, nil, nil))
}

func TestAzureBlobLocationAuth(t *testing.T) {
	t.Run("federated identity", func(t *testing.T) {
		// Synthetic: OIDC location shape from the v1.69.0 SDK types; no target showed this.
		auth := azureBlobLocationAuth(&datasync.DescribeLocationAzureBlobOutput{
			AuthenticationType: datasynctypes.AzureBlobAuthenticationTypeOidc,
			FederatedIdentity: &datasynctypes.AzureFederatedIdentityConfig{
				AwsIamRole: aws.String("arn:aws:iam::111122223333:role/datasync-federated"),
				AzureOidc: &datasynctypes.AzureOidcConfig{
					ClientId: aws.String("client-1"),
					TenantId: aws.String("tenant-1"),
				},
			},
		})
		require.NotNil(t, auth.authenticationType)
		assert.Equal(t, "OIDC", *auth.authenticationType)
		assert.Equal(t, "arn:aws:iam::111122223333:role/datasync-federated", auth.roleArn)
		assert.Equal(t, "", auth.secretArn)
		assert.Equal(t, map[string]any{"azureOidc": map[string]any{"clientId": "client-1", "tenantId": "tenant-1"}}, auth.federatedIdentity)
	})

	t.Run("stored SAS token", func(t *testing.T) {
		// Synthetic: SAS location with a DataSync-managed secret.
		auth := azureBlobLocationAuth(&datasync.DescribeLocationAzureBlobOutput{
			AuthenticationType:  datasynctypes.AzureBlobAuthenticationTypeSas,
			ManagedSecretConfig: &datasynctypes.ManagedSecretConfig{SecretArn: aws.String("arn:aws:secretsmanager:us-east-1:111122223333:secret:sas")},
		})
		require.NotNil(t, auth.authenticationType)
		assert.Equal(t, "SAS", *auth.authenticationType)
		assert.Equal(t, "arn:aws:secretsmanager:us-east-1:111122223333:secret:sas", auth.secretArn)
		assert.Equal(t, "", auth.roleArn)
		assert.Nil(t, auth.federatedIdentity)
	})

	t.Run("absent authentication type stays null", func(t *testing.T) {
		// Synthetic: no authentication type in the response.
		auth := azureBlobLocationAuth(&datasync.DescribeLocationAzureBlobOutput{})
		assert.Nil(t, auth.authenticationType)
		assert.Nil(t, auth.federatedIdentity)
		assert.Nil(t, azureBlobLocationAuth(nil).authenticationType)
	})
}

func TestObjectStorageLocationAuth(t *testing.T) {
	t.Run("federated identity", func(t *testing.T) {
		// Synthetic: Google Cloud Storage OIDC location shape from the v1.69.0 SDK types.
		auth := objectStorageLocationAuth(&datasync.DescribeLocationObjectStorageOutput{
			FederatedIdentity: &datasynctypes.ObjectStorageFederatedIdentityConfig{
				AwsIamRole: aws.String("arn:aws:iam::111122223333:role/gcs"),
				ExternalIdentity: &datasynctypes.ObjectStorageExternalIdentityConfig{
					GoogleOidc: &datasynctypes.GoogleOidcConfig{
						IdentityPoolName:     aws.String("pool"),
						IdentityProviderName: aws.String("provider"),
						ProjectName:          aws.String("project"),
						ProjectNumber:        aws.String("123456789"),
					},
				},
			},
		})
		assert.Nil(t, auth.authenticationType)
		assert.Equal(t, "arn:aws:iam::111122223333:role/gcs", auth.roleArn)
		assert.Equal(t, map[string]any{"googleOidc": map[string]any{
			"identityPoolName":     "pool",
			"identityProviderName": "provider",
			"projectName":          "project",
			"projectNumber":        "123456789",
		}}, auth.federatedIdentity)
	})

	t.Run("stored secret key", func(t *testing.T) {
		// Synthetic: access key location with a customer-supplied secret.
		auth := objectStorageLocationAuth(&datasync.DescribeLocationObjectStorageOutput{
			AccessKey:          aws.String("AKIAEXAMPLE"),
			CustomSecretConfig: &datasynctypes.CustomSecretConfig{SecretArn: aws.String("arn:aws:secretsmanager:us-east-1:111122223333:secret:key")},
		})
		assert.Equal(t, "arn:aws:secretsmanager:us-east-1:111122223333:secret:key", auth.secretArn)
		assert.Equal(t, "", auth.roleArn)
		assert.Nil(t, auth.federatedIdentity)
	})

	t.Run("role without external identity", func(t *testing.T) {
		// Synthetic: federated config carrying only the role.
		auth := objectStorageLocationAuth(&datasync.DescribeLocationObjectStorageOutput{
			FederatedIdentity: &datasynctypes.ObjectStorageFederatedIdentityConfig{AwsIamRole: aws.String("r")},
		})
		assert.Equal(t, "r", auth.roleArn)
		assert.Nil(t, auth.federatedIdentity)
	})
}

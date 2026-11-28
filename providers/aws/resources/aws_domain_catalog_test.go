// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	es_types "github.com/aws/aws-sdk-go-v2/service/elasticsearchservice/types"
	opensearch_types "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCatalogKey = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"

// Synthetic: catalog shapes from the API model; no live domain publishing to a catalog was scanned.
func TestOpensearchDomainCatalog(t *testing.T) {
	t.Run("no catalog options", func(t *testing.T) {
		c := opensearchDomainCatalog(nil)
		assert.False(t, c.enabled)
		assert.Nil(t, c.catalogType)
		assert.Nil(t, c.encryptionEnabled)
		assert.Empty(t, c.kmsKeyArn)
	})

	t.Run("disabled catalog reports nothing about it", func(t *testing.T) {
		c := opensearchDomainCatalog(&opensearch_types.CatalogOptions{
			Enabled: aws.Bool(false),
			Catalog: &opensearch_types.CatalogConfigurationMemberServiceManagedS3Tables{},
		})
		assert.False(t, c.enabled)
		assert.Nil(t, c.catalogType)
		assert.Nil(t, c.encryptionEnabled)
	})

	t.Run("S3 Tables catalog with a customer-managed key", func(t *testing.T) {
		c := opensearchDomainCatalog(&opensearch_types.CatalogOptions{
			Enabled: aws.Bool(true),
			Catalog: &opensearch_types.CatalogConfigurationMemberServiceManagedS3Tables{
				Value: opensearch_types.ServiceManagedS3TablesCatalog{
					EncryptionConfiguration: &opensearch_types.S3TablesEncryptionConfiguration{
						Enabled:   aws.Bool(true),
						KmsKeyArn: aws.String(testCatalogKey),
					},
				},
			},
		})
		assert.True(t, c.enabled)
		require.NotNil(t, c.catalogType)
		assert.Equal(t, "ServiceManagedS3Tables", *c.catalogType)
		require.NotNil(t, c.encryptionEnabled)
		assert.True(t, *c.encryptionEnabled)
		assert.Equal(t, testCatalogKey, c.kmsKeyArn)
	})

	t.Run("S3 Tables catalog without encryption settings", func(t *testing.T) {
		c := opensearchDomainCatalog(&opensearch_types.CatalogOptions{
			Enabled: aws.Bool(true),
			Catalog: &opensearch_types.CatalogConfigurationMemberServiceManagedS3Tables{},
		})
		require.NotNil(t, c.encryptionEnabled)
		assert.False(t, *c.encryptionEnabled)
		assert.Empty(t, c.kmsKeyArn)
	})

	t.Run("encryption flag set but key disabled", func(t *testing.T) {
		c := opensearchDomainCatalog(&opensearch_types.CatalogOptions{
			Enabled: aws.Bool(true),
			Catalog: &opensearch_types.CatalogConfigurationMemberServiceManagedS3Tables{
				Value: opensearch_types.ServiceManagedS3TablesCatalog{
					EncryptionConfiguration: &opensearch_types.S3TablesEncryptionConfiguration{
						Enabled:   aws.Bool(false),
						KmsKeyArn: aws.String(testCatalogKey),
					},
				},
			},
		})
		require.NotNil(t, c.encryptionEnabled)
		assert.False(t, *c.encryptionEnabled)
		assert.Empty(t, c.kmsKeyArn)
	})

	t.Run("catalog kind the SDK does not know", func(t *testing.T) {
		c := opensearchDomainCatalog(&opensearch_types.CatalogOptions{
			Enabled: aws.Bool(true),
			Catalog: &opensearch_types.UnknownUnionMember{Tag: "glueCatalog"},
		})
		require.NotNil(t, c.catalogType)
		assert.Equal(t, "glueCatalog", *c.catalogType)
	})

	t.Run("enabled with no catalog member", func(t *testing.T) {
		c := opensearchDomainCatalog(&opensearch_types.CatalogOptions{Enabled: aws.Bool(true)})
		assert.True(t, c.enabled)
		assert.Nil(t, c.catalogType)
	})
}

// Synthetic: the Elasticsearch API carries the same catalog model under its own types.
func TestEsDomainCatalog(t *testing.T) {
	assert.False(t, esDomainCatalog(nil).enabled)

	c := esDomainCatalog(&es_types.CatalogOptions{
		Enabled: aws.Bool(true),
		Catalog: &es_types.CatalogConfigurationMemberServiceManagedS3Tables{
			Value: es_types.ServiceManagedS3TablesCatalog{
				EncryptionConfiguration: &es_types.S3TablesEncryptionConfiguration{
					Enabled:   aws.Bool(true),
					KmsKeyArn: aws.String(testCatalogKey),
				},
			},
		},
	})
	assert.True(t, c.enabled)
	require.NotNil(t, c.catalogType)
	assert.Equal(t, "ServiceManagedS3Tables", *c.catalogType)
	assert.Equal(t, testCatalogKey, c.kmsKeyArn)

	args := c.args()
	assert.Equal(t, true, args["catalogEnabled"].Value)
	assert.Equal(t, "ServiceManagedS3Tables", args["catalogType"].Value)
	assert.Equal(t, true, args["catalogEncryptionEnabled"].Value)

	off := domainCatalog{}.args()
	assert.Equal(t, false, off["catalogEnabled"].Value)
	assert.Nil(t, off["catalogType"].Value)
	assert.Nil(t, off["catalogEncryptionEnabled"].Value)
}

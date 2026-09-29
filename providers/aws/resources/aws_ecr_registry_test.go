// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEcrSigningRulesToDicts(t *testing.T) {
	assert.Equal(t, []any{}, ecrSigningRulesToDicts(nil))

	got := ecrSigningRulesToDicts(&ecrtypes.SigningConfiguration{
		Rules: []ecrtypes.SigningRule{{
			SigningProfileArn: aws.String("arn:aws:signer:us-east-1:123456789012:/signing-profiles/prod"),
			RepositoryFilters: []ecrtypes.SigningRepositoryFilter{{
				Filter:     aws.String("prod-*"),
				FilterType: ecrtypes.SigningRepositoryFilterTypeWildcardMatch,
			}},
		}},
	})
	require.Len(t, got, 1)
	rule := got[0].(map[string]any)
	assert.Equal(t, "arn:aws:signer:us-east-1:123456789012:/signing-profiles/prod", rule["signingProfileArn"])
	assert.Equal(t, []any{map[string]any{"filter": "prod-*", "filterType": "WILDCARD_MATCH"}}, rule["repositoryFilters"])
}

func TestEcrRepositoryCreationTemplateEncryption(t *testing.T) {
	rt := testRuntime()
	tpl, err := newMqlEcrRepositoryCreationTemplate(rt, "us-east-1", "123456789012", ecrtypes.RepositoryCreationTemplate{
		Prefix:     aws.String("ROOT"),
		AppliedFor: []ecrtypes.RCTAppliedFor{ecrtypes.RCTAppliedForPullThroughCache},
		EncryptionConfiguration: &ecrtypes.EncryptionConfigurationForRepositoryCreationTemplate{
			EncryptionType: ecrtypes.EncryptionTypeKms,
			KmsKey:         aws.String("arn:aws:kms:us-east-1:123456789012:key/k"),
		},
		ImageTagMutability: ecrtypes.ImageTagMutabilityImmutable,
		ResourceTags:       []ecrtypes.Tag{{Key: aws.String("team"), Value: aws.String("sec")}},
	})
	require.NoError(t, err)
	assert.Equal(t, "KMS", tpl.EncryptionType.Data)
	assert.Equal(t, "IMMUTABLE", tpl.ImageTagMutability.Data)
	assert.Equal(t, []any{"PULL_THROUGH_CACHE"}, tpl.AppliedFor.Data)
	assert.Equal(t, map[string]any{"team": "sec"}, tpl.ResourceTags.Data)
	require.NotNil(t, tpl.cacheKmsKey)
	assert.Equal(t, "arn:aws:kms:us-east-1:123456789012:key/k", *tpl.cacheKmsKey)

	plain, err := newMqlEcrRepositoryCreationTemplate(rt, "us-east-1", "123456789012", ecrtypes.RepositoryCreationTemplate{
		Prefix: aws.String("team-a"),
	})
	require.NoError(t, err)
	assert.True(t, plain.EncryptionType.IsNull(), "no encryption configuration reads null")
	assert.Nil(t, plain.cacheKmsKey)
	assert.NotEqual(t, tpl.__id, plain.__id)
}

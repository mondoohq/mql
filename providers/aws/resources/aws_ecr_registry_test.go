// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
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

func TestNewMqlEcrScanningConfigurationPerRegion(t *testing.T) {
	rt := testRuntime()

	// The same account can scan with Amazon Inspector in one region and only
	// with basic scanning in another; each region is its own configuration.
	enhanced, err := newMqlEcrScanningConfiguration(rt, "eu-west-1", &ecr.GetRegistryScanningConfigurationOutput{
		RegistryId: aws.String("123456789012"),
		ScanningConfiguration: &ecrtypes.RegistryScanningConfiguration{
			ScanType: ecrtypes.ScanTypeEnhanced,
			Rules: []ecrtypes.RegistryScanningRule{{
				ScanFrequency: ecrtypes.ScanFrequencyContinuousScan,
				RepositoryFilters: []ecrtypes.ScanningRepositoryFilter{{
					Filter:     aws.String("*"),
					FilterType: ecrtypes.ScanningRepositoryFilterTypeWildcard,
				}},
			}},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, enhanced)

	basic, err := newMqlEcrScanningConfiguration(rt, "us-east-1", &ecr.GetRegistryScanningConfigurationOutput{
		RegistryId: aws.String("123456789012"),
		ScanningConfiguration: &ecrtypes.RegistryScanningConfiguration{
			ScanType: ecrtypes.ScanTypeBasic,
			Rules: []ecrtypes.RegistryScanningRule{{
				ScanFrequency: ecrtypes.ScanFrequencyScanOnPush,
				RepositoryFilters: []ecrtypes.ScanningRepositoryFilter{{
					Filter:     aws.String("prod-*"),
					FilterType: ecrtypes.ScanningRepositoryFilterTypeWildcard,
				}},
			}},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, basic)

	assert.Equal(t, "eu-west-1", enhanced.Region.Data)
	assert.Equal(t, "123456789012", enhanced.RegistryId.Data)
	assert.Equal(t, "ENHANCED", enhanced.ScanType.Data)
	assert.Equal(t, "us-east-1", basic.Region.Data)
	assert.Equal(t, "BASIC", basic.ScanType.Data)
	assert.NotEqual(t, enhanced.__id, basic.__id, "configurations of different regions must not share an id")

	require.Len(t, enhanced.Rules.Data, 1)
	require.Len(t, basic.Rules.Data, 1)
	enhancedRule := enhanced.Rules.Data[0].(*mqlAwsEcrScanningConfigurationRule)
	basicRule := basic.Rules.Data[0].(*mqlAwsEcrScanningConfigurationRule)
	assert.Equal(t, "CONTINUOUS_SCAN", enhancedRule.ScanFrequency.Data)
	assert.Equal(t, []any{map[string]any{"filter": "*", "filterType": "WILDCARD"}}, enhancedRule.RepositoryFilters.Data)
	assert.Equal(t, "SCAN_ON_PUSH", basicRule.ScanFrequency.Data)
	assert.NotEqual(t, enhancedRule.__id, basicRule.__id, "rules of different regions must not share an id")
}

func TestNewMqlEcrScanningConfigurationEmpty(t *testing.T) {
	rt := testRuntime()
	res, err := newMqlEcrScanningConfiguration(rt, "us-east-1", nil)
	require.NoError(t, err)
	assert.Nil(t, res)

	res, err = newMqlEcrScanningConfiguration(rt, "us-east-1", &ecr.GetRegistryScanningConfigurationOutput{
		RegistryId: aws.String("123456789012"),
	})
	require.NoError(t, err)
	assert.Nil(t, res)
}

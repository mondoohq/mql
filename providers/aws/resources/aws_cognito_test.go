// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cognitoidentityprovidertypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/stretchr/testify/assert"
)

// TestCognitoUserPoolArn pins the ARN shape the listing path and the reference
// resolver share. It is also the pool's __id, so the two have to agree or a
// sub-resource's userPool reference misses the cache and re-fetches.
func TestCognitoUserPoolArn(t *testing.T) {
	assert.Equal(t,
		"arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_AbCdEf",
		cognitoUserPoolArn("us-east-1", "123456789012", "us-east-1_AbCdEf"))
}

func TestCognitoAcrConfigurationToMap(t *testing.T) {
	t.Run("absent configuration stays nil", func(t *testing.T) {
		assert.Nil(t, cognitoAcrConfigurationToMap(nil))
	})

	t.Run("flattens level to ACR value", func(t *testing.T) {
		got := cognitoAcrConfigurationToMap(map[string]cognitoidentityprovidertypes.AcrLevelConfigType{
			"Level1": {AcrValue: aws.String("urn:example:acr:low")},
			"Level3": {AcrValue: aws.String("urn:example:acr:high")},
		})
		assert.Equal(t, map[string]any{
			"Level1": "urn:example:acr:low",
			"Level3": "urn:example:acr:high",
		}, got)
	})

	t.Run("level without a value is skipped", func(t *testing.T) {
		got := cognitoAcrConfigurationToMap(map[string]cognitoidentityprovidertypes.AcrLevelConfigType{
			"Level1": {AcrValue: aws.String("urn:example:acr:low")},
			"Level2": {},
		})
		assert.Equal(t, map[string]any{"Level1": "urn:example:acr:low"}, got)
	})
}

func TestCognitoAcrMappingData(t *testing.T) {
	t.Run("unset mapping is null", func(t *testing.T) {
		assert.Nil(t, cognitoAcrMappingData(nil).Value)
	})

	t.Run("mapping keeps level to provider value", func(t *testing.T) {
		got := cognitoAcrMappingData(map[string]string{"Level2": "urn:idp:mfa"})
		assert.Equal(t, map[string]any{"Level2": "urn:idp:mfa"}, got.Value)
	})

	t.Run("empty mapping is empty, not null", func(t *testing.T) {
		got := cognitoAcrMappingData(map[string]string{})
		assert.Equal(t, map[string]any{}, got.Value)
	})
}

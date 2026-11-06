// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	bacctypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/stretchr/testify/assert"
)

func TestPolicyDefinitionOf(t *testing.T) {
	// Synthetic: one definition per union member.
	kind, stmt := policyDefinitionOf(&bacctypes.PolicyDefinitionMemberCedar{
		Value: bacctypes.CedarPolicy{Statement: aws.String(`permit(principal, action, resource);`)},
	})
	assert.Equal(t, "cedar", kind)
	assert.Equal(t, `permit(principal, action, resource);`, aws.ToString(stmt))

	kind, stmt = policyDefinitionOf(&bacctypes.PolicyDefinitionMemberPolicy{
		Value: bacctypes.PolicyStatement{Statement: aws.String(`forbid(principal, action, resource);`)},
	})
	assert.Equal(t, "policy", kind)
	assert.Equal(t, `forbid(principal, action, resource);`, aws.ToString(stmt))

	kind, stmt = policyDefinitionOf(&bacctypes.PolicyDefinitionMemberPolicyGeneration{
		Value: bacctypes.PolicyGenerationDetails{PolicyGenerationId: aws.String("gen-1")},
	})
	assert.Equal(t, "policyGeneration", kind)
	assert.Nil(t, stmt)

	kind, stmt = policyDefinitionOf(nil)
	assert.Empty(t, kind)
	assert.Nil(t, stmt)
}

func TestTokenVaultKey(t *testing.T) {
	// Synthetic: customer-managed key.
	kt, keyArn := tokenVaultKey(&bacctypes.KmsConfiguration{
		KeyType:   bacctypes.KeyTypeCustomerManagedKey,
		KmsKeyArn: aws.String("arn:aws:kms:us-east-1:123456789012:key/k1"),
	})
	assert.Equal(t, "CustomerManagedKey", aws.ToString(kt))
	assert.Equal(t, "arn:aws:kms:us-east-1:123456789012:key/k1", keyArn)

	// Synthetic: a service-managed key never resolves to a KMS key, even if an ARN is echoed.
	kt, keyArn = tokenVaultKey(&bacctypes.KmsConfiguration{
		KeyType:   bacctypes.KeyTypeServiceManagedKey,
		KmsKeyArn: aws.String("arn:aws:kms:us-east-1:111111111111:key/svc"),
	})
	assert.Equal(t, "ServiceManagedKey", aws.ToString(kt))
	assert.Empty(t, keyArn)

	// Synthetic: no KMS configuration reads as null, not an assumed default.
	kt, keyArn = tokenVaultKey(nil)
	assert.Nil(t, kt)
	assert.Empty(t, keyArn)
}

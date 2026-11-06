// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/qbusiness"
	qbusinesstypes "github.com/aws/aws-sdk-go-v2/service/qbusiness/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestQbusinessBoolField(t *testing.T) {
	// Synthetic: the three states of an ENABLED/DISABLED control.
	var field plugin.TValue[bool]
	v, err := qbusinessBoolField(qbusinesstypes.AttachmentsControlModeEnabled, &field)
	require.NoError(t, err)
	assert.True(t, v)
	assert.False(t, field.IsNull())

	field = plugin.TValue[bool]{}
	v, err = qbusinessBoolField(qbusinesstypes.AttachmentsControlModeDisabled, &field)
	require.NoError(t, err)
	assert.False(t, v)
	assert.False(t, field.IsNull())

	field = plugin.TValue[bool]{}
	_, err = qbusinessBoolField(qbusinesstypes.AttachmentsControlMode(""), &field)
	require.NoError(t, err)
	assert.True(t, field.IsNull(), "an unset control is null, not false")
}

func TestQbusinessIamProviderArn(t *testing.T) {
	// Synthetic: provider ARN only applies to the matching identity type.
	detail := &qbusiness.GetApplicationOutput{
		IdentityType:           qbusinesstypes.IdentityTypeAwsIamIdpSaml,
		IamIdentityProviderArn: aws.String("arn:aws:iam::123456789012:saml-provider/okta"),
	}
	assert.Equal(t, "arn:aws:iam::123456789012:saml-provider/okta", qbusinessIamProviderArn(detail, qbusinesstypes.IdentityTypeAwsIamIdpSaml))
	assert.Empty(t, qbusinessIamProviderArn(detail, qbusinesstypes.IdentityTypeAwsIamIdpOidc))
	assert.Empty(t, qbusinessIamProviderArn(nil, qbusinesstypes.IdentityTypeAwsIamIdpSaml))
}

func TestMergeChatControlsPage(t *testing.T) {
	// Synthetic: two pages; settings on both, topics split across them.
	c := &qbusinessChatControls{}
	mergeChatControlsPage(c, &qbusiness.GetChatControlsConfigurationOutput{
		ResponseScope:                       qbusinesstypes.ResponseScopeExtendedKnowledgeEnabled,
		BlockedPhrases:                      &qbusinesstypes.BlockedPhrasesConfiguration{BlockedPhrases: []string{"salary", "acquisition"}},
		CreatorModeConfiguration:            &qbusinesstypes.AppliedCreatorModeConfiguration{CreatorModeControl: qbusinesstypes.CreatorModeControlEnabled},
		HallucinationReductionConfiguration: &qbusinesstypes.HallucinationReductionConfiguration{HallucinationReductionControl: qbusinesstypes.HallucinationReductionControlDisabled},
		TopicConfigurations:                 []qbusinesstypes.TopicConfiguration{{Name: aws.String("hr")}},
	})
	mergeChatControlsPage(c, &qbusiness.GetChatControlsConfigurationOutput{
		ResponseScope:              qbusinesstypes.ResponseScopeExtendedKnowledgeEnabled,
		BlockedPhrases:             &qbusinesstypes.BlockedPhrasesConfiguration{BlockedPhrases: []string{"salary", "acquisition"}},
		OrchestrationConfiguration: &qbusinesstypes.AppliedOrchestrationConfiguration{Control: qbusinesstypes.OrchestrationControlEnabled},
		TopicConfigurations:        []qbusinesstypes.TopicConfiguration{{Name: aws.String("legal")}, {Name: nil}},
	})
	assert.Equal(t, "EXTENDED_KNOWLEDGE_ENABLED", c.responseScope)
	assert.Equal(t, []string{"salary", "acquisition"}, c.blockedPhrases, "phrases repeated on every page are not duplicated")
	assert.Equal(t, []string{"hr", "legal"}, c.topicNames)
	assert.Equal(t, qbusinesstypes.CreatorModeControlEnabled, c.creatorMode)
	assert.Equal(t, qbusinesstypes.HallucinationReductionControlDisabled, c.hallucinationReduction)
	assert.Equal(t, qbusinesstypes.OrchestrationControlEnabled, c.orchestration)
}

func TestDataAccessorActions(t *testing.T) {
	// Synthetic: action names, skipping an empty one.
	got := dataAccessorActions([]qbusinesstypes.ActionConfiguration{
		{Action: aws.String("qbusiness:SearchRelevantContent")},
		{Action: nil},
	})
	assert.Equal(t, []any{"qbusiness:SearchRelevantContent"}, got)
	assert.Equal(t, []any{}, dataAccessorActions(nil))
}

func TestPluginAuthType(t *testing.T) {
	// Synthetic: one per union member.
	assert.Equal(t, "basicAuth", pluginAuthType(&qbusinesstypes.PluginAuthConfigurationMemberBasicAuthConfiguration{}))
	assert.Equal(t, "oAuth2ClientCredential", pluginAuthType(&qbusinesstypes.PluginAuthConfigurationMemberOAuth2ClientCredentialConfiguration{}))
	assert.Equal(t, "idcAuth", pluginAuthType(&qbusinesstypes.PluginAuthConfigurationMemberIdcAuthConfiguration{}))
	assert.Equal(t, "noAuth", pluginAuthType(&qbusinesstypes.PluginAuthConfigurationMemberNoAuthConfiguration{}))
	assert.Empty(t, pluginAuthType(nil))
}

func TestWebExperienceIdentityProviderType(t *testing.T) {
	// Synthetic: one per union member.
	assert.Equal(t, "saml", webExperienceIdentityProviderType(&qbusinesstypes.IdentityProviderConfigurationMemberSamlConfiguration{}))
	assert.Equal(t, "openIdConnect", webExperienceIdentityProviderType(&qbusinesstypes.IdentityProviderConfigurationMemberOpenIDConnectConfiguration{}))
	assert.Empty(t, webExperienceIdentityProviderType(nil))
}

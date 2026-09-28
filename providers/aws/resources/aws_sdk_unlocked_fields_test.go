// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	glue_types "github.com/aws/aws-sdk-go-v2/service/glue/types"
	kinesis_types "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNonEmptyEnum(t *testing.T) {
	assert.Nil(t, nonEmptyEnum(kinesis_types.RecordDistributionStrategy("")))
	got := nonEmptyEnum(kinesis_types.RecordDistributionStrategyAuto)
	require.NotNil(t, got)
	assert.Equal(t, "AUTO", *got)
}

func TestShouldRetryGlueTablesWithoutShareType(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"federation source failed", &glue_types.FederationSourceException{Message: aws.String("x")}, true},
		{"federation source retryable", &glue_types.FederationSourceRetryableException{Message: aws.String("x")}, true},
		{"invalid input", &glue_types.InvalidInputException{Message: aws.String("x")}, true},
		{"wrapped federation failure", fmt.Errorf("operation error: %w", &glue_types.FederationSourceException{}), true},
		{"access denied", &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}, false},
		{"entity not found", &glue_types.EntityNotFoundException{Message: aws.String("x")}, false},
		{"transport error", errors.New("dial tcp: connection refused"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, shouldRetryGlueTablesWithoutShareType(tt.err))
		})
	}
}

type fakeGlueGetTables struct {
	inputs []glue.GetTablesInput
	pages  []*glue.GetTablesOutput
}

func (f *fakeGlueGetTables) GetTables(_ context.Context, in *glue.GetTablesInput, _ ...func(*glue.Options)) (*glue.GetTablesOutput, error) {
	f.inputs = append(f.inputs, *in)
	page := f.pages[len(f.inputs)-1]
	return page, nil
}

func TestListGlueTablesRequestsShareTypeAndPaginates(t *testing.T) {
	fake := &fakeGlueGetTables{pages: []*glue.GetTablesOutput{
		{TableList: []glue_types.Table{{Name: aws.String("local")}}, NextToken: aws.String("p2")},
		{TableList: []glue_types.Table{{Name: aws.String("federated"), FederatedTable: &glue_types.FederatedTable{Identifier: aws.String("ext")}}}},
	}}
	tables, err := listGlueTables(context.Background(), fake, "db", "123", glue_types.TableResourceShareTypeAll)
	require.NoError(t, err)
	require.Len(t, tables, 2)
	assert.Equal(t, "federated", *tables[1].Name)
	require.Len(t, fake.inputs, 2)
	for _, in := range fake.inputs {
		assert.Equal(t, glue_types.TableResourceShareTypeAll, in.ResourceShareType)
	}
	assert.Equal(t, "p2", aws.ToString(fake.inputs[1].NextToken))

	// The fallback listing must not send the parameter at all.
	fallback := &fakeGlueGetTables{pages: []*glue.GetTablesOutput{{}}}
	_, err = listGlueTables(context.Background(), fallback, "db", "123", "")
	require.NoError(t, err)
	assert.Equal(t, glue_types.TableResourceShareType(""), fallback.inputs[0].ResourceShareType)
}

func TestBedrockKnowledgeBaseVpcConfigurationId(t *testing.T) {
	a := bedrockKnowledgeBaseVpcConfigurationId("us-east-1", "KB1", "cfg1")
	assert.Equal(t, "us-east-1/KB1/vpcConfiguration/cfg1", a)
	// The same configuration id under another knowledge base or region is a
	// different configuration and must not share a cache entry.
	assert.NotEqual(t, a, bedrockKnowledgeBaseVpcConfigurationId("us-east-1", "KB2", "cfg1"))
	assert.NotEqual(t, a, bedrockKnowledgeBaseVpcConfigurationId("eu-west-1", "KB1", "cfg1"))
}

func TestBedrockAgentCorePaymentConnectorId(t *testing.T) {
	m1 := "arn:aws:bedrock-agentcore:us-east-1:000000000000:payment-manager/m1"
	m2 := "arn:aws:bedrock-agentcore:us-east-1:000000000000:payment-manager/m2"
	assert.Equal(t, m1+"/paymentConnector/c1", bedrockAgentCorePaymentConnectorId(m1, "c1"))
	assert.NotEqual(t, bedrockAgentCorePaymentConnectorId(m1, "c1"), bedrockAgentCorePaymentConnectorId(m2, "c1"))
}

type unknownCredentialsProviderConfiguration struct {
	types.CredentialsProviderConfiguration
}

func TestPaymentCredentialProviderArns(t *testing.T) {
	assert.Empty(t, paymentCredentialProviderArns(nil))

	got := paymentCredentialProviderArns([]types.CredentialsProviderConfiguration{
		&types.CredentialsProviderConfigurationMemberCoinbaseCDP{Value: types.PaymentCredentialProviderConfiguration{
			CredentialProviderArn: aws.String("arn:coinbase"),
		}},
		&types.CredentialsProviderConfigurationMemberStripePrivy{Value: types.PaymentCredentialProviderConfiguration{
			CredentialProviderArn: aws.String("arn:stripe"),
		}},
		// no ARN: skipped rather than resolved to an empty reference
		&types.CredentialsProviderConfigurationMemberStripePrivy{},
		// a member this SDK version does not model
		&types.UnknownUnionMember{Tag: "futureVendor"},
		&unknownCredentialsProviderConfiguration{},
	})
	assert.Equal(t, []string{"arn:coinbase", "arn:stripe"}, got)
}

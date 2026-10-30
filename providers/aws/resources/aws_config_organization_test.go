// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cstypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestIsConfigOrganizationNotApplicable(t *testing.T) {
	// Synthetic: the typed errors the SDK decodes for these codes; the test
	// account (an organization member) answered the describe calls with empty
	// lists rather than either error.
	assert.True(t, isConfigOrganizationNotApplicable(fmt.Errorf("op: %w", &cstypes.OrganizationAccessDeniedException{})))
	assert.True(t, isConfigOrganizationNotApplicable(&cstypes.OrganizationAllFeaturesNotEnabledException{}))
	// An IAM denial is Forbidden, not an organization answer.
	assert.False(t, isConfigOrganizationNotApplicable(&smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"}))
	assert.False(t, isConfigOrganizationNotApplicable(&cstypes.NoAvailableOrganizationException{}))
	assert.False(t, isConfigOrganizationNotApplicable(nil))
}

func TestIsConfigNoOrganization(t *testing.T) {
	assert.True(t, isConfigNoOrganization(fmt.Errorf("op: %w", &cstypes.NoAvailableOrganizationException{})))
	assert.False(t, isConfigNoOrganization(&cstypes.OrganizationAccessDeniedException{}))
	assert.False(t, isConfigNoOrganization(nil))
}

func TestOrgScopeTally(t *testing.T) {
	refusal := &cstypes.OrganizationAccessDeniedException{}

	t.Run("every region refused, structured", func(t *testing.T) {
		tally := &orgScopeTally{}
		tally.refuse(refusal)
		tally.refuse(refusal)
		res, err := tally.result([]any{}, true)
		require.Error(t, err)
		assert.Nil(t, res)
		assert.True(t, errors.Is(err, llx.ErrNotApplicable))
	})

	t.Run("every region refused, unstructured", func(t *testing.T) {
		tally := &orgScopeTally{}
		tally.refuse(refusal)
		res, err := tally.result([]any{}, false)
		require.NoError(t, err)
		assert.Empty(t, res)
	})

	t.Run("one region answered", func(t *testing.T) {
		tally := &orgScopeTally{}
		tally.refuse(refusal)
		tally.answer()
		res, err := tally.result([]any{"rule"}, true)
		require.NoError(t, err)
		assert.Equal(t, []any{"rule"}, res)
	})

	t.Run("answered with nothing is an empty answer", func(t *testing.T) {
		tally := &orgScopeTally{}
		tally.answer()
		res, err := tally.result([]any{}, true)
		require.NoError(t, err)
		assert.Empty(t, res)
	})
}

func TestConfigOrganizationRegion(t *testing.T) {
	t.Run("organization refusal is tallied", func(t *testing.T) {
		tally := &orgScopeTally{}
		res, err := configOrganizationRegion(tally, "us-east-1", func() ([]any, error) {
			return nil, &cstypes.OrganizationAccessDeniedException{}
		})
		require.NoError(t, err)
		assert.Empty(t, res)
		assert.NotNil(t, tally.notApplicable)
		assert.Equal(t, 0, tally.answered)
	})

	t.Run("no organization is an answer", func(t *testing.T) {
		tally := &orgScopeTally{}
		res, err := configOrganizationRegion(tally, "us-east-1", func() ([]any, error) {
			return nil, &cstypes.NoAvailableOrganizationException{}
		})
		require.NoError(t, err)
		assert.Empty(t, res)
		assert.Equal(t, 1, tally.answered)
		assert.Nil(t, tally.notApplicable)
	})

	t.Run("other errors pass through for perRegion to classify", func(t *testing.T) {
		tally := &orgScopeTally{}
		denied := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"}
		_, err := configOrganizationRegion(tally, "us-east-1", func() ([]any, error) {
			return nil, denied
		})
		assert.Equal(t, denied, err)
		assert.Nil(t, tally.notApplicable)
	})

	t.Run("success is an answer", func(t *testing.T) {
		tally := &orgScopeTally{}
		res, err := configOrganizationRegion(tally, "us-east-1", func() ([]any, error) {
			return []any{"pack"}, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []any{"pack"}, res)
		assert.Equal(t, 1, tally.answered)
	})
}

func TestConfigOrgStatusCache(t *testing.T) {
	t.Run("fetches once and serves by name", func(t *testing.T) {
		calls := 0
		c := &configOrgStatusCache{fetch: func() (map[string]configOrgStatus, error) {
			calls++
			return map[string]configOrgStatus{
				"a": {status: "CREATE_SUCCESSFUL"},
				"b": {status: "CREATE_FAILED", errorCode: "ERR", errorMessage: "account failed"},
			}, nil
		}}
		a, err := c.get("a")
		require.NoError(t, err)
		b, err := c.get("b")
		require.NoError(t, err)
		missing, err := c.get("c")
		require.NoError(t, err)
		assert.Equal(t, 1, calls)
		assert.Equal(t, "CREATE_SUCCESSFUL", a.status)
		assert.Equal(t, configOrgStatus{status: "CREATE_FAILED", errorCode: "ERR", errorMessage: "account failed"}, b)
		assert.Equal(t, configOrgStatus{}, missing)
	})

	t.Run("caches the error", func(t *testing.T) {
		calls := 0
		boom := errors.New("throttled")
		c := &configOrgStatusCache{fetch: func() (map[string]configOrgStatus, error) {
			calls++
			return nil, boom
		}}
		_, err := c.get("a")
		assert.Equal(t, boom, err)
		_, err = c.get("b")
		assert.Equal(t, boom, err)
		assert.Equal(t, 1, calls)
	})
}

func TestOrganizationRuleDetailsOf(t *testing.T) {
	// Synthetic: shapes from the DescribeOrganizationConfigRules API reference;
	// the test account had no organization rules.
	t.Run("managed", func(t *testing.T) {
		d := organizationRuleDetailsOf(cstypes.OrganizationConfigRule{
			OrganizationManagedRuleMetadata: &cstypes.OrganizationManagedRuleMetadata{
				RuleIdentifier:            aws.String("S3_BUCKET_VERSIONING_ENABLED"),
				Description:               aws.String("versioning"),
				InputParameters:           aws.String(`{"isMfaDeleteEnabled":"true"}`),
				MaximumExecutionFrequency: cstypes.MaximumExecutionFrequencyTwentyFourHours,
				ResourceTypesScope:        []string{"AWS::S3::Bucket"},
				TagKeyScope:               aws.String("env"),
				TagValueScope:             aws.String("prod"),
			},
		})
		assert.Equal(t, "AWS", d.ruleType)
		assert.Equal(t, "S3_BUCKET_VERSIONING_ENABLED", d.sourceIdentifier)
		assert.Empty(t, d.lambdaFunctionArn)
		assert.Empty(t, d.policyRuntime)
		assert.Equal(t, "versioning", d.description)
		assert.Equal(t, `{"isMfaDeleteEnabled":"true"}`, d.inputParameters)
		assert.Equal(t, "TwentyFour_Hours", d.maximumExecutionFrequency)
		assert.Equal(t, []any{"AWS::S3::Bucket"}, d.resourceTypesScope)
		assert.Equal(t, []any{}, d.triggerTypes)
		assert.Equal(t, "env", d.tagKeyScope)
		assert.Equal(t, "prod", d.tagValueScope)
	})

	t.Run("custom lambda", func(t *testing.T) {
		d := organizationRuleDetailsOf(cstypes.OrganizationConfigRule{
			OrganizationCustomRuleMetadata: &cstypes.OrganizationCustomRuleMetadata{
				LambdaFunctionArn:                  aws.String("arn:aws:lambda:us-east-1:000000000000:function:check"),
				OrganizationConfigRuleTriggerTypes: []cstypes.OrganizationConfigRuleTriggerType{cstypes.OrganizationConfigRuleTriggerTypeConfigurationItemChangeNotification},
				ResourceIdScope:                    aws.String("i-0abc"),
			},
		})
		assert.Equal(t, "CUSTOM_LAMBDA", d.ruleType)
		assert.Empty(t, d.sourceIdentifier)
		assert.Equal(t, "arn:aws:lambda:us-east-1:000000000000:function:check", d.lambdaFunctionArn)
		assert.Equal(t, []any{"ConfigurationItemChangeNotification"}, d.triggerTypes)
		assert.Equal(t, "i-0abc", d.resourceIdScope)
		assert.Equal(t, []any{}, d.resourceTypesScope)
	})

	t.Run("custom policy", func(t *testing.T) {
		d := organizationRuleDetailsOf(cstypes.OrganizationConfigRule{
			OrganizationCustomPolicyRuleMetadata: &cstypes.OrganizationCustomPolicyRuleMetadataNoPolicy{
				PolicyRuntime:                      aws.String("guard-2.x.x"),
				OrganizationConfigRuleTriggerTypes: []cstypes.OrganizationConfigRuleTriggerTypeNoSN{cstypes.OrganizationConfigRuleTriggerTypeNoSNConfigurationItemChangeNotification},
				Description:                        aws.String("guard"),
			},
		})
		assert.Equal(t, "CUSTOM_POLICY", d.ruleType)
		assert.Equal(t, "guard-2.x.x", d.policyRuntime)
		assert.Empty(t, d.lambdaFunctionArn)
		assert.Empty(t, d.sourceIdentifier)
		assert.Equal(t, "guard", d.description)
		assert.Equal(t, []any{"ConfigurationItemChangeNotification"}, d.triggerTypes)
	})

	t.Run("no metadata", func(t *testing.T) {
		d := organizationRuleDetailsOf(cstypes.OrganizationConfigRule{})
		assert.Empty(t, d.ruleType)
		assert.Equal(t, []any{}, d.triggerTypes)
		assert.Equal(t, []any{}, d.resourceTypesScope)
	})
}

func TestParseConfigInputParameters(t *testing.T) {
	res, err := parseConfigInputParameters("")
	require.NoError(t, err)
	assert.Nil(t, res)

	res, err = parseConfigInputParameters(`{"maxAccessKeyAge":"90","flags":["a"]}`)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"maxAccessKeyAge": "90", "flags": []any{"a"}}, res)

	_, err = parseConfigInputParameters(`{"broken"`)
	assert.Error(t, err)

	_, err = parseConfigInputParameters(`["not","an","object"]`)
	assert.Error(t, err)
}

func TestConformancePackParametersMap(t *testing.T) {
	res := conformancePackParametersMap([]cstypes.ConformancePackInputParameter{
		{ParameterName: aws.String("AccessKeysRotatedParamMaxAccessKeyAge"), ParameterValue: aws.String("90")},
		{ParameterName: aws.String("Empty")},
		{ParameterValue: aws.String("orphan")},
	})
	assert.Equal(t, map[string]any{
		"AccessKeysRotatedParamMaxAccessKeyAge": "90",
		"Empty":                                 "",
	}, res)

	assert.Empty(t, conformancePackParametersMap(nil))
}

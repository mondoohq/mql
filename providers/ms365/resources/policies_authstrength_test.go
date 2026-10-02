// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// combinationConfigurationsJSON is a combinationConfigurations collection
// response as Graph returns it for a custom strength: one FIDO2 restriction,
// one certificate restriction, and a method type the SDK does not model.
const combinationConfigurationsJSON = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationStrengthPolicies('a1b2')/combinationConfigurations",
  "value": [
    {
      "@odata.type": "#microsoft.graph.fido2CombinationConfiguration",
      "id": "6a1f3c2e-0000-4000-8000-000000000001",
      "appliesToCombinations": ["fido2"],
      "allowedAAGUIDs": ["cb69481e-8ff7-4039-93ec-0a2729a154a8", "ee882879-721c-4913-9775-3dfcce97072a"]
    },
    {
      "@odata.type": "#microsoft.graph.x509CertificateCombinationConfiguration",
      "id": "6a1f3c2e-0000-4000-8000-000000000002",
      "appliesToCombinations": ["x509CertificateMultiFactor"],
      "allowedIssuerSkis": ["9A4248C6AC8C2931AB2A86537818E92E7B6C97B6"],
      "allowedPolicyOIDs": ["1.2.3.4.5"]
    },
    {
      "@odata.type": "#microsoft.graph.passkeyCombinationConfiguration",
      "id": "6a1f3c2e-0000-4000-8000-000000000003",
      "appliesToCombinations": ["fido2"]
    }
  ]
}`

func parseCombinationConfigurations(t *testing.T) []models.AuthenticationCombinationConfigurationable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(combinationConfigurationsJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateAuthenticationCombinationConfigurationCollectionResponseFromDiscriminatorValue)
	require.NoError(t, err)
	configs := parsed.(models.AuthenticationCombinationConfigurationCollectionResponseable).GetValue()
	require.Len(t, configs, 3)
	return configs
}

func TestCombinationConfigurationFields(t *testing.T) {
	configs := parseCombinationConfigurations(t)

	fido := combinationConfigurationFields(configs[0])
	assert.Equal(t, "fido2", fido.configType)
	assert.Equal(t, []string{"cb69481e-8ff7-4039-93ec-0a2729a154a8", "ee882879-721c-4913-9775-3dfcce97072a"}, fido.allowedAAGUIDs)
	assert.Empty(t, fido.allowedIssuerSkis)
	assert.Equal(t, []string{"fido2"}, convertEnumCollectionToStrings(configs[0].GetAppliesToCombinations()))

	cert := combinationConfigurationFields(configs[1])
	assert.Equal(t, "x509Certificate", cert.configType)
	assert.Equal(t, []string{"9A4248C6AC8C2931AB2A86537818E92E7B6C97B6"}, cert.allowedIssuerSkis)
	assert.Equal(t, []string{"1.2.3.4.5"}, cert.allowedPolicyOIDs)
	assert.Empty(t, cert.allowedAAGUIDs)

	// a method the SDK does not model still reports its type
	future := combinationConfigurationFields(configs[2])
	assert.Equal(t, "passkey", future.configType)
	assert.Empty(t, future.allowedAAGUIDs)
}

func TestCombinationConfigurationTypeFromOData(t *testing.T) {
	assert.Equal(t, "", combinationConfigurationTypeFromOData(nil))
	s := "#microsoft.graph.fido2CombinationConfiguration"
	assert.Equal(t, "fido2", combinationConfigurationTypeFromOData(&s))
}

// featureRolloutAppliesToJSON is a featureRolloutPolicy appliesTo response.
// Staged rollout targets groups; the user entry stands for any other
// directory object.
const featureRolloutAppliesToJSON = `{
  "value": [
    {"@odata.type": "#microsoft.graph.group", "id": "1f9a2b3c-0000-4000-8000-000000000020", "displayName": "Staged rollout pilot"},
    {"@odata.type": "#microsoft.graph.user", "id": "1f9a2b3c-0000-4000-8000-000000000021"},
    {"@odata.type": "#microsoft.graph.group", "displayName": "no id"}
  ]
}`

func TestDirectoryObjectGroupIds(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(featureRolloutAppliesToJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue)
	require.NoError(t, err)
	objects := parsed.(models.DirectoryObjectCollectionResponseable).GetValue()
	require.Len(t, objects, 3)

	assert.Equal(t, []string{"1f9a2b3c-0000-4000-8000-000000000020"}, directoryObjectGroupIds(objects))
	assert.Empty(t, directoryObjectGroupIds(nil))
}

func TestPolicyReadsClassifyRefusal(t *testing.T) {
	denied := odataErrWithCode("Authorization_RequestDenied")
	denied.ResponseStatusCode = 403
	// iterate wraps a page failure through transformError before it reaches
	// the classifier, so the refusal must still be found behind the wrapper
	for _, err := range []error{denied, transformError(denied)} {
		got := classifyGraphError(err, policyReadAll)
		require.True(t, errors.Is(got, llx.ErrForbidden), "a 403 is a refusal")
		var lerr *llx.Error
		require.True(t, errors.As(got, &lerr))
		assert.Equal(t, []string{"Policy.Read.All"}, lerr.Permissions)
	}
}

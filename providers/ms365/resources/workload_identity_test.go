// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net"
	"testing"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func workloadODataErr(status int, code string) *odataerrors.ODataError {
	err := odataErrWithCode(code)
	err.ResponseStatusCode = status
	return err
}

func TestClassifyGraphErrorWorkloadIdentity(t *testing.T) {
	assert.NoError(t, classifyGraphError(nil, "Policy.Read.All"))

	forbidden := classifyGraphError(workloadODataErr(403, "Authorization_RequestDenied"), "Application.Read.All", "Policy.Read.All")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(forbidden))
	var lerr *llx.Error
	require.True(t, errors.As(forbidden, &lerr))
	assert.Equal(t, []string{"Application.Read.All", "Policy.Read.All"}, lerr.Permissions)
	// the Graph code survives classification for callers that branch on it
	assert.Equal(t, "Authorization_RequestDenied", graphErrorCode(forbidden))

	// iterate hands back an error that already went through transformError
	pageErr := transformError(workloadODataErr(403, "Authorization_RequestDenied"))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(classifyGraphError(pageErr, "Policy.Read.All")))

	notFound := classifyGraphError(workloadODataErr(404, "Request_ResourceNotFound"), "Policy.Read.All")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(notFound))

	transport := classifyGraphError(&net.DNSError{Err: "no such host"}, "Policy.Read.All")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(transport))
}

const federatedIdentityCredentialsJSON = `{
  "value": [
    {
      "id": "8a8a2f0c-1111-4c3e-9a77-000000000001",
      "name": "github-main",
      "issuer": "https://token.actions.githubusercontent.com",
      "subject": "repo:my-org/my-repo:ref:refs/heads/main",
      "description": "deploy from main",
      "audiences": ["api://AzureADTokenExchange"]
    },
    {
      "id": "8a8a2f0c-1111-4c3e-9a77-000000000002",
      "name": "aks-workload",
      "issuer": "https://oidc.prod-aks.azure.com/00000000-0000-0000-0000-000000000000/",
      "subject": "system:serviceaccount:default:workload",
      "audiences": ["api://AzureADTokenExchange"]
    }
  ]
}`

func TestFederatedIdentityCredentialsDecode(t *testing.T) {
	coll := parseGraph(t, federatedIdentityCredentialsJSON, models.CreateFederatedIdentityCredentialCollectionResponseFromDiscriminatorValue).(models.FederatedIdentityCredentialCollectionResponseable)
	creds := coll.GetValue()
	require.Len(t, creds, 2)

	res, err := newMqlFederatedIdentityCredentials(dictTestRuntime(), "app-1", creds)
	require.NoError(t, err)
	require.Len(t, res, 2)

	gh := res[0].(*mqlMicrosoftApplicationFederatedIdentityCredential)
	assert.Equal(t, "8a8a2f0c-1111-4c3e-9a77-000000000001", gh.Id.Data)
	assert.Equal(t, "github-main", gh.Name.Data)
	assert.Equal(t, "https://token.actions.githubusercontent.com", gh.Issuer.Data)
	assert.Equal(t, "repo:my-org/my-repo:ref:refs/heads/main", gh.Subject.Data)
	assert.Equal(t, []any{"api://AzureADTokenExchange"}, gh.Audiences.Data)
	assert.Equal(t, "deploy from main", gh.Description.Data)

	aks := res[1].(*mqlMicrosoftApplicationFederatedIdentityCredential)
	assert.Equal(t, "system:serviceaccount:default:workload", aks.Subject.Data)
	// absent description is null, not an empty string
	assert.True(t, aks.Description.IsNull())
}

// A credential id is only unique within its application, so the same id on
// two parents must give two resources rather than the cached first one.
func TestFederatedIdentityCredentialIdsAreScopedToParent(t *testing.T) {
	coll := parseGraph(t, federatedIdentityCredentialsJSON, models.CreateFederatedIdentityCredentialCollectionResponseFromDiscriminatorValue).(models.FederatedIdentityCredentialCollectionResponseable)
	runtime := dictTestRuntime()

	a, err := newMqlFederatedIdentityCredentials(runtime, "app-1", coll.GetValue()[:1])
	require.NoError(t, err)

	other := models.NewFederatedIdentityCredential()
	other.SetId(coll.GetValue()[0].GetId())
	subject := "repo:other-org/other-repo:pull_request"
	other.SetSubject(&subject)
	b, err := newMqlFederatedIdentityCredentials(runtime, "sp-2", []models.FederatedIdentityCredentialable{other})
	require.NoError(t, err)

	assert.NotEqual(t, a[0].(*mqlMicrosoftApplicationFederatedIdentityCredential).MqlID(), b[0].(*mqlMicrosoftApplicationFederatedIdentityCredential).MqlID())
	assert.Equal(t, subject, b[0].(*mqlMicrosoftApplicationFederatedIdentityCredential).Subject.Data)
}

const appManagementPoliciesJSON = `{
  "value": [
    {
      "id": "db9d4b58-3488-4da4-9994-49773c454e33",
      "displayName": "Credential management policy",
      "description": "Cred policy sample",
      "isEnabled": true,
      "restrictions": {
        "passwordCredentials": [
          {
            "restrictionType": "passwordLifetime",
            "maxLifetime": "P90D",
            "state": "enabled",
            "restrictForAppsCreatedAfterDateTime": "2019-10-19T10:37:00Z"
          }
        ],
        "keyCredentials": []
      }
    },
    {
      "id": "0a1b2c3d-0000-0000-0000-000000000000",
      "displayName": "Empty policy",
      "isEnabled": false
    }
  ]
}`

func TestAppManagementPoliciesDecode(t *testing.T) {
	coll := parseGraph(t, appManagementPoliciesJSON, models.CreateAppManagementPolicyCollectionResponseFromDiscriminatorValue).(models.AppManagementPolicyCollectionResponseable)
	res, err := newMqlAppManagementPolicies(dictTestRuntime(), coll.GetValue())
	require.NoError(t, err)
	require.Len(t, res, 2)

	p := res[0].(*mqlMicrosoftPoliciesAppManagementPolicy)
	assert.Equal(t, "db9d4b58-3488-4da4-9994-49773c454e33", p.Id.Data)
	assert.Equal(t, "Credential management policy", p.DisplayName.Data)
	assert.Equal(t, "Cred policy sample", p.Description.Data)
	assert.True(t, p.IsEnabled.Data)
	pw := p.Restrictions.Data.PasswordCredentials.Data
	require.Len(t, pw, 1)
	assert.Equal(t, "passwordLifetime", pw[0].(map[string]any)["restrictionType"])
	assert.Equal(t, "P90D", pw[0].(map[string]any)["maxLifetime"])
	assert.Empty(t, p.Restrictions.Data.KeyCredentials.Data)

	empty := res[1].(*mqlMicrosoftPoliciesAppManagementPolicy)
	assert.False(t, empty.IsEnabled.Data)
	assert.True(t, empty.Description.IsNull())
	// no restrictions on the wire still yields empty restriction lists
	require.NotNil(t, empty.Restrictions.Data)
	assert.Empty(t, empty.Restrictions.Data.PasswordCredentials.Data)
	// the two policies' restriction sets are distinct resources
	assert.NotEqual(t, p.Restrictions.Data.MqlID(), empty.Restrictions.Data.MqlID())
}

const appliesToJSON = `{
  "value": [
    {"@odata.type": "#microsoft.graph.application", "id": "app-object-1"},
    {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp-object-1"},
    {"@odata.type": "#microsoft.graph.application", "id": "app-object-2"},
    {"@odata.type": "#microsoft.graph.user", "id": "user-object-1"}
  ]
}`

func TestSplitAppliesTo(t *testing.T) {
	coll := parseGraph(t, appliesToJSON, models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue).(models.DirectoryObjectCollectionResponseable)
	apps, sps := splitAppliesTo(coll.GetValue())
	assert.Equal(t, []string{"app-object-1", "app-object-2"}, apps)
	assert.Equal(t, []string{"sp-object-1"}, sps)

	apps, sps = splitAppliesTo(nil)
	assert.Empty(t, apps)
	assert.Empty(t, sps)
}

func TestPickByIdsSkipsMissing(t *testing.T) {
	byId := map[string]any{"a": "A", "b": "B"}
	assert.Equal(t, []any{"B", "A"}, pickByIds(byId, []string{"b", "missing", "a"}, "application"))
}

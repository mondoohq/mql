// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// tokenLifetimePolicyListJSON is the wire shape of GET
// /policies/tokenLifetimePolicies: `definition` is an array of strings, each
// one a JSON document.
const tokenLifetimePolicyListJSON = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/tokenLifetimePolicies",
  "value": [
    {
      "id": "4d2f137b-e8a9-46da-a5c3-cc85b2b840a4",
      "deletedDateTime": null,
      "definition": [
        "{\"TokenLifetimePolicy\":{\"Version\":1,\"AccessTokenLifetime\":\"08:00:00\"}}"
      ],
      "displayName": "Contoso token lifetime policy",
      "description": "Longer access tokens for the payroll app",
      "isOrganizationDefault": true
    }
  ]
}`

func TestTokenLifetimePolicyDecodeAndSettings(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(tokenLifetimePolicyListJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateTokenLifetimePolicyCollectionResponseFromDiscriminatorValue)
	require.NoError(t, err)
	policies := parsed.(models.TokenLifetimePolicyCollectionResponseable).GetValue()
	require.Len(t, policies, 1)

	args := stsPolicyArgs(policies[0])
	assert.Equal(t, "4d2f137b-e8a9-46da-a5c3-cc85b2b840a4", args["__id"].Value)
	assert.Equal(t, "4d2f137b-e8a9-46da-a5c3-cc85b2b840a4", args["id"].Value)
	assert.Equal(t, "Contoso token lifetime policy", args["displayName"].Value)
	assert.Equal(t, "Longer access tokens for the payroll app", args["description"].Value)
	assert.Equal(t, true, args["isOrganizationDefault"].Value)

	definition := args["definition"].Value.([]any)
	require.Len(t, definition, 1)

	settings, err := parseStsPolicyDefinition(definition)
	require.NoError(t, err)
	inner, ok := settings["TokenLifetimePolicy"].(map[string]any)
	require.True(t, ok, "settings keep the definition's top-level key")
	assert.Equal(t, "08:00:00", inner["AccessTokenLifetime"])
	assert.Equal(t, float64(1), inner["Version"])
}

func TestStsPolicyArgsAbsentOptionals(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(`{"id": "p1", "definition": []}`))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateHomeRealmDiscoveryPolicyFromDiscriminatorValue)
	require.NoError(t, err)

	args := stsPolicyArgs(parsed.(models.StsPolicyable))
	assert.Nil(t, args["description"].Value)
	assert.Nil(t, args["isOrganizationDefault"].Value, "absent isOrganizationDefault is null, not false")
	assert.Empty(t, args["definition"].Value)
}

func TestParseStsPolicyDefinition(t *testing.T) {
	t.Run("claims mapping with nested schema", func(t *testing.T) {
		def := []any{`{"ClaimsMappingPolicy":{"Version":1,"IncludeBasicClaimSet":"true","ClaimsSchema":[{"Source":"user","ID":"employeeid","SamlClaimType":"name"}]}}`}
		got, err := parseStsPolicyDefinition(def)
		require.NoError(t, err)
		inner := got["ClaimsMappingPolicy"].(map[string]any)
		assert.Equal(t, "true", inner["IncludeBasicClaimSet"])
		schema := inner["ClaimsSchema"].([]any)
		require.Len(t, schema, 1)
		assert.Equal(t, "employeeid", schema[0].(map[string]any)["ID"])
	})

	t.Run("home realm discovery booleans stay booleans", func(t *testing.T) {
		def := []any{`{"HomeRealmDiscoveryPolicy":{"AccelerateToFederatedDomain":false,"AlternateIdLogin":{"Enabled":true}}}`}
		got, err := parseStsPolicyDefinition(def)
		require.NoError(t, err)
		inner := got["HomeRealmDiscoveryPolicy"].(map[string]any)
		assert.Equal(t, false, inner["AccelerateToFederatedDomain"])
		assert.Equal(t, true, inner["AlternateIdLogin"].(map[string]any)["Enabled"])
	})

	t.Run("several documents are merged", func(t *testing.T) {
		got, err := parseStsPolicyDefinition([]any{`{"A":1}`, `{"B":2}`})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"A": float64(1), "B": float64(2)}, got)
	})

	t.Run("no definition is null", func(t *testing.T) {
		got, err := parseStsPolicyDefinition(nil)
		require.NoError(t, err)
		assert.Nil(t, got)
		got, err = parseStsPolicyDefinition([]any{})
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("blank strings are skipped", func(t *testing.T) {
		got, err := parseStsPolicyDefinition([]any{"", "  "})
		require.NoError(t, err)
		assert.Nil(t, got)

		got, err = parseStsPolicyDefinition([]any{"", `{"A":true}`})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"A": true}, got)
	})

	malformed := map[string][]any{
		"truncated json":  {`{"TokenLifetimePolicy":{"Version":1`},
		"array, not obj":  {`[1,2]`},
		"json null":       {`null`},
		"bare string":     {`"x"`},
		"not a string":    {42},
		"one of two bad":  {`{"A":1}`, `{oops}`},
		"plain text":      {`AccessTokenLifetime=08:00:00`},
		"number document": {`7`},
	}
	for name, def := range malformed {
		t.Run("malformed: "+name, func(t *testing.T) {
			got, err := parseStsPolicyDefinition(def)
			require.Error(t, err)
			assert.Nil(t, got)
			assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))
		})
	}
}

func graphError(status int, code string) error {
	e := odataerrors.NewODataError()
	e.ResponseStatusCode = status
	main := odataerrors.NewMainError()
	main.SetCode(&code)
	msg := "denied"
	main.SetMessage(&msg)
	e.SetErrorEscaped(main)
	return e
}

func TestClassifyGraphErrorPolicyRead(t *testing.T) {
	forbidden := classifyGraphError(graphError(403, "Authorization_RequestDenied"), stsPolicyPermission)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(forbidden))
	var lerr *llx.Error
	require.True(t, errors.As(forbidden, &lerr))
	assert.Equal(t, []string{"Policy.Read.All"}, lerr.Permissions)
	assert.Equal(t, "Authorization_RequestDenied", graphErrorCode(forbidden), "the Graph error stays in the chain")

	notFound := classifyGraphError(graphError(404, "Request_ResourceNotFound"), stsPolicyPermission)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(notFound))
	assert.True(t, isResourceNotFound(notFound))

	transport := classifyGraphError(errors.New("dial tcp: connection refused"), stsPolicyPermission)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(transport))

	assert.NoError(t, classifyGraphError(nil, stsPolicyPermission))
}

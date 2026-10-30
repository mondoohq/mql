// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// TestAuthorizationServerJwksNilDoesNotError pins the absence of a nil
// guard around the jwks conversion.
//
// Most authorization servers do not encrypt tokens, so entry.Jwks is nil on the
// common path. JsonToDict marshals that to the JSON literal `null` and
// unmarshals it into the result map, which encoding/json treats as a no-op
// rather than an error: the call returns a nil map and a nil error. Checked
// against a live org, the field then reports an empty dict rather than null.
//
// Guarding the call would not fix a bug, and coercing the result to an empty
// map would introduce one: `{}` asserts that a key set was returned and was
// empty, which is a different claim from there being no key set at all.
func TestAuthorizationServerJwksNilDoesNotError(t *testing.T) {
	t.Parallel()

	// The exact type and nilness the mapper sees for a server without
	// token encryption configured.
	var absent *okta.ResourceServerJsonWebKeys

	dict, err := convert.JsonToDict(absent)
	require.NoError(t, err,
		"a server without token encryption must not fail the listing")
	assert.Nil(t, dict, "the conversion yields a nil map, which reports as empty")

	// A configured key set still converts.
	kid, kty := "k1", "RSA"
	present := &okta.ResourceServerJsonWebKeys{
		Keys: []okta.ResourceServerJsonWebKey{{Kid: &kid, Kty: &kty}},
	}

	dict, err = convert.JsonToDict(present)
	require.NoError(t, err)
	require.NotNil(t, dict)
	assert.Contains(t, dict, "keys")
}

// TestResourceSetDescriptionIsTypedNotAdditional pins which of the two
// description fields the SDK types and which it does not.
//
// A resource set types `description`, so it must be read off the field. The
// resources *inside* a set do not, so theirs arrives in AdditionalProperties.
// Reading a set's description from AdditionalProperties returns empty even
// though the API sent it, which is how it shipped in #9976 and what a live
// org caught: the API returned "A resource set managed by Workflows
// Administrator" while the field read "".
func TestResourceSetDescriptionIsTypedNotAdditional(t *testing.T) {
	t.Parallel()

	const wire = `{
		"id": "WORKFLOWS_IAM_POLICY",
		"label": "Workflows Resource Set",
		"description": "A resource set managed by Workflows Administrator"
	}`

	set := &okta.ResourceSet{}
	require.NoError(t, json.Unmarshal([]byte(wire), set))

	require.NotNil(t, set.Description,
		"the SDK types this field; reading it from AdditionalProperties loses it")
	assert.Equal(t, "A resource set managed by Workflows Administrator",
		oktaStr(set.Description))
	assert.NotContains(t, set.AdditionalProperties, "description",
		"a typed field is consumed by the model and never reaches AdditionalProperties")

	// The resources inside a set are the opposite case.
	res := &okta.ResourceSetResource{}
	require.NoError(t, json.Unmarshal(
		[]byte(`{"orn":"orn:okta:workflow:x:contained","description":"carved out"}`), res))
	assert.Equal(t, "carved out", oktaStrFrom(res.AdditionalProperties["description"]),
		"this one is untyped, so it only arrives via AdditionalProperties")
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTagDefaultArgs(t *testing.T) {
	var td identity.TagDefaultSummary
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "ocid1.tagdefault.oc1..x",
		"compartmentId": "ocid1.tenancy.oc1..t",
		"tagNamespaceId": "ocid1.tagnamespace.oc1..n",
		"tagDefinitionId": "ocid1.tagdefinition.oc1..d",
		"tagDefinitionName": "CreatedBy",
		"value": "${iam.principal.name}",
		"timeCreated": "2026-10-01T12:00:00.000Z",
		"isRequired": false,
		"lifecycleState": "ACTIVE"
	}`), &td))

	args, compartment := tagDefaultArgs(td)
	assert.Equal(t, "ocid1.tenancy.oc1..t", compartment)
	assert.Equal(t, "ocid1.tagdefault.oc1..x", args["id"].Value)
	assert.Equal(t, "ocid1.tagnamespace.oc1..n", args["tagNamespaceId"].Value)
	assert.Equal(t, "ocid1.tagdefinition.oc1..d", args["tagDefinitionId"].Value)
	assert.Equal(t, "CreatedBy", args["tagDefinitionName"].Value)
	assert.Equal(t, "${iam.principal.name}", args["value"].Value, "a tag variable is reported verbatim, not expanded")
	assert.Equal(t, false, args["isRequired"].Value)
	assert.Equal(t, "ACTIVE", args["state"].Value)
	created, ok := args["created"].Value.(*time.Time)
	require.True(t, ok)
	assert.Equal(t, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), created.UTC())
}

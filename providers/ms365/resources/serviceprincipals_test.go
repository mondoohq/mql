// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
)

// servicePrincipalSourcedProperties maps a Graph property that must appear in
// the $select list to the microsoft.serviceprincipal field it populates.
//
// $select restricts the payload, so a field the creator reads out of a property
// that was not selected reads as absent forever. When that read is also
// conditional, the arg key is skipped entirely and the MQL field ends up UNSET
// rather than null -- which surfaces to the user as "encountered a primitive
// with no type information" with no attribution. termsOfServiceUrl shipped that
// way because "info" was missing here.
var servicePrincipalSourcedProperties = map[string]string{
	"info":              "termsOfServiceUrl",
	"verifiedPublisher": "verifiedPublisher",
	"appRoles":          "appRoles",
	"appId":             "appId",
	"displayName":       "name",
}

func TestServicePrincipalFieldsCoverSourcedProperties(t *testing.T) {
	selected := make(map[string]bool, len(servicePrincipalFields))
	for _, f := range servicePrincipalFields {
		selected[f] = true
	}
	for property, field := range servicePrincipalSourcedProperties {
		assert.Truef(t, selected[property],
			"$select is missing %q, which sources microsoft.serviceprincipal.%s; "+
				"Graph will omit it and the field will never resolve", property, field)
	}
}

// A duplicated entry is harmless on the wire but signals the list is being
// edited without being read, which is how "info" went missing in the first
// place.
func TestServicePrincipalFieldsHasNoDuplicates(t *testing.T) {
	seen := map[string]int{}
	for _, f := range servicePrincipalFields {
		seen[f]++
	}
	for f, n := range seen {
		assert.Equalf(t, 1, n, "servicePrincipalFields lists %q %d times", f, n)
	}
}

func TestServicePrincipalIDs(t *testing.T) {
	// Synthetic: Graph can return null entries in a collection page; no target showed one.
	a := models.NewServicePrincipal()
	idA := "sp-a"
	a.SetId(&idA)
	blank := models.NewServicePrincipal()
	empty := ""
	blank.SetId(&empty)

	assert.Equal(t, []string{"sp-a"}, servicePrincipalIDs([]models.ServicePrincipalable{nil, a, blank, models.NewServicePrincipal()}))
	assert.Empty(t, servicePrincipalIDs(nil))
}

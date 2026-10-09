// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/oci/connection"
)

func scopeCompartment(id, name string) identity.Compartment {
	return identity.Compartment{Id: common.String(id), Name: common.String(name)}
}

// compartmentItem stands in for a listed resource that records its
// compartment.
type compartmentItem struct {
	ociCompartmentRef
	name string
}

func itemIn(name, compartmentID string) *compartmentItem {
	i := &compartmentItem{name: name}
	i.setCompartmentID(compartmentID)
	return i
}

func TestOciAdmitted(t *testing.T) {
	compartments := []identity.Compartment{
		scopeCompartment("ocid1.tenancy..root", "root"),
		scopeCompartment("ocid1.compartment..testbeds", "cep-testbeds"),
		scopeCompartment("ocid1.compartment..other", "other"),
	}

	byName := ociAdmitted(connection.DiscoveryFilters{Compartments: []string{"cep-testbeds"}}, compartments)
	assert.True(t, byName("ocid1.compartment..testbeds"), "a filter by name admits the compartment's OCID")
	assert.False(t, byName("ocid1.tenancy..root"), "the root is a compartment like any other")
	assert.False(t, byName("ocid1.compartment..other"))
	assert.False(t, byName("ocid1.compartment..unknown"), "a compartment outside the tree is not admitted")

	excluded := ociAdmitted(connection.DiscoveryFilters{ExcludeCompartments: []string{"other"}}, compartments)
	assert.True(t, excluded("ocid1.tenancy..root"))
	assert.False(t, excluded("ocid1.compartment..other"))
}

func TestOciFilterAdmitted(t *testing.T) {
	admit := func(id string) bool { return id == "keep" }
	kept := itemIn("kept", "keep")
	dropped := itemIn("dropped", "drop")

	got := ociFilterAdmitted([]any{kept, dropped, "no compartment"}, admit)
	assert.Equal(t, []any{kept, "no compartment"}, got, "an item that records no compartment is kept, not hidden")
	assert.Empty(t, ociFilterAdmitted(nil, admit))
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestOciCompartmentArgs(t *testing.T) {
	created := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	compartment := identity.Compartment{
		Id:             new("ocid1.compartment.oc1..a"),
		Name:           new("platform"),
		Description:    new("shared infrastructure"),
		TimeCreated:    &common.SDKTime{Time: created},
		LifecycleState: identity.CompartmentLifecycleStateActive,
		FreeformTags:   map[string]string{"env": "prod"},
		DefinedTags: map[string]map[string]any{
			"Operations": {"CostCenter": "42"},
		},
	}

	args := ociCompartmentArgs(compartment)

	assert.Equal(t, "ocid1.compartment.oc1..a", args["id"].Value)
	assert.Equal(t, "platform", args["name"].Value)
	assert.Equal(t, "shared infrastructure", args["description"].Value)
	assert.Equal(t, "ACTIVE", args["state"].Value)
	assert.Equal(t, map[string]any{"env": "prod"}, args["freeformTags"].Value)
	assert.Equal(t, map[string]any{"Operations": map[string]any{"CostCenter": "42"}}, args["definedTags"].Value)

	ts, ok := args["created"].Value.(*time.Time)
	require.True(t, ok, "created should carry a *time.Time")
	assert.Equal(t, created, ts.UTC())
}

// A compartment with nothing set must still produce every field. An absent
// timestamp in particular has to stay null rather than becoming the zero time,
// which would report 1 January year 1 as a real creation date.
func TestOciCompartmentArgsEmpty(t *testing.T) {
	args := ociCompartmentArgs(identity.Compartment{})

	for _, name := range []string{"id", "name", "description", "created", "state", "freeformTags", "definedTags"} {
		_, ok := args[name]
		assert.True(t, ok, "field %q missing for an empty compartment", name)
	}
	assert.Nil(t, args["created"].Value, "an absent TimeCreated must stay null, not become the zero time")
	assert.Empty(t, args["freeformTags"].Value)
	assert.Empty(t, args["definedTags"].Value)
}

// initOciCompartment hand-populates args on the access-denied path. Any field
// it leaves out ships unset rather than null, and an unset field crosses the
// plugin boundary as a primitive with no type information - which surfaces to
// the user as an unattributed coercion warning instead of a readable null.
//
// This pins that the denied path covers exactly the fields the readable path
// produces, minus the id the caller already supplied.
func TestOciCompartmentUnreadableCoversEveryField(t *testing.T) {
	args := map[string]*llx.RawData{"id": llx.StringData("ocid1.compartment.oc1..a")}
	ociCompartmentUnreadable(args)

	for name := range ociCompartmentArgs(identity.Compartment{}) {
		raw, ok := args[name]
		require.True(t, ok, "field %q is unset on the access-denied path", name)
		if name == "id" {
			assert.Equal(t, "ocid1.compartment.oc1..a", raw.Value, "id must survive; it is how the caller found the compartment")
			continue
		}
		assert.Nil(t, raw.Value, "field %q must be explicitly null when the compartment cannot be read", name)
	}

	assert.Len(t, args, len(ociCompartmentArgs(identity.Compartment{})),
		"the denied path should set the same field set as the readable one, no more and no less")
}

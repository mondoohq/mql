// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestOciInitArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        map[string]*llx.RawData
		wantID      string
		wantResolve bool
	}{
		{
			// Already-complete args: the caller built the resource, nothing to
			// look up.
			name: "more than two args",
			args: map[string]*llx.RawData{
				"id": llx.StringData("ocid1.instance.oc1.iad.a"), "name": llx.StringData("x"), "state": llx.StringData("y"),
			},
			wantResolve: false,
		},
		// A bare resource with no id is a valid empty state, not a lookup miss.
		{"nil args", nil, "", false},
		{"empty args", map[string]*llx.RawData{}, "", false},
		{"id present but null", map[string]*llx.RawData{"id": llx.NilData}, "", false},
		{"id present but empty", map[string]*llx.RawData{"id": llx.StringData("")}, "", false},
		{"id present but not a string", map[string]*llx.RawData{"id": llx.IntData(7)}, "", false},
		{
			name:        "resolvable id",
			args:        map[string]*llx.RawData{"id": llx.StringData("ocid1.instance.oc1.iad.a")},
			wantID:      "ocid1.instance.oc1.iad.a",
			wantResolve: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, resolve := ociInitArgs(tt.args)
			assert.Equal(t, tt.wantResolve, resolve)
			assert.Equal(t, tt.wantID, id)
		})
	}
}

func TestOciResolveByID(t *testing.T) {
	args := map[string]*llx.RawData{"id": llx.StringData("ocid1.compartment.oc1..b")}

	t.Run("match returns the populated resource", func(t *testing.T) {
		want := &mqlOciCompartment{}
		want.Id.Data = "ocid1.compartment.oc1..b"
		want.Id.State = 1

		other := &mqlOciCompartment{}
		other.Id.Data = "ocid1.compartment.oc1..a"
		other.Id.State = 1

		gotArgs, res, err := ociResolveByID(args, "oci.compartment", "ocid1.compartment.oc1..b", []any{other, want})
		require.NoError(t, err)
		assert.Equal(t, args, gotArgs)
		assert.Same(t, want, res)
	})

	t.Run("miss is an error, never a husk", func(t *testing.T) {
		// Returning (args, nil, nil) here would build the resource from the id
		// alone and cache that husk under the real OCID.
		_, res, err := ociResolveByID(args, "oci.compartment", "ocid1.compartment.oc1..zz", []any{})
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "oci.compartment not found")
		assert.Contains(t, err.Error(), "ocid1.compartment.oc1..zz")
	})

	t.Run("non-resource entries are skipped", func(t *testing.T) {
		_, _, err := ociResolveByID(args, "oci.compartment", "ocid1.compartment.oc1..b", []any{"not a resource", 42})
		require.Error(t, err)
	})
}

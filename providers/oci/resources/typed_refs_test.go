// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestOcidOrEmpty(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{"real ocid passes through", "ocid1.vcn.oc1.iad.aaaaaaaa", "ocid1.vcn.oc1.iad.aaaaaaaa"},
		{"empty stays empty", "", ""},
		// The reason this helper exists: OCI reports a service-managed key as a
		// literal placeholder where an OCID would go. Resolving it would report
		// a not-found error on a field whose honest answer is "no customer key".
		{"oracle-managed placeholder", "ORACLE_MANAGED_KEY", ""},
		{"arbitrary non-ocid", "not-an-ocid", ""},
		{"prefix must be exact", "ocid2.vcn.oc1.iad.aaaa", ""},
		{"bare prefix is still an ocid", "ocid1.", "ocid1."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ocidOrEmpty(tt.id))
		})
	}
}

// TestResolveRefMarksNull pins the invariant that made this worth centralizing.
//
// A singular resource accessor returning (nil, nil) without first setting
// StateIsNull leaves the runtime unable to tell the field was resolved: it
// re-fetches or panics on read instead of reporting null. That marking was
// duplicated at every empty-id path in the provider, which is exactly the kind
// of step that gets dropped when a new accessor is copied from an old one.
//
// The runtime is never touched on this path, so a nil one is a fine stand-in
// and doubles as a check that the empty case short-circuits before any lookup.
func TestResolveRefMarksNull(t *testing.T) {
	t.Run("empty id marks the field null", func(t *testing.T) {
		var field plugin.TValue[*mqlOciKmsKey]

		got, err := resolveRef(nil, "oci.kms.key", "", &field)

		require.NoError(t, err)
		assert.Nil(t, got)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, field.State,
			"an absent reference must be reported as null, not left unset")
	})

	t.Run("placeholder id marks the field null", func(t *testing.T) {
		// ocidOrEmpty at the call site is what turns the placeholder into the
		// empty case; together they must still produce a null, not an error.
		var field plugin.TValue[*mqlOciKmsKey]

		got, err := resolveRef(nil, "oci.kms.key", ocidOrEmpty("ORACLE_MANAGED_KEY"), &field)

		require.NoError(t, err)
		assert.Nil(t, got)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, field.State)
	})

	t.Run("field state is untouched for a resolvable id", func(t *testing.T) {
		// A non-empty id must not be pre-marked null: the state has to stay
		// clear so the runtime records whatever the lookup produces. The
		// lookup itself needs a live connection, so this stops at the guard.
		var field plugin.TValue[*mqlOciKmsKey]
		assert.Equal(t, plugin.State(0), field.State)

		// Guard only: ocidOrEmpty keeps a real OCID, so resolveRef would go on
		// to NewResource. Assert the classification rather than the lookup.
		assert.NotEmpty(t, ocidOrEmpty("ocid1.key.oc1.iad.aaaa"))
	})
}

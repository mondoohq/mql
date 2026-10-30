// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCompartment(id, name string) identity.Compartment {
	return identity.Compartment{Id: new(id), Name: new(name)}
}

// seededConnection is a connection whose compartment tree has already been
// fetched, so the lookups below never reach the Identity API.
func seededConnection(compartments ...identity.Compartment) *OciConnection {
	return &OciConnection{
		compartmentList:  compartments,
		compartmentsDone: true,
	}
}

func TestCompartmentIndexByID(t *testing.T) {
	root := testCompartment("ocid1.tenancy.oc1..root", "tenancy")
	prod := testCompartment("ocid1.compartment.oc1..prod", "prod")

	t.Run("keys every compartment by its ocid", func(t *testing.T) {
		index := compartmentIndexByID([]identity.Compartment{root, prod})

		require.Len(t, index, 2)
		assert.Equal(t, "tenancy", *index["ocid1.tenancy.oc1..root"].Name)
		assert.Equal(t, "prod", *index["ocid1.compartment.oc1..prod"].Name)
	})

	t.Run("no compartments", func(t *testing.T) {
		assert.Empty(t, compartmentIndexByID(nil))
	})

	t.Run("an entry without an ocid is skipped, not indexed under the empty key", func(t *testing.T) {
		// An unkeyed entry stored under "" would be handed back for any id the
		// caller passes that also happens to be empty, reporting the wrong
		// compartment rather than a miss.
		index := compartmentIndexByID([]identity.Compartment{
			{Name: new("no id")},
			{Id: new(""), Name: new("empty id")},
			prod,
		})

		require.Len(t, index, 1)
		assert.Contains(t, index, "ocid1.compartment.oc1..prod")
	})

	t.Run("a repeated ocid keeps the first entry", func(t *testing.T) {
		index := compartmentIndexByID([]identity.Compartment{
			prod,
			testCompartment("ocid1.compartment.oc1..prod", "prod-again"),
		})

		require.Len(t, index, 1)
		assert.Equal(t, "prod", *index["ocid1.compartment.oc1..prod"].Name)
	})
}

func TestCompartmentByID(t *testing.T) {
	prod := testCompartment("ocid1.compartment.oc1..prod", "prod")
	ctx := context.Background()

	t.Run("a compartment in the tree is found", func(t *testing.T) {
		conn := seededConnection(prod)

		got, err := conn.CompartmentByID(ctx, "ocid1.compartment.oc1..prod")

		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "prod", *got.Name)
	})

	t.Run("an ocid outside the tree misses without an error", func(t *testing.T) {
		// Cross-tenancy, or deleted since the listing. The caller resolves
		// those directly; a miss is not a failure.
		conn := seededConnection(prod)

		got, err := conn.CompartmentByID(ctx, "ocid1.compartment.oc1..elsewhere")

		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("an empty id misses before the tree is touched", func(t *testing.T) {
		// Not seeded, so a connection that reached GetCompartments here would
		// try to build an Identity client instead of returning.
		conn := &OciConnection{}

		got, err := conn.CompartmentByID(ctx, "")

		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("the index is built once and reused", func(t *testing.T) {
		conn := seededConnection(prod)

		_, err := conn.CompartmentByID(ctx, "ocid1.compartment.oc1..prod")
		require.NoError(t, err)
		first := conn.compartmentIndex
		require.NotNil(t, first)

		_, err = conn.CompartmentByID(ctx, "ocid1.compartment.oc1..prod")
		require.NoError(t, err)

		assert.True(t, sameMap(first, conn.compartmentIndex),
			"the index must be memoized, not rebuilt per lookup")
	})

	t.Run("the returned record does not alias the memoized tree", func(t *testing.T) {
		conn := seededConnection(prod)

		got, err := conn.CompartmentByID(ctx, "ocid1.compartment.oc1..prod")
		require.NoError(t, err)
		got.Name = new("mutated")

		again, err := conn.CompartmentByID(ctx, "ocid1.compartment.oc1..prod")
		require.NoError(t, err)
		assert.Equal(t, "prod", *again.Name)
	})

	t.Run("concurrent lookups share one index", func(t *testing.T) {
		// Every resource in the provider resolves its compartment, and the
		// executor resolves fields in goroutines, so this runs concurrently by
		// construction. Run under -race.
		conn := seededConnection(prod, testCompartment("ocid1.compartment.oc1..dev", "dev"))

		var wg sync.WaitGroup
		for i := range 32 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				id := "ocid1.compartment.oc1..prod"
				if i%2 == 0 {
					id = "ocid1.compartment.oc1..dev"
				}
				got, err := conn.CompartmentByID(ctx, id)
				assert.NoError(t, err)
				assert.NotNil(t, got)
			}(i)
		}
		wg.Wait()

		assert.Len(t, conn.compartmentIndex, 2)
	})
}

// sameMap reports whether two maps are the same underlying map, which is what
// distinguishes a memoized index from one rebuilt on every lookup.
//
// It writes a probe key into a and looks for it in b, so a is mutated for the
// duration of the call. The key is removed again before returning and is
// chosen not to collide with an OCID, but a caller must not rely on a being
// untouched while this runs - in particular it is not safe to call
// concurrently with a read of either map.
func sameMap(a, b map[string]identity.Compartment) bool {
	if len(a) != len(b) {
		return false
	}
	const probe = "\x00sameMap-probe"
	a[probe] = identity.Compartment{}
	_, ok := b[probe]
	delete(a, probe)
	return ok
}

func TestCompartmentFetchBlocked(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	failure := errors.New("throttled")

	t.Run("nothing has failed yet, so nothing is held back", func(t *testing.T) {
		conn := &OciConnection{}

		assert.False(t, conn.compartmentFetchBlocked(now))
	})

	t.Run("a fresh failure is reused instead of retried", func(t *testing.T) {
		// This is the case the window exists for: every resource that reports
		// its compartment reaches GetCompartments, so retrying a throttled
		// listing per resource is what turns one throttle into hundreds.
		conn := &OciConnection{
			compartmentFetchErr: failure,
			compartmentFetchAt:  now.Add(-time.Second),
		}

		assert.True(t, conn.compartmentFetchBlocked(now))
	})

	t.Run("a failure past the window is retried", func(t *testing.T) {
		// A throttle that has cleared must not decide the compartment of
		// everything read for the rest of the scan.
		conn := &OciConnection{
			compartmentFetchErr: failure,
			compartmentFetchAt:  now.Add(-compartmentFetchRetryAfter - time.Second),
		}

		assert.False(t, conn.compartmentFetchBlocked(now))
	})

	t.Run("the window boundary itself is retried", func(t *testing.T) {
		conn := &OciConnection{
			compartmentFetchErr: failure,
			compartmentFetchAt:  now.Add(-compartmentFetchRetryAfter),
		}

		assert.False(t, conn.compartmentFetchBlocked(now))
	})
}

func TestGetCompartmentsHoldsARecentFailure(t *testing.T) {
	failure := errors.New("throttled listing")

	t.Run("a held failure is returned without reaching the api", func(t *testing.T) {
		// The connection has no configuration provider, so the OCI SDK panics
		// if the fetch is attempted. Reaching the end of this test is the
		// assertion that it was not.
		conn := &OciConnection{
			compartmentFetchErr: failure,
			compartmentFetchAt:  time.Now(),
		}

		got, err := conn.GetCompartments(context.Background())

		assert.Nil(t, got)
		assert.ErrorIs(t, err, failure)
	})

	t.Run("a fetched tree answers even with a failure recorded", func(t *testing.T) {
		// compartmentsDone wins over the retry window: once the tree is in
		// hand an earlier failure is history, not an answer.
		conn := seededConnection(testCompartment("ocid1.compartment.oc1..prod", "prod"))
		conn.compartmentFetchErr = failure
		conn.compartmentFetchAt = time.Now()

		got, err := conn.GetCompartments(context.Background())

		require.NoError(t, err)
		assert.Len(t, got, 1)
	})
}

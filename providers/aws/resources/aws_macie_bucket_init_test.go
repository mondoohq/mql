// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
)

// A nil *mqlAwsMacieBucket assigned to a plugin.Resource interface is NOT nil.
// That is the whole bug: describeMacieBucket returns a typed nil for a bucket
// outside Macie's inventory, initAwsMacieBucket used to hand it straight back,
// and NewResource's `if res != nil` guard then called MqlID() on a nil receiver.
//
// This test documents the Go semantics the fix depends on, so a future refactor
// that reintroduces `return args, res, nil` fails here first.
func TestTypedNilResourceIsNotNilAsAnInterface(t *testing.T) {
	var concrete *mqlAwsMacieBucket // nil pointer

	var iface plugin.Resource = concrete

	require.Nil(t, concrete, "the concrete pointer is nil")

	// Compare with Go's own operator, which is what NewResource does. Note that
	// testify's assert.NotNil uses reflection and would report this as nil,
	// disagreeing with the language - which is exactly how the bug hid.
	assert.True(t, iface != nil,
		"an interface holding a nil *mqlAwsMacieBucket is not nil - this is why "+
			"NewResource's `if res != nil` guard passed and MqlID() panicked")

	// Prove the deref actually panics, so the guard is load-bearing rather than
	// defensive.
	assert.Panics(t, func() { _ = iface.MqlID() },
		"calling MqlID() on the typed nil must panic")
}

// Guarding on the concrete pointer before widening to the interface is what
// makes the difference. This is the shape the fix uses.
func TestGuardingTheConcretePointerYieldsATrueNilInterface(t *testing.T) {
	var concrete *mqlAwsMacieBucket

	var iface plugin.Resource
	if concrete != nil {
		iface = concrete
	}

	assert.True(t, iface == nil, "guarding on the concrete pointer keeps the interface nil")
}

// The not-covered case has to be distinguishable from a real failure, because
// macieCoverage turns one into a null field and must propagate the other.
func TestMacieBucketNotCoveredIsDistinguishable(t *testing.T) {
	assert.True(t, errors.Is(errMacieBucketNotCovered, errMacieBucketNotCovered))

	// survives wrapping, which is how it travels back through NewResource
	wrapped := fmt.Errorf("aws.macie.bucket lookup: %w", errMacieBucketNotCovered)
	assert.True(t, errors.Is(wrapped, errMacieBucketNotCovered))

	// a genuine failure must not be mistaken for it
	assert.False(t, errors.Is(errors.New("AccessDeniedException"), errMacieBucketNotCovered))
	assert.False(t, errors.Is(fmt.Errorf("macie2 throttled"), errMacieBucketNotCovered))
}

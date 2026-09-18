// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsNoMatchError(t *testing.T) {
	wrappedLast := fmt.Errorf("no Helm charts found at /x: %w", ErrNoMatch)
	// A provider that wraps the sentinel first rather than last. errors.Is
	// still catches it, which is why normalizing inside the provider process
	// makes wrap order stop being load-bearing.
	wrappedFirst := fmt.Errorf("%w at /x", ErrNoMatch)

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"raw sentinel", ErrNoMatch, true},
		{"wrapped last", wrappedLast, true},
		{"wrapped first", wrappedFirst, true},
		{"wrapped twice", fmt.Errorf("connect: %w", wrappedLast), true},

		// The wire forms. NoMatchStatus is what GRPCServer.Connect returns.
		{"wire form of a wrapped sentinel", NoMatchStatus(wrappedLast), true},
		{"wire form of a sentinel-first wrap", NoMatchStatus(wrappedFirst), true},
		// A status the caller wrapped again: status.FromError reports ok=false
		// for this, which is the bug IsUnsupportedProviderError has.
		{"wire form, re-wrapped by the caller", fmt.Errorf("probe: %w", NoMatchStatus(wrappedLast)), true},

		// A provider binary built before the status detail existed: only the
		// message text is left to go on.
		{"text-only status", status.Error(codes.Unknown, "no Helm charts found at /x: "+ErrNoMatch.Error()), true},
		{"text-only status, sentinel alone", status.Error(codes.Unknown, ErrNoMatch.Error()), true},

		{"nil", nil, false},
		{"an ordinary failure", errors.New("permission denied"), false},
		{"the other sentinel", ErrUnsupportedProvider, false},
		{"a panic status", status.Error(codes.Internal, "panic in provider Connect: nil map"), false},
		// Anchored, not a substring search: this must not be read as a verdict.
		{"a message that merely contains the words", errors.New("found no match for this provider in the cache"), false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, IsNoMatchError(test.err))
		})
	}
}

func TestNoMatchStatusKeepsTheProvidersMessage(t *testing.T) {
	err := NoMatchStatus(fmt.Errorf("no Helm charts found at /x: %w", ErrNoMatch))

	st := status.Convert(err)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	// The provider's own explanation is the useful half and has to survive; a
	// caller that reports the error shows this text.
	assert.Equal(t, "no Helm charts found at /x: not a match for this provider", st.Message())

	details := st.Details()
	require.Len(t, details, 1)
	detail, ok := details[0].(*ErrorDetail)
	require.True(t, ok)
	assert.Equal(t, ErrorKind_ERROR_KIND_NO_MATCH, detail.GetKind())
}

func TestNormalizeConnectError(t *testing.T) {
	// A no-match becomes the wire form.
	assert.True(t, IsNoMatchError(normalizeConnectError(fmt.Errorf("nope: %w", ErrNoMatch))))

	// Everything else is handed back untouched, so a real failure keeps both
	// its identity and its message.
	real := errors.New("permission denied")
	assert.Same(t, real, normalizeConnectError(real))

	unsupported := ErrUnsupportedProvider
	assert.Same(t, unsupported, normalizeConnectError(unsupported))
	assert.False(t, IsNoMatchError(normalizeConnectError(unsupported)))
}

func TestIsUnsupportedProviderError(t *testing.T) {
	assert.True(t, IsUnsupportedProviderError(ErrUnsupportedProvider))
	assert.True(t, IsUnsupportedProviderError(status.Error(codes.Unknown, ErrUnsupportedProvider.Error())))
	assert.False(t, IsUnsupportedProviderError(nil))
	assert.False(t, IsUnsupportedProviderError(errors.New("permission denied")))
	assert.False(t, IsUnsupportedProviderError(ErrNoMatch))
}

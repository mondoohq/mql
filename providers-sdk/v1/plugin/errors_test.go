// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
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

// ADR 046: the kind has to survive the field path, which is where a provider's
// classification would otherwise be flattened into DataRes.error.

func TestTValueCarriesTheKindOntoTheWire(t *testing.T) {
	// A refused read: null value, classified error. This is the shape the ~1000
	// access-denied call sites produce once they stop returning nil, nil.
	tv := TValue[string]{
		State: StateIsSet | StateIsNull,
		Error: llx.Forbidden(errors.New("AccessDenied"),
			llx.WithPermissions("ec2:DescribeInstances")),
	}

	res := tv.ToDataRes(types.String)
	require.NotNil(t, res.ErrorDetail)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, res.ErrorDetail.Kind)
	assert.Equal(t, []string{"ec2:DescribeInstances"}, res.ErrorDetail.Permissions)
	assert.Equal(t, "AccessDenied", res.Error)

	// …and the executor rebuilds it rather than an anonymous error.
	back := llx.ErrorFromDetail(res.Error, res.ErrorDetail)
	require.Error(t, back)
	assert.True(t, errors.Is(back, llx.ErrForbidden))
	assert.Equal(t, "AccessDenied", back.Error())
}

func TestTValueWithAValueCarriesTheKind(t *testing.T) {
	// The non-null path goes through RawData.Result() instead, so it needs its
	// own coverage: a read that reports a value and an error. That still means
	// failed; a partial result is a Partial (see coverage_test.go).
	tv := TValue[string]{
		State: StateIsSet,
		Data:  "partial",
		Error: llx.TooManyRequests(errors.New("Throttling"), llx.WithRetryAfter(2*time.Second)),
	}

	res := tv.ToDataRes(types.String)
	require.NotNil(t, res.ErrorDetail)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS, res.ErrorDetail.Kind)
	assert.Equal(t, int64(2000), res.ErrorDetail.RetryAfterMs)
}

func TestUnclassifiedErrorsEncodeNoDetail(t *testing.T) {
	// Every provider that has not been migrated lands here, and must behave
	// exactly as it did before.
	tv := TValue[string]{State: StateIsSet | StateIsNull, Error: errors.New("boom")}

	res := tv.ToDataRes(types.String)
	assert.Nil(t, res.ErrorDetail)
	assert.Equal(t, "boom", res.Error)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(llx.ErrorFromDetail(res.Error, res.ErrorDetail)))
}

func TestNoMatchStatusStillCarriesItsKind(t *testing.T) {
	// ADR 045's detail arm, after the message moved packages: the type URL
	// changed, so this is the test that the status detail still round-trips.
	err := NoMatchStatus(fmt.Errorf("no Helm charts found at /x: %w", ErrNoMatch))
	assert.True(t, IsNoMatchError(err))
}

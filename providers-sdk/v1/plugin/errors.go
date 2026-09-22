// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"errors"
	"strings"

	"go.mondoo.com/mql/llx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrorKind and ErrorDetail moved to llx in ADR 046, so that llx.Result could
// carry them too - plugin imports llx, so the shared vocabulary has to live in
// the lower layer. These aliases keep every existing spelling working, and keep
// providers on one import for the classification helpers below.
type (
	ErrorKind   = llx.ErrorKind
	ErrorDetail = llx.ErrorDetail
	ErrorScope  = llx.ErrorScope
)

const (
	ErrorKind_ERROR_KIND_UNSPECIFIED       = llx.ErrorKind_ERROR_KIND_UNSPECIFIED
	ErrorKind_ERROR_KIND_NO_MATCH          = llx.ErrorKind_ERROR_KIND_NO_MATCH
	ErrorKind_ERROR_KIND_UNAUTHENTICATED   = llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED
	ErrorKind_ERROR_KIND_FORBIDDEN         = llx.ErrorKind_ERROR_KIND_FORBIDDEN
	ErrorKind_ERROR_KIND_NOT_FOUND         = llx.ErrorKind_ERROR_KIND_NOT_FOUND
	ErrorKind_ERROR_KIND_NOT_APPLICABLE    = llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE
	ErrorKind_ERROR_KIND_GONE              = llx.ErrorKind_ERROR_KIND_GONE
	ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS = llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS
	ErrorKind_ERROR_KIND_UNAVAILABLE       = llx.ErrorKind_ERROR_KIND_UNAVAILABLE
	ErrorKind_ERROR_KIND_MALFORMED_DATA    = llx.ErrorKind_ERROR_KIND_MALFORMED_DATA
	ErrorKind_ERROR_KIND_ASSET_VANISHED    = llx.ErrorKind_ERROR_KIND_ASSET_VANISHED
)

// The constructors a provider reaches for, re-exported so classifying an error
// needs no second import. See llx/errors.go for the type itself.
var (
	Unauthenticated = llx.Unauthenticated
	Forbidden       = llx.Forbidden
	NotFound        = llx.NotFound
	NotApplicable   = llx.NotApplicable
	Gone            = llx.Gone
	TooManyRequests = llx.TooManyRequests
	Unavailable     = llx.Unavailable
	MalformedData   = llx.MalformedData
	AssetVanished   = llx.AssetVanished

	WithScope       = llx.WithScope
	WithPermissions = llx.WithPermissions
	WithRetryAfter  = llx.WithRetryAfter

	KindOf = llx.KindOf
)

var (
	ErrProviderTypeDoesNotMatch = errors.New("provider type does not match")
	ErrUnsupportedProvider      = errors.New("unsupported provider")
	ErrRunCommandNotImplemented = errors.New("provider does not implement RunCommand")
	ErrFileInfoNotImplemented   = errors.New("provider does not implement FileInfo")

	// ErrNoMatch is returned by Connect when the target is not this provider's:
	// the connection type was right, the files were not. Discovery drops the
	// asset; every other error is retained and reported (ADR 045).
	//
	// A new sentinel rather than a reuse, because the two above both mean
	// *wrong connection type*, which is a wiring bug. A mismatch is the other
	// kind of statement, and the only one of the three that is a normal
	// outcome. Reusing ErrUnsupportedProvider would also inherit the four sites
	// in cli/printer/mql.go that suppress output for it.
	//
	// Wrap it last, so the message reads as the provider's own explanation
	// followed by the verdict:
	//
	//	fmt.Errorf("no Helm charts found at %s: %w", path, plugin.ErrNoMatch)
	//
	// Wrap order is not load-bearing across the process boundary -- the SDK
	// normalizes on the way out, see NoMatchStatus -- but it is what makes the
	// text arm of IsNoMatchError work for a provider built before that existed.
	ErrNoMatch = errors.New("not a match for this provider")
)

// NoMatchStatus converts err into the wire form of a no-match, keeping the
// provider's own message and attaching ERROR_KIND_NO_MATCH as a status detail.
//
// Called from GRPCServer.Connect, which runs inside the provider process: there
// errors.Is still sees the sentinel the provider wrapped, so a provider that
// wraps in an unusual order is not silently misread by the caller. That is the
// whole point of normalizing here rather than trusting nine authors.
func NoMatchStatus(err error) error {
	st := status.New(codes.FailedPrecondition, err.Error())
	// WithDetails can fail to marshal; a bare status still carries the message,
	// which the text arm of IsNoMatchError reads. Losing the error entirely
	// would be worse than losing the detail.
	if withDetails, derr := st.WithDetails(&ErrorDetail{Kind: ErrorKind_ERROR_KIND_NO_MATCH}); derr == nil {
		st = withDetails
	}
	return st.Err()
}

// IsNoMatchError reports whether e is a provider saying the target is not its
// own. Three forms, in order of authority:
//
//  1. the raw sentinel, for a builtin child connected in-process;
//  2. the ErrorDetail on the gRPC status, which GRPCServer.Connect attaches
//     for every provider built from this SDK;
//  3. the message text, for a provider binary built before (2) existed.
//
// This is a Connect-only contract. Nothing normalizes ErrNoMatch on GetData.
//
// Note status.Convert rather than status.FromError: FromError reports ok=false
// for a status reached through errors.As, i.e. any wrapped one, which is why
// IsUnsupportedProviderError below answers "no" for a wrapped
// ErrUnsupportedProvider.
func IsNoMatchError(e error) bool {
	if e == nil {
		return false
	}
	if errors.Is(e, ErrNoMatch) {
		return true
	}

	st := status.Convert(e)
	for _, detail := range st.Details() {
		if d, ok := detail.(*ErrorDetail); ok && d.GetKind() == ErrorKind_ERROR_KIND_NO_MATCH {
			return true
		}
	}

	msg := st.Message()
	return msg == ErrNoMatch.Error() || strings.HasSuffix(msg, ": "+ErrNoMatch.Error())
}

// IsUnsupportedProviderError checks if the given errors indicates an unsupported provider
// for either a direct (non-grpc) transmission or a GRPC-based call
func IsUnsupportedProviderError(e error) bool {
	if e == ErrUnsupportedProvider {
		return true
	}
	st, ok := status.FromError(e)
	if !ok {
		return false
	}
	return st.Message() == ErrUnsupportedProvider.Error()
}

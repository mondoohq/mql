// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"time"
)

// Structured provider errors (ADR 046).
//
// A failure that a provider can classify travels as an *Error: the kind says
// what went wrong in terms every consumer shares, and the wrapped error keeps
// the target's own words. Both matter. The kind is what a report groups on and
// what stops "not allowed to look" from being reported as "nothing is
// configured"; the message is what a human reads when the kind is not enough.
//
// The type lives in llx rather than in the plugin SDK because llx cannot import
// plugin (plugin imports llx), and both the executor and the printer need to
// read a kind. Providers already import llx, so constructing one costs them no
// new dependency.

// Error is a failure carrying an ErrorKind and the context a consumer needs to
// act on it.
//
// Match on it with errors.Is against the kind sentinels below, or read the kind
// directly with KindOf. Both unwrap, so a caller that wraps for context
// (fmt.Errorf("listing buckets: %w", err)) does not lose the classification -
// which is the failure mode that makes message matching unusable.
type Error struct {
	Kind    ErrorKind
	Scope   ErrorScope
	ScopeID string
	// Permissions the refused call needed, e.g. "ec2:DescribeInstances", or the
	// elevation an OS scan lacked.
	Permissions []string
	// RetryAfter is the target's own hint for 429 and 503. Carried, not acted
	// on: nothing in mql retries on it.
	RetryAfter time.Duration

	err error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.err != nil {
		return e.err.Error()
	}
	return e.Kind.Label()
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// Is folds an *Error onto its kind sentinel, so errors.Is(err, ErrForbidden)
// answers true for any forbidden error whatever its message and however deeply
// it is wrapped.
func (e *Error) Is(target error) bool {
	if e == nil {
		return false
	}
	k, ok := target.(kindSentinel)
	return ok && ErrorKind(k) == e.Kind
}

// kindSentinel is an error whose only content is a kind. It exists so that
// errors.Is has something to compare against; nothing ever returns one.
type kindSentinel ErrorKind

func (k kindSentinel) Error() string { return ErrorKind(k).Label() }

// Sentinels for errors.Is. They are never returned, only matched.
var (
	ErrUnauthenticated error = kindSentinel(ErrorKind_ERROR_KIND_UNAUTHENTICATED)
	ErrForbidden       error = kindSentinel(ErrorKind_ERROR_KIND_FORBIDDEN)
	ErrNotFound        error = kindSentinel(ErrorKind_ERROR_KIND_NOT_FOUND)
	ErrNotApplicable   error = kindSentinel(ErrorKind_ERROR_KIND_NOT_APPLICABLE)
	ErrGone            error = kindSentinel(ErrorKind_ERROR_KIND_GONE)
	ErrTooManyRequests error = kindSentinel(ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS)
	// Named for the target rather than after its kind, to keep it apart from
	// ErrVersionSkew in skew.go ("missing because of version skew"). Two
	// different absences; one name each.
	ErrTargetUnavailable error = kindSentinel(ErrorKind_ERROR_KIND_UNAVAILABLE)
	ErrMalformedData     error = kindSentinel(ErrorKind_ERROR_KIND_MALFORMED_DATA)
	ErrAssetVanished     error = kindSentinel(ErrorKind_ERROR_KIND_ASSET_VANISHED)
)

// Label names a kind for a human. Used as the message of an Error built with no
// underlying error, and by the printer.
func (k ErrorKind) Label() string {
	switch k {
	case ErrorKind_ERROR_KIND_NO_MATCH:
		return "not a match for this provider"
	case ErrorKind_ERROR_KIND_UNAUTHENTICATED:
		return "unauthenticated"
	case ErrorKind_ERROR_KIND_FORBIDDEN:
		return "access denied"
	case ErrorKind_ERROR_KIND_NOT_FOUND:
		return "not found"
	case ErrorKind_ERROR_KIND_NOT_APPLICABLE:
		return "not applicable"
	case ErrorKind_ERROR_KIND_GONE:
		return "gone"
	case ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS:
		return "too many requests"
	case ErrorKind_ERROR_KIND_UNAVAILABLE:
		return "unavailable"
	case ErrorKind_ERROR_KIND_MALFORMED_DATA:
		return "malformed data"
	case ErrorKind_ERROR_KIND_ASSET_VANISHED:
		return "asset vanished"
	default:
		return "error"
	}
}

// ErrorOption sets one of the fields that ride beside the kind.
type ErrorOption func(*Error)

// WithScope records how far the failure reaches. A partition scope names the
// region, project, or subscription it covers.
func WithScope(scope ErrorScope, id string) ErrorOption {
	return func(e *Error) {
		e.Scope = scope
		e.ScopeID = id
	}
}

// WithPermissions records the permissions the refused call needed.
func WithPermissions(permissions ...string) ErrorOption {
	return func(e *Error) {
		e.Permissions = append(e.Permissions, permissions...)
	}
}

// WithRetryAfter records the target's own wait hint.
func WithRetryAfter(d time.Duration) ErrorOption {
	return func(e *Error) { e.RetryAfter = d }
}

// NewError classifies err as kind. A nil err is allowed: the kind's label
// becomes the message.
func NewError(kind ErrorKind, err error, opts ...ErrorOption) *Error {
	res := &Error{Kind: kind, err: err}
	for i := range opts {
		opts[i](res)
	}
	return res
}

// One constructor per kind, so a call site reads as the statement it is making.
// ERROR_KIND_NO_MATCH has no constructor here: it is a Connect outcome and
// keeps plugin.ErrNoMatch.

func Unauthenticated(err error, opts ...ErrorOption) *Error {
	return NewError(ErrorKind_ERROR_KIND_UNAUTHENTICATED, err, opts...)
}

func Forbidden(err error, opts ...ErrorOption) *Error {
	return NewError(ErrorKind_ERROR_KIND_FORBIDDEN, err, opts...)
}

func NotFound(err error, opts ...ErrorOption) *Error {
	return NewError(ErrorKind_ERROR_KIND_NOT_FOUND, err, opts...)
}

func NotApplicable(err error, opts ...ErrorOption) *Error {
	return NewError(ErrorKind_ERROR_KIND_NOT_APPLICABLE, err, opts...)
}

func Gone(err error, opts ...ErrorOption) *Error {
	return NewError(ErrorKind_ERROR_KIND_GONE, err, opts...)
}

func TooManyRequests(err error, opts ...ErrorOption) *Error {
	return NewError(ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS, err, opts...)
}

func Unavailable(err error, opts ...ErrorOption) *Error {
	return NewError(ErrorKind_ERROR_KIND_UNAVAILABLE, err, opts...)
}

func MalformedData(err error, opts ...ErrorOption) *Error {
	return NewError(ErrorKind_ERROR_KIND_MALFORMED_DATA, err, opts...)
}

func AssetVanished(err error, opts ...ErrorOption) *Error {
	return NewError(ErrorKind_ERROR_KIND_ASSET_VANISHED, err, opts...)
}

// KindOf reports how err was classified, unwrapping as needed.
// ERROR_KIND_UNSPECIFIED for a nil error and for anything unclassified, which
// is the same answer on purpose: neither carries a claim.
func KindOf(err error) ErrorKind {
	if err == nil {
		return ErrorKind_ERROR_KIND_UNSPECIFIED
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ErrorKind_ERROR_KIND_UNSPECIFIED
}

// ErrorDetailOf renders err into its wire form, or nil when err carries no
// classification. Encoding nothing for an unclassified error is what keeps this
// free for the overwhelming majority of results, which have no error at all.
func ErrorDetailOf(err error) *ErrorDetail {
	if err == nil {
		return nil
	}
	var e *Error
	if !errors.As(err, &e) || e.Kind == ErrorKind_ERROR_KIND_UNSPECIFIED {
		return nil
	}
	return &ErrorDetail{
		Kind:         e.Kind,
		Scope:        e.Scope,
		ScopeId:      e.ScopeID,
		Permissions:  e.Permissions,
		RetryAfterMs: e.RetryAfter.Milliseconds(),
	}
}

// ErrorFromDetail rebuilds a classified error from the wire, keeping msg as the
// message so the target's own words survive the round trip.
//
// A detail with no kind rebuilds as a plain error: an unclassified failure
// stays unclassified rather than acquiring a meaning it never had. A nil detail
// and an empty message together mean no error at all.
func ErrorFromDetail(msg string, detail *ErrorDetail) error {
	if detail.GetKind() == ErrorKind_ERROR_KIND_UNSPECIFIED {
		if msg == "" {
			return nil
		}
		return errors.New(msg)
	}

	var inner error
	if msg != "" {
		inner = errors.New(msg)
	}
	return &Error{
		Kind:        detail.GetKind(),
		Scope:       detail.GetScope(),
		ScopeID:     detail.GetScopeId(),
		Permissions: detail.GetPermissions(),
		RetryAfter:  time.Duration(detail.GetRetryAfterMs()) * time.Millisecond,
		err:         inner,
	}
}

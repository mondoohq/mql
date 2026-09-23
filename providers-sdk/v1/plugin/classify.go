// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"net/http"
	"strconv"
	"time"

	"go.mondoo.com/mql/llx"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The SDK's default mapping from a target's status to an mql ErrorKind
// (ADR 046 §1).
//
// It is a starting point, never the whole answer. The body can overrule the
// status: GCP answers 403 for an API that was never enabled, which is not
// applicable rather than forbidden. So a provider runs its own checks first
// and calls these last:
//
//	if isServiceDisabled(err) {
//		return nil, plugin.NotApplicable(err)
//	}
//	return nil, plugin.ClassifyGRPC(err)
//
// An error that is already classified passes through untouched, so the order
// is safe even when a provider's own check ran further down the stack.

// ErrorKindFromHTTPStatus returns the mql ErrorKind an HTTP status stands for,
// or ERROR_KIND_UNSPECIFIED for a status that makes no claim on its own (any
// 2xx-3xx, a plain 400, a 409, and every 5xx but 501 and 503). An ErrorKind
// exists because there is something for the user to do; a 500 or a 504 gives
// them nothing (ADR 046 §1). Malformed data and asset vanished have no status
// and never come out of here.
func ErrorKindFromHTTPStatus(code int) llx.ErrorKind {
	switch code {
	case http.StatusUnauthorized:
		return llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED
	case http.StatusForbidden:
		return llx.ErrorKind_ERROR_KIND_FORBIDDEN
	case http.StatusNotFound:
		return llx.ErrorKind_ERROR_KIND_NOT_FOUND
	case http.StatusGone:
		return llx.ErrorKind_ERROR_KIND_GONE
	case http.StatusTooManyRequests:
		return llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS
	case http.StatusNotImplemented:
		return llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE
	case http.StatusServiceUnavailable:
		return llx.ErrorKind_ERROR_KIND_UNAVAILABLE
	default:
		return llx.ErrorKind_ERROR_KIND_UNSPECIFIED
	}
}

// ErrorKindFromGRPCCode returns the mql ErrorKind a gRPC status code stands
// for, or ERROR_KIND_UNSPECIFIED.
//
// Internal, Unknown, DataLoss and DeadlineExceeded stay unclassified for the
// same reason 500 and 504 do: they give the user nothing to act on.
func ErrorKindFromGRPCCode(code codes.Code) llx.ErrorKind {
	switch code {
	case codes.Unauthenticated:
		return llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED
	case codes.PermissionDenied:
		return llx.ErrorKind_ERROR_KIND_FORBIDDEN
	case codes.NotFound:
		return llx.ErrorKind_ERROR_KIND_NOT_FOUND
	case codes.ResourceExhausted:
		return llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS
	case codes.Unimplemented:
		return llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE
	case codes.Unavailable:
		return llx.ErrorKind_ERROR_KIND_UNAVAILABLE
	default:
		return llx.ErrorKind_ERROR_KIND_UNSPECIFIED
	}
}

// ClassifyHTTPStatus classifies err by the HTTP status the target answered
// with. The provider extracts the status from its SDK's error type
// (smithy's ResponseError, azcore.ResponseError, googleapi.Error), which keeps
// the SDK free of every cloud's client library.
//
// header may be nil. When it is not, a Retry-After on a 429 or 503 rides along
// as the wait hint. err is returned unchanged when it is nil, already
// classified, or the status makes no claim.
func ClassifyHTTPStatus(err error, code int, header http.Header, opts ...llx.ErrorOption) error {
	if err == nil || llx.KindOf(err) != llx.ErrorKind_ERROR_KIND_UNSPECIFIED {
		return err
	}
	kind := ErrorKindFromHTTPStatus(code)
	if kind == llx.ErrorKind_ERROR_KIND_UNSPECIFIED {
		return err
	}
	if code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable {
		if d := RetryAfterFromHeader(header, time.Now()); d > 0 {
			opts = append([]llx.ErrorOption{llx.WithRetryAfter(d)}, opts...)
		}
	}
	return llx.NewError(kind, err, opts...)
}

// ClassifyGRPC classifies err by its gRPC status code, found through any
// wrapping. A RetryInfo detail on the status rides along as the wait hint. err
// is returned unchanged when it is nil, already classified, not a status, or
// its code makes no claim.
func ClassifyGRPC(err error, opts ...llx.ErrorOption) error {
	if err == nil || llx.KindOf(err) != llx.ErrorKind_ERROR_KIND_UNSPECIFIED {
		return err
	}
	// status.Code finds a status through any wrapping; a plain error reads as
	// codes.Unknown, which maps to nothing.
	kind := ErrorKindFromGRPCCode(status.Code(err))
	if kind == llx.ErrorKind_ERROR_KIND_UNSPECIFIED {
		return err
	}
	if d := retryAfterFromStatus(err); d > 0 {
		opts = append([]llx.ErrorOption{llx.WithRetryAfter(d)}, opts...)
	}
	return llx.NewError(kind, err, opts...)
}

// RetryAfterFromHeader reads a Retry-After header, in either of its two forms:
// delay-seconds or an HTTP-date, measured against now. Zero means no usable
// hint, including a date already in the past.
func RetryAfterFromHeader(header http.Header, now time.Time) time.Duration {
	v := header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

func retryAfterFromStatus(err error) time.Duration {
	st, ok := status.FromError(err)
	if !ok {
		return 0
	}
	for _, detail := range st.Details() {
		if ri, ok := detail.(*errdetails.RetryInfo); ok {
			if d := ri.GetRetryDelay().AsDuration(); d > 0 {
				return d
			}
		}
	}
	return 0
}

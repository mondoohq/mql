// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestErrorKindFromHTTPStatus(t *testing.T) {
	cases := map[int]llx.ErrorKind{
		200: llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
		304: llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
		400: llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
		401: llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED,
		403: llx.ErrorKind_ERROR_KIND_FORBIDDEN,
		404: llx.ErrorKind_ERROR_KIND_NOT_FOUND,
		409: llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
		410: llx.ErrorKind_ERROR_KIND_GONE,
		429: llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS,
		500: llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
		501: llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE,
		502: llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
		503: llx.ErrorKind_ERROR_KIND_UNAVAILABLE,
		504: llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
		600: llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
	}
	for code, want := range cases {
		assert.Equal(t, want, ErrorKindFromHTTPStatus(code), "status %d", code)
	}
}

func TestErrorKindFromGRPCCode(t *testing.T) {
	cases := map[codes.Code]llx.ErrorKind{
		codes.OK:                 llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
		codes.Unauthenticated:    llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED,
		codes.PermissionDenied:   llx.ErrorKind_ERROR_KIND_FORBIDDEN,
		codes.NotFound:           llx.ErrorKind_ERROR_KIND_NOT_FOUND,
		codes.ResourceExhausted:  llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS,
		codes.Unimplemented:      llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE,
		codes.Unavailable:        llx.ErrorKind_ERROR_KIND_UNAVAILABLE,
		codes.DeadlineExceeded:   llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
		codes.Internal:           llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
		codes.Unknown:            llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
		codes.DataLoss:           llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
		codes.FailedPrecondition: llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
		codes.InvalidArgument:    llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
	}
	for code, want := range cases {
		assert.Equal(t, want, ErrorKindFromGRPCCode(code), "code %s", code)
	}
}

func TestClassifyHTTPStatus(t *testing.T) {
	upstream := errors.New("AccessDenied: not authorized to perform ec2:DescribeInstances")

	t.Run("classifies and keeps the message", func(t *testing.T) {
		err := ClassifyHTTPStatus(upstream, 403, nil, llx.WithPermissions("ec2:DescribeInstances"))
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
		assert.Equal(t, upstream.Error(), err.Error())
		assert.ErrorIs(t, err, upstream)
		assert.Equal(t, []string{"ec2:DescribeInstances"}, llx.ErrorDetailOf(err).Permissions)
	})

	t.Run("unclassified status returns err unchanged", func(t *testing.T) {
		assert.Same(t, upstream, ClassifyHTTPStatus(upstream, 400, nil))
	})

	t.Run("nil stays nil", func(t *testing.T) {
		assert.NoError(t, ClassifyHTTPStatus(nil, 403, nil))
	})

	t.Run("an already classified error wins over the status", func(t *testing.T) {
		// GCP's 403 for an API that was never enabled: the provider's own check
		// ran first and said not applicable.
		mine := fmt.Errorf("listing: %w", llx.NotApplicable(upstream))
		err := ClassifyHTTPStatus(mine, 403, nil)
		assert.Same(t, mine, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(err))
	})

	t.Run("retry-after on 429 and 503", func(t *testing.T) {
		h := http.Header{}
		h.Set("Retry-After", "7")
		for _, code := range []int{429, 503} {
			err := ClassifyHTTPStatus(upstream, code, h)
			assert.Equal(t, int64(7000), llx.ErrorDetailOf(err).RetryAfterMs, "status %d", code)
		}
	})

	t.Run("retry-after ignored on other statuses", func(t *testing.T) {
		h := http.Header{}
		h.Set("Retry-After", "7")
		err := ClassifyHTTPStatus(upstream, 401, h)
		assert.Zero(t, llx.ErrorDetailOf(err).RetryAfterMs)
	})
}

func TestClassifyGRPC(t *testing.T) {
	t.Run("classifies through wrapping", func(t *testing.T) {
		st := status.New(codes.PermissionDenied, "Permission 'compute.instances.list' denied")
		err := ClassifyGRPC(fmt.Errorf("listing instances: %w", st.Err()))
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
		assert.Contains(t, err.Error(), "compute.instances.list")
	})

	t.Run("plain error is not a status", func(t *testing.T) {
		plain := errors.New("dial tcp: connection refused")
		assert.Same(t, plain, ClassifyGRPC(plain))
	})

	t.Run("unclassified code returns err unchanged", func(t *testing.T) {
		internal := status.Error(codes.Internal, "boom")
		assert.Same(t, internal, ClassifyGRPC(internal))
	})

	t.Run("an already classified error wins over the code", func(t *testing.T) {
		mine := llx.NotApplicable(status.Error(codes.PermissionDenied, "SERVICE_DISABLED"))
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(ClassifyGRPC(mine)))
	})

	t.Run("retry info rides along", func(t *testing.T) {
		st, err := status.New(codes.ResourceExhausted, "quota exceeded").
			WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(1500 * time.Millisecond)})
		require.NoError(t, err)
		res := ClassifyGRPC(fmt.Errorf("wrapped: %w", st.Err()))
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS, llx.KindOf(res))
		assert.Equal(t, int64(1500), llx.ErrorDetailOf(res).RetryAfterMs)
	})
}

func TestRetryAfterFromHeader(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	header := func(v string) http.Header {
		h := http.Header{}
		h.Set("Retry-After", v)
		return h
	}

	assert.Equal(t, 120*time.Second, RetryAfterFromHeader(header("120"), now))
	assert.Equal(t, 30*time.Second, RetryAfterFromHeader(header(now.Add(30*time.Second).Format(http.TimeFormat)), now))
	assert.Zero(t, RetryAfterFromHeader(header(now.Add(-time.Minute).Format(http.TimeFormat)), now), "date in the past")
	assert.Zero(t, RetryAfterFromHeader(header("0"), now))
	assert.Zero(t, RetryAfterFromHeader(header("-5"), now))
	assert.Zero(t, RetryAfterFromHeader(header("soon"), now), "unparseable")
	assert.Zero(t, RetryAfterFromHeader(nil, now), "no header")
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestWrapRefusal(t *testing.T) {
	denied := status.Error(codes.PermissionDenied, "not authorized")
	if err := wrap(denied); !errors.Is(err, ErrNeedsAdmin) {
		t.Errorf("wrap(PermissionDenied) = %v, want ErrNeedsAdmin", err)
	}
	// The status code survives the wrapping, for callers that read it.
	if err := wrap(denied); status.Code(err) != codes.PermissionDenied {
		t.Errorf("wrap(PermissionDenied) lost the status: %v", err)
	}
	if err := wrap(fmt.Errorf("stream: %w", denied)); !errors.Is(err, ErrNeedsAdmin) {
		t.Errorf("wrap(wrapped PermissionDenied) = %v, want ErrNeedsAdmin", err)
	}
}

// A transport error is never a refusal, even when its message says so.
func TestWrapTransportError(t *testing.T) {
	for _, err := range []error{
		status.Error(codes.Unavailable, "connection error: PermissionDenied by proxy"),
		errors.New("dial tcp 10.5.0.2:50000: PermissionDenied"),
	} {
		if got := wrap(err); errors.Is(got, ErrNeedsAdmin) {
			t.Errorf("wrap(%v) = ErrNeedsAdmin, want a plain error", err)
		}
	}
}

func TestIsNotFound(t *testing.T) {
	if !IsNotFound(status.Error(codes.NotFound, "resource doesn't exist")) {
		t.Error("IsNotFound(NotFound status) = false")
	}
	if !IsNotFound(fmt.Errorf("get: %w", status.Error(codes.NotFound, "x"))) {
		t.Error("IsNotFound(wrapped NotFound status) = false")
	}
	for _, err := range []error{
		nil,
		errors.New("NotFound in the message only"),
		status.Error(codes.Unavailable, "resource doesn't exist"),
	} {
		if IsNotFound(err) {
			t.Errorf("IsNotFound(%v) = true", err)
		}
	}
}

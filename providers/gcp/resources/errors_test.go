// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// classifierCase is one error and the expected verdict from all three
// classifiers, so every case documents the full tier picture rather than one
// slice of it.
type classifierCase struct {
	name         string
	err          error
	disabled     bool // isServiceDisabled
	skippable    bool // isSkippable
	inapplicable bool // isInapplicable
}

func classifierCases() []classifierCase {
	return []classifierCase{
		{name: "nil", err: nil},

		// --- REST / googleapi ---
		{
			name:         "http 403 permission denied",
			err:          &googleapi.Error{Code: 403, Message: "permission denied"},
			skippable:    true,
			inapplicable: true,
		},
		{
			name:         "http 404 not found",
			err:          &googleapi.Error{Code: 404, Message: "not found"},
			disabled:     true,
			skippable:    true,
			inapplicable: true,
		},
		{
			name: "http 500 is a real failure",
			err:  &googleapi.Error{Code: 500, Message: "backend error"},
		},
		{
			name: "http 400 alone is a real failure",
			err:  &googleapi.Error{Code: 400, Message: "malformed request"},
		},
		{
			name:         "http 403 carrying the not-enabled marker",
			err:          &googleapi.Error{Code: 403, Message: "Cloud Composer API has not been used in project 1234 before or it is disabled"},
			disabled:     true,
			skippable:    true,
			inapplicable: true,
		},

		// --- gRPC ---
		{
			name:         "grpc PermissionDenied",
			err:          status.Error(codes.PermissionDenied, "no access"),
			skippable:    true,
			inapplicable: true,
		},
		{
			name:         "grpc NotFound",
			err:          status.Error(codes.NotFound, "missing"),
			skippable:    true,
			inapplicable: true,
		},
		{
			name:         "grpc Unimplemented",
			err:          status.Error(codes.Unimplemented, "not implemented"),
			disabled:     true,
			skippable:    true,
			inapplicable: true,
		},
		{
			// A regional service saying "not offered here". Only the widest
			// tier treats it as nothing-to-see; a plain lister must still fail
			// on it, because it usually means we built a bad request.
			name:         "grpc InvalidArgument",
			err:          status.Error(codes.InvalidArgument, "location us-west8 is not supported"),
			inapplicable: true,
		},
		{
			name:         "grpc FailedPrecondition",
			err:          status.Error(codes.FailedPrecondition, "RAG data service is not supported in region"),
			inapplicable: true,
		},
		{
			name: "grpc Internal is a real failure",
			err:  status.Error(codes.Internal, "boom"),
		},
		{
			name: "grpc Unavailable is a real failure",
			err:  status.Error(codes.Unavailable, "try again"),
		},

		// --- plain errors ---
		{
			name:         "plain error carrying the not-enabled phrasing",
			err:          errors.New("Cloud KMS API has not been used in project foo"),
			disabled:     true,
			skippable:    true,
			inapplicable: true,
		},
		{
			name: "unrelated plain error",
			err:  errors.New("connection reset by peer"),
		},
		{
			// A stringified transport error is deliberately NOT classifiable:
			// the status is gone and only the prose remains. This is why no
			// provider code may rewrap an API error as a plain string -- see
			// TestNoStringifiedAPIErrors and initGcpOrganization, which used
			// to return errors.New("403: permission denied") and forced
			// discovery into substring matching to recognize its own denials.
			name: "stringified 403 is not classifiable",
			err:  errors.New("403: permission denied"),
		},
	}
}

func TestErrorClassifiers(t *testing.T) {
	for _, tc := range classifierCases() {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.disabled, isServiceDisabled(tc.err), "isServiceDisabled")
			require.Equal(t, tc.skippable, isSkippable(tc.err), "isSkippable")
			require.Equal(t, tc.inapplicable, isInapplicable(tc.err), "isInapplicable")
		})
	}
}

// TestClassifiersSurviveWrapping is the regression guard for the reason this
// file exists. The predicates this replaced used a bare err.(*googleapi.Error)
// assertion, which fails on any error a caller wrapped for context -- so the
// degrade path silently did not fire and a permission gap on one sub-resource
// failed the entire listing instead of returning what it could read.
func TestClassifiersSurviveWrapping(t *testing.T) {
	for _, tc := range classifierCases() {
		if tc.err == nil {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			wrapped := fmt.Errorf("listing widgets in project foo: %w", tc.err)
			require.Equal(t, tc.disabled, isServiceDisabled(wrapped), "isServiceDisabled")
			require.Equal(t, tc.skippable, isSkippable(wrapped), "isSkippable")
			require.Equal(t, tc.inapplicable, isInapplicable(wrapped), "isInapplicable")

			// and through two layers, which is what a nested accessor produces
			twice := fmt.Errorf("resolving parent: %w", wrapped)
			require.Equal(t, tc.skippable, isSkippable(twice), "isSkippable (double-wrapped)")
		})
	}
}

// TestClassifierTiersNest pins the documented containment:
// isServiceDisabled implies isSkippable implies isInapplicable. Call sites pick
// a tier by name on the assumption that a narrower one never matches something
// the wider one misses; if that inverts, a caller silently widens what it
// swallows.
func TestClassifierTiersNest(t *testing.T) {
	for _, tc := range classifierCases() {
		t.Run(tc.name, func(t *testing.T) {
			if isServiceDisabled(tc.err) {
				require.True(t, isSkippable(tc.err), "service-disabled must also be skippable")
			}
			if isSkippable(tc.err) {
				require.True(t, isInapplicable(tc.err), "skippable must also be inapplicable")
			}
		})
	}
}

// TestServiceDisabledMarkersAreCaseInsensitive guards a real inconsistency in
// the predicates this replaced: isHTTPSkippable matched the marker
// case-sensitively while isNotebooksSkippable lowercased first, so the same
// disabled-API error classified differently depending on which service the
// caller happened to be in. Google's capitalization is not stable.
func TestServiceDisabledMarkersAreCaseInsensitive(t *testing.T) {
	variants := []string{
		"Compute Engine API has not been used in project 1234",
		"compute engine api HAS NOT BEEN USED in project 1234",
		"Vertex AI API is Not Enabled for this project",
		"vertex ai api is not enabled for this project",
	}
	for _, msg := range variants {
		t.Run(msg, func(t *testing.T) {
			require.True(t, isServiceDisabled(&googleapi.Error{Code: 400, Message: msg}))
		})
	}
}

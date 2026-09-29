// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestClassifyRefusal(t *testing.T) {
	cases := []struct {
		name string
		err  error
		kind llx.ErrorKind
		nil  bool
	}{
		{name: "nil", err: nil, nil: true},
		{name: "REST 403", err: &googleapi.Error{Code: http.StatusForbidden, Message: "caller lacks permission"}, kind: llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{name: "REST 403 wrapped", err: fmt.Errorf("listing: %w", &googleapi.Error{Code: http.StatusForbidden}), kind: llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{
			name: "REST 403 API disabled",
			err:  &googleapi.Error{Code: http.StatusForbidden, Message: "Firebase Rules API has not been used in project 123 before or it is disabled"},
			kind: llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE,
		},
		{name: "REST 404 is not a refusal", err: &googleapi.Error{Code: http.StatusNotFound}, nil: true},
		{name: "REST 500 is not a refusal", err: &googleapi.Error{Code: http.StatusInternalServerError}, nil: true},
		{name: "gRPC PermissionDenied", err: status.Error(codes.PermissionDenied, "denied"), kind: llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{name: "gRPC disabled", err: status.Error(codes.PermissionDenied, "Secret Manager API not enabled"), kind: llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE},
		{name: "gRPC NotFound is not a refusal", err: status.Error(codes.NotFound, "no such parent"), nil: true},
		{name: "transport error is not a refusal", err: errors.New("dial tcp: connection refused"), nil: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyRefusal(tc.err, "x.y.list")
			if tc.nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tc.kind, llx.KindOf(got))
		})
	}
}

func TestListRefusalHonorsStructuredErrors(t *testing.T) {
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })
	denied := &googleapi.Error{Code: http.StatusForbidden}

	// v13 behavior: a refusal reads as an empty list.
	plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)}))
	res, err := listRefusal(denied, "test", "x.y.list")
	assert.NoError(t, err)
	assert.Nil(t, res)

	// Structured errors: the refusal is returned, classified.
	plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
	_, err = listRefusal(denied, "test", "x.y.list")
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrForbidden))

	// A failure that is not a refusal is returned unchanged either way.
	boom := errors.New("boom")
	_, err = listRefusal(boom, "test", "x.y.list")
	assert.Same(t, boom, err)
}

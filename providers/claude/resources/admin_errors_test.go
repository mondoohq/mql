// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// testAdminClient points an SDK client at a test server, with retries off so
// an error status reaches the classifier on the first attempt.
func testAdminClient(t *testing.T, handler http.HandlerFunc) *anthropic.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := anthropic.NewClient(
		option.WithAPIKey("sk-ant-admin-test"),
		option.WithBaseURL(srv.URL),
		option.WithMaxRetries(0),
	)
	return &client
}

func listGroups(client *anthropic.Client) ([]anthropic.BetaRBACGroup, error) {
	return collectCursorPages(client.Beta.Organization.RBACGroups.List(
		context.Background(), anthropic.BetaOrganizationRBACGroupListParams{Limit: anthropic.Int(1000)}))
}

func TestCollectCursorPagesFollowsNextPage(t *testing.T) {
	var calls atomic.Int32
	client := testAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "":
			_, _ = w.Write([]byte(`{"data":[{"id":"rbacgrp_1","name":"a"},{"id":"rbacgrp_2","name":"b"}],"next_page":"p2"}`))
		case "p2":
			_, _ = w.Write([]byte(`{"data":[{"id":"rbacgrp_3","name":"c"}],"next_page":null}`))
		default:
			t.Errorf("unexpected page %q", r.URL.Query().Get("page"))
		}
	})

	groups, err := listGroups(client)
	require.NoError(t, err)
	ids := []string{}
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	assert.Equal(t, []string{"rbacgrp_1", "rbacgrp_2", "rbacgrp_3"}, ids)
	assert.Equal(t, int32(2), calls.Load())
}

// A server that keeps returning the same cursor would hold the scan forever.
// It must surface as an error, not as the rows read so far, which every
// assertion over the list would accept.
func TestCollectCursorPagesRejectsRepeatedCursor(t *testing.T) {
	var calls atomic.Int32
	client := testAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 10 {
			t.Fatal("cursor walk did not stop")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"rbacgrp_1","name":"a"}],"next_page":"stuck"}`))
	})

	_, err := listGroups(client)
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))
}

func TestCollectCursorPagesEmptyListIsNotNil(t *testing.T) {
	client := testAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[],"next_page":"ignored"}`))
	})

	groups, err := listGroups(client)
	require.NoError(t, err)
	assert.NotNil(t, groups)
	assert.Empty(t, groups)
}

func TestClassifyAdminError(t *testing.T) {
	cases := []struct {
		name   string
		status int
		on404  notFoundMeaning
		want   llx.ErrorKind
	}{
		{"unauthenticated", http.StatusUnauthorized, endpointUnavailable, llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		{"forbidden", http.StatusForbidden, endpointUnavailable, llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{"enterprise endpoint absent", http.StatusNotFound, endpointUnavailable, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE},
		{"parent gone", http.StatusNotFound, parentMissing, llx.ErrorKind_ERROR_KIND_NOT_FOUND},
		{"rate limited", http.StatusTooManyRequests, endpointUnavailable, llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS},
		{"server error", http.StatusInternalServerError, endpointUnavailable, llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{"bad request stays unclassified", http.StatusBadRequest, endpointUnavailable, llx.ErrorKind_ERROR_KIND_UNSPECIFIED},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := testAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"type":"error","error":{"type":"x","message":"refused"}}`))
			})
			_, err := listGroups(client)
			require.Error(t, err)
			assert.Equal(t, tc.want, llx.KindOf(classifyAdminError(err, tc.on404)))
		})
	}
}

func TestClassifyAdminErrorCarriesPermissionsAndRetryAfter(t *testing.T) {
	client := testAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := listGroups(client)
	var classified *llx.Error
	require.True(t, errors.As(classifyAdminError(err, endpointUnavailable, "read:plugins"), &classified))
	assert.Equal(t, []string{"read:plugins"}, classified.Permissions)

	client = testAdminClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	_, err = listGroups(client)
	require.True(t, errors.As(classifyAdminError(err, endpointUnavailable), &classified))
	assert.Equal(t, 7*time.Second, classified.RetryAfter)
}

// A failure the API never answered, such as a refused connection, carries no
// claim about access and must not be reported as one.
func TestClassifyAdminErrorLeavesTransportErrorsAlone(t *testing.T) {
	err := errors.New("dial tcp: connection refused")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyAdminError(err, endpointUnavailable)))
	assert.Nil(t, classifyAdminError(nil, endpointUnavailable))
}

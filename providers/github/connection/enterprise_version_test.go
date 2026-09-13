// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-github/v90/github"
	"github.com/stretchr/testify/require"
)

func enterpriseTestConnection(t *testing.T, handler http.HandlerFunc) (*GithubConnection, string) {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client, err := github.NewClient(github.WithEnterpriseURLs(srv.URL, srv.URL))
	require.NoError(t, err)

	return &GithubConnection{client: client, ctx: context.Background()}, srv.URL
}

// An installation stamps its version header on a rejection as readily as on a
// success. Giving up on the error without looking at the response throws away a
// version that was right there, and the probe runs once per scan, so that
// version is not read again.
func TestEnterpriseVersionReadsHeaderFromErrorResponse(t *testing.T) {
	conn, url := enterpriseTestConnection(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-GitHub-Enterprise-Version", "3.14.2")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Resource not accessible"}`))
	})
	conn.enterpriseURL = url

	require.Equal(t, "3.14.2", conn.EnterpriseVersion())
	require.True(t, conn.IsEnterpriseServer())
}

// A probe that fails outright must not take the rest of the scan with it. The
// release is unknown, which the caller reports as null, but the target is still
// recognisably an Enterprise Server installation from the URL it was given.
func TestEnterpriseVersionSurvivesAFailedProbe(t *testing.T) {
	var calls int
	conn, url := enterpriseTestConnection(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	})
	conn.enterpriseURL = url

	require.Empty(t, conn.EnterpriseVersion())
	require.True(t, conn.IsEnterpriseServer(), "a configured Enterprise Server URL stands on its own")

	// Repeated asks are answered from the one probe, so a scan of many
	// organizations does not re-ask a server that already failed.
	require.Empty(t, conn.EnterpriseVersion())
	require.True(t, conn.IsEnterpriseServer())
	require.Equal(t, 1, calls)
}

// GitHub.com sends no version header, and nothing about that is an error: the
// feature answer comes from the organization's plan instead.
func TestEnterpriseVersionEmptyOnGitHubDotCom(t *testing.T) {
	conn, _ := enterpriseTestConnection(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`"Keep it logically awesome."`))
	})

	require.Empty(t, conn.EnterpriseVersion())
	require.False(t, conn.IsEnterpriseServer(), "no header and no configured URL means the hosted product")
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package selfupdate

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/utils/verify"
)

func TestArchiveNameFromURL(t *testing.T) {
	tests := []struct {
		url, want string
		wantErr   bool
	}{
		// Synthetic: goreleaser's default archive names. A version carries dots,
		// which is what an earlier parser split on.
		{url: "https://releases.mondoo.com/mql/13.4.1/mql_13.4.1_linux_amd64.tar.gz", want: "mql_13.4.1_linux_amd64.tar.gz"},
		{url: "https://releases.mondoo.com/mql/13.4.1/mql_13.4.1_linux_armv7.tar.gz", want: "mql_13.4.1_linux_armv7.tar.gz"},
		{url: "https://releases.mondoo.com/mql/13.4.1/mql_13.4.1_windows_amd64.zip?sig=abc", want: "mql_13.4.1_windows_amd64.zip"},
		{url: "https://releases.mondoo.com/", wantErr: true},
	}
	for _, tc := range tests {
		got, err := archiveNameFromURL(tc.url)
		if tc.wantErr {
			assert.Error(t, err, tc.url)
			continue
		}
		require.NoError(t, err, tc.url)
		assert.Equal(t, tc.want, got)
	}
}

func useBinarySignaturePolicy(t *testing.T, p verify.SignaturePolicy) {
	t.Helper()
	orig := binarySignaturePolicy()
	SetBinarySignaturePolicy(p)
	t.Cleanup(func() { SetBinarySignaturePolicy(orig) })
}

func TestVerifyDownloadManifest(t *testing.T) {
	ctx := context.Background()
	// Synthetic: names follow .goreleaser.yml (archives and the
	// "<name>_v<version>_SHA256SUMS" checksum template); contents are made up.
	archive := []byte("archive bytes")
	digest := fmt.Sprintf("%x", sha256.Sum256(archive))
	const archiveName = "mql_13.4.1_linux_amd64.tar.gz"

	serve := func(t *testing.T, manifestStatus int, manifest string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/mql/13.4.1/mql_v13.4.1_SHA256SUMS":
				w.WriteHeader(manifestStatus)
				_, _ = w.Write([]byte(manifest))
			case "/mql/13.4.1/mql_v13.4.1_SHA256SUMS.sig":
				// A signature that cannot be fetched is optional under auto.
				w.WriteHeader(http.StatusForbidden)
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)
		return srv.URL + "/mql/13.4.1/" + archiveName
	}

	t.Run("manifest matches", func(t *testing.T) {
		u := serve(t, http.StatusOK, digest+"  "+archiveName+"\n")
		assert.NoError(t, verifyDownloadManifest(ctx, u, "mql", "13.4.1", digest))
	})

	t.Run("manifest disagrees", func(t *testing.T) {
		u := serve(t, http.StatusOK, fmt.Sprintf("%x  %s\n", sha256.Sum256([]byte("other")), archiveName))
		err := verifyDownloadManifest(ctx, u, "mql", "13.4.1", digest)
		assert.ErrorIs(t, err, verify.ErrChecksumMismatch)
	})

	t.Run("manifest does not list the archive", func(t *testing.T) {
		u := serve(t, http.StatusOK, digest+"  mql_13.4.1_darwin_arm64.tar.gz\n")
		err := verifyDownloadManifest(ctx, u, "mql", "13.4.1", digest)
		assert.ErrorIs(t, err, verify.ErrChecksumNotFound)
	})

	t.Run("no manifest under auto", func(t *testing.T) {
		u := serve(t, http.StatusNotFound, "")
		assert.NoError(t, verifyDownloadManifest(ctx, u, "mql", "13.4.1", digest))
	})

	t.Run("manifest refused under auto", func(t *testing.T) {
		u := serve(t, http.StatusForbidden, "")
		assert.NoError(t, verifyDownloadManifest(ctx, u, "mql", "13.4.1", digest))
	})

	t.Run("no manifest under require", func(t *testing.T) {
		useBinarySignaturePolicy(t, verify.SignatureRequire)
		u := serve(t, http.StatusNotFound, "")
		assert.Error(t, verifyDownloadManifest(ctx, u, "mql", "13.4.1", digest))
	})
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hetznercloud

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMetadataDocument = "hostname: mql-test\ninstance-id: 4242\npublic-ipv4: 203.0.113.7\nregion: eu-central\navailability-zone: fsn1-dc14\n"

// runMetadataScript runs windowsMetadataScript in Windows PowerShell against
// url instead of the metadata service, and returns its stdout and exit code.
func runMetadataScript(t *testing.T, url string) (string, int) {
	t.Helper()
	script := strings.Replace(windowsMetadataScript, metadataSvcURL, url, 1)
	require.NotEqual(t, windowsMetadataScript, script, "the script must name the metadata service URL")
	path := filepath.Join(t.TempDir(), "metadata.ps1")
	require.NoError(t, os.WriteFile(path, []byte(script), 0o600))

	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path).Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return string(out), exitErr.ExitCode()
	}
	require.NoError(t, err)
	return string(out), 0
}

// Invoke-WebRequest returns Content as a string only for a text content type;
// for any other it is a byte array, which the script must decode rather than
// print as System.Byte[].
func TestWindowsMetadataScriptReadsEveryContentType(t *testing.T) {
	for _, contentType := range []string{"text/plain; charset=utf-8", "application/x-yaml", "application/octet-stream", ""} {
		t.Run(contentType, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if contentType == "" {
					w.Header()["Content-Type"] = nil // no Content-Type header at all
				} else {
					w.Header().Set("Content-Type", contentType)
				}
				_, _ = w.Write([]byte(testMetadataDocument))
			}))
			defer srv.Close()

			out, code := runMetadataScript(t, srv.URL)
			assert.Equal(t, 0, code)
			assert.Equal(t, testMetadataDocument, out)
		})
	}
}

func TestWindowsMetadataScriptFailsWhenTheServiceErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	out, code := runMetadataScript(t, srv.URL)
	assert.NotEqual(t, 0, code)
	assert.Empty(t, out)
}

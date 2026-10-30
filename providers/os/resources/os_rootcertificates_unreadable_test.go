// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func bundleWithContent(path string, content string, err error) *mqlFile {
	return &mqlFile{
		Path:    plugin.TValue[string]{Data: path, State: plugin.StateIsSet},
		Content: plugin.TValue[string]{Data: content, Error: err, State: plugin.StateIsSet},
	}
}

// Rocky 9 as non-root after `chmod 600` on the RHEL bundle: the only bundle
// could not be read, and os.rootCertificates reported 0 certificates, so
// `list.none(subject.commonName == "<distrusted CA>")` passed.
func TestOsRootCertificatesUnreadableBundle(t *testing.T) {
	denied := &fs.PathError{Op: "open", Path: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", Err: fs.ErrPermission}
	s := &mqlOsRootCertificates{}
	unreadable := []any{bundleWithContent(denied.Path, "", denied)}

	t.Run("v13 behavior keeps the empty list", func(t *testing.T) {
		require.False(t, plugin.StructuredErrors())
		contents, err := s.content(unreadable)
		require.NoError(t, err)
		assert.Empty(t, contents)
	})

	t.Run("structured errors", func(t *testing.T) {
		enableStructuredErrorsForTest(t)

		_, err := s.content(unreadable)
		require.Error(t, err)
		assert.True(t, errors.Is(err, llx.ErrForbidden))

		// another readable bundle still answers
		contents, err := s.content([]any{
			unreadable[0],
			bundleWithContent("/etc/ssl/certs/ca-bundle.crt", "-----BEGIN CERTIFICATE-----\n", nil),
		})
		require.NoError(t, err)
		assert.Len(t, contents, 1)

		// no bundle at all is an absence
		contents, err = s.content(nil)
		require.NoError(t, err)
		assert.Empty(t, contents)
	})
}

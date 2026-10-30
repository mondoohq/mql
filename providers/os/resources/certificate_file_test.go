// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// enableStructuredErrorsForTest turns the process-wide flag on for one test.
func enableStructuredErrorsForTest(t *testing.T) {
	t.Helper()
	plugin.ReadFeatures([]byte(mql.Features{byte(mql.StructuredErrors)}))
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })
}

// A certificate file the scan cannot read is a refusal, not an empty list: an
// empty list passes every expiry and key-size check on a certificate nobody
// read. mongod's PEM (mode 0600, owned by mongod) is the common case for a
// non-root scan.
func TestCertificateReadError(t *testing.T) {
	denied := &fs.PathError{Op: "open", Path: "/etc/ssl/mongod.pem", Err: fs.ErrPermission}
	missing := fmt.Errorf("stat /etc/ssl/missing.pem: %w", fs.ErrNotExist)

	t.Run("v13 behavior keeps the empty list", func(t *testing.T) {
		require.False(t, plugin.StructuredErrors())
		assert.NoError(t, certificateReadError(denied))
	})

	t.Run("structured errors", func(t *testing.T) {
		enableStructuredErrorsForTest(t)

		err := certificateReadError(denied)
		require.Error(t, err)
		assert.True(t, errors.Is(err, llx.ErrForbidden), "permission denied is Forbidden")
		assert.ErrorIs(t, err, fs.ErrPermission)

		assert.NoError(t, certificateReadError(missing), "a missing file is an absence")
		assert.NoError(t, certificateReadError(nil))

		other := errors.New("connection reset")
		assert.Equal(t, other, certificateReadError(other), "other failures pass through unclassified")
	})
}

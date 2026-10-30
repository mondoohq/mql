// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
)

func TestErrorKinds(t *testing.T) {
	t.Run("a package format without a file database is not applicable", func(t *testing.T) {
		conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})
		_, err := LinuxOwners(conn, []string{"ebuild"}, []string{"/usr/bin/x"})
		require.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(err))
	})

	t.Run("a platform without running binaries is not applicable", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("the local connection runs a unix shell")
		}
		conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{
			Platform: &inventory.Platform{Name: "freebsd", Family: []string{"bsd", "unix", "os"}},
		})
		_, err := List(conn)
		require.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(err))
	})

	t.Run("a missing package manager is not found", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("owner queries run in a unix shell")
		}
		conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})
		_, err := bulkOwners(conn, "mql-test-no-such-tool", requireTool("mql-test-no-such-tool")+"mql-test-no-such-tool -qf /usr/bin/x", []string{"/usr/bin/x"}, parseRpmOwners)
		require.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_FOUND, llx.KindOf(err))
		assert.Contains(t, err.Error(), "mql-test-no-such-tool not found")
	})

	t.Run("unreadable PowerShell output is malformed data", func(t *testing.T) {
		_, err := parseWindowsProcessBinaries([]byte("{not json"))
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))
		_, err = parseWindowsSignatures([]byte("{not json"))
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))
	})
}

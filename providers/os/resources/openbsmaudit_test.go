// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestOpenBSMAuditParser(t *testing.T) {
	content := `#
# $P4: //depot/projects/trustedbsd/openbsm/etc/audit_control#8 $
#
dir:/var/audit
flags:lo,ad,fm,-all,fd
minfree:5
naflags:lo,aa
policy:cnt,argv
filesz:2M
expire-after:60d OR 1024M
superuser-set-sflags-mask:has_authenticated,has_console_access
superuser-clear-sflags-mask:has_authenticated,has_console_access
member-set-sflags-mask:
member-clear-sflags-mask:has_authenticated
`

	x := &mqlOpenBSMAudit{}

	// Test params parsing
	params, err := x.params(content)
	require.NoError(t, err)
	require.NotNil(t, params)

	// Test dir field
	dir, err := x.dir(params)
	require.NoError(t, err)
	assert.Equal(t, "/var/audit", dir)

	// Test flags field
	flags, err := x.flags(params)
	require.NoError(t, err)
	assert.Equal(t, []any{"lo", "ad", "fm", "-all", "fd"}, flags)

	// Test minfree field
	minfree, err := x.minfree(params)
	require.NoError(t, err)
	assert.Equal(t, int64(5), minfree)

	// Test naflags field
	naflags, err := x.naflags(params)
	require.NoError(t, err)
	assert.Equal(t, []any{"lo", "aa"}, naflags)

	// Test policy field
	policy, err := x.policy(params)
	require.NoError(t, err)
	assert.Equal(t, []any{"cnt", "argv"}, policy)

	// Test filesz field
	filesz, err := x.filesz(params)
	require.NoError(t, err)
	assert.Equal(t, "2M", filesz)

	// Test expireAfter field
	expireAfter, err := x.expireAfter(params)
	require.NoError(t, err)
	assert.Equal(t, "60d OR 1024M", expireAfter)

	// Test superuserSetSflagsMask field
	superuserSetFlags, err := x.superuserSetSflagsMask(params)
	require.NoError(t, err)
	assert.Equal(t, []any{"has_authenticated", "has_console_access"}, superuserSetFlags)

	// Test superuserClearSflagsMask field
	superuserClearFlags, err := x.superuserClearSflagsMask(params)
	require.NoError(t, err)
	assert.Equal(t, []any{"has_authenticated", "has_console_access"}, superuserClearFlags)

	// Test memberSetSflagsMask field (empty)
	memberSetFlags, err := x.memberSetSflagsMask(params)
	require.NoError(t, err)
	assert.Equal(t, []any{}, memberSetFlags)

	// Test memberClearSflagsMask field
	memberClearFlags, err := x.memberClearSflagsMask(params)
	require.NoError(t, err)
	assert.Equal(t, []any{"has_authenticated"}, memberClearFlags)
}

func TestOpenBSMAuditParserMinimal(t *testing.T) {
	content := `dir:/var/audit
flags:lo
minfree:5
`

	x := &mqlOpenBSMAudit{}

	params, err := x.params(content)
	require.NoError(t, err)
	require.NotNil(t, params)

	dir, err := x.dir(params)
	require.NoError(t, err)
	assert.Equal(t, "/var/audit", dir)

	flags, err := x.flags(params)
	require.NoError(t, err)
	assert.Equal(t, []any{"lo"}, flags)

	minfree, err := x.minfree(params)
	require.NoError(t, err)
	assert.Equal(t, int64(5), minfree)
}

func TestOpenBSMAuditPlatformValidation(t *testing.T) {
	tests := []struct {
		name           string
		platformName   string
		platformFamily string
		shouldError    bool
	}{
		{
			name:           "macOS supported",
			platformName:   "macos",
			platformFamily: "darwin",
			shouldError:    false,
		},
		{
			name:         "FreeBSD supported",
			platformName: "freebsd",
			shouldError:  false,
		},
		{
			name:         "Linux unsupported",
			platformName: "ubuntu",
			shouldError:  true,
		},
		{
			name:         "Windows unsupported",
			platformName: "windows",
			shouldError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock connection with the specified platform
			platform := &inventory.Platform{
				Name:   tt.platformName,
				Family: []string{tt.platformFamily},
			}
			if tt.platformFamily == "" {
				platform.Family = []string{tt.platformName}
			}

			conn, err := mock.New(0, &inventory.Asset{
				Platform: platform,
			})
			require.NoError(t, err)

			runtime := &plugin.Runtime{
				Connection: conn,
			}

			_, _, err = initOpenBSMAudit(runtime, map[string]*llx.RawData{})

			if tt.shouldError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "only supported on macOS and FreeBSD")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

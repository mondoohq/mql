// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

var aixPlatform = &inventory.Platform{Name: "aix", Version: "7.3", Family: []string{"unix", "os"}}

// aixPasswd is /etc/passwd of AIX 7.3 TL4 SP2, cut to the users the tests
// read, plus a user without a stanza in any security file.
const aixPasswd = "root:!:0:0::/:/usr/bin/ksh\n" +
	"daemon:!:1:1::/etc:\n" +
	"uucp:!:5:5::/usr/lib/uucp:\n" +
	"esaadmin:*:7:0::/var/esa:/usr/bin/ksh\n" +
	"mqluser1:*:3001:3000:MQL Sweep User:/home/mqluser1:/usr/bin/ksh\n" +
	"nostanza:*:3005:3000::/home/nostanza:/usr/bin/ksh\n"

// newAixRuntime returns a runtime on a mock AIX connection whose files are
// read from aix/testdata, keyed by the path they stand in for.
func newAixRuntime(t *testing.T, pf *inventory.Platform, files map[string]string, commands map[string]*mock.Command) *plugin.Runtime {
	t.Helper()
	mockFiles := map[string]*mock.MockFileData{
		"/etc/passwd": {Path: "/etc/passwd", Content: aixPasswd},
	}
	for path, fixture := range files {
		data, err := os.ReadFile(fixture)
		require.NoError(t, err)
		mockFiles[path] = &mock.MockFileData{Path: path, Content: string(data)}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: pf}, mock.WithData(&mock.TomlData{Files: mockFiles, Commands: commands}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func TestRequireAix(t *testing.T) {
	assert.NoError(t, requireAix(newAixRuntime(t, aixPlatform, nil, nil), "aix.x"))

	linux := &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}
	err := requireAix(newAixRuntime(t, linux, nil, nil), "aix.x")
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(err))
}

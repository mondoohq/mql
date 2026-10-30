// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// A path named explicitly must exist, as with snmpd.config, nginx.conf and
// haproxy.config: reading it as an empty configuration let
// localInterfaces.all(_ == "127.0.0.1") and acls.none(...) pass on a file
// that is not there. A missing default location still means not installed.
func TestSquidExplicitMissingConfigPaths(t *testing.T) {
	t.Run("squid.conf", func(t *testing.T) {
		rt := missingPathRuntime(t, rhel9Platform, map[string]*mock.MockFileData{}, nil)
		res, err := NewResource(rt, "squid.conf", map[string]*llx.RawData{"path": llx.StringData("/nonexistent/squid.conf")})
		require.NoError(t, err)
		conf := res.(*mqlSquidConf)
		assert.ErrorContains(t, conf.GetAcls().Error, "/nonexistent/squid.conf")

		rt = missingPathRuntime(t, rhel9Platform, map[string]*mock.MockFileData{}, nil)
		res, err = NewResource(rt, "squid.conf", nil)
		require.NoError(t, err)
		acls := res.(*mqlSquidConf).GetAcls()
		require.NoError(t, acls.Error)
		assert.Empty(t, acls.Data)
	})
}

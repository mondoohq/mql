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

func aixAudit(t *testing.T, query string) *mqlAixAudit {
	t.Helper()
	rt := newAixRuntime(t, aixPlatform, map[string]string{
		"/etc/security/audit/config": "aix/testdata/audit_config_aix73.txt",
	}, map[string]*mock.Command{
		"audit query": {Stdout: query},
	})
	r, err := CreateResource(rt, "aix.audit", map[string]*llx.RawData{})
	require.NoError(t, err)
	return r.(*mqlAixAudit)
}

func TestAixAudit(t *testing.T) {
	// audit query on AIX 7.3 after audit start
	a := aixAudit(t, "auditing on\naudit bin manager is process 23331264\naudit events:\n")
	assert.True(t, a.GetRunning().Data)
	assert.True(t, a.GetBinMode().Data)
	assert.False(t, a.GetStreamMode().Data)

	users := a.GetUsers()
	require.NoError(t, users.Error)
	assert.Equal(t, map[string]any{"root": []any{"general"}}, users.Data)

	classes := a.GetClasses()
	require.NoError(t, classes.Error)
	assert.Contains(t, classes.Data["general"], "USER_SU")
}

func TestAixAuditOff(t *testing.T) {
	a := aixAudit(t, "auditing off\nbin processing off\n")
	assert.False(t, a.GetRunning().Data)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const setNull = plugin.StateIsSet | plugin.StateIsNull

// A refused configuration must leave every field it feeds null, so the
// accessors' defaults (AllowAllAuthenticator, localJmx true, port 3306) never
// reach a check as if they had been read.
func TestMarkUnsetFieldsNull(t *testing.T) {
	c := &mqlCassandraConf{}
	c.ClusterName = plugin.TValue[string]{Data: "computed", State: plugin.StateIsSet}
	markUnsetFieldsNull(c)

	assert.Equal(t, setNull, c.File.State)
	assert.Equal(t, setNull, c.Params.State)
	assert.Equal(t, setNull, c.Authenticator.State)
	assert.Equal(t, setNull, c.AuthenticationEnabled.State)
	assert.Equal(t, plugin.StateIsSet, c.ClusterName.State, "a field already computed keeps its value")
	assert.Equal(t, "computed", c.ClusterName.Data)
}

func TestMarkUnsetFieldsNullKeepsNamedFields(t *testing.T) {
	m := &mqlMysqlConf{}
	markUnsetFieldsNull(m, "UserFiles")

	assert.Equal(t, plugin.State(0), m.UserFiles.State, "userFiles does not come from the option files")
	assert.Equal(t, setNull, m.ServerOptions.State)
	assert.Equal(t, setNull, m.LocalInfile.State)
	assert.Equal(t, setNull, m.BindAddress.State)
	assert.False(t, m.resolved, "internal state is left alone")
}

func TestMarkUnsetFieldsNullIgnoresNonPointers(t *testing.T) {
	assert.NotPanics(t, func() {
		markUnsetFieldsNull(mqlCassandraConf{})
		markUnsetFieldsNull(nil)
		markUnsetFieldsNull(42)
	})
}

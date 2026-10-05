// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/users"
)

func TestParseDsclListResult(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/osx.toml"))
	if err != nil {
		t.Fatal(err)
	}

	// check user shells
	c, err := mock.RunCommand("dscl . -list /Users UserShell")
	if err != nil {
		t.Fatal(err)
	}

	m, err := users.ParseDsclListResult(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 8, len(m), "detected the right amount of users")
	assert.Equal(t, "/usr/bin/false", m["_www"], "detected uid name")

	// check uid
	c, err = mock.RunCommand("dscl . -list /Users UniqueID")
	if err != nil {
		t.Fatal(err)
	}

	m, err = users.ParseDsclListResult(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 8, len(m), "detected the right amount of users")
	assert.Equal(t, "70", m["_www"], "detected uid name")

	// check user home
	c, err = mock.RunCommand("dscl . -list /Users NFSHomeDirectory")
	if err != nil {
		t.Fatal(err)
	}

	m, err = users.ParseDsclListResult(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 7, len(m), "detected the right amount of users")
	assert.Equal(t, "/Library/WebServer", m["_www"], "detected uid name")
	assert.Equal(t, "/var/root /private/var/root", m["root"], "detected root name")
}

func TestOSXUserManagerEnabledIsUnknown(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"os", "unix", "darwin"}},
	}, mock.WithPath("./testdata/osx.toml"))
	require.NoError(t, err)
	m, err := users.ResolveManager(conn)
	require.NoError(t, err)

	list, err := m.List()
	require.NoError(t, err)
	require.NotEmpty(t, list)
	for _, u := range list {
		assert.True(t, u.EnabledUnknown, u.Name)
	}
}

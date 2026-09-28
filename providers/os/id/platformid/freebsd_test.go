// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package platformid

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func freebsdIdProvider(t *testing.T, fixture string) UniquePlatformIDProvider {
	t.Helper()
	path, err := filepath.Abs(fixture)
	require.NoError(t, err)
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath(path))
	require.NoError(t, err)

	p, err := MachineIDProvider(conn, &inventory.Platform{Name: "freebsd", Family: []string{"bsd", "unix", "os"}})
	require.NoError(t, err)
	require.NotNil(t, p)
	return p
}

func TestFreebsdMachineIdFromSysctl(t *testing.T) {
	id, err := freebsdIdProvider(t, "./testdata/freebsd_hostuuid.toml").ID()
	require.NoError(t, err)
	assert.Equal(t, "ec2a1b2c-3d4e-5f60-7182-93a4b5c6d7e8", id)
}

// Without the sysctl, the UUID saved in /etc/hostid is read instead.
func TestFreebsdMachineIdFromHostidFile(t *testing.T) {
	id, err := freebsdIdProvider(t, "./testdata/freebsd_hostid_file.toml").ID()
	require.NoError(t, err)
	assert.Equal(t, "4c4c4544-0042-3510-8052-b4c04f4a4d32", id)
}

func TestParseFreebsdHostUUID(t *testing.T) {
	_, err := parseFreebsdHostUUID("00000000-0000-0000-0000-000000000000\n")
	assert.Error(t, err, "the unset kern.hostuuid identifies no machine")

	_, err = parseFreebsdHostUUID("\n")
	assert.Error(t, err)
}

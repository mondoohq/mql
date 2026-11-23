// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
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

// newCommandTestRuntime returns a runtime over a mock connection that answers
// the given commands.
func newCommandTestRuntime(t *testing.T, platform string, commands map[string]*mock.Command) *plugin.Runtime {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{Name: platform}},
		mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func newGeliTestResource(t *testing.T, platform string, commands map[string]*mock.Command) *mqlGeli {
	t.Helper()
	res, err := NewResource(newCommandTestRuntime(t, platform, commands), ResourceGeli, nil)
	require.NoError(t, err)
	return res.(*mqlGeli)
}

// The fixture is `geli list` with three attached providers, laid out the way
// FreeBSD prints it: geom(8) list_one_geom() in sbin/geom/core/geom.c prints
// the geom, its configuration and the numbered Providers and Consumers, and
// g_eli_dumpconf() in sys/geom/eli/g_eli.c supplies the configuration (the
// handbook and geli(8) show no sample output). ada1.eli has data
// authentication, ada0p2.eli is a one-time swap provider (no UsedKey, no
// authentication), and ada0p3.eli is suspended.
func readGeliFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/freebsd-geli-list.txt")
	require.NoError(t, err)
	return string(data)
}

func TestParseGeliList(t *testing.T) {
	providers, err := parseGeliList(readGeliFixture(t))
	require.NoError(t, err)
	require.Len(t, providers, 3)

	assert.Equal(t, geliProvider{
		name:                    "ada1.eli",
		device:                  "ada1",
		encryptionAlgorithm:     "AES-XTS",
		keyLength:               256,
		authenticationAlgorithm: "HMAC/SHA256",
		state:                   "ACTIVE",
	}, providers[0])

	// no AuthenticationAlgorithm line: must not inherit the previous geom's
	assert.Equal(t, geliProvider{
		name:                "ada0p2.eli",
		device:              "ada0p2",
		encryptionAlgorithm: "AES-XTS",
		keyLength:           128,
		state:               "ACTIVE",
	}, providers[1])

	assert.Equal(t, geliProvider{
		name:                "ada0p3.eli",
		device:              "ada0p3",
		encryptionAlgorithm: "AES-CBC",
		keyLength:           192,
		state:               "SUSPENDED",
	}, providers[2])
}

func TestParseGeliListEmpty(t *testing.T) {
	providers, err := parseGeliList("")
	require.NoError(t, err)
	assert.NotNil(t, providers)
	assert.Empty(t, providers)
}

func TestParseGeliListMalformed(t *testing.T) {
	_, err := parseGeliList("usage: geli list [-a] [name ...]\n")
	assert.Error(t, err)

	_, err = parseGeliList("Geom name: ada0.eli\nKeyLength: many\n")
	assert.Error(t, err)
}

func TestGeliProviders(t *testing.T) {
	geli := newGeliTestResource(t, "freebsd", map[string]*mock.Command{
		"geli list": {Stdout: readGeliFixture(t)},
	})
	providers := geli.GetProviders()
	require.NoError(t, providers.Error)
	require.Len(t, providers.Data, 3)

	p := providers.Data[0].(*mqlGeliProvider)
	assert.Equal(t, "ada1.eli", p.Name.Data)
	assert.Equal(t, "ada1", p.Device.Data)
	assert.Equal(t, int64(256), p.KeyLength.Data)
	assert.Equal(t, "HMAC/SHA256", p.AuthenticationAlgorithm.Data)
	assert.Equal(t, "", providers.Data[1].(*mqlGeliProvider).AuthenticationAlgorithm.Data)
	assert.Equal(t, "SUSPENDED", providers.Data[2].(*mqlGeliProvider).State.Data)
}

func TestGeliClassNotLoaded(t *testing.T) {
	for _, stderr := range []string{
		// geom(8) refuses list while g_eli is not loaded
		"geli: Command 'list' not available; try 'load' first.\n",
		"geli: Class 'ELI' not found.\n",
	} {
		geli := newGeliTestResource(t, "freebsd", map[string]*mock.Command{
			"geli list": {Stderr: stderr, ExitStatus: 1},
		})
		providers := geli.GetProviders()
		require.NoError(t, providers.Error, stderr)
		assert.Empty(t, providers.Data)
	}

	geli := newGeliTestResource(t, "freebsd", map[string]*mock.Command{"geli list": {}})
	providers := geli.GetProviders()
	require.NoError(t, providers.Error)
	assert.Empty(t, providers.Data)
}

func TestGeliFailureIsAnError(t *testing.T) {
	geli := newGeliTestResource(t, "freebsd", map[string]*mock.Command{
		"geli list": {Stderr: "geli: Cannot get GEOM tree: Operation not permitted\n", ExitStatus: 1},
	})
	providers := geli.GetProviders()
	require.Error(t, providers.Error)
	assert.Contains(t, providers.Error.Error(), "Operation not permitted")
}

func TestGeliNotApplicableOffFreeBSD(t *testing.T) {
	geli := newGeliTestResource(t, "ubuntu", nil)
	providers := geli.GetProviders()
	require.Error(t, providers.Error)
	assert.True(t, errors.Is(providers.Error, llx.ErrNotApplicable))
}

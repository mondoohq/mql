// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

// resetViper clears the two keys these tests set, so one case cannot leak into
// the next through viper's global state.
func resetViper(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		viper.Set("providers_url", "")
		viper.Set("updates_url", "")
	})
	viper.Set("providers_url", "")
	viper.Set("updates_url", "")
}

// Nothing configured leaves the default registry in place.
func TestProviderRegistryURLUnset(t *testing.T) {
	resetViper(t)
	assert.Empty(t, RegistryURL())
}

func TestProviderRegistryURLFromUpdatesURL(t *testing.T) {
	resetViper(t)
	viper.Set("updates_url", "https://install.mondoo.com")
	assert.Equal(t, "https://install.mondoo.com/providers", RegistryURL())

	// A trailing slash must not double up into "//providers".
	viper.Set("updates_url", "https://install.mondoo.com/")
	assert.Equal(t, "https://install.mondoo.com/providers", RegistryURL())
}

// providers_url names the registry itself, so it is used exactly as given. An
// operator mirroring providers internally has it pointing at their mirror, and
// appending or stripping anything would send the downloads somewhere else.
func TestProviderRegistryURLHonoursDeprecatedProvidersURL(t *testing.T) {
	resetViper(t)
	viper.Set("providers_url", "https://releases.example.de/providers")
	assert.Equal(t, "https://releases.example.de/providers", RegistryURL())
}

// A mirror that is not laid out as "<host>/providers" must still be used as
// given rather than second-guessed.
func TestProviderRegistryURLDoesNotRewriteAnUnusualPath(t *testing.T) {
	resetViper(t)
	viper.Set("providers_url", "https://artifacts.example.de/mondoo/registry")
	assert.Equal(t, "https://artifacts.example.de/mondoo/registry", RegistryURL())
}

// The deprecated key wins, which is the precedence it had before it was removed:
// an operator who set both meant the specific one.
func TestProviderRegistryURLPrefersProvidersURL(t *testing.T) {
	resetViper(t)
	viper.Set("providers_url", "https://releases.example.de/providers")
	viper.Set("updates_url", "https://install.example.de")
	assert.Equal(t, "https://releases.example.de/providers", RegistryURL())
}

// An empty or whitespace value is not a configured mirror; it must fall through
// rather than set the registry to "".
func TestProviderRegistryURLIgnoresBlankValues(t *testing.T) {
	resetViper(t)
	viper.Set("providers_url", "   ")
	assert.Empty(t, RegistryURL())

	viper.Set("updates_url", "  ")
	assert.Empty(t, RegistryURL())
}

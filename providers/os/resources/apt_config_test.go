// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func aptConfigFixture(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile("testdata/apt-config/" + name + ".txt")
	require.NoError(t, err)
	res := map[string]any{}
	for k, v := range parseAptConfigDump(string(b)) {
		res[k] = v
	}
	return res
}

func TestParseAptConfigDump(t *testing.T) {
	got := parseAptConfigDump(`APT "";
APT::Architecture "amd64";
APT::Install-Recommends "1";
APT::NeverAutoRemove "";
APT::NeverAutoRemove:: "^firmware-linux.*";
APT::NeverAutoRemove:: "^linux-firmware$";
Acquire::http::Proxy "http://proxy.example:3128/";
Dir::State::status "/var/lib/dpkg/status";
Empty::Value "";
not a config line
`)
	assert.Equal(t, map[string]string{
		"APT":                     "",
		"APT::Architecture":       "amd64",
		"APT::Install-Recommends": "1",
		"APT::NeverAutoRemove":    "^firmware-linux.*\n^linux-firmware$",
		"Acquire::http::Proxy":    "http://proxy.example:3128/",
		"Dir::State::status":      "/var/lib/dpkg/status",
		"Empty::Value":            "",
	}, got)
}

func TestAptConfigDefaults(t *testing.T) {
	a := &mqlAptConfig{}
	for _, fixture := range []string{"debian-bookworm", "debian-trixie", "ubuntu-24-04"} {
		t.Run(fixture, func(t *testing.T) {
			params := aptConfigFixture(t, fixture)
			assert.NotEmpty(t, params["APT::Architecture"])

			v, _ := a.allowInsecureRepositories(params)
			assert.False(t, v)
			v, _ = a.allowWeakRepositories(params)
			assert.False(t, v)
			v, _ = a.allowDowngradeToInsecureRepositories(params)
			assert.False(t, v)
			// not printed by apt-config dump: APT's default applies
			_, printed := params["Acquire::Check-Date"]
			assert.False(t, printed)
			v, _ = a.checkDate(params)
			assert.True(t, v)
			v, _ = a.installRecommends(params)
			assert.True(t, v)
			v, _ = a.installSuggests(params)
			assert.False(t, v)
		})
	}
}

func TestAptConfigCustom(t *testing.T) {
	a := &mqlAptConfig{}
	params := aptConfigFixture(t, "debian-trixie-custom")

	v, _ := a.allowInsecureRepositories(params) // "true"
	assert.True(t, v)
	v, _ = a.allowWeakRepositories(params) // "yes"
	assert.True(t, v)
	v, _ = a.allowDowngradeToInsecureRepositories(params) // "false"
	assert.False(t, v)
	v, _ = a.checkDate(params) // "false"
	assert.False(t, v)
	v, _ = a.installRecommends(params) // "0"
	assert.False(t, v)
	v, _ = a.installSuggests(params) // "1"
	assert.True(t, v)

	assert.Equal(t, "http://proxy.example:3128/", params["Acquire::http::Proxy"])
	assert.Equal(t, "echo one\necho two", params["DPkg::Pre-Invoke"])
}

func TestAptBoolParam(t *testing.T) {
	for value, want := range map[string]bool{
		"1": true, "0": false, "2": true, "true": true, "FALSE": false, "Yes": true, "no": false,
		"on": true, "off": false, "with": true, "without": false, "enable": true, "disable": false,
		" true ": true,
	} {
		assert.Equal(t, want, aptBoolParam(map[string]any{"k": value}, "k", !want), "value %q", value)
	}
	assert.True(t, aptBoolParam(map[string]any{}, "k", true), "absent: the default")
	assert.False(t, aptBoolParam(map[string]any{"k": "maybe"}, "k", false), "unrecognized: the default")
	assert.True(t, aptBoolParam(map[string]any{"k": "maybe"}, "k", true), "unrecognized: the default")
}

// APT option names are case-insensitive, and apt-config dump prints a key in
// the case it was first set in. These lines are from Ubuntu 24.04 with an
// apt.conf.d file written in lower and upper case: Acquire::Check-Date has no
// built-in default, so the dump keeps the file's `check-date`, and
// `apt-config shell V Acquire::Check-Date/b` answers false. checkDate used to
// miss the key and report APT's default, true.
func TestAptConfigKeysIgnoreCase(t *testing.T) {
	a := &mqlAptConfig{}
	params := map[string]any{}
	for k, v := range parseAptConfigDump(`APT::Install-Recommends "false";
APT::Install-Suggests "yes";
Acquire::AllowInsecureRepositories "true";
Acquire::AllowWeakRepositories "on";
Acquire::AllowDowngradeToInsecureRepositories "true";
Acquire::check-date "no";
`) {
		params[k] = v
	}

	v, _ := a.checkDate(params)
	assert.False(t, v)
	v, _ = a.allowWeakRepositories(params)
	assert.True(t, v)

	assert.True(t, aptBoolParam(map[string]any{"acquire::allowinsecurerepositories": "true"}, "Acquire::AllowInsecureRepositories", false))
	assert.False(t, aptBoolParam(map[string]any{"APT::INSTALL-RECOMMENDS": "0"}, "APT::Install-Recommends", true))
}

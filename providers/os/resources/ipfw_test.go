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
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func newIpfwTestResource(t *testing.T, platform string, commands map[string]*mock.Command) *mqlIpfw {
	t.Helper()
	res, err := NewResource(newCommandTestRuntime(t, platform, commands), ResourceIpfw, nil)
	require.NoError(t, err)
	return res.(*mqlIpfw)
}

// The fixture is `ipfw list` for the example ruleset of the FreeBSD
// Handbook (Firewalls, IPFW, Example Ruleset): its first rules, with the
// x.x.x.x DNS server as 192.0.2.53, written the way ipfw prints rules back:
// zero-padded rule numbers (RULENUM_FORMAT "%05d" in sbin/ipfw/ipfw2.c),
// "all" as "ip", the state name after check-state and keep-state, and the
// default rule 65535.
func readIpfwFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/freebsd-ipfw-list.txt")
	require.NoError(t, err)
	return string(data)
}

const ipfwUnknownOid = "sysctl: unknown oid 'net.inet.ip.fw.enable'\n"

func TestParseIpfwList(t *testing.T) {
	rules := parseIpfwList(readIpfwFixture(t))
	require.Len(t, rules, 9)
	assert.Equal(t, "00005 allow ip from any to any via xl0", rules[0])
	assert.Equal(t, "00101 check-state :default", rules[2])
	assert.Equal(t, "65535 deny ip from any to any", rules[8])

	assert.NotNil(t, parseIpfwList(""))
	assert.Empty(t, parseIpfwList("\n"))
}

func TestIpfwEnabled(t *testing.T) {
	ipfw := newIpfwTestResource(t, "freebsd", map[string]*mock.Command{
		"sysctl -n net.inet.ip.fw.enable":            {Stdout: "1\n"},
		"sysctl -n net.inet.ip.fw.default_to_accept": {Stdout: "0\n"},
		"ipfw list": {Stdout: readIpfwFixture(t)},
	})

	enabled := ipfw.GetEnabled()
	require.NoError(t, enabled.Error)
	assert.True(t, enabled.Data)

	defaultAccept := ipfw.GetDefaultAccept()
	require.NoError(t, defaultAccept.Error)
	assert.False(t, defaultAccept.Data)

	rules := ipfw.GetRules()
	require.NoError(t, rules.Error)
	require.Len(t, rules.Data, 9)
	assert.Equal(t, "00010 allow ip from any to any via lo0", rules.Data[1])
}

func TestIpfwDisabledAcceptByDefault(t *testing.T) {
	ipfw := newIpfwTestResource(t, "freebsd", map[string]*mock.Command{
		"sysctl -n net.inet.ip.fw.enable":            {Stdout: "0\n"},
		"sysctl -n net.inet.ip.fw.default_to_accept": {Stdout: "1\n"},
		"ipfw list": {Stdout: "65535 allow ip from any to any\n"},
	})

	enabled := ipfw.GetEnabled()
	require.NoError(t, enabled.Error)
	assert.False(t, enabled.Data)

	defaultAccept := ipfw.GetDefaultAccept()
	require.NoError(t, defaultAccept.Error)
	assert.True(t, defaultAccept.Data)

	rules := ipfw.GetRules()
	require.NoError(t, rules.Error)
	assert.Equal(t, []any{"65535 allow ip from any to any"}, rules.Data)
}

func TestIpfwNotLoaded(t *testing.T) {
	ipfw := newIpfwTestResource(t, "freebsd", map[string]*mock.Command{
		"sysctl -n net.inet.ip.fw.enable":            {Stderr: ipfwUnknownOid, ExitStatus: 1},
		"sysctl -n net.inet.ip.fw.default_to_accept": {Stderr: "sysctl: unknown oid 'net.inet.ip.fw.default_to_accept'\n", ExitStatus: 1},
		"ipfw list": {Stderr: "ipfw: retrieving config failed: Protocol not available\n", ExitStatus: 71},
	})

	enabled := ipfw.GetEnabled()
	require.NoError(t, enabled.Error)
	assert.False(t, enabled.Data)

	defaultAccept := ipfw.GetDefaultAccept()
	require.NoError(t, defaultAccept.Error)
	assert.False(t, defaultAccept.Data)

	rules := ipfw.GetRules()
	require.NoError(t, rules.Error)
	assert.NotNil(t, rules.Data)
	assert.Empty(t, rules.Data)
}

func TestIpfwRulesNeedRoot(t *testing.T) {
	ipfw := newIpfwTestResource(t, "freebsd", map[string]*mock.Command{
		"sysctl -n net.inet.ip.fw.enable": {Stdout: "1\n"},
		"ipfw list":                       {Stderr: "ipfw: socket: Operation not permitted\n", ExitStatus: 69},
	})
	rules := ipfw.GetRules()
	require.Error(t, rules.Error)
	assert.True(t, errors.Is(rules.Error, llx.ErrForbidden))
}

func TestIpfwUnexpectedSysctlValue(t *testing.T) {
	ipfw := newIpfwTestResource(t, "freebsd", map[string]*mock.Command{
		"sysctl -n net.inet.ip.fw.enable": {Stdout: "yes\n"},
	})
	assert.Error(t, ipfw.GetEnabled().Error)
}

func TestIpfwNotApplicableOffFreeBSD(t *testing.T) {
	ipfw := newIpfwTestResource(t, "macos", nil)
	for _, err := range []error{ipfw.GetEnabled().Error, ipfw.GetRules().Error, ipfw.GetDefaultAccept().Error} {
		require.Error(t, err)
		assert.True(t, errors.Is(err, llx.ErrNotApplicable))
	}
}

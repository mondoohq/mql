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

func newIpfilterTestResource(t *testing.T, platform string, commands map[string]*mock.Command) *mqlIpfilter {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{Name: platform}},
		mock.WithData(&mock.TomlData{
			Files: map[string]*mock.MockFileData{
				"/etc/ipf/ipf.conf": {Path: "/etc/ipf/ipf.conf", Content: "block in log quick from 10.0.0.0/8 to any\n"},
			},
			Commands: commands,
		}))
	require.NoError(t, err)
	rt := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	res, err := NewResource(rt, "ipfilter", nil)
	require.NoError(t, err)
	return res.(*mqlIpfilter)
}

// The ipfstat fixtures are Examples 21-1 and 21-5 ("Working With IP Filter
// Rule Sets") of Oracle Solaris Administration: IP Services, Oracle Solaris 11
// (docs.oracle.com/cd/E23824_01/html/821-1453/eubbd.html).
func readIpfilterFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/ipfilter/" + name)
	require.NoError(t, err)
	return string(data)
}

func TestParseIpfstatRules(t *testing.T) {
	assert.Equal(t, []string{
		"pass in quick on dmfe1 from 192.168.1.0/24 to any",
		"pass in all",
		"block in on dmfe1 from 192.168.1.10/32 to any",
	}, parseIpfstatRules(readIpfilterFixture(t, "solaris11_ipfstat_io.txt")))

	assert.Equal(t, []string{
		"block out log on dmf0 all",
		"block in log quick from 10.0.0.0/8 to any",
	}, parseIpfstatRules(readIpfilterFixture(t, "solaris11_ipfstat_io_out_in.txt")))

	assert.Equal(t, []string{}, parseIpfstatRules(readIpfilterFixture(t, "solaris11_ipfstat_io_empty.txt")))

	// Example 21-4 of the same guide spells it "ipfilter (out)"
	assert.Equal(t, []string{"block in log quick from 10.0.0.0/8 to any"},
		parseIpfstatRules("empty list for ipfilter (out)\n\n# comment\nblock in log quick from 10.0.0.0/8 to any\n"))
}

func TestIpfilterOnline(t *testing.T) {
	ipf := newIpfilterTestResource(t, "solaris", map[string]*mock.Command{
		"/usr/bin/svcs -H -o state svc:/network/ipfilter:default": {Stdout: "online\n"},
		"/usr/sbin/ipfstat -io":                                   {Stdout: readIpfilterFixture(t, "solaris11_ipfstat_io.txt")},
	})

	enabled := ipf.GetEnabled()
	require.NoError(t, enabled.Error)
	assert.True(t, enabled.Data)

	rules := ipf.GetRules()
	require.NoError(t, rules.Error)
	assert.Equal(t, []any{
		"pass in quick on dmfe1 from 192.168.1.0/24 to any",
		"pass in all",
		"block in on dmfe1 from 192.168.1.10/32 to any",
	}, rules.Data)

	file := ipf.GetFile()
	require.NoError(t, file.Error)
	assert.Equal(t, "/etc/ipf/ipf.conf", file.Data.Path.Data)
}

func TestIpfilterDisabled(t *testing.T) {
	ipf := newIpfilterTestResource(t, "solaris", map[string]*mock.Command{
		"/usr/bin/svcs -H -o state svc:/network/ipfilter:default": {Stdout: "disabled\n"},
	})
	enabled := ipf.GetEnabled()
	require.NoError(t, enabled.Error)
	assert.False(t, enabled.Data)
}

func TestIpfilterNoService(t *testing.T) {
	ipf := newIpfilterTestResource(t, "solaris", map[string]*mock.Command{
		"/usr/bin/svcs -H -o state svc:/network/ipfilter:default": {
			Stderr:     "svcs: Pattern 'svc:/network/ipfilter:default' doesn't match any instances\n",
			ExitStatus: 1,
		},
	})
	enabled := ipf.GetEnabled()
	require.NoError(t, enabled.Error)
	assert.False(t, enabled.Data)
}

// ipfstat reports the failed open of the IP Filter device; the wording here
// is illustrative, the "Permission denied" from open(2) is what counts.
func TestIpfilterRefused(t *testing.T) {
	ipf := newIpfilterTestResource(t, "solaris", map[string]*mock.Command{
		"/usr/sbin/ipfstat -io": {Stderr: "open device: Permission denied\n", ExitStatus: 1},
	})
	rules := ipf.GetRules()
	require.Error(t, rules.Error)
	assert.True(t, errors.Is(rules.Error, llx.ErrForbidden))
}

func TestIpfilterNotApplicable(t *testing.T) {
	for _, platform := range []string{"freebsd", "ubuntu", "macos"} {
		t.Run(platform, func(t *testing.T) {
			ipf := newIpfilterTestResource(t, platform, nil)
			enabled := ipf.GetEnabled()
			require.Error(t, enabled.Error)
			assert.True(t, errors.Is(enabled.Error, llx.ErrNotApplicable))
			assert.True(t, errors.Is(ipf.GetRules().Error, llx.ErrNotApplicable))
			assert.True(t, errors.Is(ipf.GetFile().Error, llx.ErrNotApplicable))
		})
	}
}

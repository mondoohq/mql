// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestParseNetBsdServiceList(t *testing.T) {
	data := `/etc/rc.d/sshd
/etc/rc.d/cron
/etc/rc.d/ntpd
/etc/rc.d/postfix
`
	result := ParseNetBsdServiceList(strings.NewReader(data))
	assert.Equal(t, 4, len(result), "should parse 4 services")
	assert.Equal(t, "/etc/rc.d/sshd", result["sshd"], "should extract service name from path")
	assert.Equal(t, "/etc/rc.d/cron", result["cron"], "should extract service name from path")
	assert.Equal(t, "/etc/rc.d/ntpd", result["ntpd"], "should extract service name from path")
	assert.Equal(t, "/etc/rc.d/postfix", result["postfix"], "should extract service name from path")
}

func TestNetBsdServiceManager(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "netbsd",
			Family: []string{"unix", "bsd"},
		},
	}, mock.WithPath("./testdata/netbsd9.toml"))
	require.NoError(t, err)

	netbsd := NetBsdServiceManager{conn: mock}
	servicesResult, err := netbsd.List()
	require.NoError(t, err)

	// We have 56 services total in service -l output
	assert.Equal(t, 56, len(servicesResult), "should detect all services")

	// Check specific services with different states
	serviceMap := make(map[string]*Service)
	for _, srv := range servicesResult {
		serviceMap[srv.Name] = srv
	}

	// sshd: enabled and running
	sshd, ok := serviceMap["sshd"]
	require.True(t, ok, "sshd should be in service list")
	assert.Equal(t, "sshd", sshd.Name)
	assert.True(t, sshd.Installed, "sshd should be installed")
	assert.True(t, sshd.Enabled, "sshd should be enabled")
	assert.True(t, sshd.Running, "sshd should be running")
	assert.Equal(t, ServiceRunning, sshd.State)
	assert.Equal(t, "netbsd", sshd.Type)
	assert.Equal(t, "/etc/rc.d/sshd", sshd.Path)

	// cron: enabled and running
	cron, ok := serviceMap["cron"]
	require.True(t, ok, "cron should be in service list")
	assert.True(t, cron.Enabled, "cron should be enabled")
	assert.True(t, cron.Running, "cron should be running")
	assert.Equal(t, ServiceRunning, cron.State)

	// ntpd: enabled but NOT running
	ntpd, ok := serviceMap["ntpd"]
	require.True(t, ok, "ntpd should be in service list")
	assert.True(t, ntpd.Installed, "ntpd should be installed")
	assert.True(t, ntpd.Enabled, "ntpd should be enabled")
	assert.False(t, ntpd.Running, "ntpd should not be running")
	assert.Equal(t, ServiceStopped, ntpd.State)

	// ipfilter: installed but NOT enabled, NOT running
	ipfilter, ok := serviceMap["ipfilter"]
	require.True(t, ok, "ipfilter should be in service list")
	assert.True(t, ipfilter.Installed, "ipfilter should be installed")
	assert.False(t, ipfilter.Enabled, "ipfilter should not be enabled")
	assert.False(t, ipfilter.Running, "ipfilter should not be running")
	assert.Equal(t, ServiceStopped, ipfilter.State)
	assert.Equal(t, "/etc/rc.d/ipfilter", ipfilter.Path)
}

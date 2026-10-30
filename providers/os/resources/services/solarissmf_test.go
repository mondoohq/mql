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

func TestParseSolarisSmfServices(t *testing.T) {
	// Real output from Solaris 11 system
	testOutput := `STATE          STIME           FMRI
legacy_run     22:02:03        lrc:/etc/rc2_d/S89PRESERVE
disabled       22:01:40        svc:/network/dns/client:default
disabled       22:01:40        svc:/network/firewall:default
disabled       22:01:40        svc:/network/ipsec/ike:default
disabled       22:01:40        svc:/network/ipsec/ike:ikev2
disabled       22:01:40        svc:/network/ipsec/manual-key:default
disabled       22:01:40        svc:/network/nis/client:default
disabled       22:01:40        svc:/network/nis/domain:default
disabled       22:01:40        svc:/system/device/mpxio-upgrade:default
disabled       22:01:40        svc:/system/labeld:default
disabled       22:01:40        svc:/system/name-service-cache:default
disabled       22:01:41        svc:/network/ldap/client:default
disabled       22:01:42        svc:/network/nfs/cbd:default
disabled       22:01:42        svc:/network/nfs/client:default
disabled       22:01:42        svc:/network/nfs/mapid:default
disabled       22:01:42        svc:/network/nfs/nlockmgr:default
disabled       22:01:42        svc:/network/nfs/status:default
disabled       22:01:42        svc:/network/smb/client:default
disabled       22:01:42        svc:/system/device/policy-upgrade:default
disabled       22:01:42        svc:/system/idmap:default
disabled       22:01:42        svc:/system/kerberos/install:default
disabled       22:01:42        svc:/system/pools:default
disabled       22:01:42        svc:/system/rcap:default
disabled       22:01:42        svc:/system/system-log:rsyslog
disabled       22:01:43        svc:/application/management/net-snmp:default
disabled       22:01:43        svc:/application/pkg/depot:default
disabled       22:01:43        svc:/network/ntp:default
disabled       22:01:43        svc:/network/smtp:sendmail
disabled       22:01:44        svc:/application/pkg/dynamic-mirror:default
disabled       22:01:44        svc:/application/pkg/mirror:default
disabled       22:01:44        svc:/application/pkg/server:default
disabled       22:01:44        svc:/application/pkg/system-repository:default
disabled       22:01:44        svc:/application/pkg/zones-proxyd:default
disabled       22:01:44        svc:/application/security/tcsd:default
disabled       22:01:44        svc:/network/dhcp/relay:ipv4
disabled       22:01:44        svc:/network/dhcp/relay:ipv6
disabled       22:01:44        svc:/network/dhcp/server:ipv4
disabled       22:01:44        svc:/network/dhcp/server:ipv6
disabled       22:01:44        svc:/network/diagnostics:default
disabled       22:01:44        svc:/network/dlmp:default
disabled       22:01:44        svc:/network/dns/multicast:default
disabled       22:01:44        svc:/network/dns/server:default
disabled       22:01:44        svc:/network/firewall/ftp-proxy:default
disabled       22:01:44        svc:/network/firewall/pflog:default
disabled       22:01:44        svc:/network/ftp:default
disabled       22:01:44        svc:/network/http:apache24
disabled       22:01:44        svc:/network/ipmievd:default
disabled       22:01:44        svc:/network/ipsec/policy:logger
disabled       22:01:44        svc:/network/ldap/server:openldap
disabled       22:01:44        svc:/network/nfs/server:default
disabled       22:01:44        svc:/system/filesystem/reparse:default
disabled       22:01:45        svc:/network/loadbalancer/ilb:default
disabled       22:01:45        svc:/network/routing/legacy-routing:ipv4
disabled       22:01:45        svc:/network/routing/legacy-routing:ipv6
disabled       22:01:45        svc:/network/routing/ripng:default
disabled       22:01:45        svc:/network/security/kadmin:default
disabled       22:01:45        svc:/network/security/krb5_prop:default
disabled       22:01:45        svc:/network/security/krb5kdc:default
disabled       22:01:45        svc:/network/sendmail-client:default
disabled       22:01:45        svc:/network/smb/server:default
disabled       22:01:45        svc:/network/socket-filter:pf_divert
disabled       22:01:45        svc:/system/apache-stats-24:default
disabled       22:01:45        svc:/system/avahi-bridge-dsd:default
disabled       22:01:45        svc:/system/consadm:default
disabled       22:01:45        svc:/system/console-login:terma
disabled       22:01:45        svc:/system/console-login:termb
online         22:01:39        svc:/system/early-manifest-import:default
online         22:01:39        svc:/system/svc/restarter:default
online         22:01:41        svc:/milestone/immutable-setup:default
online         22:01:55        svc:/network/ssh:default
online         22:01:56        svc:/system/cron:default
online         22:01:56        svc:/system/filesystem/local:default
online         22:02:00        svc:/system/auditd:default
online         22:02:00        svc:/system/console-login:default
offline        22:01:46        svc:/system/fm/smtp-notify:default
incomplete     22:01:42        svc:/application/graphical-login/gdm:default
`

	services := ParseSolarisSmfServices(strings.NewReader(testOutput))

	// Verify total count (header line excluded)
	assert.Equal(t, 76, len(services), "should parse all services")

	// Test legacy_run service
	legacyService := findServiceByName(services, "lrc:/etc/rc2_d/S89PRESERVE")
	require.NotNil(t, legacyService, "should find legacy_run service")
	assert.True(t, legacyService.Running, "legacy_run should be running")
	assert.True(t, legacyService.Enabled, "legacy_run should be enabled")
	assert.True(t, legacyService.Installed, "legacy_run should be installed")
	assert.Equal(t, "smf", legacyService.Type)
	assert.Equal(t, ServiceRunning, legacyService.State)

	// Test disabled service
	disabledService := findServiceByName(services, "svc:/network/dns/client:default")
	require.NotNil(t, disabledService, "should find disabled service")
	assert.False(t, disabledService.Running, "disabled should not be running")
	assert.False(t, disabledService.Enabled, "disabled should not be enabled")
	assert.True(t, disabledService.Installed, "disabled should be installed")
	assert.Equal(t, "smf", disabledService.Type)
	assert.Equal(t, ServiceStopped, disabledService.State)

	// Test online service
	sshService := findServiceByName(services, "svc:/network/ssh:default")
	require.NotNil(t, sshService, "should find ssh service")
	assert.True(t, sshService.Running, "online should be running")
	assert.True(t, sshService.Enabled, "online should be enabled")
	assert.True(t, sshService.Installed, "online should be installed")
	assert.Equal(t, "smf", sshService.Type)
	assert.Equal(t, ServiceRunning, sshService.State)

	// Test offline service (enabled but not running)
	offlineService := findServiceByName(services, "svc:/system/fm/smtp-notify:default")
	require.NotNil(t, offlineService, "should find offline service")
	assert.False(t, offlineService.Running, "offline should not be running")
	assert.True(t, offlineService.Enabled, "offline should be enabled")
	assert.True(t, offlineService.Installed, "offline should be installed")
	assert.Equal(t, ServiceStopped, offlineService.State)

	// Test incomplete service
	incompleteService := findServiceByName(services, "svc:/application/graphical-login/gdm:default")
	require.NotNil(t, incompleteService, "should find incomplete service")
	assert.False(t, incompleteService.Running, "incomplete should not be running")
	assert.False(t, incompleteService.Enabled, "incomplete should not be enabled")
	assert.False(t, incompleteService.Installed, "incomplete should not be installed")
	assert.Equal(t, ServiceStopped, incompleteService.State)
}

func TestParseSolarisSmfServicesEmpty(t *testing.T) {
	// Test with just header
	testOutput := `STATE          STIME           FMRI
`
	services := ParseSolarisSmfServices(strings.NewReader(testOutput))
	assert.Equal(t, 0, len(services), "should return empty list for header-only output")
}

func TestParseSolarisSmfServicesAllStates(t *testing.T) {
	// Test all possible SMF states
	testOutput := `STATE          STIME           FMRI
online         22:01:39        svc:/test/online:default
offline        22:01:40        svc:/test/offline:default
disabled       22:01:41        svc:/test/disabled:default
maintenance    22:01:42        svc:/test/maintenance:default
degraded       22:01:43        svc:/test/degraded:default
legacy_run     22:01:44        lrc:/etc/rc2_d/S99legacy
incomplete     22:01:45        svc:/test/incomplete:default
`

	services := ParseSolarisSmfServices(strings.NewReader(testOutput))
	assert.Equal(t, 7, len(services), "should parse all state types")

	testCases := []struct {
		fmri    string
		running bool
		enabled bool
		state   State
	}{
		{"svc:/test/online:default", true, true, ServiceRunning},
		{"svc:/test/offline:default", false, true, ServiceStopped},
		{"svc:/test/disabled:default", false, false, ServiceStopped},
		{"svc:/test/maintenance:default", false, true, ServiceStopped},
		{"svc:/test/degraded:default", true, true, ServiceRunning},
		{"lrc:/etc/rc2_d/S99legacy", true, true, ServiceRunning},
		{"svc:/test/incomplete:default", false, false, ServiceStopped},
	}

	for _, tc := range testCases {
		svc := findServiceByName(services, tc.fmri)
		require.NotNil(t, svc, "should find service %s", tc.fmri)
		assert.Equal(t, tc.running, svc.Running, "%s running state", tc.fmri)
		assert.Equal(t, tc.enabled, svc.Enabled, "%s enabled state", tc.fmri)
		assert.Equal(t, tc.state, svc.State, "%s service state", tc.fmri)
	}
}

func TestSmfStateMapping(t *testing.T) {
	testCases := []struct {
		state   string
		running bool
		enabled bool
	}{
		{"online", true, true},
		{"degraded", true, true},
		{"legacy_run", true, true},
		{"offline", false, true},
		{"maintenance", false, true},
		{"incomplete", false, false},
		{"disabled", false, false},
		{"uninitialized", false, false},
		{"unknown_state", false, false},
	}

	for _, tc := range testCases {
		running, enabled := smfStateToRunningEnabled(tc.state)
		assert.Equal(t, tc.running, running, "state %s running", tc.state)
		assert.Equal(t, tc.enabled, enabled, "state %s enabled", tc.state)
	}
}

func TestSmfTransitioningStates(t *testing.T) {
	// SMF shows asterisk suffix for transitioning states (e.g., "online*" while starting)
	testOutput := `STATE          STIME           FMRI
online*        22:01:39        svc:/test/starting:default
offline*       22:01:40        svc:/test/stopping:default
disabled*      22:01:41        svc:/test/disabling:default
`

	services := ParseSolarisSmfServices(strings.NewReader(testOutput))
	assert.Equal(t, 3, len(services), "should parse transitioning states")

	// online* should be treated as online (running)
	startingSvc := findServiceByName(services, "svc:/test/starting:default")
	require.NotNil(t, startingSvc, "should find starting service")
	assert.True(t, startingSvc.Running, "online* should be running")
	assert.True(t, startingSvc.Enabled, "online* should be enabled")
	assert.Equal(t, ServiceRunning, startingSvc.State)

	// offline* should be treated as offline (not running but enabled)
	stoppingSvc := findServiceByName(services, "svc:/test/stopping:default")
	require.NotNil(t, stoppingSvc, "should find stopping service")
	assert.False(t, stoppingSvc.Running, "offline* should not be running")
	assert.True(t, stoppingSvc.Enabled, "offline* should be enabled")
	assert.Equal(t, ServiceStopped, stoppingSvc.State)

	// disabled* should be treated as disabled
	disablingSvc := findServiceByName(services, "svc:/test/disabling:default")
	require.NotNil(t, disablingSvc, "should find disabling service")
	assert.False(t, disablingSvc.Running, "disabled* should not be running")
	assert.False(t, disablingSvc.Enabled, "disabled* should not be enabled")
	assert.Equal(t, ServiceStopped, disablingSvc.State)
}

func TestSmfUninitializedState(t *testing.T) {
	testOutput := `STATE          STIME           FMRI
uninitialized  22:01:39        svc:/test/uninit:default
`

	services := ParseSolarisSmfServices(strings.NewReader(testOutput))
	assert.Equal(t, 1, len(services), "should parse uninitialized state")

	svc := findServiceByName(services, "svc:/test/uninit:default")
	require.NotNil(t, svc, "should find uninitialized service")
	assert.False(t, svc.Running, "uninitialized should not be running")
	assert.False(t, svc.Enabled, "uninitialized should not be enabled")
	assert.Equal(t, ServiceStopped, svc.State)
}

// Verbatim `svcs -a` lines from an Oracle Solaris 11.4.86 instance. 11.4 prints
// STIME as an ISO timestamp rather than the wall-clock time older releases used.
func TestParseSolarisSmfServices114(t *testing.T) {
	testOutput := `STATE          STIME               FMRI
legacy_run     2026-08-27T07:02:19 lrc:/etc/rc2_d/S89PRESERVE
disabled       2026-08-27T07:01:57 svc:/application/management/net-snmp:default
online         2026-08-27T07:01:40 svc:/network/ssh:default
offline*       2026-08-27T07:01:57 svc:/application/man-index:default
incomplete     2026-08-27T07:01:33 svc:/system/early-manifest-import:default`

	services := ParseSolarisSmfServices(strings.NewReader(testOutput))
	require.Len(t, services, 5)

	legacy := findServiceByName(services, "lrc:/etc/rc2_d/S89PRESERVE")
	require.NotNil(t, legacy)
	assert.True(t, legacy.Running, "legacy_run is running")

	ssh := findServiceByName(services, "svc:/network/ssh:default")
	require.NotNil(t, ssh)
	assert.True(t, ssh.Running)
	assert.True(t, ssh.Enabled)

	// a transitioning state carries a trailing asterisk
	manIndex := findServiceByName(services, "svc:/application/man-index:default")
	require.NotNil(t, manIndex)
	assert.False(t, manIndex.Running, "offline* is not yet running")
	assert.True(t, manIndex.Enabled, "offline* is still enabled")

	snmp := findServiceByName(services, "svc:/application/management/net-snmp:default")
	require.NotNil(t, snmp)
	assert.False(t, snmp.Running)
	assert.False(t, snmp.Enabled)
}

// Headerless output must not lose its first service.
func TestParseSolarisSmfServicesHeaderless(t *testing.T) {
	testOutput := `online         2026-08-27T07:01:40 svc:/network/ssh:default
disabled       2026-08-27T07:01:31 svc:/network/telnet:default`

	services := ParseSolarisSmfServices(strings.NewReader(testOutput))
	require.Len(t, services, 2)

	ssh := findServiceByName(services, "svc:/network/ssh:default")
	require.NotNil(t, ssh, "the first service must not be swallowed as a header")
	assert.True(t, ssh.Running)

	telnet := findServiceByName(services, "svc:/network/telnet:default")
	require.NotNil(t, telnet)
	assert.False(t, telnet.Running)
}

// A failing or unavailable `svcs` must surface an error rather than reporting a
// system with no services at all.
func TestSolarisSmfManagerCommandFailure(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"svcs -a": {
				Stderr:     "bash: svcs: command not found",
				ExitStatus: 127,
			},
		},
	}))
	require.NoError(t, err)

	svcs, err := (&SolarisSmfServiceManager{conn: conn}).List()
	require.Error(t, err)
	assert.Empty(t, svcs)
}

func findServiceByName(services []*Service, name string) *Service {
	for _, svc := range services {
		if svc.Name == name {
			return svc
		}
	}
	return nil
}

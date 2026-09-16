// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hostname_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers/os/connection/mock"
	"go.mondoo.com/mql/v13/providers/os/detector"
	"go.mondoo.com/mql/v13/providers/os/id/hostname"
)

func TestHostnameLinuxEtcHostname(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_arch.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "9be843c4be9f", hn)
}

// Bottlerocket never writes /etc/hostname, and a mounted host root cannot run
// the hostname command, so before the environment file was consulted every scan
// of such a node reported "cannot determine hostname".
func TestHostnameBottlerocket(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_bottlerocket.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)
	require.Equal(t, "bottlerocket", platform.Name)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "ip-10-0-42-17.us-west-2.compute.internal", hn)
}

func TestHostnameLinuxEtcHosts(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_etc_hosts.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "debian-box.example.com", hn)
}

// An empty /etc/hostname used to resolve the hostname to "" and report success.
func TestHostnameLinuxEmptyEtcHostname(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_empty_etc_hostname.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "debian-box.example.com", hn)
}

func TestHostnameLinux(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_linux.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "abefed34cc9c", hn)
}

func TestHostnameLinuxFqdn(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_fqdn.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "myhost.example.com", hn)
}

func TestHostnameLinuxGetentIPv4(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_getent_hosts_ipv4.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "myhost.example.com", hn)
}

func TestHostnameLinuxGetentIPv6(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_getent_hosts_ipv6.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "myhost.example.com", hn)
}

func TestHostnameWindows(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_windows.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "WIN-ABCDEFGVHLD", hn)
}

func TestHostnameMacos(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_macos.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "moonshot.local", hn)
}

func TestHostnameFreeBSD(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_freebsd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "freebsd-server.local", hn)
}

func TestHostnameOpenBSD(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_openbsd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "openbsd-server.local", hn)
}

func TestHostnameNetBSD(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_netbsd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "netbsd-server.local", hn)
}

func TestHostnameDragonFlyBSD(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/hostname_dragonflybsd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	hn, ok := hostname.Hostname(conn, platform)
	require.True(t, ok)

	assert.Equal(t, "dragonfly-server.local", hn)
}

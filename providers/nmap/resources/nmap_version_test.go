// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestNmapVersionParsing(t *testing.T) {
	const nmapVersionOutput = `Nmap version 7.95 ( https://nmap.org )
Platform: arm-apple-darwin23.4.0
Compiled with: liblua-5.4.6 openssl-3.3.1 libssh2-1.11.0 libz-1.2.12 libpcre2-10.44 nmap-libpcap-1.10.4 nmap-libdnet-1.12 ipv6
Compiled without:
Available nsock engines: kqueue poll select
`
	version := parseNmapVersionOutput(strings.NewReader(nmapVersionOutput))
	assert.Equal(t, "7.95", version.Version)
	assert.Equal(t, "arm-apple-darwin23.4.0", version.Platform)
	assert.Equal(t, []string{"liblua-5.4.6", "openssl-3.3.1", "libssh2-1.11.0", "libz-1.2.12", "libpcre2-10.44", "nmap-libpcap-1.10.4", "nmap-libdnet-1.12", "ipv6"}, version.CompiledWith)
	assert.Equal(t, []string{}, version.CompiledWithout)
	assert.Equal(t, []string{"kqueue", "poll", "select"}, version.AvailableNsockEngines)
}

func TestNmapVersionParsingLinux(t *testing.T) {
	const nmapVersionOutput = `Nmap version 7.94 ( https://nmap.org )
Platform: x86_64-pc-linux-gnu
Compiled with: liblua-5.4.6 openssl-3.0.13 nmap-libssh2-1.11.0 nmap-libz-1.3 libpcre2-10.42 nmap-libpcap-1.10.4 nmap-libdnet-1.12 ipv6
Compiled without:
Available nsock engines: epoll poll select
`
	version := parseNmapVersionOutput(strings.NewReader(nmapVersionOutput))
	assert.Equal(t, "7.94", version.Version)
	assert.Equal(t, "x86_64-pc-linux-gnu", version.Platform)
	assert.Equal(t, []string{"epoll", "poll", "select"}, version.AvailableNsockEngines)
}

// A malformed "Nmap version" line must not panic on the version-field index.
func TestNmapVersionParsingMalformed(t *testing.T) {
	version := parseNmapVersionOutput(strings.NewReader("Nmap version\nPlatform: x86_64-pc-linux-gnu\n"))
	assert.Equal(t, "", version.Version)
	assert.Equal(t, "x86_64-pc-linux-gnu", version.Platform)
}

func TestNmapVersionParsingEmpty(t *testing.T) {
	version := parseNmapVersionOutput(strings.NewReader(""))
	assert.Equal(t, "", version.Version)
	assert.Equal(t, "", version.Platform)
	assert.Equal(t, []string{}, version.CompiledWith)
}

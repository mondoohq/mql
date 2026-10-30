// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func TestParseResolvectlGlobal_Basic(t *testing.T) {
	input := `Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub
Current DNS Server: 1.1.1.1
       DNS Servers: 1.1.1.1 1.0.0.1
        DNS Domain: corp.example.com ~example.com

Link 2 (eth0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS
Current DNS Server: 192.168.1.1
`
	g := &resolvedGlobal{}
	parseResolvectlGlobal(input, g)

	assert.Equal(t, []string{"1.1.1.1", "1.0.0.1"}, g.dns)
	assert.Equal(t, "1.1.1.1", g.currentDnsServer)
	assert.Equal(t, []string{"corp.example.com", "~example.com"}, g.domains)
	assert.Equal(t, "stub", g.resolvConfMode)
	assert.Equal(t, "no", g.dnssec, "the mode, without whether the server supports it")
	assert.Equal(t, "no", g.llmnr)
	assert.Equal(t, "no", g.multicastDns)
	assert.Equal(t, "no", g.dnsOverTls)
	assert.True(t, g.cache, "cache defaults to true when no explicit field is present")

	// Per-link DNS server should NOT leak into the global block.
	for _, addr := range g.dns {
		assert.NotEqual(t, "192.168.1.1", addr)
	}
}

func TestParseResolvectlGlobal_CacheDisabled(t *testing.T) {
	// systemd versions that emit a `Cache:` line must override the default.
	input := `Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
             Cache: no
       DNS Servers: 1.1.1.1
`
	g := &resolvedGlobal{}
	parseResolvectlGlobal(input, g)

	assert.False(t, g.cache, "explicit `Cache: no` overrides default of true")
}

func TestParseResolvectlGlobal_CacheEnabledExplicit(t *testing.T) {
	input := `Global
             Cache: yes
       DNS Servers: 1.1.1.1
`
	g := &resolvedGlobal{}
	parseResolvectlGlobal(input, g)

	assert.True(t, g.cache, "explicit `Cache: yes` matches the default")
}

func TestParseResolvectlGlobal_CurrentDnsServerOnly(t *testing.T) {
	// Some hosts only have a Current DNS Server line (e.g., when no static
	// global DNS is configured but resolvectl reports the active selection).
	input := `Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 9.9.9.9
`
	g := &resolvedGlobal{}
	parseResolvectlGlobal(input, g)

	assert.Equal(t, "9.9.9.9", g.currentDnsServer)
	assert.Empty(t, g.dns, "no DNS Servers line means dns stays empty")
}

func TestParseResolvectlGlobal_PositiveProtocols(t *testing.T) {
	input := `Global
         Protocols: +LLMNR +mDNS +DNSOverTLS DNSSEC=yes
  resolv.conf mode: static
       DNS Servers: 9.9.9.9
Fallback DNS Servers: 8.8.8.8 8.8.4.4
`
	g := &resolvedGlobal{}
	parseResolvectlGlobal(input, g)

	assert.Equal(t, "yes", g.llmnr)
	assert.Equal(t, "yes", g.multicastDns)
	assert.Equal(t, "yes", g.dnsOverTls)
	assert.Equal(t, "yes", g.dnssec)
	assert.Equal(t, "static", g.resolvConfMode)
	assert.Equal(t, []string{"9.9.9.9"}, g.dns)
	assert.Equal(t, []string{"8.8.8.8", "8.8.4.4"}, g.fallbackDns)
}

func TestParseResolvectlGlobal_KeyValueProtocols(t *testing.T) {
	// Some resolvectl versions render protocols as full KEY=VALUE tokens.
	input := `Global
         Protocols: LLMNR=resolve MulticastDNS=resolve DNSOverTLS=opportunistic DNSSEC=allow-downgrade
       DNS Servers: 1.1.1.1
`
	g := &resolvedGlobal{}
	parseResolvectlGlobal(input, g)

	assert.Equal(t, "resolve", g.llmnr)
	assert.Equal(t, "resolve", g.multicastDns)
	assert.Equal(t, "opportunistic", g.dnsOverTls)
	assert.Equal(t, "allow-downgrade", g.dnssec)
}

func TestParseResolvectlGlobal_EmptyInput(t *testing.T) {
	g := &resolvedGlobal{}
	parseResolvectlGlobal("", g)
	assert.Empty(t, g.dns)
	assert.Empty(t, g.fallbackDns)
	assert.True(t, g.cache, "default cache is true")
}

func TestParseResolvectlGlobal_StopsAtBlankLine(t *testing.T) {
	// Once the Global block ends, subsequent lines must not be parsed even
	// if they look like Global fields (e.g. per-link "DNS Servers").
	input := `Global
       DNS Servers: 1.2.3.4

       DNS Servers: 9.9.9.9
`
	g := &resolvedGlobal{}
	parseResolvectlGlobal(input, g)
	assert.Equal(t, []string{"1.2.3.4"}, g.dns)
}

// Ubuntu 20.04 (systemd 245): protocol settings on their own lines, and one
// server or domain per line.
const ubuntu2004ResolvectlStatus = `Global
       LLMNR setting: no                  
MulticastDNS setting: no                  
  DNSOverTLS setting: opportunistic       
      DNSSEC setting: no                  
    DNSSEC supported: no                  
  Current DNS Server: 172.17.0.2          
         DNS Servers: 172.17.0.2          
                      169.254.169.253     
Fallback DNS Servers: 192.0.2.53          
                      198.51.100.53       
          DNS Domain: g04.example.test    
                      corp.example.test   
          DNSSEC NTA: 10.in-addr.arpa     
                      16.172.in-addr.arpa 
                      test                

Link 2 (ens5)
      Current Scopes: DNS
DefaultRoute setting: yes
       LLMNR setting: yes
         DNS Servers: 172.17.0.2
`

// Ubuntu 18.04 (systemd 237), from systemd-resolve --status: the Global block
// carries no protocol settings at all.
const ubuntu1804ResolveStatus = `Global
         DNS Servers: 172.17.0.2
                      169.254.169.253
          DNS Domain: g04.example.test
                      corp.example.test
          DNSSEC NTA: 10.in-addr.arpa
                      test

Link 2 (ens5)
      Current Scopes: DNS
       LLMNR setting: yes
MulticastDNS setting: no
      DNSSEC setting: no
    DNSSEC supported: no
`

// Ubuntu 22.04 (systemd 249): the Protocols line wraps onto the next line.
const ubuntu2204ResolvectlStatus = `Global
           Protocols: -LLMNR -mDNS DNSOverTLS=opportunistic
                      DNSSEC=no/unsupported
    resolv.conf mode: stub
  Current DNS Server: 172.17.0.2
         DNS Servers: 172.17.0.2 169.254.169.253
Fallback DNS Servers: 192.0.2.53 198.51.100.53
          DNS Domain: corp.example.test g04.example.test

Link 2 (ens5)
    Current Scopes: DNS
         Protocols: +DefaultRoute +LLMNR -mDNS DNSOverTLS=opportunistic
                    DNSSEC=no/unsupported
Current DNS Server: 172.17.0.2
`

func TestParseResolvectlGlobal_Systemd245(t *testing.T) {
	g := &resolvedGlobal{}
	parseResolvectlGlobal(ubuntu2004ResolvectlStatus, g)

	assert.Equal(t, []string{"172.17.0.2", "169.254.169.253"}, g.dns)
	assert.Equal(t, []string{"192.0.2.53", "198.51.100.53"}, g.fallbackDns)
	assert.Equal(t, []string{"g04.example.test", "corp.example.test"}, g.domains)
	assert.Equal(t, "172.17.0.2", g.currentDnsServer)
	assert.Equal(t, "no", g.llmnr)
	assert.Equal(t, "no", g.multicastDns)
	assert.Equal(t, "opportunistic", g.dnsOverTls)
	assert.Equal(t, "no", g.dnssec)
}

func TestParseResolvectlGlobal_Systemd237(t *testing.T) {
	g := &resolvedGlobal{}
	parseResolvectlGlobal(ubuntu1804ResolveStatus, g)

	assert.Equal(t, []string{"172.17.0.2", "169.254.169.253"}, g.dns)
	assert.Equal(t, []string{"g04.example.test", "corp.example.test"}, g.domains)
	// the link's settings are not the global ones
	assert.Empty(t, g.llmnr)
	assert.Empty(t, g.dnssec)
	assert.Nil(t, g.fallbackDns)
}

func TestParseResolvectlGlobal_WrappedProtocols(t *testing.T) {
	g := &resolvedGlobal{}
	parseResolvectlGlobal(ubuntu2204ResolvectlStatus, g)

	assert.Equal(t, "no", g.llmnr)
	assert.Equal(t, "no", g.multicastDns)
	assert.Equal(t, "opportunistic", g.dnsOverTls)
	assert.Equal(t, "no", g.dnssec)
	assert.Equal(t, "stub", g.resolvConfMode)
	assert.Equal(t, []string{"172.17.0.2", "169.254.169.253"}, g.dns)
}

// An IPv6 server on a continuation line holds colons but is not a key.
func TestParseResolvectlGlobal_IPv6Continuation(t *testing.T) {
	input := `Global
         DNS Servers: 192.0.2.1
                      2001:db8::53
          DNS Domain: example.test
`
	g := &resolvedGlobal{}
	parseResolvectlGlobal(input, g)
	assert.Equal(t, []string{"192.0.2.1", "2001:db8::53"}, g.dns)
	assert.Equal(t, []string{"example.test"}, g.domains)
}

func TestResolvedDnssecMode(t *testing.T) {
	assert.Equal(t, "no", resolvedDnssecMode("no/unsupported"))
	assert.Equal(t, "yes", resolvedDnssecMode("yes/supported"))
	assert.Equal(t, "allow-downgrade", resolvedDnssecMode("allow-downgrade"))
}

// resolved.conf as Ubuntu 18.04 ships it.
const ubuntu1804ResolvedConf = `#  This file is part of systemd.
#
# Entries in this file show the compile time defaults.
# You can change settings by editing this file.
# Defaults can be restored by simply deleting this file.
#
# See resolved.conf(5) for details

[Resolve]
#DNS=
#FallbackDNS=
#Domains=
#LLMNR=no
#MulticastDNS=no
#DNSSEC=no
#Cache=yes
#DNSStubListener=yes
`

func TestResolvedConf(t *testing.T) {
	conf := newResolvedConf()
	conf.applyCompiledDefaults(ubuntu1804ResolvedConf)
	conf.apply(ubuntu1804ResolvedConf)
	conf.apply("[Resolve]\nDNS=192.0.2.1\nDNS=192.0.2.2\nCache=no\nDNSSEC=allow-downgrade\n")
	conf.apply("[Resolve]\nCache=no-negative\n[Other]\nCache=no\n")

	assert.Equal(t, "192.0.2.1 192.0.2.2", conf.values["DNS"])
	assert.Equal(t, "no-negative", conf.values["Cache"])
	assert.Equal(t, "allow-downgrade", conf.values["DNSSEC"])
	assert.Equal(t, "no", conf.values["LLMNR"])
	assert.Equal(t, "", conf.values["FallbackDNS"])

	// an empty assignment clears a list
	conf.apply("[Resolve]\nDNS=\nDNS=198.51.100.1\n")
	assert.Equal(t, "198.51.100.1", conf.values["DNS"])
}

// The first FallbackDNS= assignment replaces the compiled-in list rather than
// adding to it.
func TestResolvedConf_FallbackReplacesCompiledDefault(t *testing.T) {
	conf := newResolvedConf()
	conf.applyCompiledDefaults("[Resolve]\n#FallbackDNS=8.8.8.8 8.8.4.4\n#LLMNR=yes\n")
	assert.Equal(t, "8.8.8.8 8.8.4.4", conf.values["FallbackDNS"])

	conf.apply("[Resolve]\nFallbackDNS=192.0.2.53\n")
	assert.Equal(t, "192.0.2.53", conf.values["FallbackDNS"])
}

func TestParseResolvedCache(t *testing.T) {
	assert.False(t, parseResolvedCache("no", true))
	assert.True(t, parseResolvedCache("yes", false))
	assert.True(t, parseResolvedCache("no-negative", false))
	assert.True(t, parseResolvedCache("bogus", true))
}

func resolvedMockRuntime(t *testing.T, cmds map[string]*mock.Command, files map[string]*mock.MockFileData) *plugin.Runtime {
	t.Helper()
	for path, file := range files {
		file.Path = path
	}
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}, Version: "18.04"},
	}, mock.WithData(&mock.TomlData{Commands: cmds, Files: files}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func resolvedFile(content string) *mock.MockFileData {
	return &mock.MockFileData{StatData: mock.FileInfo{Mode: 0o644}, Content: content}
}

// Ubuntu 18.04 has no resolvectl. Before, every field came back empty there;
// the report now comes from systemd-resolve --status, and what it leaves out
// from resolved.conf and its drop-ins.
func TestSystemdResolved_Systemd237(t *testing.T) {
	runtime := resolvedMockRuntime(t, map[string]*mock.Command{
		"systemctl is-active -- systemd-resolved": {},
		"resolvectl status --no-pager":            {Stderr: "bash: resolvectl: command not found", ExitStatus: 127},
		"systemd-resolve --status --no-pager":     {Stdout: ubuntu1804ResolveStatus},
	}, map[string]*mock.MockFileData{
		"/etc/systemd/resolved.conf":                resolvedFile(ubuntu1804ResolvedConf),
		"/etc/systemd/resolved.conf.d":              {StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
		"/etc/systemd/resolved.conf.d/50-test.conf": resolvedFile("[Resolve]\nFallbackDNS=192.0.2.53 198.51.100.53\nDNSSEC=allow-downgrade\nCache=no\n"),
	})

	raw, err := CreateResource(runtime, "systemd.resolved", nil)
	require.NoError(t, err)
	r := raw.(*mqlSystemdResolved)

	dns := r.GetDns()
	require.NoError(t, dns.Error)
	assert.Equal(t, []any{"172.17.0.2", "169.254.169.253"}, dns.Data)
	fallback := r.GetFallbackDns()
	require.NoError(t, fallback.Error)
	assert.Equal(t, []any{"192.0.2.53", "198.51.100.53"}, fallback.Data)
	assert.Equal(t, "allow-downgrade", r.GetDnssec().Data)
	assert.Equal(t, "no", r.GetLlmnr().Data)
	// Cache=no in a drop-in, which reading resolved.conf alone missed
	assert.False(t, r.GetCache().Data)
}

// Ubuntu 26.04 ships Cache=no-negative as a vendor drop-in that sorts after a
// local 50-*.conf, so it is the value in effect.
func TestSystemdResolved_VendorDropinOrder(t *testing.T) {
	runtime := resolvedMockRuntime(t, map[string]*mock.Command{
		"systemctl is-active -- systemd-resolved": {},
		"resolvectl status --no-pager":            {Stdout: ubuntu2204ResolvectlStatus},
	}, map[string]*mock.MockFileData{
		"/etc/systemd/resolved.conf":                              resolvedFile("[Resolve]\n#Cache=yes\n"),
		"/etc/systemd/resolved.conf.d":                            {StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
		"/etc/systemd/resolved.conf.d/50-local.conf":              resolvedFile("[Resolve]\nCache=no\n"),
		"/usr/lib/systemd/resolved.conf.d":                        {StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
		"/usr/lib/systemd/resolved.conf.d/cache-no-negative.conf": resolvedFile("[Resolve]\nCache=no-negative\n"),
	})

	raw, err := CreateResource(runtime, "systemd.resolved", nil)
	require.NoError(t, err)
	r := raw.(*mqlSystemdResolved)
	assert.True(t, r.GetCache().Data)
	assert.Equal(t, "no", r.GetDnssec().Data)
}

// `resolvectl status --no-pager` on Debian 12 (systemd 252) with DNS= and
// Domains= set in a resolved.conf drop-in
const debian12ResolvectlStatus = `Global
       Protocols: -LLMNR -mDNS DNSOverTLS=opportunistic DNSSEC=no/unsupported
resolv.conf mode: uplink
      DNS Servers 192.0.2.53
       DNS Domain g04.example

Link 2 (ens5)
Current Scopes: DNS
     Protocols: +DefaultRoute +LLMNR -mDNS DNSOverTLS=opportunistic
                DNSSEC=no/unsupported
   DNS Servers: 172.17.0.2
`

// The same host with FallbackDNS= and a routing-only domain added, which
// widens the label column
const debian12ResolvectlStatusFallback = `Global
          Protocols: -LLMNR -mDNS DNSOverTLS=opportunistic DNSSEC=no/unsupported
   resolv.conf mode: uplink
         DNS Servers 192.0.2.53
Fallback DNS Servers 192.0.2.54 2001:db8::54
          DNS Domain g04.example ~corp.example
`

func TestParseResolvectlGlobal_Systemd252(t *testing.T) {
	g := &resolvedGlobal{}
	parseResolvectlGlobal(debian12ResolvectlStatus, g)

	assert.Equal(t, []string{"192.0.2.53"}, g.dns)
	assert.Equal(t, []string{"g04.example"}, g.domains)
	assert.Equal(t, "uplink", g.resolvConfMode)
	assert.Equal(t, "no", g.llmnr)
	assert.Equal(t, "opportunistic", g.dnsOverTls)
	assert.Equal(t, "no", g.dnssec)
	// the link's server is not a global one
	assert.Empty(t, g.currentDnsServer)

	g = &resolvedGlobal{}
	parseResolvectlGlobal(debian12ResolvectlStatusFallback, g)
	assert.Equal(t, []string{"192.0.2.53"}, g.dns)
	assert.Equal(t, []string{"192.0.2.54", "2001:db8::54"}, g.fallbackDns)
	assert.Equal(t, []string{"g04.example", "~corp.example"}, g.domains)
	assert.Equal(t, "uplink", g.resolvConfMode)
}

// A resolved that is installed but not running is never asked for its
// status: asking starts it over D-Bus. Its settings come from the
// configuration instead.
func TestSystemdResolved_NotRunningIsNotQueried(t *testing.T) {
	runtime := resolvedMockRuntime(t, map[string]*mock.Command{
		"systemctl is-active -- systemd-resolved": {ExitStatus: 3},
		// what a started resolved would answer
		"resolvectl status --no-pager": {Stdout: debian12ResolvectlStatus},
	}, map[string]*mock.MockFileData{
		"/etc/systemd/resolved.conf": resolvedFile("[Resolve]\nDNS=198.51.100.53\n"),
	})

	raw, err := CreateResource(runtime, "systemd.resolved", nil)
	require.NoError(t, err)
	r := raw.(*mqlSystemdResolved)

	assert.False(t, r.GetActive().Data)
	dns := r.GetDns()
	require.NoError(t, dns.Error)
	assert.Equal(t, []any{"198.51.100.53"}, dns.Data)
	mode := r.GetResolvConfMode()
	require.NoError(t, mode.Error)
	assert.True(t, mode.IsNull(), "resolvConfMode is null when resolved is not running")
}

// `resolvectl status` on Rocky Linux 8 (systemd 239) has no "resolv.conf
// mode" line, so the mode is not known.
func TestSystemdResolved_Systemd239HasNoResolvConfMode(t *testing.T) {
	runtime := resolvedMockRuntime(t, map[string]*mock.Command{
		"systemctl is-active -- systemd-resolved": {},
		"resolvectl status --no-pager": {Stdout: `Global
       LLMNR setting: no
MulticastDNS setting: no
  DNSOverTLS setting: opportunistic
      DNSSEC setting: allow-downgrade
    DNSSEC supported: yes
         DNS Servers: 192.0.2.53
          DNS Domain: g04.example
`},
	}, map[string]*mock.MockFileData{
		"/etc/systemd/resolved.conf": resolvedFile("[Resolve]\nDNS=192.0.2.53\n"),
	})

	raw, err := CreateResource(runtime, "systemd.resolved", nil)
	require.NoError(t, err)
	r := raw.(*mqlSystemdResolved)

	assert.Equal(t, "opportunistic", r.GetDnsOverTls().Data)
	mode := r.GetResolvConfMode()
	require.NoError(t, mode.Error)
	assert.True(t, mode.IsNull(), "resolvConfMode is null when systemd does not report it")
}

// A reported mode is kept.
func TestSystemdResolved_ResolvConfModeReported(t *testing.T) {
	runtime := resolvedMockRuntime(t, map[string]*mock.Command{
		"systemctl is-active -- systemd-resolved": {},
		"resolvectl status --no-pager":            {Stdout: debian12ResolvectlStatus},
	}, map[string]*mock.MockFileData{})

	raw, err := CreateResource(runtime, "systemd.resolved", nil)
	require.NoError(t, err)
	r := raw.(*mqlSystemdResolved)

	mode := r.GetResolvConfMode()
	require.NoError(t, mode.Error)
	assert.False(t, mode.IsNull())
	assert.Equal(t, "uplink", mode.Data)
}

// The resolved.conf drop-in used on the Ubuntu 18.04 and Debian 9 test hosts.
const g04ResolvedDropin = "[Resolve]\nDNSOverTLS=opportunistic\nCache=no-negative\nLLMNR=no\nMulticastDNS=no\nDomains=g04.example g04b.example\nDNS=192.0.2.53\n"

// Ubuntu 18.04 (systemd 237): resolved logs "Unknown lvalue 'DNSOverTLS'"
// and runs without it, so the drop-in's DNSOverTLS is not in effect. Debian 9
// (systemd 232) does not know MulticastDNS either.
func TestSystemdResolved_SettingsTheReleaseLacksAreNull(t *testing.T) {
	for _, tc := range []struct {
		name         string
		library      string
		version      string
		dnsOverTls   any
		multicastDns any
	}{
		{name: "ubuntu 18.04", library: "/lib/systemd/libsystemd-shared-237.so", dnsOverTls: nil, multicastDns: "no"},
		{name: "debian 9", library: "/lib/systemd/libsystemd-shared-232.so", dnsOverTls: nil, multicastDns: nil},
		{name: "debian 9 via systemctl", version: "systemd 232\n+PAM +AUDIT +SELINUX\n", dnsOverTls: nil, multicastDns: nil},
		{name: "debian 12", library: "/usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-252.so", dnsOverTls: "opportunistic", multicastDns: "no"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmds := map[string]*mock.Command{
				"systemctl is-active -- systemd-resolved": {ExitStatus: 3},
			}
			if tc.version != "" {
				cmds["systemctl --version"] = &mock.Command{Stdout: tc.version}
			}
			files := map[string]*mock.MockFileData{
				"/etc/systemd/resolved.conf":               resolvedFile("[Resolve]\n#DNS=\n"),
				"/etc/systemd/resolved.conf.d":             {StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
				"/etc/systemd/resolved.conf.d/50-g04.conf": resolvedFile(g04ResolvedDropin),
			}
			if tc.library != "" {
				files[tc.library] = resolvedFile("")
				files[path.Dir(tc.library)] = &mock.MockFileData{StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}}
			}
			raw, err := CreateResource(resolvedMockRuntime(t, cmds, files), "systemd.resolved", nil)
			require.NoError(t, err)
			r := raw.(*mqlSystemdResolved)

			dot := r.GetDnsOverTls()
			require.NoError(t, dot.Error)
			if tc.dnsOverTls == nil {
				assert.True(t, dot.IsNull(), "dnsOverTls is %q", dot.Data)
			} else {
				assert.Equal(t, tc.dnsOverTls, dot.Data)
			}
			mdns := r.GetMulticastDns()
			require.NoError(t, mdns.Error)
			if tc.multicastDns == nil {
				assert.True(t, mdns.IsNull(), "multicastDns is %q", mdns.Data)
			} else {
				assert.Equal(t, tc.multicastDns, mdns.Data)
			}
			// settings every release has are still read
			assert.Equal(t, "no", r.GetLlmnr().Data)
		})
	}
}

func TestParseSystemctlRelease(t *testing.T) {
	assert.Equal(t, 237, parseSystemctlRelease("systemd 237\n+PAM +AUDIT\n"))
	assert.Equal(t, 252, parseSystemctlRelease("systemd 252 (252.39-1~deb12u2)\n+PAM\n"))
	assert.Equal(t, 0, parseSystemctlRelease("bash: systemctl: command not found\n"))
}

// systemdRelease takes the release from libsystemd-shared without running
// anything, and confirms a release before 231 (read from the manager binary,
// or the stand-in when the binary does not say) with systemctl.
func TestSystemdRelease(t *testing.T) {
	rhel7Manager := "ignoring: %m\x00\x00\x00\x00systemd 219 running in %ssystem mode. (+PAM +AUDIT +SELINUX"
	tests := map[string]struct {
		files map[string]*mock.MockFileData
		cmds  map[string]*mock.Command
		want  int
	}{
		"shared library wins without asking systemctl": {
			files: map[string]*mock.MockFileData{
				"/lib/systemd":                          {StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true}},
				"/lib/systemd/libsystemd-shared-252.so": resolvedFile(""),
			},
			cmds: map[string]*mock.Command{"systemctl --version": {Stdout: "systemd 999\n"}},
			want: 252,
		},
		"manager binary release confirmed by systemctl": {
			files: map[string]*mock.MockFileData{"/usr/lib/systemd/systemd": resolvedFile(rhel7Manager)},
			cmds:  map[string]*mock.Command{"systemctl --version": {Stdout: "systemd 219\n+PAM +AUDIT\n"}},
			want:  219,
		},
		"stand-in refined by systemctl": {
			files: map[string]*mock.MockFileData{"/lib/systemd/systemd": resolvedFile("\x7fELF")},
			cmds:  map[string]*mock.Command{"systemctl --version": {Stdout: "systemd 229\n"}},
			want:  229,
		},
		"stand-in kept when systemctl fails": {
			files: map[string]*mock.MockFileData{"/lib/systemd/systemd": resolvedFile("\x7fELF")},
			cmds:  map[string]*mock.Command{"systemctl --version": {Stderr: "systemctl: command not found", ExitStatus: 127}},
			want:  230,
		},
		"manager binary release kept when systemctl fails": {
			files: map[string]*mock.MockFileData{"/usr/lib/systemd/systemd": resolvedFile(rhel7Manager)},
			cmds:  map[string]*mock.Command{"systemctl --version": {ExitStatus: 1}},
			want:  219,
		},
		"no systemd on disk, systemctl answers": {
			cmds: map[string]*mock.Command{"systemctl --version": {Stdout: "systemd 237\n"}},
			want: 237,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := systemdRelease(resolvedMockRuntime(t, tc.cmds, tc.files))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

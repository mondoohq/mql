// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sysproxy

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http/httpproxy"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func TestParseEnabled(t *testing.T) {
	for _, v := range []string{"false", "FALSE", " 0 ", "no", "off", "disabled"} {
		assert.False(t, ParseEnabled(v), v)
	}
	for _, v := range []string{"", "true", "1", "yes", "on", "anything"} {
		assert.True(t, ParseEnabled(v), v)
	}
}

func TestEnabled(t *testing.T) {
	t.Setenv(EnvSystemProxy, "")
	assert.True(t, Enabled(), "an empty value is not an opt-out")
	t.Setenv(EnvSystemProxy, "false")
	assert.False(t, Enabled())
	t.Setenv(EnvSystemProxy, "true")
	assert.True(t, Enabled())
}

func TestSplitList(t *testing.T) {
	assert.Equal(t, []string{"a:1", "b:2", "c", "d"}, SplitList("a:1;b:2, c\td"))
	assert.Empty(t, SplitList(" ; , "))
	assert.Empty(t, SplitList(""))
}

func TestProxyForScheme(t *testing.T) {
	tests := []struct {
		name   string
		list   string
		scheme string
		want   string
	}{
		{"plain host applies to every scheme", "proxy.corp:8080", "https", "http://proxy.corp:8080"},
		{"plain host for http", "proxy.corp:8080", "http", "http://proxy.corp:8080"},
		{"keyed list picks the target scheme", "http=a:1;https=b:2;ftp=c:3", "https", "http://b:2"},
		{"keyed list picks http", "http=a:1;https=b:2", "http", "http://a:1"},
		{"keyed list without an entry for the scheme connects directly", "http=a:1", "https", ""},
		{"socks covers schemes without an entry", "http=a:1;socks=s:1080", "https", "socks5://s:1080"},
		{"specific entry beats the generic one", "generic:1;https=specific:2", "https", "http://specific:2"},
		{"scheme in the value is kept", "https=https://tls-proxy:443", "https", "https://tls-proxy:443"},
		{"keys are case insensitive", "HTTPS=b:2", "https", "http://b:2"},
		{"empty list", "", "https", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := proxyForScheme(tt.list, tt.scheme)
			require.NoError(t, err)
			if tt.want == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.want, got.String())
		})
	}

	t.Run("unsupported scheme is an error, not a silent direct connection", func(t *testing.T) {
		_, err := proxyForScheme("ftp://proxy:21", "https")
		require.Error(t, err)
	})
	t.Run("entry without a host is an error", func(t *testing.T) {
		_, err := proxyForScheme("http://:8080", "https")
		require.Error(t, err)
	})
}

func TestFirstProxy(t *testing.T) {
	t.Run("takes the first of a failover list", func(t *testing.T) {
		p, err := firstProxy("proxy1:8080;proxy2:8080", "https")
		require.NoError(t, err)
		assert.Equal(t, "http://proxy1:8080", p.String())
	})
	t.Run("skips entries it cannot use", func(t *testing.T) {
		p, err := firstProxy("ftp://nope:21;proxy2:8080", "https")
		require.NoError(t, err)
		assert.Equal(t, "http://proxy2:8080", p.String())
	})
	t.Run("socks entry", func(t *testing.T) {
		p, err := firstProxy("socks=s:1080", "https")
		require.NoError(t, err)
		assert.Equal(t, "socks5://s:1080", p.String())
	})
	t.Run("entry keyed for another scheme is skipped", func(t *testing.T) {
		p, err := firstProxy("http=a:1", "https")
		require.NoError(t, err)
		assert.Nil(t, p)
	})
	t.Run("only unusable entries surface the error", func(t *testing.T) {
		_, err := firstProxy("ftp://nope:21", "https")
		require.Error(t, err)
	})
}

func TestNormalizeProxyURL(t *testing.T) {
	p, err := normalizeProxyURL("SOCKS://s:1080", false)
	require.NoError(t, err)
	assert.Equal(t, "socks5://s:1080", p.String(), "Windows' socks means SOCKS5 to Go")

	p, err = normalizeProxyURL("  ", false)
	require.NoError(t, err)
	assert.Nil(t, p)

	p, err = normalizeProxyURL("user:pass@proxy:8080", false)
	require.NoError(t, err)
	assert.Equal(t, "http://user:pass@proxy:8080", p.String())
	assert.Equal(t, "http://user:xxxxx@proxy:8080", p.Redacted())
}

func TestBypassed(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		target  string
		want    bool
	}{
		{"exact host", []string{"intranet.corp"}, "https://intranet.corp/x", true},
		{"exact host does not match subdomains", []string{"corp.example"}, "https://www.corp.example/", false},
		{"case insensitive", []string{"INTRANET.CORP"}, "https://Intranet.Corp/", true},
		{"wildcard subdomain", []string{"*.corp.example"}, "https://git.corp.example/", true},
		{"wildcard subdomain needs a subdomain", []string{"*.corp.example"}, "https://corp.example/", false},
		{"leading dot behaves like *.", []string{".corp.example"}, "https://git.corp.example/", true},
		{"prefix wildcard", []string{"web*"}, "https://webserver/", true},
		{"question mark", []string{"host?"}, "https://host1/", true},
		{"question mark is exactly one character", []string{"host?"}, "https://host10/", false},
		{"ip prefix", []string{"10.*"}, "https://10.20.30.40/", true},
		{"ip prefix mismatch", []string{"10.*"}, "https://11.0.0.1/", false},
		{"two octet prefix", []string{"192.168.*"}, "http://192.168.1.5:8080/", true},
		{"cidr", []string{"10.0.0.0/8"}, "https://10.1.2.3/", true},
		{"cidr mismatch", []string{"10.0.0.0/8"}, "https://172.16.0.1/", false},
		{"cidr against a hostname never matches", []string{"10.0.0.0/8"}, "https://ten.example/", false},
		{"local matches dotless hosts", []string{tokenLocal}, "https://fileserver/", true},
		{"local does not match qualified hosts", []string{tokenLocal}, "https://fileserver.corp.example/", false},
		{"local does not match ip addresses", []string{tokenLocal}, "https://10.0.0.1/", false},
		{"loopback token is not a pattern", []string{tokenKeepLoopback}, "https://-loopback/", false},
		{"scheme specific entry matches its scheme", []string{"https://secure.corp"}, "https://secure.corp/", true},
		{"scheme specific entry skips other schemes", []string{"https://secure.corp"}, "http://secure.corp/", false},
		{"path is ignored", []string{"host.corp/some/path"}, "https://host.corp/other", true},
		{"port must match when given", []string{"host.corp:8443"}, "https://host.corp:8443/", true},
		{"port mismatch", []string{"host.corp:8443"}, "https://host.corp/", false},
		{"default port matches", []string{"host.corp:443"}, "https://host.corp/", true},
		{"ipv6 literal", []string{"[fd00::1]"}, "https://[fd00::1]/", true},
		{"ipv6 literal with port", []string{"[fd00::1]:8443"}, "https://[fd00::1]:8443/", true},
		{"bare ipv6", []string{"fd00::1"}, "https://[fd00::1]/", true},
		{"empty entries are skipped", []string{"", " "}, "https://host/", false},
		{"no entries", nil, "https://host/", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, bypassed(tt.entries, mustURL(t, tt.target)))
		})
	}
}

func TestMatchGlob(t *testing.T) {
	assert.True(t, matchGlob("*", "anything"))
	assert.True(t, matchGlob("*", ""))
	assert.True(t, matchGlob("a*c", "abbbc"))
	assert.True(t, matchGlob("a*c", "ac"))
	assert.False(t, matchGlob("a*c", "axd"))
	assert.True(t, matchGlob("*.b.c", "a.b.c"))
	assert.False(t, matchGlob("*.b.c", "b.c"))
	assert.True(t, matchGlob("a?c", "abc"))
	assert.False(t, matchGlob("a?c", "ac"))
	assert.True(t, matchGlob("**a", "xa"))
	assert.False(t, matchGlob("", "x"))
	assert.True(t, matchGlob("", ""))
}

func TestToNoProxy(t *testing.T) {
	got := ToNoProxy([]string{
		"*.corp.example", "10.*", "192.168.1.*", "172.16.0.0/12", "intranet",
		"host.corp:8443", "https://secure.corp/path", "*example.net", "web*", tokenLocal, tokenKeepLoopback, "",
		"*.corp.example", // duplicate
	})
	assert.Equal(t, "*.corp.example,10.0.0.0/8,192.168.1.0/24,172.16.0.0/12,intranet,host.corp:8443,secure.corp,example.net", got)

	assert.Equal(t, "*", ToNoProxy([]string{"host", "*"}), "a bare star bypasses everything")
	assert.Equal(t, "", ToNoProxy(nil))
	assert.Equal(t, "", ToNoProxy([]string{tokenLocal}), "<local> has no NO_PROXY form")
}

func TestIPv4WildcardToCIDR(t *testing.T) {
	for in, want := range map[string]string{
		"10.*":       "10.0.0.0/8",
		"10.1.*":     "10.1.0.0/16",
		"10.1.2.*":   "10.1.2.0/24",
		"192.168.*":  "192.168.0.0/16",
		"10.*.*":     "",
		"10.1.2.3.*": "",
		"256.*":      "",
		"01.*":       "",
		"a.*":        "",
		"10.1.2.3":   "",
		"*.10":       "",
	} {
		got, ok := ipv4WildcardToCIDR(in)
		assert.Equal(t, want != "", ok, in)
		assert.Equal(t, want, got, in)
	}
}

func TestConnectionSettingsFlags(t *testing.T) {
	// version 0x46, counter 3, flags: manual proxy (0x02) + auto-detect (0x08)
	blob := []byte{0x46, 0, 0, 0, 3, 0, 0, 0, 0x0a, 0, 0, 0, 0, 0, 0, 0}
	flags, ok := connectionSettingsFlags(blob)
	require.True(t, ok)
	assert.NotZero(t, flags&connectionSettingsAutoDetect)

	_, ok = connectionSettingsFlags([]byte{0x46, 0, 0, 0, 3, 0, 0, 0, 0x0a})
	assert.False(t, ok, "a truncated blob must not be read as flags")
}

// testSelector wires a selector to canned settings and a canned script.
type testSelector struct {
	*selector
	settings    *Settings
	detectCalls int
	scriptCalls int
	script      scriptResult
	enabled     bool
}

func newTestSelector(env *httpproxy.Config, settings *Settings) *testSelector {
	ts := &testSelector{settings: settings, enabled: true}
	ts.selector = newSelector(env,
		func() bool { return ts.enabled },
		func() (*Settings, error) { ts.detectCalls++; return ts.settings, nil },
		func(*Settings, *url.URL) scriptResult { ts.scriptCalls++; return ts.script },
	)
	return ts
}

func (ts *testSelector) resolve(t *testing.T, raw string) string {
	t.Helper()
	p, err := ts.proxyForURL(mustURL(t, raw))
	require.NoError(t, err)
	if p == nil {
		return ""
	}
	return p.String()
}

func TestSelectorPrecedence(t *testing.T) {
	manual := &Settings{Proxy: "sysproxy.corp:3128", Bypass: []string{"*.corp.example", "10.*"}}

	t.Run("environment proxy decides alone", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{HTTPSProxy: "http://envproxy:9", NoProxy: "skip.example"}, manual)
		assert.Equal(t, "http://envproxy:9", ts.resolve(t, "https://api.example/"))
		assert.Equal(t, "", ts.resolve(t, "https://skip.example/"), "NO_PROXY applies to the environment proxy")
		assert.Equal(t, "", ts.resolve(t, "http://api.example/"), "HTTPS_PROXY alone leaves http targets direct, as Go does")
		assert.Zero(t, ts.detectCalls, "system settings are not read when the environment names a proxy")
	})

	t.Run("disabled system proxy connects directly", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, manual)
		ts.enabled = false
		assert.Equal(t, "", ts.resolve(t, "https://api.example/"))
		assert.Zero(t, ts.detectCalls)
	})

	t.Run("no settings connects directly", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, nil)
		assert.Equal(t, "", ts.resolve(t, "https://api.example/"))
		assert.Equal(t, 1, ts.detectCalls)
	})

	t.Run("manual proxy with exceptions", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, manual)
		assert.Equal(t, "http://sysproxy.corp:3128", ts.resolve(t, "https://api.example/"))
		assert.Equal(t, "http://sysproxy.corp:3128", ts.resolve(t, "http://api.example/"))
		assert.Equal(t, "", ts.resolve(t, "https://git.corp.example/"))
		assert.Equal(t, "", ts.resolve(t, "https://10.1.1.1/"))
		assert.Zero(t, ts.scriptCalls, "no script configured, none evaluated")
	})

	t.Run("loopback is exempt unless the bypass list says otherwise", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, manual)
		assert.Equal(t, "", ts.resolve(t, "http://localhost:8989/"))
		assert.Equal(t, "", ts.resolve(t, "http://127.0.0.1:8989/"))
		assert.Equal(t, "", ts.resolve(t, "http://[::1]:8989/"))

		keep := &Settings{Proxy: "sysproxy.corp:3128", Bypass: []string{tokenKeepLoopback}}
		ts = newTestSelector(&httpproxy.Config{}, keep)
		assert.Equal(t, "http://sysproxy.corp:3128", ts.resolve(t, "http://localhost:8989/"))
	})

	t.Run("NO_PROXY applies to the system proxy too", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{NoProxy: "api.example,.internal.example"}, manual)
		assert.Equal(t, "", ts.resolve(t, "https://api.example/"))
		assert.Equal(t, "", ts.resolve(t, "https://svc.internal.example/"))
		assert.Equal(t, "http://sysproxy.corp:3128", ts.resolve(t, "https://other.example/"))
	})

	t.Run("script answer wins over the manual proxy", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{AutoConfigURL: "http://pac.corp/proxy.pac", Proxy: "manual:1"})
		ts.script = scriptResult{proxies: "pacproxy:8080;backup:8080"}
		assert.Equal(t, "http://pacproxy:8080", ts.resolve(t, "https://api.example/"))
		assert.Equal(t, 1, ts.scriptCalls)
	})

	t.Run("script DIRECT is direct even with a manual proxy", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{AutoDetect: true, Proxy: "manual:1"})
		ts.script = scriptResult{}
		assert.Equal(t, "", ts.resolve(t, "https://api.example/"))
	})

	t.Run("script failure falls back to the manual proxy", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{AutoDetect: true, Proxy: "manual:1"})
		ts.script = scriptResult{err: errors.New("WPAD failed")}
		assert.Equal(t, "http://manual:1", ts.resolve(t, "https://api.example/"))
	})

	t.Run("script failure without a manual proxy is direct", func(t *testing.T) {
		// The Windows default: auto-detect on, nothing else. Must cost nothing
		// beyond the failed probe and must connect directly.
		ts := newTestSelector(&httpproxy.Config{}, &Settings{AutoDetect: true})
		ts.script = scriptResult{err: errors.New("WPAD failed")}
		assert.Equal(t, "", ts.resolve(t, "https://api.example/"))
	})

	t.Run("machine proxy applies when the user has none", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{AutoDetect: true, MachineProxy: "netsh.corp:8080", MachineBypass: []string{"<local>"}})
		ts.script = scriptResult{err: errors.New("WPAD failed")}
		assert.Equal(t, "http://netsh.corp:8080", ts.resolve(t, "https://api.example/"))
		assert.Equal(t, "", ts.resolve(t, "https://fileserver/"))
	})

	t.Run("user proxy wins over the machine proxy", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{Proxy: "user:1", MachineProxy: "machine:2"})
		assert.Equal(t, "http://user:1", ts.resolve(t, "https://api.example/"))
	})

	t.Run("keyed list without an https entry connects https directly", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{Proxy: "http=only-http:1"})
		assert.Equal(t, "", ts.resolve(t, "https://api.example/"))
		assert.Equal(t, "http://only-http:1", ts.resolve(t, "http://api.example/"))
	})

	t.Run("broken system proxy setting is reported, not swallowed", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{Proxy: "ftp://nope:21"})
		_, err := ts.proxyForURL(mustURL(t, "https://api.example/"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ftp://nope:21")
	})

	t.Run("nil URL", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, manual)
		p, err := ts.proxyForURL(nil)
		require.NoError(t, err)
		assert.Nil(t, p)
	})
}

func TestSelectorEnvironment(t *testing.T) {
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	rep := mustURL(t, "https://us.api.mondoo.com")

	t.Run("nothing when the environment already names a proxy", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{HTTPProxy: "http://env:1"}, &Settings{Proxy: "sys:1"})
		assert.Nil(t, ts.environment(rep))
	})

	t.Run("nothing when disabled or unconfigured", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{Proxy: "sys:1"})
		ts.enabled = false
		assert.Nil(t, ts.environment(rep))
		ts = newTestSelector(&httpproxy.Config{}, nil)
		assert.Nil(t, ts.environment(rep))
	})

	t.Run("manual proxy with exceptions", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{Proxy: "sys.corp:3128", Bypass: []string{"*.corp.example", "10.*", "<local>"}})
		assert.Equal(t, []string{
			"HTTP_PROXY=http://sys.corp:3128",
			"HTTPS_PROXY=http://sys.corp:3128",
			"NO_PROXY=*.corp.example,10.0.0.0/8",
		}, ts.environment(rep))
	})

	t.Run("keyed list exports per scheme", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{Proxy: "http=a:1;https=b:2"})
		assert.Equal(t, []string{"HTTP_PROXY=http://a:1", "HTTPS_PROXY=http://b:2"}, ts.environment(rep))

		ts = newTestSelector(&httpproxy.Config{}, &Settings{Proxy: "https=b:2"})
		assert.Equal(t, []string{"HTTPS_PROXY=http://b:2"}, ts.environment(rep))
	})

	t.Run("an existing NO_PROXY is left alone", func(t *testing.T) {
		t.Setenv("NO_PROXY", "mine.example")
		ts := newTestSelector(&httpproxy.Config{NoProxy: "mine.example"}, &Settings{Proxy: "sys.corp:3128", Bypass: []string{"*.corp.example"}})
		assert.Equal(t, []string{"HTTP_PROXY=http://sys.corp:3128", "HTTPS_PROXY=http://sys.corp:3128"}, ts.environment(rep))
	})

	t.Run("script is evaluated for the representative URL", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{AutoConfigURL: "http://pac/p.pac", Proxy: "manual:1", Bypass: []string{"*.corp.example"}})
		ts.script = scriptResult{proxies: "pacproxy:8080"}
		assert.Equal(t, []string{"HTTP_PROXY=http://pacproxy:8080", "HTTPS_PROXY=http://pacproxy:8080"}, ts.environment(rep))
	})

	t.Run("script DIRECT for the representative exports nothing", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{AutoConfigURL: "http://pac/p.pac", Proxy: "manual:1"})
		ts.script = scriptResult{}
		assert.Nil(t, ts.environment(rep))
	})

	t.Run("script without a representative exports nothing on its own", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{AutoDetect: true})
		assert.Nil(t, ts.environment(nil))
		assert.Zero(t, ts.scriptCalls)
	})

	t.Run("script that cannot run leaves the manual proxy and its exceptions in charge", func(t *testing.T) {
		// The Windows default: auto-detect on and no WPAD on the network, with a
		// netsh proxy whose bypass list covers the API host. Found on a real
		// machine: the representative being bypassed used to export nothing,
		// sending the provider's cloud SDK traffic direct.
		ts := newTestSelector(&httpproxy.Config{}, &Settings{AutoDetect: true, MachineProxy: "netsh:8080", MachineBypass: []string{"*.mondoo.com", "<local>"}})
		ts.script = scriptResult{err: errors.New("WPAD failed")}
		assert.Equal(t, []string{"HTTP_PROXY=http://netsh:8080", "HTTPS_PROXY=http://netsh:8080", "NO_PROXY=*.mondoo.com"}, ts.environment(rep))
		assert.Equal(t, 1, ts.scriptCalls)
	})

	t.Run("script that cannot run without a representative still exports the manual proxy", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{AutoDetect: true, Proxy: "manual:1"})
		ts.script = scriptResult{err: errors.New("WPAD failed")}
		assert.Equal(t, []string{"HTTP_PROXY=http://manual:1", "HTTPS_PROXY=http://manual:1"}, ts.environment(nil))
		assert.Zero(t, ts.scriptCalls, "nothing to evaluate the script for")
	})

	t.Run("manual exceptions covering the representative still export the proxy", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{Proxy: "sys:3128", Bypass: []string{"*.mondoo.com"}})
		assert.Equal(t, []string{"HTTP_PROXY=http://sys:3128", "HTTPS_PROXY=http://sys:3128", "NO_PROXY=*.mondoo.com"}, ts.environment(rep))
	})

	t.Run("machine proxy", func(t *testing.T) {
		ts := newTestSelector(&httpproxy.Config{}, &Settings{MachineProxy: "netsh:8080", MachineBypass: []string{"intranet"}})
		assert.Equal(t, []string{"HTTP_PROXY=http://netsh:8080", "HTTPS_PROXY=http://netsh:8080", "NO_PROXY=intranet"}, ts.environment(rep))
	})
}

func TestDetectCaches(t *testing.T) {
	calls := 0
	orig := detectFn
	detectFn = func() (*Settings, error) {
		calls++
		return &Settings{Proxy: "p:1"}, nil
	}
	t.Cleanup(func() {
		detectFn = orig
		resetDetection()
	})
	resetDetection()

	s, err := Detect()
	require.NoError(t, err)
	require.NotNil(t, s)
	_, _ = Detect()
	assert.Equal(t, 1, calls, "a second call within the TTL is served from the cache")

	detectFn = func() (*Settings, error) { calls++; return &Settings{}, nil }
	resetDetection()
	s, err = Detect()
	require.NoError(t, err)
	assert.Nil(t, s, "empty settings read as none")
}

func TestSettingsString(t *testing.T) {
	assert.Equal(t, "none", (*Settings)(nil).String())
	assert.Equal(t, "auto-detect, script http://pac/p.pac, proxy p:1, machine proxy m:2",
		(&Settings{AutoDetect: true, AutoConfigURL: "http://pac/p.pac", Proxy: "p:1", MachineProxy: "m:2"}).String())
}

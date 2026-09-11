// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package sysproxy selects the proxy for outbound HTTP requests from the
// process environment and from the operating system's own proxy settings.
//
// net/http only understands the HTTP_PROXY, HTTPS_PROXY and NO_PROXY
// convention. Windows keeps its proxy elsewhere: per user in Internet Settings
// (Settings > Network & internet > Proxy: a manual proxy with exceptions, a
// setup script URL, or "automatically detect settings"), and per machine in
// the WinHTTP default proxy that administrators configure with
// `netsh winhttp set proxy` for services. Reading both is what lets a client
// installed on such a machine reach Mondoo Platform without any proxy
// configuration of its own.
//
// Precedence for each request:
//  1. HTTP_PROXY, HTTPS_PROXY and NO_PROXY when either proxy variable is set
//     (Go semantics, unchanged from before this package existed)
//  2. the operating system's settings: the setup script or auto-detected
//     script when configured, otherwise the per-user manual proxy with its
//     exceptions, otherwise the machine-wide WinHTTP proxy with its exceptions
//  3. a direct connection
//
// MONDOO_SYSTEM_PROXY=false turns step 2 off. Platforms other than Windows
// have no settings to read, so step 2 selects nothing there.
package sysproxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/http/httpproxy"
)

// EnvSystemProxy is the environment variable that disables reading the
// operating system's proxy settings when set to false, 0, no or off. The CLI
// sets it for provider subprocesses when mondoo.yml says system_proxy: false,
// so providers make the same choice as the process that started them.
const EnvSystemProxy = "MONDOO_SYSTEM_PROXY"

// detectTTL bounds how long detected settings are reused. A process that runs
// for days (cnspec serve as a Windows service) picks up a changed proxy within
// this window instead of needing a restart, while a scan never pays for more
// than one detection.
const detectTTL = 5 * time.Minute

// Bypass list tokens with a meaning of their own on Windows.
const (
	// tokenLocal matches hosts without a dot in their name.
	tokenLocal = "<local>"
	// tokenKeepLoopback cancels the implicit exemption of loopback addresses.
	tokenKeepLoopback = "<-loopback>"
)

// Settings are the operating system's proxy settings, as configured by the
// user or an administrator. Windows fills them in; other platforms have none.
type Settings struct {
	// AutoDetect is the per-user "Automatically detect settings" switch
	// (WPAD). Windows turns it on by default, so it is set on most machines,
	// including ones with no proxy at all.
	AutoDetect bool
	// AutoConfigURL is the per-user setup script (PAC) URL.
	AutoConfigURL string
	// Proxy is the per-user manual proxy, empty when manual proxying is off.
	// Either "host:port" for every scheme, or a "scheme=host:port;..." list
	// as Windows stores it when protocols use different proxies.
	Proxy string
	// Bypass are the manual proxy's exceptions in Windows syntax: hostnames
	// with * wildcards, IP prefixes like "10.*", plus the "<local>" token for
	// hosts without a dot and "<-loopback>" to stop exempting loopback.
	Bypass []string
	// MachineProxy and MachineBypass are the WinHTTP machine-wide defaults
	// (`netsh winhttp set proxy`), used when the per-user settings select
	// nothing. A Windows service running as LocalSystem has no proxy of its
	// own, so this is the layer such a service ends up on.
	MachineProxy  string
	MachineBypass []string
}

// IsZero reports whether nothing at all is configured.
func (s *Settings) IsZero() bool {
	return s == nil || (!s.AutoDetect && s.AutoConfigURL == "" && s.Proxy == "" && s.MachineProxy == "")
}

// usesScript reports whether a setup script or auto-detection is configured.
func (s *Settings) usesScript() bool {
	return s != nil && (s.AutoDetect || s.AutoConfigURL != "")
}

// String summarizes the settings for logs and status output.
func (s *Settings) String() string {
	if s.IsZero() {
		return "none"
	}
	var parts []string
	if s.AutoDetect {
		parts = append(parts, "auto-detect")
	}
	if s.AutoConfigURL != "" {
		parts = append(parts, "script "+s.AutoConfigURL)
	}
	if s.Proxy != "" {
		parts = append(parts, "proxy "+s.Proxy)
	}
	if s.MachineProxy != "" {
		parts = append(parts, "machine proxy "+s.MachineProxy)
	}
	return strings.Join(parts, ", ")
}

// Enabled reports whether the operating system's settings may be consulted:
// MONDOO_SYSTEM_PROXY is unset, empty or anything other than false/0/no/off.
func Enabled() bool {
	v, ok := os.LookupEnv(EnvSystemProxy)
	if !ok {
		return true
	}
	return ParseEnabled(v)
}

// ParseEnabled interprets a MONDOO_SYSTEM_PROXY (or system_proxy) value.
// Only an explicit false, 0, no, off or disabled turns detection off.
func ParseEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0", "no", "off", "disabled":
		return false
	}
	return true
}

var (
	detectMu   sync.Mutex
	detectedAt time.Time
	detected   *Settings
	detectErr  error
	// detectFn is the platform implementation; tests swap it out.
	detectFn = detect
)

// Detect returns the operating system's proxy settings, or nil when none are
// configured or the platform has none. The result is cached for detectTTL.
func Detect() (*Settings, error) {
	detectMu.Lock()
	defer detectMu.Unlock()
	if !detectedAt.IsZero() && time.Since(detectedAt) < detectTTL {
		return detected, detectErr
	}
	s, err := detectFn()
	if err != nil {
		log.Debug().Err(err).Msg("could not read the operating system's proxy settings")
	} else if s.IsZero() {
		s = nil
	} else {
		log.Debug().Stringer("settings", s).Msg("read the operating system's proxy settings")
	}
	detected, detectErr, detectedAt = s, err, time.Now()
	return s, err
}

// resetDetection forgets cached settings so the next Detect reads again.
func resetDetection() {
	detectMu.Lock()
	defer detectMu.Unlock()
	detectedAt, detected, detectErr = time.Time{}, nil, nil
}

// EnvironmentConfigured reports whether HTTP_PROXY or HTTPS_PROXY names a
// proxy, in which case the environment decides and system settings are not
// consulted.
func EnvironmentConfigured() bool {
	return environmentConfigured(httpproxy.FromEnvironment())
}

func environmentConfigured(cfg *httpproxy.Config) bool {
	return cfg.HTTPProxy != "" || cfg.HTTPSProxy != ""
}

// EnvironmentProxyFunc returns a selector that applies HTTP_PROXY, HTTPS_PROXY
// and NO_PROXY exactly as http.ProxyFromEnvironment does, except that it reads
// the environment when it is created instead of once per process. It is the
// selector for "system proxy off", and what tests can exercise without the
// process-wide snapshot http.ProxyFromEnvironment keeps.
func EnvironmentProxyFunc() func(*http.Request) (*url.URL, error) {
	fn := httpproxy.FromEnvironment().ProxyFunc()
	return func(req *http.Request) (*url.URL, error) {
		return fn(req.URL)
	}
}

// ProxyFunc returns a selector for http.Transport.Proxy that applies the
// precedence documented for this package. Operating system settings are read
// lazily on the first request and refreshed every detectTTL.
func ProxyFunc() func(*http.Request) (*url.URL, error) {
	return newSelector(httpproxy.FromEnvironment(), Enabled, Detect, evaluateScript).proxyForRequest
}

// ProxyForURL resolves the proxy for one URL the way ProxyFunc would. It
// exists for diagnostics such as the status command.
func ProxyForURL(u *url.URL) (*url.URL, error) {
	return ProxyFunc()(&http.Request{URL: u})
}

// Environment returns HTTP_PROXY, HTTPS_PROXY and NO_PROXY assignments that
// hand the system proxy to a child process which only understands the
// environment convention (the cloud SDKs inside provider subprocesses). It
// returns nothing when the environment already names a proxy, when system
// settings are disabled, or when none are configured. Variables the parent
// already has are left alone. A setup script can only be represented by its
// answer for one URL, so representative should be the destination that
// matters most, the Mondoo API endpoint.
func Environment(representative *url.URL) []string {
	return newSelector(httpproxy.FromEnvironment(), Enabled, Detect, evaluateScript).environment(representative)
}

// scriptResult is what a setup script or auto-detection produced for one URL.
type scriptResult struct {
	// proxies is the script's proxy list ("host:port;host2:port"); empty
	// with a nil err means the script asked for a direct connection.
	proxies string
	err     error
}

// scriptEvaluator runs the configured script for one URL. Windows implements
// it with WinHTTP; other platforms never get here because they have no
// settings.
type scriptEvaluator func(s *Settings, u *url.URL) scriptResult

// selector is ProxyFunc's state. It carries the environment as read when the
// client was built, matching how http.ProxyFromEnvironment snapshots it, and
// asks for system settings per request so the detection cache can refresh.
type selector struct {
	// envProxy is set when the environment names a proxy and then decides alone.
	envProxy func(*url.URL) (*url.URL, error)
	// noProxy applies NO_PROXY, Go's reading of it, to system proxies too. Nil
	// when NO_PROXY is unset.
	noProxy func(*url.URL) bool
	enabled func() bool
	detect  func() (*Settings, error)
	script  scriptEvaluator
}

func newSelector(env *httpproxy.Config, enabled func() bool, detect func() (*Settings, error), script scriptEvaluator) *selector {
	s := &selector{enabled: enabled, detect: detect, script: script}
	switch {
	case environmentConfigured(env):
		s.envProxy = env.ProxyFunc()
	case env.NoProxy != "":
		// Give Go's matcher a stand-in proxy and read "no proxy" back as
		// "bypass", so NO_PROXY keeps exactly its usual meaning.
		match := (&httpproxy.Config{
			HTTPProxy:  "http://no-proxy.invalid",
			HTTPSProxy: "http://no-proxy.invalid",
			NoProxy:    env.NoProxy,
		}).ProxyFunc()
		s.noProxy = func(u *url.URL) bool {
			p, _ := match(u)
			return p == nil
		}
	}
	return s
}

func (s *selector) proxyForRequest(req *http.Request) (*url.URL, error) {
	return s.proxyForURL(req.URL)
}

func (s *selector) proxyForURL(u *url.URL) (*url.URL, error) {
	if u == nil {
		return nil, nil
	}
	if s.envProxy != nil {
		return s.envProxy(u)
	}
	if !s.enabled() {
		return nil, nil
	}
	settings, err := s.detect()
	if err != nil || settings == nil {
		return nil, nil
	}
	return s.systemProxy(settings, u)
}

// announce logs the first proxy that system settings select, once per
// process. Connectivity problems on a proxied machine are hard to place
// without knowing that a proxy was picked and where it came from.
var announce sync.Once

// systemProxy applies the operating system's settings to one URL.
func (s *selector) systemProxy(settings *Settings, u *url.URL) (*url.URL, error) {
	host := u.Hostname()
	if host == "" {
		return nil, nil
	}
	if s.noProxy != nil && s.noProxy(u) {
		return nil, nil
	}
	// Windows never proxies loopback unless a bypass list says "<-loopback>".
	if isLoopback(host) && !hasToken(settings.Bypass, tokenKeepLoopback) && !hasToken(settings.MachineBypass, tokenKeepLoopback) {
		return nil, nil
	}

	if settings.usesScript() && s.script != nil {
		res := s.script(settings, u)
		switch {
		case res.err != nil:
			// Windows falls back to the manual proxy when the script cannot
			// be run, so do the same.
			log.Debug().Err(res.err).Str("url", u.Redacted()).Msg("proxy script unavailable, using the manual proxy settings")
		case res.proxies == "":
			return nil, nil // the script asked for a direct connection
		default:
			p, err := firstProxy(res.proxies, u.Scheme)
			if err != nil {
				return nil, fmt.Errorf("proxy script returned %q: %w", res.proxies, err)
			}
			logSelected(p, "proxy script")
			return p, nil
		}
	}
	if settings.Proxy != "" {
		return manualProxy(settings.Proxy, settings.Bypass, "Internet Settings", u)
	}
	if settings.MachineProxy != "" {
		return manualProxy(settings.MachineProxy, settings.MachineBypass, "WinHTTP default proxy", u)
	}
	return nil, nil
}

func manualProxy(list string, bypass []string, source string, u *url.URL) (*url.URL, error) {
	if bypassed(bypass, u) {
		return nil, nil
	}
	p, err := proxyForScheme(list, u.Scheme)
	if err != nil {
		return nil, fmt.Errorf("invalid system proxy setting %q: %w", list, err)
	}
	logSelected(p, source)
	return p, nil
}

func logSelected(p *url.URL, source string) {
	if p == nil {
		return
	}
	announce.Do(func() {
		log.Info().Str("proxy", p.Redacted()).Str("source", source).Msg("using the operating system's proxy settings for outbound connections")
	})
}

// environment implements Environment for one selector.
func (s *selector) environment(representative *url.URL) []string {
	if s.envProxy != nil || !s.enabled() {
		return nil
	}
	settings, err := s.detect()
	if err != nil || settings == nil {
		return nil
	}

	var httpProxy, httpsProxy *url.URL
	var bypass []string
	switch {
	case settings.usesScript():
		if representative == nil {
			return nil
		}
		// The script is the authority on exceptions; nothing to carry over.
		p, err := s.systemProxy(settings, representative)
		if err != nil || p == nil {
			return nil
		}
		httpProxy, httpsProxy = p, p
	case settings.Proxy != "":
		httpProxy, _ = proxyForScheme(settings.Proxy, "http")
		httpsProxy, _ = proxyForScheme(settings.Proxy, "https")
		bypass = settings.Bypass
	case settings.MachineProxy != "":
		httpProxy, _ = proxyForScheme(settings.MachineProxy, "http")
		httpsProxy, _ = proxyForScheme(settings.MachineProxy, "https")
		bypass = settings.MachineBypass
	}
	if httpProxy == nil && httpsProxy == nil {
		return nil
	}

	var env []string
	if httpProxy != nil {
		env = append(env, "HTTP_PROXY="+httpProxy.String())
	}
	if httpsProxy != nil {
		env = append(env, "HTTPS_PROXY="+httpsProxy.String())
	}
	// envProxy == nil already says neither proxy variable is set; NO_PROXY may
	// still be, and a value the user set is not overridden.
	if noProxy := ToNoProxy(bypass); noProxy != "" && os.Getenv("NO_PROXY") == "" && os.Getenv("no_proxy") == "" {
		env = append(env, "NO_PROXY="+noProxy)
	}
	return env
}

// SplitList splits a Windows proxy or bypass list. Windows writes semicolons;
// whitespace and commas turn up in hand-edited registry values and netsh
// output, and no entry legitimately contains any of them.
func SplitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ';' || r == ',' || unicode.IsSpace(r)
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// proxyForScheme picks the proxy for a target scheme out of a Windows proxy
// list: "host:port" applies to every scheme, "scheme=host:port" only to its
// own, and "socks=host:port" to schemes without an entry of their own. A
// scheme with no applicable entry connects directly, which is what WinHTTP
// does with such a list.
func proxyForScheme(list, scheme string) (*url.URL, error) {
	scheme = strings.ToLower(scheme)
	var generic, specific, socks string
	for _, entry := range SplitList(list) {
		key, value, keyed := strings.Cut(entry, "=")
		if !keyed {
			if generic == "" {
				generic = entry
			}
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case scheme:
			specific = value
		case "socks":
			socks = value
		}
	}
	switch {
	case specific != "":
		return normalizeProxyURL(specific, false)
	case generic != "":
		return normalizeProxyURL(generic, false)
	case socks != "":
		return normalizeProxyURL(socks, true)
	}
	return nil, nil
}

// firstProxy picks the first usable entry out of a script's proxy list.
// Scripts may name several proxies for failover; http.Transport takes one.
func firstProxy(list, scheme string) (*url.URL, error) {
	scheme = strings.ToLower(scheme)
	var lastErr error
	for _, entry := range SplitList(list) {
		candidate, socks := entry, false
		if key, value, keyed := strings.Cut(entry, "="); keyed {
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "socks":
				candidate, socks = value, true
			case scheme:
				candidate = value
			default:
				continue
			}
		}
		p, err := normalizeProxyURL(candidate, socks)
		if err != nil {
			lastErr = err
			continue
		}
		if p != nil {
			return p, nil
		}
	}
	return nil, lastErr
}

// ParseProxyURL parses a proxy given by a user or by the operating system into
// a URL http.Transport accepts: "proxy.corp:3128" gets the http scheme it is
// implied to have, "socks" becomes Go's socks5, and anything without a host or
// with a scheme http.Transport cannot speak is an error. An empty string is a
// nil URL.
func ParseProxyURL(raw string) (*url.URL, error) {
	return normalizeProxyURL(raw, false)
}

// normalizeProxyURL turns a Windows proxy entry into a URL http.Transport
// accepts. Windows writes "host:port" without a scheme; the proxy is spoken
// to over HTTP (CONNECT for https targets) unless it is a SOCKS proxy.
func normalizeProxyURL(entry string, socks bool) (*url.URL, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil, nil
	}
	if !strings.Contains(entry, "://") {
		if socks {
			entry = "socks5://" + entry
		} else {
			entry = "http://" + entry
		}
	}
	u, err := url.Parse(entry)
	if err != nil {
		return nil, err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	case "socks":
		u.Scheme = "socks5"
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("proxy %q has no host", entry)
	}
	return u, nil
}

// bypassed reports whether u matches a Windows bypass list: hostname patterns
// with * and ? wildcards, IP addresses with the same wildcards ("10.*"),
// CIDR blocks, an optional scheme:// prefix and an optional :port, and the
// "<local>" token for hosts without a dot. A pattern without wildcards must
// match the whole host.
func bypassed(entries []string, u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	port := u.Port()
	if port == "" {
		port = defaultPort(u.Scheme)
	}
	ip := net.ParseIP(host)
	scheme := strings.ToLower(u.Scheme)

	for _, raw := range entries {
		e := strings.ToLower(strings.TrimSpace(raw))
		switch e {
		case "", tokenKeepLoopback:
			continue
		case tokenLocal:
			if ip == nil && !strings.Contains(host, ".") {
				return true
			}
			continue
		}
		if i := strings.Index(e, "://"); i >= 0 {
			if e[:i] != scheme {
				continue
			}
			e = e[i+3:]
		}
		if strings.Contains(e, "/") {
			if _, cidr, err := net.ParseCIDR(e); err == nil {
				if ip != nil && cidr.Contains(ip) {
					return true
				}
				continue
			}
			e = e[:strings.IndexByte(e, '/')]
		}
		pattern, patternPort := splitPattern(e)
		if pattern == "" || (patternPort != "" && patternPort != port) {
			continue
		}
		if strings.HasPrefix(pattern, ".") {
			pattern = "*" + pattern
		}
		if matchGlob(pattern, host) {
			return true
		}
	}
	return false
}

// splitPattern separates an optional :port from a bypass pattern. IPv6
// literals carry brackets when they have a port and several colons when
// they do not.
func splitPattern(e string) (host, port string) {
	if strings.HasPrefix(e, "[") {
		if h, p, err := net.SplitHostPort(e); err == nil {
			return h, p
		}
		return strings.Trim(e, "[]"), ""
	}
	if strings.Count(e, ":") == 1 {
		h, p, _ := strings.Cut(e, ":")
		return h, p
	}
	return e, ""
}

func defaultPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// matchGlob matches s against pattern, where * stands for any run of
// characters, including none, and ? for exactly one.
func matchGlob(pattern, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			mark++
			pi, si = star+1, mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func isLoopback(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func hasToken(entries []string, token string) bool {
	for _, e := range entries {
		if strings.EqualFold(strings.TrimSpace(e), token) {
			return true
		}
	}
	return false
}

// ToNoProxy converts Windows bypass entries into a NO_PROXY value with the
// same meaning where Go's syntax can express it. "*.example.com" is
// understood by Go as is, "10.*" style prefixes become CIDR blocks, and a
// scheme or path is dropped. "<local>" has no counterpart and is left out;
// loopback needs no entry because Go never proxies it.
func ToNoProxy(entries []string) string {
	var out []string
	seen := map[string]bool{}
	add := func(e string) {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	for _, raw := range entries {
		e := strings.ToLower(strings.TrimSpace(raw))
		if e == "" || e == tokenLocal || e == tokenKeepLoopback {
			continue
		}
		if i := strings.Index(e, "://"); i >= 0 {
			e = e[i+3:]
		}
		if _, _, err := net.ParseCIDR(e); err == nil {
			add(e)
			continue
		}
		if i := strings.IndexByte(e, '/'); i >= 0 {
			e = e[:i]
		}
		switch {
		case e == "":
			continue
		case e == "*":
			return "*"
		}
		if cidr, ok := ipv4WildcardToCIDR(e); ok {
			add(cidr)
			continue
		}
		if strings.HasPrefix(e, "*.") {
			add(e)
			continue
		}
		if strings.HasPrefix(e, "*") {
			// "*example.com" also matches "myexample.com" on Windows; the
			// closest Go can get is the domain and its subdomains.
			if rest := strings.TrimLeft(e, "*"); rest != "" && !strings.ContainsAny(rest, "*?") {
				add(rest)
			}
			continue
		}
		if strings.ContainsAny(e, "*?") {
			continue // no NO_PROXY equivalent
		}
		add(e)
	}
	return strings.Join(out, ",")
}

// ipv4WildcardToCIDR turns "10.*", "10.1.*" and "10.1.2.*" into CIDR blocks.
func ipv4WildcardToCIDR(e string) (string, bool) {
	if !strings.HasSuffix(e, ".*") {
		return "", false
	}
	octets := strings.Split(strings.TrimSuffix(e, ".*"), ".")
	if len(octets) == 0 || len(octets) > 3 {
		return "", false
	}
	for _, o := range octets {
		n, err := strconv.Atoi(o)
		if err != nil || n < 0 || n > 255 || strconv.Itoa(n) != o {
			return "", false
		}
	}
	bits := 8 * len(octets)
	for len(octets) < 4 {
		octets = append(octets, "0")
	}
	return strings.Join(octets, ".") + "/" + strconv.Itoa(bits), true
}

// Flags in the DefaultConnectionSettings registry blob, which is where
// Windows keeps the "automatically detect settings" switch. Only the bit this
// package reads is named.
const connectionSettingsAutoDetect = 0x08

// connectionSettingsFlags extracts the flags word out of a
// DefaultConnectionSettings blob: a version DWORD, a change counter DWORD,
// then the flags. Anything shorter is not a settings blob.
func connectionSettingsFlags(blob []byte) (uint32, bool) {
	if len(blob) < 12 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(blob[8:12]), true
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package sysproxy

import (
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Everything here goes through winhttp.dll rather than the registry because
// WinHTTP is what resolves the effective settings: it reads the per-user
// Internet Settings the way Windows itself does, it knows the machine-wide
// default that netsh writes, and it is the only supported way to run a setup
// script or WPAD discovery without a browser engine. The calls go through the
// lazy DLL loader, so the binary stays free of cgo, as the release build
// requires (CGO_ENABLED=0).

var (
	modwinhttp  = windows.NewLazySystemDLL("winhttp.dll")
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procWinHttpOpen                           = modwinhttp.NewProc("WinHttpOpen")
	procWinHttpSetTimeouts                    = modwinhttp.NewProc("WinHttpSetTimeouts")
	procWinHttpGetIEProxyConfigForCurrentUser = modwinhttp.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	procWinHttpGetDefaultProxyConfiguration   = modwinhttp.NewProc("WinHttpGetDefaultProxyConfiguration")
	procWinHttpGetProxyForUrl                 = modwinhttp.NewProc("WinHttpGetProxyForUrl")
	procGlobalFree                            = modkernel32.NewProc("GlobalFree")
)

// Constants from winhttp.h.
const (
	winhttpAccessTypeNoProxy    = 1
	winhttpAccessTypeNamedProxy = 3

	winhttpAutoproxyAutoDetect = 0x00000001
	winhttpAutoproxyConfigURL  = 0x00000002
	winhttpAutoDetectTypeDHCP  = 0x00000001
	winhttpAutoDetectTypeDNSA  = 0x00000002

	// errorWinhttpAutodetectionFailed is what WPAD reports on a network that
	// has no WPAD, which is most networks.
	errorWinhttpAutodetectionFailed syscall.Errno = 12180
)

// winhttpProxyInfo is WINHTTP_PROXY_INFO.
type winhttpProxyInfo struct {
	accessType  uint32
	proxy       *uint16
	proxyBypass *uint16
}

// winhttpCurrentUserIEProxyConfig is WINHTTP_CURRENT_USER_IE_PROXY_CONFIG.
type winhttpCurrentUserIEProxyConfig struct {
	autoDetect    int32
	autoConfigURL *uint16
	proxy         *uint16
	proxyBypass   *uint16
}

// winhttpAutoproxyOptions is WINHTTP_AUTOPROXY_OPTIONS.
type winhttpAutoproxyOptions struct {
	flags                 uint32
	autoDetectFlags       uint32
	autoConfigURL         *uint16
	reserved              uintptr
	reservedFlags         uint32
	autoLogonIfChallenged int32
}

// takeString copies a WinHTTP-allocated string and frees it. WinHTTP hands
// out these strings from the global heap and documents GlobalFree for them.
func takeString(p *uint16) string {
	if p == nil {
		return ""
	}
	s := windows.UTF16PtrToString(p)
	_, _, _ = procGlobalFree.Call(uintptr(unsafe.Pointer(p)))
	return s
}

// detect reads the per-user Internet Settings, the per-machine Internet
// Settings when group policy makes them per machine, and the WinHTTP default.
func detect() (*Settings, error) {
	s := &Settings{}

	var ie winhttpCurrentUserIEProxyConfig
	if r, _, err := procWinHttpGetIEProxyConfigForCurrentUser.Call(uintptr(unsafe.Pointer(&ie))); r != 0 {
		s.AutoDetect = ie.autoDetect != 0
		s.AutoConfigURL = takeString(ie.autoConfigURL)
		s.Proxy = takeString(ie.proxy)
		s.Bypass = SplitList(takeString(ie.proxyBypass))
	} else {
		// No profile to read from, which is what a service account looks like.
		log.Debug().Err(err).Msg("no per-user proxy settings to read")
	}

	// Group policy can keep the Internet Settings per machine
	// (ProxySettingsPerUser = 0) under HKLM, where WinHTTP does not look.
	if s.Proxy == "" && s.AutoConfigURL == "" {
		if m := readMachineInternetSettings(); m != nil {
			s.AutoDetect = s.AutoDetect || m.AutoDetect
			s.AutoConfigURL = m.AutoConfigURL
			s.Proxy = m.Proxy
			s.Bypass = m.Bypass
		}
	}

	var pi winhttpProxyInfo
	if r, _, err := procWinHttpGetDefaultProxyConfiguration.Call(uintptr(unsafe.Pointer(&pi))); r != 0 {
		proxy, bypass := takeString(pi.proxy), takeString(pi.proxyBypass)
		if pi.accessType == winhttpAccessTypeNamedProxy {
			s.MachineProxy = proxy
			s.MachineBypass = SplitList(bypass)
		}
	} else {
		log.Debug().Err(err).Msg("could not read the WinHTTP default proxy")
	}

	if s.IsZero() {
		return nil, nil
	}
	return s, nil
}

const (
	regInternetSettings       = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	regInternetSettingsPolicy = `Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings`
)

// readMachineInternetSettings returns the HKLM Internet Settings when group
// policy makes proxy settings per machine, nil otherwise. The value names are
// the same ones the per-user hive uses.
func readMachineInternetSettings() *Settings {
	policy, err := registry.OpenKey(registry.LOCAL_MACHINE, regInternetSettingsPolicy, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	perUser, _, err := policy.GetIntegerValue("ProxySettingsPerUser")
	policy.Close()
	if err != nil || perUser != 0 {
		return nil
	}

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regInternetSettings, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()

	s := &Settings{}
	if enable, _, err := k.GetIntegerValue("ProxyEnable"); err == nil && enable != 0 {
		s.Proxy, _, _ = k.GetStringValue("ProxyServer")
		bypass, _, _ := k.GetStringValue("ProxyOverride")
		s.Bypass = SplitList(bypass)
	}
	s.AutoConfigURL, _, _ = k.GetStringValue("AutoConfigURL")
	if c, err := registry.OpenKey(k, "Connections", registry.QUERY_VALUE); err == nil {
		blob, _, err := c.GetBinaryValue("DefaultConnectionSettings")
		c.Close()
		if err == nil {
			if flags, ok := connectionSettingsFlags(blob); ok {
				s.AutoDetect = flags&connectionSettingsAutoDetect != 0
			}
		}
	}
	if s.IsZero() {
		return nil
	}
	return s
}

// scriptTimeout bounds one script evaluation as seen by the request waiting
// on it. WPAD discovery on a network without WPAD takes a few seconds (a DHCP
// probe and DNS lookups), and a setup script on a dead host must not hang the
// request behind it. Results are cached, so this is paid once per host.
const scriptTimeout = 15 * time.Second

// scriptTTL keeps script results long enough to make a scan cheap and short
// enough for a long-running service to follow a changed script.
const scriptTTL = 5 * time.Minute

type scriptCacheEntry struct {
	done chan struct{}
	res  scriptResult
	// expires is zero while the evaluation is still running.
	expires time.Time
}

// winhttpScript evaluates setup scripts through WinHttpGetProxyForUrl, which
// downloads and runs the script (and performs WPAD discovery) inside the
// WinHTTP Web Proxy Auto-Discovery Service, so repeated calls are served from
// that service's cache.
type winhttpScript struct {
	mu      sync.Mutex
	opened  bool
	session uintptr
	sessErr error
	cache   map[string]*scriptCacheEntry
	// autoDetectFailedUntil skips WPAD after a failed discovery, the way .NET
	// does, so a machine that merely left "automatically detect settings" on
	// (the Windows default) pays for the failed probe once, not once per host.
	autoDetectFailedUntil time.Time
}

var script = &winhttpScript{cache: map[string]*scriptCacheEntry{}}

func evaluateScript(s *Settings, u *url.URL) scriptResult {
	return script.evaluate(s, u)
}

// evaluate returns the cached answer for u's origin or starts one evaluation
// per origin and waits for it up to scriptTimeout. A request that gives up
// waiting leaves the evaluation running so its answer is there for the next
// one.
func (w *winhttpScript) evaluate(s *Settings, u *url.URL) scriptResult {
	// The script sees the origin only. Paths carry nothing a script routes on
	// in practice, and keeping them out of the cache key and the logs keeps
	// query strings out of both.
	target := u.Scheme + "://" + u.Host + "/"

	w.mu.Lock()
	now := time.Now()
	if e, ok := w.cache[target]; ok && (e.expires.IsZero() || now.Before(e.expires)) {
		w.mu.Unlock()
		return w.wait(e)
	}
	w.sweep(now)
	e := &scriptCacheEntry{done: make(chan struct{})}
	w.cache[target] = e
	skipAutoDetect := now.Before(w.autoDetectFailedUntil)
	w.mu.Unlock()

	go func() {
		res, autoDetectFailed := w.call(s, target, skipAutoDetect)
		w.mu.Lock()
		e.res = res
		e.expires = time.Now().Add(scriptTTL)
		if autoDetectFailed {
			w.autoDetectFailedUntil = time.Now().Add(scriptTTL)
		}
		w.mu.Unlock()
		close(e.done)
	}()
	return w.wait(e)
}

func (w *winhttpScript) wait(e *scriptCacheEntry) scriptResult {
	select {
	case <-e.done:
		return e.res
	case <-time.After(scriptTimeout):
		return scriptResult{err: errors.New("proxy script evaluation timed out")}
	}
}

// sweep drops expired entries once the cache has grown past a handful of
// origins. Called with mu held.
func (w *winhttpScript) sweep(now time.Time) {
	if len(w.cache) < 256 {
		return
	}
	for k, e := range w.cache {
		if !e.expires.IsZero() && now.After(e.expires) {
			delete(w.cache, k)
		}
	}
}

// openSession creates the WinHTTP session the script runs under, once. It
// uses no proxy of its own: setup scripts live on the intranet and are
// fetched directly, which is also what browsers do.
func (w *winhttpScript) openSession() (uintptr, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.opened {
		return w.session, w.sessErr
	}
	w.opened = true
	h, _, err := procWinHttpOpen.Call(0, winhttpAccessTypeNoProxy, 0, 0, 0)
	if h == 0 {
		w.sessErr = fmt.Errorf("WinHttpOpen: %w", err)
		return 0, w.sessErr
	}
	// Resolve, connect, send and receive timeouts for the script download,
	// in milliseconds. WinHTTP's own defaults run to a minute per stage.
	_, _, _ = procWinHttpSetTimeouts.Call(h, 5000, 5000, 5000, 10000)
	w.session = h
	return h, nil
}

// call runs WinHttpGetProxyForUrl for target. It reports whether WPAD
// discovery failed so the caller can stop asking for it for a while.
func (w *winhttpScript) call(s *Settings, target string, skipAutoDetect bool) (res scriptResult, autoDetectFailed bool) {
	session, err := w.openSession()
	if err != nil {
		return scriptResult{err: err}, false
	}

	opts := winhttpAutoproxyOptions{autoLogonIfChallenged: 1}
	if s.AutoDetect && !skipAutoDetect {
		opts.flags |= winhttpAutoproxyAutoDetect
		opts.autoDetectFlags = winhttpAutoDetectTypeDHCP | winhttpAutoDetectTypeDNSA
	}
	var pac *uint16
	if s.AutoConfigURL != "" {
		pac, err = windows.UTF16PtrFromString(s.AutoConfigURL)
		if err != nil {
			return scriptResult{err: err}, false
		}
		opts.flags |= winhttpAutoproxyConfigURL
		opts.autoConfigURL = pac
	}
	if opts.flags == 0 {
		return scriptResult{err: errors.New("auto-detection failed recently and no setup script is configured")}, false
	}

	u16, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return scriptResult{err: err}, false
	}

	var info winhttpProxyInfo
	r, _, callErr := procWinHttpGetProxyForUrl.Call(session, uintptr(unsafe.Pointer(u16)), uintptr(unsafe.Pointer(&opts)), uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == errorWinhttpAutodetectionFailed {
			autoDetectFailed = true
			if pac != nil {
				// Discovery failed but a script is configured: ask for the
				// script alone.
				opts.flags = winhttpAutoproxyConfigURL
				opts.autoDetectFlags = 0
				r, _, callErr = procWinHttpGetProxyForUrl.Call(session, uintptr(unsafe.Pointer(u16)), uintptr(unsafe.Pointer(&opts)), uintptr(unsafe.Pointer(&info)))
			}
		}
		if r == 0 {
			runtime.KeepAlive(pac)
			return scriptResult{err: fmt.Errorf("WinHttpGetProxyForUrl: %w", callErr)}, autoDetectFailed
		}
	}
	runtime.KeepAlive(pac)

	proxies := takeString(info.proxy)
	_ = takeString(info.proxyBypass) // a script has no bypass list; free it regardless
	if info.accessType != winhttpAccessTypeNamedProxy {
		return scriptResult{}, autoDetectFailed // DIRECT
	}
	return scriptResult{proxies: proxies}, autoDetectFailed
}

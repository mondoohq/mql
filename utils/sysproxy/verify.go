// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sysproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// A proxy that the operating system names is used only after a probe has
// shown that it carries our traffic to the destination. Before system proxy
// support every client connected directly; a machine whose Windows settings
// name a proxy that requires NTLM, allows only browser destinations, or is
// simply stale would otherwise switch from a working direct connection to a
// failing proxied one on upgrade. When the probe fails, the connection is made
// directly, as before, and the reason is logged and shown by the status
// command. Explicit configuration (api_proxy, HTTPS_PROXY) is never probed:
// it is deliberate and stays authoritative.

const (
	// probeTimeout bounds one probe: connecting, the CONNECT exchange and the
	// TLS handshake together.
	probeTimeout = 10 * time.Second
	// probeDialTimeout bounds the connection to the proxy alone. A proxy that
	// drops packets costs this much once per process per probeTTL, since an
	// unreachable proxy is remembered for every destination; proxies answer
	// in milliseconds, so this is generous.
	probeDialTimeout = 5 * time.Second
	// probeTTL is how long a verdict is trusted, for both outcomes.
	probeTTL = 5 * time.Minute
)

// probeFunc runs the network probe for one proxy and destination.
type probeFunc func(ctx context.Context, proxy, target *url.URL) error

// unreachableError marks a probe that never got to talk to the proxy. Such a
// verdict holds for every destination, not just the one probed.
type unreachableError struct{ err error }

func (e *unreachableError) Error() string { return "connect to proxy: " + e.err.Error() }
func (e *unreachableError) Unwrap() error { return e.err }

// verifier caches probe verdicts per proxy and destination, running one probe
// per key at a time. A proxy that could not be reached at all is remembered
// per proxy, so a proxy that drops packets costs one dial timeout, not one
// per destination.
type verifier struct {
	mu    sync.Mutex
	cache map[string]*probeEntry
	// unreachable holds, per proxy URL, the entry of the probe that failed to
	// connect to it, until that entry expires.
	unreachable map[string]*probeEntry
	// probe replaces the network probe in tests.
	probe probeFunc
	// tlsConfig is cloned for the handshake with the destination; nil means
	// the system trust store, the one the real connection uses.
	tlsConfig *tls.Config
	// timeout and ttl default to probeTimeout and probeTTL.
	timeout time.Duration
	ttl     time.Duration
}

type probeEntry struct {
	done chan struct{}
	// err is nil when the proxy carried the probe. Read only after done.
	err error
	// expires is zero while the probe is running.
	expires time.Time
	// proxy is the redacted proxy, for diagnostics.
	proxy string
}

var defaultVerifier = &verifier{cache: map[string]*probeEntry{}}

// FallbackReason explains why the operating system's proxy is not used for
// u: the current failed verdict for that destination, worded for people, or
// "" when the proxy is in use or none was ever selected.
func FallbackReason(u *url.URL) string {
	return defaultVerifier.fallbackReason(u)
}

func probeKey(proxy, target *url.URL) string {
	return proxy.String() + " " + target.Scheme + "://" + target.Host
}

func (v *verifier) budget() (time.Duration, time.Duration) {
	timeout, ttl := v.timeout, v.ttl
	if timeout == 0 {
		timeout = probeTimeout
	}
	if ttl == 0 {
		ttl = probeTTL
	}
	return timeout, ttl
}

// usable reports whether proxy carries traffic to target, probing once per
// proxy and destination per ttl. Callers arriving while a probe runs wait for
// its verdict.
func (v *verifier) usable(proxy, target *url.URL) error {
	timeout, ttl := v.budget()
	key := probeKey(proxy, target)

	v.mu.Lock()
	now := time.Now()
	if e, ok := v.cache[key]; ok && (e.expires.IsZero() || now.Before(e.expires)) {
		v.mu.Unlock()
		return e.wait(timeout)
	}
	if u, ok := v.unreachable[proxy.String()]; ok && now.Before(u.expires) {
		// The proxy itself was unreachable moments ago; that holds for this
		// destination too. Record it there so diagnostics find it.
		v.cache[key] = u
		v.mu.Unlock()
		return u.err
	}
	v.sweep(now)
	e := &probeEntry{done: make(chan struct{}), proxy: proxy.Redacted()}
	v.cache[key] = e
	v.mu.Unlock()

	// The goroutine outlives this call when the caller gives up waiting, so
	// it works on its own copies of the URLs rather than the caller's.
	proxyCopy, targetCopy := *proxy, *target
	destination := target.Host
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		probe := v.probe
		if probe == nil {
			probe = v.networkProbe
		}
		err := probe(ctx, &proxyCopy, &targetCopy)

		v.mu.Lock()
		e.err = err
		e.expires = time.Now().Add(ttl)
		var unreachable *unreachableError
		if errors.As(err, &unreachable) {
			if v.unreachable == nil {
				v.unreachable = map[string]*probeEntry{}
			}
			v.unreachable[proxyCopy.String()] = e
		}
		v.mu.Unlock()
		close(e.done)

		if err != nil {
			log.Warn().Str("proxy", e.proxy).Str("destination", destination).Err(err).
				Msg("the operating system's proxy cannot carry this connection, connecting directly instead")
		} else {
			log.Debug().Str("proxy", e.proxy).Str("destination", destination).
				Msg("the operating system's proxy verified for this destination")
		}
	}()
	return e.wait(timeout)
}

func (e *probeEntry) wait(timeout time.Duration) error {
	select {
	case <-e.done:
		return e.err
	case <-time.After(timeout + time.Second):
		return errors.New("proxy verification timed out")
	}
}

// sweep drops expired verdicts once the cache has grown. Called with mu held.
func (v *verifier) sweep(now time.Time) {
	if len(v.cache) < 256 {
		return
	}
	for k, e := range v.cache {
		if !e.expires.IsZero() && now.After(e.expires) {
			delete(v.cache, k)
		}
	}
	for k, e := range v.unreachable {
		if now.After(e.expires) {
			delete(v.unreachable, k)
		}
	}
}

func (v *verifier) fallbackReason(u *url.URL) string {
	if u == nil {
		return ""
	}
	suffix := " " + u.Scheme + "://" + u.Host
	v.mu.Lock()
	defer v.mu.Unlock()
	now := time.Now()
	for key, e := range v.cache {
		if strings.HasSuffix(key, suffix) && !e.expires.IsZero() && now.Before(e.expires) && e.err != nil {
			return fmt.Sprintf("system proxy %s not usable: %v", e.proxy, e.err)
		}
	}
	return ""
}

// networkProbe connects to the proxy, asks it to tunnel to the destination,
// and completes a TLS handshake with the destination through that tunnel, so
// an unreachable proxy, a 407, a destination the proxy refuses, and an
// intercepting proxy whose certificate the machine does not trust all fail
// here rather than on the real request. A SOCKS proxy or a plain http
// destination is only checked for reachability.
func (v *verifier) networkProbe(ctx context.Context, proxy, target *url.URL) error {
	dialer := net.Dialer{Timeout: probeDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", hostPort(proxy))
	if err != nil {
		return &unreachableError{err: err}
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	switch proxy.Scheme {
	case "socks5", "socks5h":
		return nil
	case "https":
		tc := tls.Client(conn, v.tlsClientConfig(proxy.Hostname()))
		if err := tc.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("TLS handshake with the proxy: %w", err)
		}
		conn = tc
	}
	if target.Scheme != "https" {
		return nil
	}

	targetAddr := hostPort(target)
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetAddr},
		Host:   targetAddr,
		Header: http.Header{"User-Agent": {"mondoo-proxy-check"}},
	}
	if user := proxy.User; user != nil {
		password, _ := user.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user.Username()+":"+password)))
	}
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("send CONNECT to proxy: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return fmt.Errorf("read CONNECT response from proxy: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		// The body is the proxy's error page; drain and close it before the
		// connection goes.
		_ = resp.Body.Close()
		return fmt.Errorf("proxy answered CONNECT %s with %s", targetAddr, resp.Status)
	}
	// On a 2xx the "body" is the tunnel itself, which the TLS handshake below
	// uses through conn; it is deliberately not read or closed here, as in
	// net/http's own CONNECT handling.
	if br.Buffered() > 0 {
		return errors.New("proxy sent data before the tunnel was used")
	}

	tc := tls.Client(conn, v.tlsClientConfig(target.Hostname()))
	if err := tc.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake with %s through the proxy: %w", target.Hostname(), err)
	}
	return nil
}

func (v *verifier) tlsClientConfig(serverName string) *tls.Config {
	cfg := &tls.Config{}
	if v.tlsConfig != nil {
		cfg = v.tlsConfig.Clone()
	}
	cfg.ServerName = serverName
	return cfg
}

// hostPort returns u's host with an explicit port, filling in the scheme's
// default when the URL has none.
func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	port := defaultPort(u.Scheme)
	if port == "" {
		switch u.Scheme {
		case "socks5", "socks5h":
			port = "1080"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

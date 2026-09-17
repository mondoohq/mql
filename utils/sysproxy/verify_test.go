// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sysproxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCert is a self-signed certificate for host and a pool that trusts it.
func testCert(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// fakeProxy answers every CONNECT with status and, on a 2xx, speaks TLS as
// the destination would, which is exactly what the probe needs to see.
type fakeProxy struct {
	ln       net.Listener
	status   string
	cert     tls.Certificate
	connects atomic.Int32
	mu       sync.Mutex
	lastAuth string
	lastHost string
}

func startFakeProxy(t *testing.T, status string, cert tls.Certificate) *fakeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	fp := &fakeProxy{ln: ln, status: status, cert: cert}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go fp.handle(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return fp
}

func (fp *fakeProxy) handle(c net.Conn) {
	defer c.Close()
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil {
		return
	}
	fp.connects.Add(1)
	fp.mu.Lock()
	fp.lastAuth = req.Header.Get("Proxy-Authorization")
	fp.lastHost = req.Host
	fp.mu.Unlock()
	if !strings.HasPrefix(fp.status, "200") {
		fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Length: 0\r\n\r\n", fp.status)
		return
	}
	fmt.Fprintf(c, "HTTP/1.1 %s\r\n\r\n", fp.status)
	_ = tls.Server(c, &tls.Config{Certificates: []tls.Certificate{fp.cert}}).Handshake()
}

func (fp *fakeProxy) url(userinfo string) *url.URL {
	u := &url.URL{Scheme: "http", Host: fp.ln.Addr().String()}
	if userinfo != "" {
		u.User = url.UserPassword(strings.Split(userinfo, ":")[0], strings.Split(userinfo, ":")[1])
	}
	return u
}

func TestNetworkProbe(t *testing.T) {
	cert, pool := testCert(t, "api.example.test")
	target := mustURL(t, "https://api.example.test/ping")
	trusting := &verifier{cache: map[string]*probeEntry{}, tlsConfig: &tls.Config{RootCAs: pool}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("unreachable proxy", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		closed := ln.Addr().String()
		ln.Close()
		err = trusting.networkProbe(ctx, &url.URL{Scheme: "http", Host: closed}, target)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "connect to proxy")
	})

	t.Run("proxy that wants authentication", func(t *testing.T) {
		fp := startFakeProxy(t, "407 Proxy Authentication Required", cert)
		err := trusting.networkProbe(ctx, fp.url(""), target)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "407 Proxy Authentication Required")
		assert.Contains(t, err.Error(), "api.example.test:443", "the destination the proxy refused is named")
	})

	t.Run("proxy that refuses the destination", func(t *testing.T) {
		fp := startFakeProxy(t, "403 Forbidden", cert)
		err := trusting.networkProbe(ctx, fp.url(""), target)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "403 Forbidden")
	})

	t.Run("tunnel to a destination the machine trusts", func(t *testing.T) {
		fp := startFakeProxy(t, "200 Connection Established", cert)
		require.NoError(t, trusting.networkProbe(ctx, fp.url(""), target))
		fp.mu.Lock()
		defer fp.mu.Unlock()
		assert.Equal(t, "api.example.test:443", fp.lastHost)
		assert.Empty(t, fp.lastAuth)
	})

	t.Run("credentials in the proxy URL are presented", func(t *testing.T) {
		fp := startFakeProxy(t, "200 Connection Established", cert)
		require.NoError(t, trusting.networkProbe(ctx, fp.url("alice:s3cret"), target))
		fp.mu.Lock()
		defer fp.mu.Unlock()
		assert.Equal(t, "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:s3cret")), fp.lastAuth)
	})

	t.Run("intercepting proxy with an untrusted certificate", func(t *testing.T) {
		fp := startFakeProxy(t, "200 Connection Established", cert)
		distrusting := &verifier{cache: map[string]*probeEntry{}, tlsConfig: &tls.Config{RootCAs: x509.NewCertPool()}}
		err := distrusting.networkProbe(ctx, fp.url(""), target)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TLS handshake with api.example.test")
	})

	t.Run("plain http destination is only checked for reachability", func(t *testing.T) {
		fp := startFakeProxy(t, "407 Proxy Authentication Required", cert)
		require.NoError(t, trusting.networkProbe(ctx, fp.url(""), mustURL(t, "http://api.example.test/")))
		assert.Zero(t, fp.connects.Load(), "no CONNECT is sent for an http destination")
	})

	t.Run("socks proxy is only checked for reachability", func(t *testing.T) {
		fp := startFakeProxy(t, "407 Proxy Authentication Required", cert)
		socks := fp.url("")
		socks.Scheme = "socks5"
		require.NoError(t, trusting.networkProbe(ctx, socks, target))
		assert.Zero(t, fp.connects.Load())
	})
}

func TestVerifierCachesVerdicts(t *testing.T) {
	var calls atomic.Int32
	v := &verifier{
		cache:   map[string]*probeEntry{},
		timeout: time.Second,
		ttl:     time.Minute,
		probe: func(_ context.Context, proxy, target *url.URL) error {
			calls.Add(1)
			if target.Host == "good.example" {
				return nil
			}
			return errors.New("407 Proxy Authentication Required")
		},
	}
	proxy := mustURL(t, "http://alice:secret@proxy.corp:3128")
	bad := mustURL(t, "https://bad.example/a")
	good := mustURL(t, "https://good.example/b")

	require.Error(t, v.usable(proxy, bad))
	require.Error(t, v.usable(proxy, mustURL(t, "https://bad.example/other-path")))
	assert.Equal(t, int32(1), calls.Load(), "one probe per proxy and destination, paths do not matter")

	require.NoError(t, v.usable(proxy, good))
	assert.Equal(t, int32(2), calls.Load())

	assert.Equal(t, "system proxy http://alice:xxxxx@proxy.corp:3128 not usable: 407 Proxy Authentication Required", v.fallbackReason(bad),
		"the reason names the redacted proxy and the verdict")
	assert.Empty(t, v.fallbackReason(good))
	assert.Empty(t, v.fallbackReason(mustURL(t, "https://never.example/")))
	assert.Empty(t, v.fallbackReason(nil))

	// a different port is a different destination
	require.Error(t, v.usable(proxy, mustURL(t, "https://bad.example:8443/")))
	assert.Equal(t, int32(3), calls.Load())
}

func TestVerifierUnreachableProxyIsRememberedForEveryDestination(t *testing.T) {
	var calls atomic.Int32
	v := &verifier{
		cache:   map[string]*probeEntry{},
		timeout: time.Second,
		ttl:     time.Minute,
		probe: func(_ context.Context, proxy, _ *url.URL) error {
			calls.Add(1)
			if proxy.Host == "dead:3128" {
				return &unreachableError{err: errors.New("dial tcp: i/o timeout")}
			}
			return errors.New("403 Forbidden")
		},
	}
	dead, refusing := mustURL(t, "http://dead:3128"), mustURL(t, "http://refusing:3128")
	api, releases := mustURL(t, "https://api.example/"), mustURL(t, "https://releases.example/")

	err := v.usable(dead, api)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connect to proxy: dial tcp: i/o timeout")
	require.Error(t, v.usable(dead, releases))
	assert.Equal(t, int32(1), calls.Load(), "a proxy that cannot be reached is not probed again per destination")
	assert.Contains(t, v.fallbackReason(releases), "connect to proxy", "the shared verdict is on record for the second destination too")

	// A proxy that answers, even with a refusal, is judged per destination.
	require.Error(t, v.usable(refusing, api))
	require.Error(t, v.usable(refusing, releases))
	assert.Equal(t, int32(3), calls.Load())
}

func TestVerifierConcurrentCallersShareOneProbe(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	v := &verifier{
		cache:   map[string]*probeEntry{},
		timeout: 2 * time.Second,
		probe: func(ctx context.Context, _, _ *url.URL) error {
			calls.Add(1)
			<-release
			return nil
		},
	}
	proxy, target := mustURL(t, "http://p:1"), mustURL(t, "https://a.example/")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, v.usable(proxy, target))
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	assert.Equal(t, int32(1), calls.Load())
}

func TestVerifierProbeTimeout(t *testing.T) {
	v := &verifier{
		cache:   map[string]*probeEntry{},
		timeout: 30 * time.Millisecond,
		probe: func(ctx context.Context, _, _ *url.URL) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	start := time.Now()
	err := v.usable(mustURL(t, "http://p:1"), mustURL(t, "https://a.example/"))
	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second)
}

func TestHostPort(t *testing.T) {
	for in, want := range map[string]string{
		"http://p":           "p:80",
		"https://p":          "p:443",
		"socks5://p":         "p:1080",
		"http://p:3128":      "p:3128",
		"http://[::1]:8080":  "[::1]:8080",
		"http://[::1]":       "[::1]:80",
		"https://api.x/path": "api.x:443",
	} {
		assert.Equal(t, want, hostPort(mustURL(t, in)), in)
	}
}

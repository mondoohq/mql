// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tlsshake

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeHelloServer is a minimal TLS/SSL endpoint that reads one ClientHello per
// connection and answers it with a ServerHello carrying whatever cipher suite
// choose returns, or a handshake_failure alert when choose returns "".
// It stops accepting after maxConns connections, so a scanner stuck in a
// retry loop fails the test with a dial error instead of running forever.
type fakeHelloServer struct {
	ln      net.Listener
	version []byte
	choose  func(offered []string) string
	conns   atomic.Int64
}

const fakeServerMaxConns = 500

func newFakeHelloServer(t *testing.T, version string, choose func(offered []string) string) *fakeHelloServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s := &fakeHelloServer{ln: ln, version: []byte(VERSIONS[version]), choose: choose}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s
}

func (s *fakeHelloServer) port() int {
	return s.ln.Addr().(*net.TCPAddr).Port
}

func (s *fakeHelloServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		if s.conns.Add(1) > fakeServerMaxConns {
			_ = conn.Close()
			_ = s.ln.Close()
			return
		}
		go s.handle(conn)
	}
}

// handle answers one ClientHello. The connection made by Test's reachability
// check sends nothing, so a read error just closes it.
func (s *fakeHelloServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	body := make([]byte, bytes2int(header[3:5]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return
	}
	offered := offeredCipherIDs(body)

	chosen := s.choose(offered)
	if chosen == "" {
		// Alert record: level fatal (2), description handshake_failure (40)
		_, _ = conn.Write(constructTLSMsg(CONTENT_TYPE_Alert, []byte{0x02, 0x28}, s.version))
		return
	}

	var hello bytes.Buffer
	hello.Write(s.version)
	hello.Write(make([]byte, 32)) // random
	hello.WriteByte(0)            // session ID length
	hello.WriteString(chosen)     // cipher suite
	hello.WriteByte(0)            // compression method

	var handshakes bytes.Buffer
	handshakes.WriteByte(HANDSHAKE_TYPE_ServerHello)
	handshakes.Write(int3bytes(hello.Len()))
	handshakes.Write(hello.Bytes())
	handshakes.Write([]byte{HANDSHAKE_TYPE_ServerHelloDone, 0, 0, 0})

	_, _ = conn.Write(constructTLSMsg(CONTENT_TYPE_Handshake, handshakes.Bytes(), s.version))
}

// offeredCipherIDs extracts the 2-byte cipher suite IDs from a ClientHello
// handshake body as produced by constructTLSHello.
func offeredCipherIDs(handshake []byte) []string {
	// type(1) + length(3) + version(2) + random(32)
	idx := 4 + 2 + 32
	idx += 1 + int(handshake[idx]) // session ID
	n := bytes2int(handshake[idx : idx+2])
	idx += 2
	var res []string
	for i := idx; i+2 <= idx+n; i += 2 {
		res = append(res, string(handshake[i:i+2]))
	}
	return res
}

// runScan runs Test against the fake server and fails the test if the scan
// has not returned within the deadline (the pre-fix behaviour was to never
// return).
func runScan(t *testing.T, srv *fakeHelloServer, versions []string) *Tester {
	t.Helper()
	tester := New("tcp", "", "127.0.0.1", srv.port())
	done := make(chan error, 1)
	go func() {
		done <- tester.Test(ScanConfig{Versions: versions, ConnectTimeout: time.Second})
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(20 * time.Second):
		t.Fatalf("scan did not finish; the fake server saw %d connections", srv.conns.Load())
	}
	return tester
}

// An SSLv3 server picks suites like 0x000a, which ALL_CIPHERS names
// TLS_RSA_WITH_3DES_EDE_CBC_SHA while the SSLv3 offer is built from
// SSL3_CIPHERS (SSL_RSA_WITH_3DES_EDE_CBC_SHA). Recording the negotiated suite
// under the TLS name left the SSL name in every following offer, so the probe
// loop re-sent the same offer forever. This is what an OpenSSL 1.0.2 server
// with SSLv3 enabled (RHEL 7's openssl s_server) does to the scanner.
func TestProbeLoop_SSL3NegotiatedCipherLeavesTheOffer(t *testing.T) {
	supported := []string{"\x00\x0a", "\x00\x05", "\x00\x04"}
	srv := newFakeHelloServer(t, "ssl3", func(offered []string) string {
		for _, o := range offered {
			for _, s := range supported {
				if o == s {
					return s
				}
			}
		}
		return ""
	})

	tester := runScan(t, srv, []string{"ssl3"})

	assert.Equal(t, map[string]bool{"ssl3": true}, tester.Findings.Versions)
	for _, name := range []string{
		"SSL_RSA_WITH_3DES_EDE_CBC_SHA",
		"SSL_RSA_WITH_RC4_128_SHA",
		"SSL_RSA_WITH_RC4_128_MD5",
	} {
		assert.True(t, tester.Findings.Ciphers[name], name)
	}
	assert.False(t, tester.Findings.Ciphers["SSL_RSA_WITH_DES_CBC_SHA"])
	assert.NotContains(t, tester.Findings.Ciphers, "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"an SSLv3 suite is reported under its SSLv3 name")

	// 1 reachability check + 3 accepted suites + 1 final handshake failure
	assert.Equal(t, int64(5), srv.conns.Load())
}

// A server that answers with a suite it was never offered (a protocol
// violation, recorded as "unknown") does not shrink the next offer at all.
// The probe must stop instead of reconnecting forever.
func TestProbeLoop_StopsWhenOfferDoesNotShrink(t *testing.T) {
	srv := newFakeHelloServer(t, "tls1.2", func(offered []string) string {
		return "\xfe\xfd" // in no cipher table, never offered
	})

	tester := runScan(t, srv, []string{"tls1.2"})

	assert.True(t, tester.Findings.Versions["tls1.2"])
	assert.True(t, tester.Findings.Ciphers["unknown"])
	// 1 reachability check, the first probe, and the probe that showed no
	// progress, then the SNI and fake-SNI follow-up probes for tls1.2
	assert.LessOrEqual(t, srv.conns.Load(), int64(5))
	assert.Contains(t, tester.Findings.Errors,
		"stopped probing tls1.2 ciphers: the server negotiated a cipher suite that was not offered")
}

// The suite a server picked leaves the next offer by its 2-byte ID, even when
// the name filter would keep it (here a filter that keeps every name).
// Without the ID exclusion the second offer equals the first and the probe
// stops after a single suite.
func TestProbeLoop_ExcludesNegotiatedSuiteByID(t *testing.T) {
	supported := []string{"\x00\x2f", "\x00\x35", "\x00\x0a"}
	srv := newFakeHelloServer(t, "tls1.2", func(offered []string) string {
		for _, o := range offered {
			for _, s := range supported {
				if o == s {
					return s
				}
			}
		}
		return ""
	})

	tester := New("tcp", "", "127.0.0.1", srv.port())
	conf := &ScanConfig{
		version:       "tls1.2",
		ciphersFilter: func(string) bool { return true },
	}
	require.NoError(t, tester.probeCiphers(conf))

	for _, name := range []string{
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	} {
		assert.True(t, tester.Findings.Ciphers[name], name)
	}
	assert.Empty(t, tester.Findings.Errors)
	// 3 accepted suites + 1 final handshake failure
	assert.Equal(t, int64(4), srv.conns.Load())
}

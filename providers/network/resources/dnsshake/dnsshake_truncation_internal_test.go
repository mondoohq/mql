// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dnsshake

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testResolver serves one TXT set two ways: over UDP it answers the way a
// resolver signals a response that did not fit, with the truncation bit set and
// nothing in the answer section, and over TCP it answers in full.
//
// truncateUDP switches the UDP behavior off, so the same helper covers the
// ordinary case where the answer fits and no retry should happen.
func testResolver(t *testing.T, name string, values []string, truncateUDP bool) string {
	t.Helper()

	answer := func(req *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(req)
		for _, v := range values {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Txt: []string{v},
			})
		}
		return m
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if _, overTCP := w.RemoteAddr().(*net.TCPAddr); !overTCP && truncateUDP {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}
		_ = w.WriteMsg(answer(req))
	})

	packetConn, listener, port := listenBoth(t)

	udp := &dns.Server{PacketConn: packetConn, Handler: handler}
	tcp := &dns.Server{Listener: listener, Handler: handler}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
	})

	return port
}

// listenBoth binds UDP and TCP on the same port. The two are separate port
// spaces, so a port free in one can be taken in the other; retry rather than
// letting that flake the test.
func listenBoth(t *testing.T) (net.PacketConn, net.Listener, string) {
	t.Helper()

	for range 20 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		_, port, err := net.SplitHostPort(listener.Addr().String())
		require.NoError(t, err)

		packetConn, err := net.ListenPacket("udp", "127.0.0.1:"+port)
		if err != nil {
			_ = listener.Close()
			continue
		}
		return packetConn, listener, port
	}

	t.Fatal("could not bind the same port on both udp and tcp")
	return nil, nil, ""
}

func queryTestResolver(t *testing.T, name, port string) map[string]DnsRecord {
	t.Helper()

	client, err := New(name)
	require.NoError(t, err)
	client.config = &dns.ClientConfig{Servers: []string{"127.0.0.1"}, Port: port}

	res, err := client.queryDnsTypeAt("127.0.0.1", true, name, "TXT")
	require.NoError(t, err)
	return res
}

func TestQueryRetriesTruncatedAnswersOverTCP(t *testing.T) {
	// A large TXT set is the common case: SPF and the verification records that
	// accumulate at a busy apex routinely push the response past what fits in a
	// datagram. Before the TCP retry the type was dropped from the result map
	// entirely, so a domain with a strict SPF policy reported no TXT records and
	// no SPF record, which reads exactly like a domain that publishes neither.
	values := []string{"v=spf1 include:_spf.example.com -all", "example-site-verification=abc123"}
	port := testResolver(t, "example.com", values, true)

	res := queryTestResolver(t, "example.com", port)

	rec, ok := res["TXT"]
	require.True(t, ok, "the TXT record must survive a truncated UDP answer")
	assert.Equal(t, values, rec.RData)
	assert.Equal(t, "NOERROR", rec.RCode)
	assert.NoError(t, rec.Error)
}

func TestQueryLeavesUntruncatedAnswersAlone(t *testing.T) {
	// The retry must not change the ordinary path: an answer that fits is served
	// from the UDP response, exactly as before.
	values := []string{"v=spf1 -all"}
	port := testResolver(t, "example.com", values, false)

	res := queryTestResolver(t, "example.com", port)

	rec, ok := res["TXT"]
	require.True(t, ok)
	assert.Equal(t, values, rec.RData)
	assert.Equal(t, int64(300), rec.TTL)
}

// rawResolver serves a hand-built UDP response whose header counts more records
// than the body carries, and answers normally over TCP. Such a response fails to
// unpack with the truncation bit clear, so it is only reached by retrying on the
// error rather than on the bit.
func rawResolver(t *testing.T, name string, values []string) string {
	t.Helper()

	packetConn, listener, port := listenBoth(t)

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := packetConn.ReadFrom(buf)
			if err != nil {
				return
			}

			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}

			// A well-formed reply carrying one answer, then an answer count that
			// claims far more than the body holds. That is what an oversized
			// response looks like on the wire when the truncation bit does not
			// come with it: the header parses, the body runs out.
			reply := new(dns.Msg)
			reply.SetReply(req)
			reply.Answer = append(reply.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Txt: []string{"partial"},
			})
			packed, err := reply.Pack()
			if err != nil {
				continue
			}
			// A second answer that starts and does not finish: name pointer and
			// type, then nothing. The header counts it, the body cannot supply
			// it, and the unpack fails partway through.
			packed = append(packed, 0xC0, 0x0C, 0x00, 0x10)
			binary.BigEndian.PutUint16(packed[6:8], 2)
			_, _ = packetConn.WriteTo(packed, addr)
		}
	}()

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		for _, v := range values {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Txt: []string{v},
			})
		}
		_ = w.WriteMsg(m)
	})

	tcp := &dns.Server{Listener: listener, Handler: handler}
	go func() { _ = tcp.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = tcp.Shutdown()
		_ = packetConn.Close()
	})

	return port
}

func TestQueryRetriesUnpackFailuresOverTCP(t *testing.T) {
	// The truncation bit is not the only way an oversized answer arrives. A
	// response whose header overcounts fails to unpack with the bit clear, and
	// retrying only on the bit would report the name as publishing no TXT.
	values := []string{"v=spf1 -all"}
	port := rawResolver(t, "example.com", values)

	res := queryTestResolver(t, "example.com", port)

	rec, ok := res["TXT"]
	require.True(t, ok, "the TXT record must survive a UDP answer that will not unpack")
	assert.Equal(t, values, rec.RData)
	assert.NoError(t, rec.Error)
}

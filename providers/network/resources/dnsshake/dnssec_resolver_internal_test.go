// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dnsshake

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dnssecResolver stands up a local resolver on an ephemeral port. When
// honorsDnssecOk is set it echoes the DNSSEC OK bit and answers with an RRSIG
// alongside the address, the way a resolver on a path that carries EDNS0 does.
// Otherwise it answers with neither, which is what a resolver that strips EDNS0
// returns for a signed zone and an unsigned one alike.
//
// bindAddr and bindPort pin where it listens; an empty bindPort takes an
// ephemeral one. Pinning both is what lets two resolvers that differ only in
// behavior sit behind one dns.ClientConfig, which carries a single port for
// every server it lists.
func dnssecResolver(t *testing.T, name, bindAddr, bindPort string, honorsDnssecOk bool) string {
	t.Helper()

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		if req.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.1"),
			})
		}

		if honorsDnssecOk {
			opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
			opt.SetUDPSize(4096)
			opt.SetDo()
			m.Extra = append(m.Extra, opt)

			if req.Question[0].Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.RRSIG{
					Hdr:         dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
					TypeCovered: dns.TypeA,
					Algorithm:   13,
					Labels:      2,
					OrigTtl:     300,
					Expiration:  0xFFFFFFF0,
					Inception:   1,
					KeyTag:      1234,
					SignerName:  dns.Fqdn(name),
					Signature:   "AAAA",
				})
			}
		}

		_ = w.WriteMsg(m)
	})

	if bindPort == "" {
		bindPort = "0"
	}
	packetConn, err := net.ListenPacket("udp", net.JoinHostPort(bindAddr, bindPort))
	require.NoError(t, err)

	_, port, err := net.SplitHostPort(packetConn.LocalAddr().String())
	require.NoError(t, err)

	server := &dns.Server{PacketConn: packetConn, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	return port
}

// validateAgainst runs a validation against one local resolver.
func validateAgainst(t *testing.T, name, port string) *DnssecValidation {
	t.Helper()

	client, err := New(name)
	require.NoError(t, err)
	client.config = &dns.ClientConfig{
		Servers: []string{"127.0.0.1"},
		Port:    port,
		Timeout: 2,
	}

	res, err := client.ValidateDnssec("A", "SOA")
	require.NoError(t, err)
	return res
}

func TestValidateDnssecReportsUnknownWhenTheResolverStripsDnssec(t *testing.T) {
	// The resolver answers without the DNSSEC OK bit and without signatures,
	// which is indistinguishable from an unsigned zone. Concluding "the zone is
	// not signed" from that reported correctly signed zones as unsigned.
	port := dnssecResolver(t, "example.com", "127.0.0.1", "", false)

	res := validateAgainst(t, "example.com", port)

	assert.False(t, res.DnssecOk)
	assert.Empty(t, res.Signatures)
	assert.False(t, res.SignaturesVerified)
	assert.False(t, res.ChainOfTrustValidated)
	assert.Contains(t, res.Error, "did not return DNSSEC records")
	assert.NotContains(t, res.Error, "the zone is not signed")

	// The exchange itself is still described, so the reason stays readable.
	assert.Equal(t, "NOERROR", res.ResponseCode)
	assert.Equal(t, "A", res.RecordType)
}

func TestValidateDnssecReadsSignaturesWhenTheResolverHonorsDnssec(t *testing.T) {
	// The same name through a resolver that does carry DNSSEC: the signature is
	// seen, so the "not signed" conclusion is never reached.
	port := dnssecResolver(t, "example.com", "127.0.0.1", "", true)

	res := validateAgainst(t, "example.com", port)

	assert.True(t, res.DnssecOk)
	require.Len(t, res.Signatures, 1)
	assert.Equal(t, "A", res.Signatures[0].TypeCovered)
	assert.NotContains(t, res.Error, "did not return DNSSEC records")
	assert.NotContains(t, res.Error, "the zone is not signed")
}

func TestValidateDnssecPrefersAResolverThatHonorsDnssec(t *testing.T) {
	// resolv.conf commonly lists more than one resolver and they need not behave
	// alike. Settling for Servers[0] means one EDNS0-stripping resolver decides
	// the answer for every zone the host scans.
	//
	// Both resolvers listen on the same port, one on the IPv4 loopback and one on
	// the IPv6 loopback, because dns.ClientConfig carries a single port for every
	// server it lists.
	if probe, err := net.ListenPacket("udp", "[::1]:0"); err != nil {
		t.Skip("this host has no IPv6 loopback:", err)
	} else {
		_ = probe.Close()
	}

	port := dnssecResolver(t, "example.com", "127.0.0.1", "", false)
	dnssecResolver(t, "example.com", "::1", port, true)

	client, err := New("example.com")
	require.NoError(t, err)
	client.config = &dns.ClientConfig{
		// The stripping resolver is listed first, so taking the first answer
		// would report this zone as unsigned.
		Servers: []string{"127.0.0.1", "::1"},
		Port:    port,
		Timeout: 2,
	}

	res, err := client.ValidateDnssec("A", "SOA")
	require.NoError(t, err)

	assert.True(t, res.DnssecOk, "should have moved past the resolver that strips DNSSEC")
	assert.Len(t, res.Signatures, 1)
	assert.NotContains(t, res.Error, "the zone is not signed")
}

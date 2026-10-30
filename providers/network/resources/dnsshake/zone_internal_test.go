// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dnsshake

import (
	"net"
	"strconv"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// zoneFixture serves a synthetic tree that carries the three shapes the walk has
// to tell apart, none of which a live domain can be relied on to hold still:
//
//   - example.test is a zone apex and answers NS at its own name
//   - www.example.test is a name inside it, published as a CNAME. A resolver
//     answers an NS query for it with NOERROR and the CNAME in the answer
//     section, which is the shape that makes "answered successfully" and
//     "carries NS records" two different questions
//   - corp.example.test is delegated, so it answers NS at its own name and is a
//     zone in its own right, which is where the delegation walk and the public
//     suffix list disagree
//
// Every other name answers NOERROR with nothing, so a name under no zone walks
// to the top without finding one.
func zoneFixture(t *testing.T) *dns.ClientConfig {
	t.Helper()

	delegations := map[string][]string{
		"example.test.":      {"ns1.example.test.", "ns2.example.test."},
		"corp.example.test.": {"ns1.corp.example.test."},
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		q := r.Question[0]
		switch {
		case q.Qtype == dns.TypeNS && len(delegations[q.Name]) > 0:
			for _, ns := range delegations[q.Name] {
				m.Answer = append(m.Answer, &dns.NS{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  ns,
				})
			}
		case q.Name == "www.example.test.":
			// A CNAME is what a resolver returns for any type asked of this
			// name, NS included. It answers successfully and carries no NS.
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "example.test.",
			})
		}

		_ = w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	host, port, err := net.SplitHostPort(pc.LocalAddr().String())
	require.NoError(t, err)

	// Attempts is honoured by queryNS; Timeout is not, because queryDnsTypeAt
	// builds a dns.Client with the library default and never reads it.
	return &dns.ClientConfig{Servers: []string{host}, Port: port, Attempts: 1}
}

func fixtureClient(t *testing.T, fqdn string) *DnsClient {
	t.Helper()
	return &DnsClient{config: zoneFixture(t), fqdn: fqdn}
}

func TestZone(t *testing.T) {
	tests := []struct {
		name string
		fqdn string
		want string
	}{
		{"an apex is its own zone", "example.test", "example.test"},
		// www.example.test is a CNAME, so this also covers that answering
		// successfully and carrying NS records are two different questions.
		{"a name inside a zone reports the apex", "www.example.test", "example.test"},
		{"a delegated subdomain is its own zone", "corp.example.test", "corp.example.test"},
		{"a name inside a delegated subzone reports that subzone", "vpn.corp.example.test", "corp.example.test"},
		{"a name under no zone reports none", "absent.test", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			zone, err := fixtureClient(t, tc.fqdn).Zone()
			require.NoError(t, err)
			assert.Equal(t, tc.want, zone)
		})
	}
}

func TestZoneRejectsRoot(t *testing.T) {
	// The root is a zone, and reporting it would make every name look like it
	// sits in one. A name that cannot name a zone has to fail instead.
	for _, fqdn := range []string{"", "."} {
		_, err := fixtureClient(t, fqdn).Zone()
		assert.Error(t, err, "fqdn %q must not walk to the root", fqdn)
	}
}

func TestZoneReportsQueryFailureAsError(t *testing.T) {
	// A resolver that cannot be reached must not read as a name that belongs to
	// no zone: the first is unknown, the second is a fact, and a check filtered
	// on the zone would silently skip on the strength of the difference.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	require.NoError(t, err)
	require.NoError(t, pc.Close()) // nothing listens here now

	c := &DnsClient{
		config: &dns.ClientConfig{Servers: []string{"127.0.0.1"}, Port: port, Timeout: 1, Attempts: 1},
		fqdn:   "www.example.test",
	}

	_, err = c.Zone()
	assert.Error(t, err)
}

func TestWalkToDelegationContinuesWhenTheCallerRejectsAZone(t *testing.T) {
	// authoritativeNameservers depends on this: a delegation whose nameservers
	// do not resolve is not usable to it, and the walk has to climb past it
	// rather than stopping at the first name that merely answered.
	c := fixtureClient(t, "vpn.corp.example.test")

	var offered []string
	zone, found, err := c.walkToDelegation(func(zone string, _ DnsRecord) bool {
		offered = append(offered, zone)
		return zone == "example.test"
	})

	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "example.test", zone)
	assert.Equal(t, []string{"corp.example.test", "example.test"}, offered,
		"the rejected delegation should be offered first, then the walk continues")
}

func TestPortIsNumeric(t *testing.T) {
	// Guards the fixture itself: a non-numeric port would make every query fail
	// and every zone come back empty, which the table above would read as a
	// passing "no zone" case.
	cfg := zoneFixture(t)
	_, err := strconv.Atoi(cfg.Port)
	require.NoError(t, err)
}

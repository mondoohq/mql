// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dnsshake

import (
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The delegation walk ends on a query that did not happen rather than climbing
// past it, because climbing would answer with whichever ancestor did respond and
// hide the delegation below it. That is only a safe reading if a query that
// could have been answered was, and a single UDP datagram is not that: one lost
// reply would otherwise read as "this resolver cannot answer" and fail every
// field behind the walk.
//
// These tests fix the two halves of that: a transient loss is retried and does
// not surface, while a resolver that genuinely cannot answer still errors.

// flakyResolver serves the zone tree of zoneFixture, dropping the first
// dropFirst queries it receives for dropName so a caller sees a lost reply
// before a real answer.
type flakyResolver struct {
	mu        sync.Mutex
	dropName  string
	dropFirst int
	queries   int
	dropped   int
}

func (f *flakyResolver) serve(t *testing.T) *dns.ClientConfig {
	t.Helper()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		q := r.Question[0]

		f.mu.Lock()
		f.queries++
		drop := (f.dropName == "" || q.Name == f.dropName) && f.dropped < f.dropFirst
		if drop {
			f.dropped++
		}
		f.mu.Unlock()

		if drop {
			// No reply at all: the client waits and reports a timeout, which is
			// exactly what a lost datagram looks like.
			return
		}

		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if q.Qtype == dns.TypeNS && q.Name == "example.test." {
			m.Answer = append(m.Answer, &dns.NS{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.example.test.",
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

	return &dns.ClientConfig{Servers: []string{host}, Port: port, Attempts: 2}
}

func (f *flakyResolver) counts() (queries, dropped int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queries, f.dropped
}

// deadResolverConfig points at a port nothing listens on, so every query is
// lost rather than answered.
func deadResolverConfig(t *testing.T, servers int, attempts int) *dns.ClientConfig {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	require.NoError(t, err)
	require.NoError(t, pc.Close())

	addrs := make([]string, servers)
	for i := range addrs {
		addrs[i] = "127.0.0.1"
	}
	return &dns.ClientConfig{Servers: addrs, Port: port, Attempts: attempts}
}

// TestZoneRetriesALostReply is the case that made the walk's strictness a
// liability: the apex answers fine, one datagram on the way to it goes missing,
// and before the retry that reported an error on dns.zone and on every
// authoritative field.
func TestZoneRetriesALostReply(t *testing.T) {
	f := &flakyResolver{dropName: "example.test.", dropFirst: 1}
	c := &DnsClient{config: f.serve(t), fqdn: "example.test"}

	zone, err := c.Zone()
	require.NoError(t, err, "one lost reply must not fail the walk")
	assert.Equal(t, "example.test", zone)

	queries, dropped := f.counts()
	assert.Equal(t, 1, dropped, "the fixture should have dropped exactly one reply")
	assert.Equal(t, 2, queries, "the lost query should have been retried once")
}

// TestQueryNSFailsOverToTheNextResolver: resolv.conf commonly lists several
// nameservers, and asking only the first throws away the redundancy the host is
// configured for. One unreachable resolver should cost latency, not the answer.
func TestQueryNSFailsOverToTheNextResolver(t *testing.T) {
	live := zoneFixture(t)

	c := &DnsClient{
		config: &dns.ClientConfig{
			// Nothing listens on 127.0.0.2 at the fixture's port, so answering
			// at all requires moving on to the second resolver.
			Servers:  []string{"127.0.0.2", live.Servers[0]},
			Port:     live.Port,
			Attempts: 1,
		},
		fqdn: "example.test",
	}

	zone, err := c.Zone()
	require.NoError(t, err, "an unreachable first resolver must fail over, not fail")
	assert.Equal(t, "example.test", zone)
}

// TestZoneStillErrorsWhenNoResolverAnswers keeps the property the retry must not
// weaken. A resolver outage is not evidence that a name belongs to no zone, and
// reporting an empty zone for it would make a check filtered on the zone skip
// silently.
func TestZoneStillErrorsWhenNoResolverAnswers(t *testing.T) {
	c := &DnsClient{config: deadResolverConfig(t, 2, 2), fqdn: "www.example.test"}

	zone, err := c.Zone()
	require.Error(t, err, "an unreachable resolver must not read as a name with no zone")
	assert.Empty(t, zone)
	assert.Contains(t, err.Error(), "querying NS for")
}

func TestQueryNSWithoutAResolverIsAnError(t *testing.T) {
	c := &DnsClient{config: &dns.ClientConfig{Port: "53"}, fqdn: "example.test"}

	_, err := c.queryNS("example.test")
	require.Error(t, err, "no configured resolver cannot silently mean no zone")
}

// TestAuthoritativeNameserversEndsTheWalkOnAQueryFailure pins the behaviour
// change #10542 made to a shipped field. Before it, a lost reply at the queried
// name climbed to the parent and returned the parent's nameservers, which answer
// referrals rather than the records the caller wanted. It is an error now, and
// after the retry above it takes a resolver that really cannot answer.
func TestAuthoritativeNameserversEndsTheWalkOnAQueryFailure(t *testing.T) {
	c := &DnsClient{config: deadResolverConfig(t, 1, 1), fqdn: "www.example.test"}

	addrs, err := c.authoritativeNameservers()
	require.Error(t, err)
	assert.Empty(t, addrs)
	assert.Contains(t, err.Error(), "querying NS for")
}

// TestAuthoritativeNameserversClimbsPastAnUnresolvableDelegation is the
// leniency the walk keeps, and the reason walkToDelegation takes an accept
// callback: a delegation whose nameservers do not resolve is not usable, so the
// walk continues to one that is. The injected resolver is what makes this
// reachable in a test at all.
func TestAuthoritativeNameserversClimbsPastAnUnresolvableDelegation(t *testing.T) {
	var asked []string
	c := &DnsClient{
		config: zoneFixture(t),
		fqdn:   "vpn.corp.example.test",
		lookupHost: func(name string) ([]string, error) {
			asked = append(asked, name)
			// corp.example.test's nameserver does not resolve; example.test's does.
			switch name {
			case "ns1.corp.example.test":
				return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
			case "ns1.example.test":
				return []string{"192.0.2.1"}, nil
			default:
				return []string{"192.0.2.2"}, nil
			}
		},
	}

	addrs, err := c.authoritativeNameservers()
	require.NoError(t, err)
	assert.Equal(t, []string{"192.0.2.1", "192.0.2.2"}, addrs,
		"every resolvable nameserver of the accepted zone should be returned")
	assert.Equal(t, []string{"ns1.corp.example.test", "ns1.example.test", "ns2.example.test"}, asked,
		"the unresolvable delegation should be tried first, then the walk continues to the parent")
}

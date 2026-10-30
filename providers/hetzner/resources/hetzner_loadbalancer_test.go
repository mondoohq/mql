// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net"
	"testing"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/stretchr/testify/assert"
)

func TestTargetServerIDs(t *testing.T) {
	srv := func(id int64) hcloud.LoadBalancerTarget {
		return hcloud.LoadBalancerTarget{
			Type:   hcloud.LoadBalancerTargetTypeServer,
			Server: &hcloud.LoadBalancerTargetServer{Server: &hcloud.Server{ID: id}},
		}
	}

	t.Run("empty", func(t *testing.T) {
		assert.Empty(t, targetServerIDs(nil))
	})

	t.Run("extracts and dedupes server ids", func(t *testing.T) {
		got := targetServerIDs([]hcloud.LoadBalancerTarget{srv(10), srv(20), srv(10)})
		assert.Equal(t, []int64{10, 20}, got)
	})

	t.Run("skips entries without a resolved server", func(t *testing.T) {
		targets := []hcloud.LoadBalancerTarget{
			srv(10),
			{Type: hcloud.LoadBalancerTargetTypeServer, Server: nil},
			{Type: hcloud.LoadBalancerTargetTypeServer, Server: &hcloud.LoadBalancerTargetServer{Server: nil}},
			srv(30),
		}
		assert.Equal(t, []int64{10, 30}, targetServerIDs(targets))
	})
}

func TestLoadBalancerCertificateIDs(t *testing.T) {
	svc := func(port int, certIDs ...int64) hcloud.LoadBalancerService {
		certs := make([]*hcloud.Certificate, 0, len(certIDs))
		for _, id := range certIDs {
			certs = append(certs, &hcloud.Certificate{ID: id})
		}
		return hcloud.LoadBalancerService{
			Protocol:   hcloud.LoadBalancerServiceProtocolHTTPS,
			ListenPort: port,
			HTTP:       hcloud.LoadBalancerServiceHTTP{Certificates: certs},
		}
	}

	t.Run("no services", func(t *testing.T) {
		assert.Empty(t, loadBalancerCertificateIDs(nil))
	})

	// A plain TCP or HTTP listener terminates no TLS, so it contributes
	// nothing to the union.
	t.Run("service without certificates", func(t *testing.T) {
		tcp := hcloud.LoadBalancerService{Protocol: hcloud.LoadBalancerServiceProtocolTCP, ListenPort: 5432}
		assert.Empty(t, loadBalancerCertificateIDs([]hcloud.LoadBalancerService{tcp}))
	})

	t.Run("unions across services", func(t *testing.T) {
		got := loadBalancerCertificateIDs([]hcloud.LoadBalancerService{svc(443, 1, 2), svc(8443, 3)})
		assert.Equal(t, []int64{1, 2, 3}, got)
	})

	// One certificate serving several listeners is the common case. Reporting
	// it once per listener would make a single expiring certificate look like
	// several distinct findings.
	t.Run("dedupes a certificate shared by listeners", func(t *testing.T) {
		got := loadBalancerCertificateIDs([]hcloud.LoadBalancerService{svc(443, 1), svc(8443, 1), svc(9443, 1, 2)})
		assert.Equal(t, []int64{1, 2}, got)
	})

	t.Run("preserves first-seen order", func(t *testing.T) {
		got := loadBalancerCertificateIDs([]hcloud.LoadBalancerService{svc(443, 9, 4), svc(8443, 4, 1)})
		assert.Equal(t, []int64{9, 4, 1}, got)
	})

	t.Run("skips nil and zero-id certificates", func(t *testing.T) {
		s := hcloud.LoadBalancerService{
			Protocol:   hcloud.LoadBalancerServiceProtocolHTTPS,
			ListenPort: 443,
			HTTP: hcloud.LoadBalancerServiceHTTP{Certificates: []*hcloud.Certificate{
				nil,
				{ID: 0},
				{ID: 11},
			}},
		}
		assert.Equal(t, []int64{11}, loadBalancerCertificateIDs([]hcloud.LoadBalancerService{s}))
	})
}

func TestCertificateByID(t *testing.T) {
	certs := []*hcloud.Certificate{nil, {ID: 1, Name: "one"}, {ID: 2, Name: "two"}}

	got := certificateByID(certs, 2)
	if assert.NotNil(t, got) {
		assert.Equal(t, "two", got.Name)
	}
	assert.Nil(t, certificateByID(certs, 99))
	assert.Nil(t, certificateByID(nil, 1))
}

// The load balancer carries one PTR per public address, unlike a server, whose
// public IPv6 is a /64 with a PTR per address in it. Reading the wrong field
// would report an empty name for every internet-facing load balancer.
func TestLoadBalancerPublicNetDNSPtr(t *testing.T) {
	lb := hcloud.LoadBalancer{PublicNet: hcloud.LoadBalancerPublicNet{
		Enabled: true,
		IPv4:    hcloud.LoadBalancerPublicNetIPv4{IP: net.ParseIP("203.0.113.10"), DNSPtr: "lb.example.com"},
		IPv6:    hcloud.LoadBalancerPublicNetIPv6{IP: net.ParseIP("2001:db8::1"), DNSPtr: "lb6.example.com"},
	}}

	assert.Equal(t, "lb.example.com", lb.PublicNet.IPv4.DNSPtr)
	assert.Equal(t, "lb6.example.com", lb.PublicNet.IPv6.DNSPtr)
}

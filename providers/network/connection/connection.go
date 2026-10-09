// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	OPTION_FOLLOW_REDIRECTS = "follow-redirects"
)

type HostConnection struct {
	plugin.Connection
	Conf            *inventory.Config
	FollowRedirects bool
	asset           *inventory.Asset
	transport       *http.Transport
}

func NewHostConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) *HostConnection {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	// A scanner has to read servers that only speak TLS 1.0/1.1 or offer only
	// RSA-key-exchange and CBC suites (an Apache 2.2 / OpenSSL 0.9.8 stack): Go's
	// client defaults refuse them since Go 1.22, so http.get on such a server failed
	// with "server selected unsupported protocol version" and every header check
	// errored. The server still picks the version and suite, so a modern server
	// negotiates what it would anyway; TLS 1.3 ignores the suite list.
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       allCipherSuites(),
		InsecureSkipVerify: conf.Insecure, //nolint:gosec // only when the user asked for --insecure
	}

	var followRedirects bool
	if followRedirectsStr, ok := conf.Options[OPTION_FOLLOW_REDIRECTS]; ok {
		followRedirects = followRedirectsStr == "true"
	}

	return &HostConnection{
		Connection:      plugin.NewConnection(id, asset),
		Conf:            conf,
		asset:           asset,
		transport:       transport,
		FollowRedirects: followRedirects,
	}
}

func (h *HostConnection) Name() string {
	return "host"
}

func (p *HostConnection) Asset() *inventory.Asset {
	return p.asset
}

func (p *HostConnection) FQDN() string {
	if p.Conf == nil {
		return ""
	}
	return p.Conf.Host
}

func (p *HostConnection) Client(followRedirects bool) *http.Client {
	c := &http.Client{
		Transport: p.transport,
	}

	if !followRedirects {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}

// allCipherSuites returns every TLS 1.0-1.2 cipher suite Go implements, including
// the ones it considers insecure, so the client can still complete a handshake
// with a legacy server and report what it serves.
func allCipherSuites() []uint16 {
	suites := make([]uint16, 0, 32)
	for _, cs := range tls.CipherSuites() {
		suites = append(suites, cs.ID)
	}
	for _, cs := range tls.InsecureCipherSuites() {
		suites = append(suites, cs.ID)
	}
	return suites
}

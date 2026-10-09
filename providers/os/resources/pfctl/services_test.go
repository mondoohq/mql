// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pfctl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// lines from the /etc/services of macOS
const servicesExcerpt = `#
# Network services, Internet style
#
ssh              22/udp     # SSH Remote Login Protocol
ssh              22/tcp     # SSH Remote Login Protocol
domain           53/udp     # Domain Name Server
domain           53/tcp     # Domain Name Server
http             80/udp     www www-http # World Wide Web HTTP
http             80/tcp     www www-http # World Wide Web HTTP
`

func TestParseServices(t *testing.T) {
	s := ParseServices(servicesExcerpt)
	assert.Equal(t, "22", s["ssh/tcp"])
	assert.Equal(t, "53", s["domain/udp"])
	assert.Equal(t, "80", s["www/tcp"])
	assert.Equal(t, "80", s["www-http/udp"])
	_, ok := s["Network/tcp"]
	assert.False(t, ok)
}

func TestNormalizePort(t *testing.T) {
	s := ParseServices(servicesExcerpt)
	assert.Equal(t, "22", s.normalizePort("= ssh", "tcp"))
	assert.Equal(t, "!= 22", s.normalizePort("!= ssh", "tcp"))
	assert.Equal(t, "> 1024", s.normalizePort("> 1024", "tcp"))
	assert.Equal(t, "6000:6010", s.normalizePort("6000:6010", "tcp"))
	// no protocol on the rule: falls back to the tcp entry
	assert.Equal(t, "53", s.normalizePort("= domain", ""))
	// an unknown name stays as printed
	assert.Equal(t, "= nosuchsvc", s.normalizePort("= nosuchsvc", "tcp"))
	assert.Equal(t, "", s.normalizePort("", "tcp"))

	var none Services
	assert.Equal(t, "= ssh", none.normalizePort("= ssh", "tcp"))
}

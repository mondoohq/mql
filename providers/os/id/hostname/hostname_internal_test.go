// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hostname

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseEtcHostname(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{"plain name", "myhost\n", "myhost"},
		{"fqdn", "myhost.example.com\n", "myhost.example.com"},
		{"no trailing newline", "myhost", "myhost"},
		{"surrounding whitespace", "  myhost  \n", "myhost"},
		{"leading blank lines", "\n\nmyhost\n", "myhost"},
		{"comment first", "# set by cloud-init\nmyhost\n", "myhost"},
		{"empty file", "", ""},
		{"whitespace only", "\n  \n\n", ""},
		{"comments only", "# nothing here\n", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, parseEtcHostname(test.content))
		})
	}
}

func TestParseHostnameEnv(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			"bottlerocket",
			"HOSTNAME=ip-10-0-42-17.us-west-2.compute.internal\n",
			"ip-10-0-42-17.us-west-2.compute.internal",
		},
		{"quoted", "HOSTNAME=\"myhost.example.com\"\n", "myhost.example.com"},
		{"spaces around the assignment", "HOSTNAME = myhost \n", "myhost"},
		{"other variables present", "PROXY=http://p:3128\nHOSTNAME=myhost\n", "myhost"},
		{"commented out", "#HOSTNAME=myhost\n", ""},
		// A different variable must not answer for HOSTNAME.
		{"different variable", "NO_PROXY=localhost\n", ""},
		{"set but empty", "HOSTNAME=\n", ""},
		{"quoted empty", "HOSTNAME=\"\"\n", ""},
		{"empty file", "", ""},
		{"not an env file at all", "just some text\n", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, parseHostnameEnv(test.content))
		})
	}
}

func TestIsLocalhostVariant(t *testing.T) {
	localhosts := []string{
		"localhost", "LOCALHOST", "localhost.localdomain",
		"localhost4", "localhost4.localdomain4",
		"localhost6", "localhost6.localdomain6",
		"ip6-localhost", "ip6-loopback",
	}
	for _, host := range localhosts {
		t.Run(host, func(t *testing.T) {
			assert.True(t, isLocalhostVariant(host))
		})
	}

	realHosts := []string{
		"myhost", "myhost.example.com",
		"ip-10-0-42-17.us-west-2.compute.internal",
		"localhostess", "notlocalhost",
	}
	for _, host := range realHosts {
		t.Run(host, func(t *testing.T) {
			assert.False(t, isLocalhostVariant(host))
		})
	}
}

func TestParseEtcHosts(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			"bottlerocket loopback aliases",
			"127.0.0.1 localhost localhost.localdomain localhost4 localhost4.localdomain4 ip-10-0-42-17.us-west-2.compute.internal\n" +
				"::1 localhost localhost.localdomain localhost6 localhost6.localdomain6 ip-10-0-42-17.us-west-2.compute.internal\n",
			"ip-10-0-42-17.us-west-2.compute.internal",
		},
		{
			"debian 127.0.1.1 convention",
			"127.0.0.1\tlocalhost\n127.0.1.1\tdebian-box.example.com\tdebian-box\n",
			"debian-box.example.com",
		},
		{
			"ipv6 loopback only",
			"::1 localhost ip6-localhost ip6-loopback myhost.example.com\n",
			"myhost.example.com",
		},
		{
			// The routable entries of /etc/hosts name other machines at least as
			// often as they name this one, so they are never an answer.
			"routable addresses are ignored",
			"127.0.0.1 localhost\n10.0.0.9 buildserver.example.com buildserver\n",
			"",
		},
		{
			"comment stripped from the alias list",
			"127.0.1.1 myhost # the box itself\n",
			"myhost",
		},
		{
			"fully commented line",
			"# 127.0.1.1 myhost\n127.0.0.1 localhost\n",
			"",
		},
		{"only localhost aliases", "127.0.0.1 localhost localhost.localdomain\n::1 ip6-localhost ip6-loopback\n", ""},
		{"address with no alias", "127.0.0.1\n", ""},
		{"malformed address", "not-an-ip myhost\n", ""},
		{"empty file", "", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, parseEtcHosts(test.content))
		})
	}
}

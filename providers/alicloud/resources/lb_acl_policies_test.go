// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTlsAllowsLegacy(t *testing.T) {
	tests := []struct {
		name     string
		versions []string
		expected bool
	}{
		{"modern only", []string{"TLSv1.2", "TLSv1.3"}, false},
		{"tls 1.0 admitted", []string{"TLSv1.0", "TLSv1.2"}, true},
		{"tls 1.1 admitted", []string{"TLSv1.1"}, true},
		// the API spells the oldest version both ways
		{"bare TLSv1 spelling", []string{"TLSv1"}, true},
		{"case insensitive", []string{"tlsv1.1"}, true},
		{"whitespace tolerated", []string{" TLSv1.0 "}, true},
		// a policy whose versions could not be read must not be reported as
		// admitting legacy TLS
		{"empty", nil, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, tlsAllowsLegacy(test.versions))
		})
	}
}

func TestSplitCommaList(t *testing.T) {
	tests := []struct {
		name     string
		raw      *string
		expected []string
	}{
		{"single", new("TLSv1.2"), []string{"TLSv1.2"}},
		{"multiple", new("TLSv1.2,TLSv1.3"), []string{"TLSv1.2", "TLSv1.3"}},
		{"whitespace tolerated", new(" TLSv1.2 , TLSv1.3 "), []string{"TLSv1.2", "TLSv1.3"}},
		{"trailing separator", new("TLSv1.2,"), []string{"TLSv1.2"}},
		// nil rather than a list holding "": an empty value is no versions,
		// not one blank version
		{"empty", new(""), nil},
		{"absent", nil, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, splitCommaList(test.raw))
		})
	}
}

func TestAclCoversAllAddresses(t *testing.T) {
	tests := []struct {
		name     string
		entries  []any
		expected bool
	}{
		{"restrictive list", []any{"10.0.0.0/8", "192.0.2.0/24"}, false},
		// an allowlist holding the default route restricts nothing, while the
		// listener still reports access control as enabled
		{"ipv4 default route", []any{"10.0.0.0/8", "0.0.0.0/0"}, true},
		{"ipv6 default route", []any{"::/0"}, true},
		{"whitespace tolerated", []any{" 0.0.0.0/0 "}, true},
		// a single host, not the whole internet
		{"host address", []any{"0.0.0.0/32"}, false},
		{"empty list", []any{}, false},
		{"non-string entries ignored", []any{42, nil}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, aclCoversAllAddresses(test.entries))
		})
	}
}

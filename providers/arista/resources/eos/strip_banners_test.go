// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStripBanners_SuppressionQuotedNegationHidesRealConfig is the dangerous
// direction: a banner quoting a command overwrites what the device really
// says. Here root is enabled with a secret, and an operational notice telling
// people not to run "no aaa root" turns the answer into "root is disabled" --
// a "root must be disabled" check passes on a device that fails it.
func TestStripBanners_SuppressionQuotedNegationHidesRealConfig(t *testing.T) {
	cfg := `aaa root secret sha512 $6$salt$hash
banner login
NOTICE: this device is managed. Do not run:
no aaa root
EOF
`
	assert.False(t, ParseRootAccount(cfg).Enabled, "precondition: the raw config is misread")

	got := ParseRootAccount(StripBanners(cfg))
	assert.True(t, got.Enabled, "root is enabled with a secret")
	assert.Equal(t, "sha512", got.SecretFormat)
}

// TestStripBanners_FabricationQuotedCommandInventsConfig is the other
// direction: a banner quoting a community string reports a read-write
// plaintext community the device does not have, which is unfalsifiable from
// the query output.
func TestStripBanners_FabricationQuotedCommandInventsConfig(t *testing.T) {
	cfg := `banner login
Authorized use only. Reminder from netops:
snmp-server community public rw
is prohibited on this device.
EOF
snmp-server community realcomm ro MGMT-ACL
`
	require.Len(t, ParseSnmpCommunities(cfg), 2, "precondition: the raw config is misread")

	got := ParseSnmpCommunities(StripBanners(cfg))
	require.Len(t, got, 1)
	assert.Equal(t, "realcomm", got[0].Name)
	assert.Equal(t, "ro", got[0].Access)
}

// TestStripBanners_KeepsEverythingElseIntact guards against the strip eating
// real configuration, including a line that merely mentions a banner.
func TestStripBanners_KeepsEverythingElseIntact(t *testing.T) {
	cfg := `hostname leaf1
banner motd
maintenance window Sunday
EOF
management ssh
   idle-timeout 15
!
no banner login
`
	got := StripBanners(cfg)
	assert.Contains(t, got, "hostname leaf1")
	assert.Contains(t, got, "management ssh")
	assert.Contains(t, got, "   idle-timeout 15")
	assert.Contains(t, got, "no banner login")
	assert.NotContains(t, got, "maintenance window Sunday")

	// The header and terminator stay, so the shape of the config is
	// unchanged and line numbering is preserved.
	assert.Contains(t, got, "banner motd")
	assert.Contains(t, got, "EOF")
	assert.Equal(t, strings.Count(cfg, "\n"), strings.Count(got, "\n"))
}

// TestStripBanners_ParseBannersStillReadsTheBody keeps the banner resources
// reading the real text: they take the raw config, not the stripped one.
func TestStripBanners_ParseBannersStillReadsTheBody(t *testing.T) {
	cfg := `banner login
Authorized use only.
EOF
`
	assert.Equal(t, "Authorized use only.", ParseBanners(cfg).Login)
	assert.Empty(t, ParseBanners(StripBanners(cfg)).Login)
}

// TestStripBanners_TruncatedBannerDoesNotEatTheRest covers a config that ends
// mid-banner: everything up to that point must survive.
func TestStripBanners_TruncatedBannerDoesNotEatTheRest(t *testing.T) {
	cfg := `hostname leaf1
banner motd
no terminator here
`
	got := StripBanners(cfg)
	assert.Contains(t, got, "hostname leaf1")
	assert.NotContains(t, got, "no terminator here")
}

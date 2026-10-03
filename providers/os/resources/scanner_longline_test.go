// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Each of these parsers reads a whole file already held in memory. A line
// over 64 KiB must not end the parse and drop the settings after it.

func TestParseSelinuxConfigAfterLongLine(t *testing.T) {
	mode, policyType := ParseSelinuxConfig("# " + strings.Repeat("x", 70000) + "\nSELINUX=permissive\nSELINUXTYPE=targeted\n")
	assert.Equal(t, "permissive", mode)
	assert.Equal(t, "targeted", policyType)
}

func TestParseSysrcAfterLongLine(t *testing.T) {
	entries := ParseSysrc("ifconfig_em0_aliases=\"" + strings.Repeat("x", 70000) + "\"\nsshd_enable=\"YES\"\n")
	require.Len(t, entries, 2)
	assert.Equal(t, SysrcEntry{Name: "sshd_enable", Value: "YES"}, entries[1])
}

func TestParseGrubPasswordConfigAfterLongLine(t *testing.T) {
	cfg := ParseGrubPasswordConfig([]byte("# " + strings.Repeat("x", 70000) + "\nset superusers=\"root\"\npassword_pbkdf2 root grub.pbkdf2.sha512.10000.ABC123.DEF456\n"))
	assert.True(t, cfg.Protected())
}

func TestParseGrubLegacyPasswordProtectedAfterLongLine(t *testing.T) {
	assert.True(t, ParseGrubLegacyPasswordProtected([]byte("# "+strings.Repeat("x", 70000)+"\npassword --md5 $1$4Ktpx$aYSvUvC8JTHKbLZmPQz4S0\ntitle Linux\nkernel /vmlinuz ro\n")))
}

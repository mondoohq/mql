// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseBanners_LoginAndMotd(t *testing.T) {
	cfg := `management ssh
   no shutdown
banner login
Authorized users only. All activity is monitored.
EOF
banner motd
   ******************************************
   *   Restricted system                    *
   ******************************************
EOF
management telnet
   shutdown
`
	b := ParseBanners(cfg)
	assert.Equal(t, "Authorized users only. All activity is monitored.", b.Login)
	// Indentation is part of the displayed text and must survive verbatim.
	assert.Equal(t, `   ******************************************
   *   Restricted system                    *
   ******************************************`, b.Motd)
}

func TestParseBanners_None(t *testing.T) {
	b := ParseBanners("management ssh\n   no shutdown\n")
	assert.Empty(t, b.Login)
	assert.Empty(t, b.Motd)
}

func TestParseBanners_DeeplyIndentedBody(t *testing.T) {
	// Banner bodies can be indented far deeper than any real config nesting.
	// The body is read from raw lines, so the indentation heuristics used by
	// the section parsers never come into play.
	b := ParseBanners(deepIndentConfig)
	assert.Equal(t, "         welcome to the switch\n                  please authenticate", b.Login)
	assert.Empty(t, b.Motd)
}

func TestParseBanners_EmptyBody(t *testing.T) {
	// A banner configured with no text is indistinguishable from no banner,
	// which is the right answer for an audit either way.
	b := ParseBanners("banner login\nEOF\n")
	assert.Empty(t, b.Login)
}

func TestParseBanners_TruncatedBannerDoesNotHang(t *testing.T) {
	// A capture that ends mid-banner yields what was read.
	b := ParseBanners("banner motd\nline one\nline two\n")
	assert.Equal(t, "line one\nline two", b.Motd)
}

func TestParseBanners_Negated(t *testing.T) {
	cfg := `banner login
old text
EOF
no banner login
`
	b := ParseBanners(cfg)
	assert.Empty(t, b.Login)
}

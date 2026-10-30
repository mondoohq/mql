// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// managementBlocks is shaped after the `management ssh` and
// `management api http-commands` blocks as EOS renders them in
// `show running-config`, with a nested `vrf` sub-block under each.
const managementBlocks = `!
management api http-commands
   protocol https port 443
   no shutdown
   !
   vrf MGMT
      no shutdown
!
management ssh
   idle-timeout 15
   shutdown
   !
   vrf MGMT
      no shutdown
!
interface Ethernet1
   no switchport
!
`

func TestSectionBody_KeepsNestingAndStopsAtNextBlock(t *testing.T) {
	body := SectionBody(managementBlocks, "management ssh")

	// The nested `no shutdown` belongs to the MGMT routing instance, and the
	// block-level `shutdown` to the default one. GetSection flattens both to
	// the same level; SectionBody must not.
	assert.Contains(t, body, "   idle-timeout 15")
	assert.Contains(t, body, "      no shutdown")
	// The next top-level block ends the section.
	assert.NotContains(t, body, "no switchport")

	flattened := GetSection(strings.NewReader(managementBlocks), "management ssh")
	assert.NotContains(t, flattened, "no shutdown",
		"GetSection is expected to drop the nested line; SectionBody exists because of it")
}

func TestSectionBody_AbsentHeader(t *testing.T) {
	assert.Equal(t, "", SectionBody(managementBlocks, "management console"))
}

func TestSectionBody_HeaderIsNotAPrefixMatch(t *testing.T) {
	// `management api http-commands` must not be reached by asking for
	// `management api`, which is a different (gnmi/models) block.
	assert.Equal(t, "", SectionBody(managementBlocks, "management api"))
}

func TestEachSubBlock_SplitsNestedBlocks(t *testing.T) {
	got := map[string]string{}
	eachSubBlock(SectionBody(managementBlocks, "management api http-commands"),
		func(line, block string) { got[line] = block })

	assert.Equal(t, "", got["protocol https port 443"])
	assert.Equal(t, "", got["no shutdown"])
	assert.Equal(t, "no shutdown\n", got["vrf MGMT"])
}

func TestEachSubBlock_Empty(t *testing.T) {
	calls := 0
	eachSubBlock("", func(line, block string) { calls++ })
	assert.Equal(t, 0, calls)
}

func TestParseEnableSecret(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cfg        string
		configured bool
		format     string
	}{
		{
			// Shape of a saved running-config: the hash follows the encoding
			// selector, exactly as `aaa root secret` renders it.
			name:       "sha512",
			cfg:        "enable secret sha512 $6$saltsalt$hashhashhash\n",
			configured: true,
			format:     "sha512",
		},
		{
			name:       "md5 crypt",
			cfg:        "enable secret 5 $1$8bPBrJnd$Z8wbKLHpJEd7d4tc5Z/6h/\n",
			configured: true,
			format:     "5",
		},
		{
			name:       "explicit cleartext selector",
			cfg:        "enable secret 0 examplepassphrase\n",
			configured: true,
			format:     "0",
		},
		{
			// `enable password` is the current spelling of the same command
			// and appears in place of `enable secret` on modern releases.
			name:       "enable password spelling",
			cfg:        "enable password 5 $1$8bPBrJnd$Z8wbKLHpJEd7d4tc5Z/6h/\n",
			configured: true,
			format:     "5",
		},
		{
			// The absent case: no line at all means escalation needs no
			// password. This must read as "not configured", never as a
			// configured-but-unknown format.
			name:       "absent",
			cfg:        "hostname switch\n!\n",
			configured: false,
		},
		{
			name:       "negated",
			cfg:        "enable secret 5 $1$salt$hash\nno enable secret\n",
			configured: false,
		},
		{
			name:       "negated with the password spelling",
			cfg:        "enable password sha512 $6$salt$hash\nno enable password\n",
			configured: false,
		},
		{
			// An `enable secret` inside an indented block is not the
			// device-wide setting and must not be picked up.
			name:       "indented line is not top level",
			cfg:        "management console\n   enable secret 5 $1$salt$hash\n",
			configured: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseEnableSecret(tc.cfg)
			assert.Equal(t, tc.configured, got.Configured)
			assert.Equal(t, tc.format, got.Format)
		})
	}
}

// The encoding selector is optional. Taking the first token positionally
// would publish the password itself as the format, so the selector is
// matched against a closed set instead. EOS documents the bare form as
// equivalent to cleartext, which is what it must report.
func TestParseEnableSecret_BareFormIsCleartextAndHidesThePassword(t *testing.T) {
	const password = "ExamplePassphraseValue"
	got := ParseEnableSecret("enable secret " + password + "\n")
	assert.True(t, got.Configured)
	assert.Equal(t, "0", got.Format)
	assert.NotEqual(t, password, got.Format)
}

func TestParseEnableSecret_NeverCarriesTheHash(t *testing.T) {
	const hash = "$6$Zx1ExampleSalt$ExampleHashValueOnly"
	got := ParseEnableSecret("enable secret sha512 " + hash + "\n")
	assert.True(t, got.Configured)
	assert.NotContains(t, got.Format, hash)
}

func TestParseConsoleSettings(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		cfg := `management console
   idle-timeout 15
!
`
		got := ParseConsoleSettings(cfg)
		assert.True(t, got.Configured)
		assert.Equal(t, 15, got.IdleTimeout)
	})

	t.Run("block present but timeout unset", func(t *testing.T) {
		// A block that exists without an idle-timeout leaves sessions open
		// indefinitely, the same as no block. `configured` is what separates
		// the two, so it has to stay true here.
		cfg := "management console\n   exec-timeout 0\n!\n"
		got := ParseConsoleSettings(cfg)
		assert.True(t, got.Configured)
		assert.Equal(t, 0, got.IdleTimeout)
	})

	t.Run("absent", func(t *testing.T) {
		got := ParseConsoleSettings("hostname switch\n!\n")
		assert.False(t, got.Configured)
		assert.Equal(t, 0, got.IdleTimeout)
	})

	t.Run("explicit zero", func(t *testing.T) {
		got := ParseConsoleSettings("management console\n   idle-timeout 0\n!\n")
		assert.True(t, got.Configured)
		assert.Equal(t, 0, got.IdleTimeout)
	})
}

// sshAndEapiContainment follows the block shapes Arista's own AVD
// eos_cli_config_gen reference configurations render, which is where the
// nested `vrf` sub-blocks and the containment sub-commands appear together.
const sshAndEapiContainment = `!
management api http-commands
   protocol https
   no protocol http
   no shutdown
   session timeout 60 minutes
   !
   vrf MGMT
      no shutdown
      ip access-group ACL-API
   !
   vrf default
      shutdown
!
management ssh
   ip access-group ACL-SSH in
   idle-timeout 15
   authentication protocol keyboard-interactive password public-key
   connection limit 50
   connection per-host 10
   fips restrictions
   authentication empty-passwords permit
   client-alive interval 666
   client-alive count-max 42
   login timeout 120
   no shutdown
   log-level debug
   !
   vrf MGMT
      no shutdown
   !
   vrf default
      no shutdown
!
`

func TestParseSshSettings_Containment(t *testing.T) {
	s := ParseSshSettings(sshAndEapiContainment)

	assert.True(t, s.Enabled)
	assert.Equal(t, 15, s.IdleTimeout)
	assert.Equal(t, 120, s.LoginTimeout)
	assert.Equal(t, 50, s.ConnectionLimit)
	assert.Equal(t, 10, s.ConnectionPerHostLimit)
	assert.Equal(t, "permit", s.EmptyPasswords)
	assert.Equal(t, "debug", s.LogLevel)
	assert.Equal(t, 666, s.ClientAliveInterval)
	assert.Equal(t, 42, s.ClientAliveCountMax)
	assert.True(t, s.FipsRestrictions)
	assert.Equal(t, []string{"MGMT", "default"}, s.Vrfs)
}

func TestParseSshSettings_ShutdownVrfIsNotReported(t *testing.T) {
	cfg := `management ssh
   no shutdown
   !
   vrf MGMT
      no shutdown
   !
   vrf default
      shutdown
!
`
	s := ParseSshSettings(cfg)
	assert.Equal(t, []string{"MGMT"}, s.Vrfs)
}

// A `no shutdown` nested under a VRF governs that instance only. Reading it
// as the service-level state would report a shut-down SSH server as running,
// which is the failure direction that matters.
func TestParseSshSettings_NestedNoShutdownDoesNotEnableTheService(t *testing.T) {
	cfg := `management ssh
   shutdown
   !
   vrf MGMT
      no shutdown
!
`
	s := ParseSshSettings(cfg)
	assert.False(t, s.Enabled)
	assert.Equal(t, []string{"MGMT"}, s.Vrfs)
}

func TestParseSshSettings_EmptyPasswordsDefaultsToAuto(t *testing.T) {
	// EOS defaults `authentication empty-passwords` to auto, so a block that
	// does not set it reports the effective value rather than an empty one.
	assert.Equal(t, "auto", ParseSshSettings("management ssh\n   no shutdown\n!\n").EmptyPasswords)
	assert.Equal(t, "auto", ParseSshSettings("hostname switch\n").EmptyPasswords)
}

func TestParseSshSettings_NoVrfSubBlocks(t *testing.T) {
	s := ParseSshSettings("management ssh\n   idle-timeout 30\n!\n")
	assert.Empty(t, s.Vrfs)
	assert.Equal(t, 30, s.IdleTimeout)
}

func TestParseEapiContainment(t *testing.T) {
	e := ParseEapiContainment(sshAndEapiContainment)
	assert.True(t, e.Configured)
	assert.Equal(t, 60, e.SessionTimeout)
	// The default instance is explicitly shut down here, so eAPI is reachable
	// only through MGMT.
	assert.Equal(t, []string{"MGMT"}, e.Vrfs)
}

func TestParseEapiContainment_Absent(t *testing.T) {
	e := ParseEapiContainment("hostname switch\n!\n")
	assert.False(t, e.Configured)
	assert.Empty(t, e.Vrfs)
	assert.Equal(t, 0, e.SessionTimeout)
}

func TestParseEapiContainment_DefaultShutdownForm(t *testing.T) {
	// A device at defaults renders the VRF sub-block as `default shutdown`,
	// which is the shipped-off state and must not count as enabled.
	cfg := `management api http-commands
   vrf default
      default shutdown
!
`
	e := ParseEapiContainment(cfg)
	assert.True(t, e.Configured)
	assert.Empty(t, e.Vrfs)
}

func TestParseConsoleSettings_SessionTimeout(t *testing.T) {
	cfg := `management console
   idle-timeout 15
   timeout 30 warning 25
!
`
	got := ParseConsoleSettings(cfg)
	assert.True(t, got.Configured)
	assert.Equal(t, 15, got.IdleTimeout)
	assert.Equal(t, 30, got.SessionTimeout)
	assert.Equal(t, 25, got.SessionTimeoutWarning)
}

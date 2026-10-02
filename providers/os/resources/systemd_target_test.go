// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSystemdShowOutput(t *testing.T) {
	input := `Description=Multi-User System
LoadState=loaded
ActiveState=active
SubState=active
UnitFileState=enabled
FragmentPath=/lib/systemd/system/multi-user.target
Wants=systemd-logind.service systemd-user-sessions.service
Requires=basic.target
After=basic.target rescue.service rescue.target
Environment=FOO=bar BAZ=qux
`
	props := parseSystemdShowOutput(input)
	assert.Equal(t, "Multi-User System", props["Description"])
	assert.Equal(t, "loaded", props["LoadState"])
	assert.Equal(t, "active", props["ActiveState"])
	assert.Equal(t, "enabled", props["UnitFileState"])
	assert.Equal(t, "/lib/systemd/system/multi-user.target", props["FragmentPath"])
	assert.Equal(t, "systemd-logind.service systemd-user-sessions.service", props["Wants"])
	assert.Equal(t, "basic.target", props["Requires"])

	// Value containing '=' must be preserved verbatim (split on first '=' only).
	assert.Equal(t, "FOO=bar BAZ=qux", props["Environment"])
}

func TestParseSystemdShowOutputEmptyValue(t *testing.T) {
	// Optional properties get reported as `Key=` (empty value).
	input := `LoadState=loaded
UnitFileState=
After=
`
	props := parseSystemdShowOutput(input)
	assert.Equal(t, "loaded", props["LoadState"])
	assert.Equal(t, "", props["UnitFileState"])
	_, ok := props["After"]
	assert.True(t, ok, "empty values should still be recorded")
}

func TestSplitSystemdUnitList(t *testing.T) {
	assert.Equal(t, []any{}, splitSystemdUnitList(""))
	assert.Equal(t, []any{"basic.target"}, splitSystemdUnitList("basic.target"))
	assert.Equal(t,
		[]any{"systemd-logind.service", "systemd-user-sessions.service"},
		splitSystemdUnitList("systemd-logind.service systemd-user-sessions.service"))
	// Extra whitespace collapses.
	assert.Equal(t,
		[]any{"a.service", "b.service"},
		splitSystemdUnitList("  a.service   b.service  "))
}

func TestShellQuoteUnit(t *testing.T) {
	// Normal unit names pass through unchanged.
	assert.Equal(t, "multi-user.target", shellQuoteUnit("multi-user.target"))
	assert.Equal(t, "getty@tty1.service", shellQuoteUnit("getty@tty1.service"))
	// Backslash is a shell metacharacter, so escaped unit names (rare but
	// possible in device units like `dev-disk-by\x2dlabel-root.device`) get
	// quoted defensively. The backslash survives literally inside '...'.
	assert.Equal(t, `'dev-disk-by\x2dlabel-root.device'`, shellQuoteUnit(`dev-disk-by\x2dlabel-root.device`))

	// Empty string -> ''.
	assert.Equal(t, "''", shellQuoteUnit(""))

	// Defensive quoting against unexpected characters.
	assert.Equal(t, "'has space'", shellQuoteUnit("has space"))
	assert.Equal(t, `'it'\''s'`, shellQuoteUnit("it's"))
}

func TestListSystemdTargetNames_Parse(t *testing.T) {
	// Verify the de-dup + suffix-stripping logic used by listSystemdTargetNames,
	// driving it through the same string-processing path it would see at runtime.
	installed := `basic.target                       static
default.target                     alias
multi-user.target                  enabled
graphical.target                   static
`
	active := `basic.target              loaded active active   Basic System
multi-user.target         loaded active active   Multi-User System
sysinit.target            loaded active active   System Initialization
`
	seen := map[string]struct{}{}
	var names []string
	for _, line := range strings.Split(installed+"\n"+active, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		unit := fields[0]
		if !strings.HasSuffix(unit, ".target") {
			continue
		}
		name := strings.TrimSuffix(unit, ".target")
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}

	// Order preserved as encountered; duplicates dropped; suffixes stripped.
	require.Equal(t,
		[]string{"basic", "default", "multi-user", "graphical", "sysinit"},
		names)
}

func TestSplitSystemctlShowBlocks(t *testing.T) {
	// Two unit blocks separated by a single blank line, like `systemctl
	// show --no-pager -- basic.target multi-user.target` emits.
	input := `Description=Basic System
LoadState=loaded
ActiveState=active

Description=Multi-User System
LoadState=loaded
ActiveState=active
`
	blocks := splitSystemctlShowBlocks(input)
	require.Len(t, blocks, 2)
	assert.Contains(t, blocks[0], "Description=Basic System")
	assert.Contains(t, blocks[1], "Description=Multi-User System")

	// Each block parses independently.
	first := parseSystemdShowOutput(blocks[0])
	second := parseSystemdShowOutput(blocks[1])
	assert.Equal(t, "Basic System", first["Description"])
	assert.Equal(t, "Multi-User System", second["Description"])

	// Trailing blank lines (common from systemctl) don't produce an empty
	// final block.
	withTrailing := input + "\n\n"
	assert.Len(t, splitSystemctlShowBlocks(withTrailing), 2)

	// CRLF survives normalization.
	crlf := strings.ReplaceAll(input, "\n", "\r\n")
	crlfBlocks := splitSystemctlShowBlocks(crlf)
	require.Len(t, crlfBlocks, 2)
	assert.Contains(t, crlfBlocks[0], "Description=Basic System")

	// Empty input returns no blocks.
	assert.Empty(t, splitSystemctlShowBlocks(""))
}

func TestSplitSystemdTemplateTargets(t *testing.T) {
	concrete, templates := splitSystemdTemplateTargets([]string{
		"basic", "blockdev@", "getty", "container-getty@", "user-runtime-dir@1000",
	})
	assert.Equal(t, []string{"basic", "getty", "user-runtime-dir@1000"}, concrete)
	assert.Equal(t, []string{"blockdev@", "container-getty@"}, templates)
}

// Blocks taken from a live Ubuntu 24.04 host (systemd 255), trimmed to a few
// properties: `systemctl show --no-pager -- basic.target default.target
// multi-user.target`. default.target is an alias and answers with the
// graphical.target block.
const liveTargetShowBlocks = `Id=basic.target
Names=basic.target
Description=Basic System
ActiveState=active
SubState=active

Id=graphical.target
Names=graphical.target default.target runlevel5.target
Before=shutdown.target systemd-update-utmp-runlevel.service
Description=Graphical Interface
ActiveState=active
SubState=active

Id=multi-user.target
Names=multi-user.target runlevel2.target runlevel4.target runlevel3.target
Before=shutdown.target graphical.target cloud-init.target cloud-final.service systemd-update-utmp-runlevel.service
Description=Multi-User System
ActiveState=active
SubState=active
`

func TestMapSystemdShowBlocksToNames(t *testing.T) {
	blocks := splitSystemctlShowBlocks(liveTargetShowBlocks)

	t.Run("alias resolves to its unit's block", func(t *testing.T) {
		out := mapSystemdShowBlocksToNames(blocks, []string{"basic", "default", "multi-user"})
		require.Len(t, out, 3)
		assert.Equal(t, "Basic System", out["basic"]["Description"])
		assert.Equal(t, "Graphical Interface", out["default"]["Description"])
		assert.Equal(t, "Multi-User System", out["multi-user"]["Description"])
		assert.Equal(t, "active", out["multi-user"]["ActiveState"])
	})

	t.Run("a missing block does not shift the others", func(t *testing.T) {
		// systemctl printed nothing for "gone"; every later name must still
		// get its own block, not its neighbour's.
		out := mapSystemdShowBlocksToNames(blocks, []string{"basic", "gone", "default", "multi-user"})
		assert.NotContains(t, out, "gone")
		assert.Equal(t, "Graphical Interface", out["default"]["Description"])
		assert.Equal(t, "Multi-User System", out["multi-user"]["Description"])
	})

	t.Run("a block without Id is ignored", func(t *testing.T) {
		out := mapSystemdShowBlocksToNames([]string{"Description=orphan\n"}, []string{"orphan"})
		assert.Empty(t, out)
	})
}

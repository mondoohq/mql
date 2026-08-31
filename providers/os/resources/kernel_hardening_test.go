// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// =============================================================================
// kernel.cmdline parser
// =============================================================================

func TestParseKernelCmdline_Typical(t *testing.T) {
	// Typical Debian/Ubuntu boot line.
	raw := `BOOT_IMAGE=/boot/vmlinuz-6.5.0-1-amd64 root=UUID=abcd-1234 ro quiet splash mitigations=auto`
	params, flags := parseKernelCmdline(raw)

	assert.Equal(t, "/boot/vmlinuz-6.5.0-1-amd64", params["BOOT_IMAGE"])
	assert.Equal(t, "UUID=abcd-1234", params["root"], "value containing '=' is preserved verbatim")
	assert.Equal(t, "auto", params["mitigations"])

	// `ro`, `quiet`, `splash` are bare flags.
	assert.Contains(t, flags, "ro")
	assert.Contains(t, flags, "quiet")
	assert.Contains(t, flags, "splash")
	assert.NotContains(t, flags, "mitigations")
}

func TestParseKernelCmdline_DuplicateLastWins(t *testing.T) {
	// `console=` typically appears twice (serial + virtual terminal).
	raw := `console=tty0 console=ttyS0,115200n8`
	params, flags := parseKernelCmdline(raw)
	assert.Equal(t, "ttyS0,115200n8", params["console"], "last occurrence wins")
	assert.Empty(t, flags)
}

func TestParseKernelCmdline_Empty(t *testing.T) {
	params, flags := parseKernelCmdline("")
	assert.Empty(t, params)
	assert.Empty(t, flags)
}

func TestParseKernelCmdline_EmptyValue(t *testing.T) {
	// `key=` is a parameter with an empty string value, not a flag.
	raw := `root=UUID=x foo= quiet`
	params, flags := parseKernelCmdline(raw)
	assert.Equal(t, "", params["foo"])
	_, ok := params["foo"]
	assert.True(t, ok, "key= must produce a parameter, not be dropped")
	assert.Contains(t, flags, "quiet")
	assert.NotContains(t, flags, "foo")
}

func TestParseKernelCmdline_LeadingEquals(t *testing.T) {
	// A token starting with `=` has no key; treat it as a flag so we
	// don't index a map by an empty string.
	raw := `=weird ro`
	params, flags := parseKernelCmdline(raw)
	assert.Contains(t, flags, "=weird")
	assert.Contains(t, flags, "ro")
	_, ok := params[""]
	assert.False(t, ok, "empty-key parameters must not appear in the map")
}

// =============================================================================
// kernel.taint
// =============================================================================

func TestTaintReasons_Clean(t *testing.T) {
	assert.Empty(t, taintReasons(0))
}

func TestTaintReasons_SingleBit(t *testing.T) {
	// Bit 12 = O = out-of-tree module loaded (the common case on
	// systems running e.g. VirtualBox kernel modules).
	r := taintReasons(1 << 12)
	require.Len(t, r, 1)
	assert.Equal(t, "out-of-tree module loaded", r[0])
}

func TestTaintReasons_MultipleBits(t *testing.T) {
	// Bits 0 (proprietary), 7 (oops), 12 (out-of-tree).
	bitmask := int64((1 << 0) | (1 << 7) | (1 << 12))
	r := taintReasons(bitmask)
	require.Len(t, r, 3)
	assert.Equal(t, "proprietary module loaded", r[0])
	assert.Equal(t, "kernel oops or BUG", r[1])
	assert.Equal(t, "out-of-tree module loaded", r[2])
}

func TestTaintReasons_UnknownBitsIgnored(t *testing.T) {
	// Set a high bit beyond what we have a name for. The known bits
	// should still resolve; the unknown bit is silently skipped rather
	// than poisoning the list.
	bitmask := int64((1 << 0) | (1 << 30))
	r := taintReasons(bitmask)
	require.Len(t, r, 1)
	assert.Equal(t, "proprietary module loaded", r[0])
}

// =============================================================================
// kernel.lockdown
// =============================================================================

func TestParseLockdownMode_None(t *testing.T) {
	// Default state: lockdown LSM compiled in but not engaged.
	assert.Equal(t, "none", parseLockdownMode("[none] integrity confidentiality\n"))
}

func TestParseLockdownMode_Integrity(t *testing.T) {
	assert.Equal(t, "integrity", parseLockdownMode("none [integrity] confidentiality\n"))
}

func TestParseLockdownMode_Confidentiality(t *testing.T) {
	assert.Equal(t, "confidentiality", parseLockdownMode("none integrity [confidentiality]\n"))
}

func TestParseLockdownMode_Empty(t *testing.T) {
	// Empty content → kernel returned the file but with nothing in it.
	// We don't claim "none" here because that would be wrong.
	assert.Equal(t, "unknown", parseLockdownMode(""))
	assert.Equal(t, "unknown", parseLockdownMode("\n"))
}

func TestParseLockdownMode_NoBracketedToken(t *testing.T) {
	// Malformed: no token has brackets. Don't guess.
	assert.Equal(t, "unknown", parseLockdownMode("none integrity confidentiality"))
}

// =============================================================================
// kernel.aslr
// =============================================================================

func TestAslrLevel(t *testing.T) {
	assert.Equal(t, "disabled", aslrLevel(0))
	assert.Equal(t, "conservative", aslrLevel(1))
	assert.Equal(t, "full", aslrLevel(2))
	// CIS benchmarks require 2; anything outside the documented set is
	// "unknown" rather than guessed.
	assert.Equal(t, "unknown", aslrLevel(3))
	assert.Equal(t, "unknown", aslrLevel(-1))
}

// =============================================================================
// helpers
// =============================================================================

func TestStringsAsAnySlice(t *testing.T) {
	out := stringsAsAnySlice([]string{"a", "b"})
	require.Len(t, out, 2)
	assert.Equal(t, "a", out[0])
	assert.Equal(t, "b", out[1])
	assert.Empty(t, stringsAsAnySlice(nil))
}

// =============================================================================
// unmeasured controls must read null, never a measured negative
//
// The three hardening controls read a file in /proc or /sys. A container
// image, an extracted root filesystem, or any scan of a disk rather than a
// running kernel has none of those files. Before the guard below, that absence
// was reported as ASLR disabled, lockdown disabled, and the kernel clean --
// and "not tainted" is the answer a compliance check passes on.
// =============================================================================

// kernelFromFixture builds the kernel resource against a mock root filesystem.
func kernelFromFixture(t *testing.T, fixture string) *mqlKernel {
	t.Helper()

	fixturePath, err := filepath.Abs(fixture)
	require.NoError(t, err)

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "debian",
			Family: []string{"debian", "linux", "unix"},
		},
	}, mock.WithPath(fixturePath))
	require.NoError(t, err)

	raw, err := CreateResource(&plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}, "kernel", map[string]*llx.RawData{})
	require.NoError(t, err)
	return raw.(*mqlKernel)
}

func TestKernelAslr_AbsentFileReadsNull(t *testing.T) {
	aslr := kernelFromFixture(t, "testdata/kernel_hardening_absent.toml").GetAslr()
	require.NoError(t, aslr.Error)
	require.NoError(t, aslr.Data.Enabled.Error)

	// The sentinels stay, so the report says why nothing is known.
	assert.Equal(t, int64(-1), aslr.Data.Mode.Data)
	assert.Equal(t, "unknown", aslr.Data.Level.Data)

	// enabled must not answer. `false` here reads as "ASLR is off on this
	// host", which is a claim about a kernel that was never consulted.
	assert.True(t, aslr.Data.Enabled.IsNull(),
		"an absent randomize_va_space must leave enabled null, not false")
}

func TestKernelLockdown_AbsentFileReadsNull(t *testing.T) {
	lockdown := kernelFromFixture(t, "testdata/kernel_hardening_absent.toml").GetLockdown()
	require.NoError(t, lockdown.Error)
	require.NoError(t, lockdown.Data.Enabled.Error)

	assert.Equal(t, "unavailable", lockdown.Data.Mode.Data)
	assert.True(t, lockdown.Data.Enabled.IsNull(),
		"an absent lockdown file must leave enabled null, not false")
}

func TestKernelTaint_AbsentFileReadsNull(t *testing.T) {
	taint := kernelFromFixture(t, "testdata/kernel_hardening_absent.toml").GetTaint()
	require.NoError(t, taint.Error)
	require.NoError(t, taint.Data.Tainted.Error)

	// taint carries no sentinel field: bitmask 0 / reasons [] / tainted false
	// is byte-identical to a verified-clean kernel, so all three must be null.
	assert.True(t, taint.Data.Tainted.IsNull(),
		"an absent tainted file must leave tainted null -- false is the PASSING answer")
	assert.True(t, taint.Data.Bitmask.IsNull(),
		"bitmask 0 is a real measurement and must not be forged")
	assert.True(t, taint.Data.Reasons.IsNull(),
		"an empty reasons list would read as a verified-clean kernel")
}

func TestKernelHardening_MeasuredValuesUnchanged(t *testing.T) {
	k := kernelFromFixture(t, "testdata/kernel_hardening_measured.toml")

	aslr := k.GetAslr()
	require.NoError(t, aslr.Error)
	assert.Equal(t, int64(2), aslr.Data.Mode.Data)
	assert.Equal(t, "full", aslr.Data.Level.Data)
	assert.False(t, aslr.Data.Enabled.IsNull())
	assert.True(t, aslr.Data.Enabled.Data)

	lockdown := k.GetLockdown()
	require.NoError(t, lockdown.Error)
	assert.Equal(t, "integrity", lockdown.Data.Mode.Data)
	assert.False(t, lockdown.Data.Enabled.IsNull())
	assert.True(t, lockdown.Data.Enabled.Data)

	taint := k.GetTaint()
	require.NoError(t, taint.Error)
	assert.False(t, taint.Data.Bitmask.IsNull())
	assert.Equal(t, int64(4096), taint.Data.Bitmask.Data)
	assert.True(t, taint.Data.Tainted.Data)
	assert.Equal(t, []any{"out-of-tree module loaded"}, taint.Data.Reasons.Data)
}

// TestKernelHardening_MeasuredNegativesAreNotNull is the test the whole change
// turns on: a kernel that was read and reported "off" must keep saying so. If
// the guard were widened from "the file was not read" to "the value is zero",
// every clean kernel would silently become unmeasured and stop failing.
func TestKernelHardening_MeasuredNegativesAreNotNull(t *testing.T) {
	k := kernelFromFixture(t, "testdata/kernel_hardening_clean.toml")

	taint := k.GetTaint()
	require.NoError(t, taint.Error)
	assert.False(t, taint.Data.Tainted.IsNull(),
		"a tainted file holding 0 is a measured clean kernel, not an unmeasured one")
	assert.False(t, taint.Data.Tainted.Data)
	assert.False(t, taint.Data.Bitmask.IsNull())
	assert.Equal(t, int64(0), taint.Data.Bitmask.Data)
	assert.Empty(t, taint.Data.Reasons.Data)
	assert.False(t, taint.Data.Reasons.IsNull())

	aslr := k.GetAslr()
	require.NoError(t, aslr.Error)
	assert.Equal(t, int64(0), aslr.Data.Mode.Data)
	assert.Equal(t, "disabled", aslr.Data.Level.Data)
	assert.False(t, aslr.Data.Enabled.IsNull(),
		"randomize_va_space of 0 is a measured negative, not an unmeasured one")
	assert.False(t, aslr.Data.Enabled.Data)

	lockdown := k.GetLockdown()
	require.NoError(t, lockdown.Error)
	assert.Equal(t, "none", lockdown.Data.Mode.Data)
	assert.False(t, lockdown.Data.Enabled.IsNull(),
		"a lockdown file reporting [none] is a measured negative")
	assert.False(t, lockdown.Data.Enabled.Data)
}

// A file that IS there but cannot be read is not the absent case. The
// measurement failed for a reason the user should see, so the error is
// reported rather than folded into an unexplained null.
func TestReadKernelHardeningFile_UnreadableFileSurfacesTheError(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}

	unreadable := &mqlFile{MqlRuntime: runtime, __id: "/proc/sys/kernel/tainted"}
	unreadable.Path = plugin.TValue[string]{Data: "/proc/sys/kernel/tainted", State: plugin.StateIsSet}
	unreadable.Content = plugin.TValue[string]{
		Error: errors.New("permission denied"),
		State: plugin.StateIsSet | plugin.StateIsNull,
	}
	runtime.Resources.Set("file\x00/proc/sys/kernel/tainted", unreadable)

	_, ok, err := readKernelHardeningFile(runtime, "/proc/sys/kernel/tainted")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	assert.False(t, ok)
}

// =============================================================================
// argument builders
// =============================================================================

func TestKernelAslrArgs(t *testing.T) {
	unmeasured := kernelAslrArgs("", false)
	assert.Same(t, llx.NilData, unmeasured["enabled"])
	assert.Equal(t, int64(-1), unmeasured["mode"].Value)
	assert.Equal(t, "unknown", unmeasured["level"].Value)

	// The file was read but holds something that is not a number: still
	// nothing measured, so still null.
	garbage := kernelAslrArgs("yes please\n", true)
	assert.Same(t, llx.NilData, garbage["enabled"])

	off := kernelAslrArgs("0\n", true)
	assert.Equal(t, false, off["enabled"].Value)
	assert.Equal(t, "disabled", off["level"].Value)

	full := kernelAslrArgs("2\n", true)
	assert.Equal(t, true, full["enabled"].Value)
	assert.Equal(t, int64(2), full["mode"].Value)
}

func TestKernelLockdownArgs(t *testing.T) {
	unmeasured := kernelLockdownArgs("", false)
	assert.Same(t, llx.NilData, unmeasured["enabled"])
	assert.Equal(t, "unavailable", unmeasured["mode"].Value)

	// Read, but no bracketed token: the mode is unknown, so enabled cannot
	// be derived from it.
	malformed := kernelLockdownArgs("none integrity confidentiality", true)
	assert.Same(t, llx.NilData, malformed["enabled"])
	assert.Equal(t, "unknown", malformed["mode"].Value)

	none := kernelLockdownArgs("[none] integrity confidentiality\n", true)
	assert.Equal(t, false, none["enabled"].Value)

	for _, mode := range []string{"integrity", "confidentiality"} {
		on := kernelLockdownArgs("none ["+mode+"]\n", true)
		assert.Equal(t, true, on["enabled"].Value, mode+" is an engaged lockdown")
	}
}

func TestKernelTaintArgs(t *testing.T) {
	unmeasured := kernelTaintArgs("", false)
	assert.Same(t, llx.NilData, unmeasured["tainted"])
	assert.Same(t, llx.NilData, unmeasured["bitmask"])
	assert.Same(t, llx.NilData, unmeasured["reasons"])

	garbage := kernelTaintArgs("not a number", true)
	assert.Same(t, llx.NilData, garbage["tainted"])
	assert.Same(t, llx.NilData, garbage["bitmask"])

	clean := kernelTaintArgs("0\n", true)
	assert.Equal(t, false, clean["tainted"].Value, "a measured 0 is a clean kernel, not an unread one")
	assert.Equal(t, int64(0), clean["bitmask"].Value)
	assert.Equal(t, []any{}, clean["reasons"].Value)

	tainted := kernelTaintArgs("4096\n", true)
	assert.Equal(t, true, tainted["tainted"].Value)
	assert.Equal(t, int64(4096), tainted["bitmask"].Value)
	assert.Equal(t, []any{"out-of-tree module loaded"}, tainted["reasons"].Value)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// =============================================================================
// kernel.cmdline — /proc/cmdline
// =============================================================================

func (k *mqlKernel) cmdline() (*mqlKernelCmdline, error) {
	raw, ok, err := readKernelHardeningFile(k.MqlRuntime, "/proc/cmdline")
	if err != nil {
		return nil, err
	}
	if !ok {
		raw = ""
	}
	raw = strings.TrimRight(raw, "\n")

	params, flags := parseKernelCmdline(raw)

	resource, err := CreateResource(k.MqlRuntime, "kernel.cmdline", map[string]*llx.RawData{
		"raw":        llx.StringData(raw),
		"parameters": llx.MapData(params, types.String),
		"flags":      llx.ArrayData(flags, types.String),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlKernelCmdline), nil
}

func (c *mqlKernelCmdline) id() (string, error) {
	return "kernel.cmdline", nil
}

// parseKernelCmdline splits /proc/cmdline into `key=value` parameters
// and bare flags. Duplicate parameters collapse to the last occurrence
// (extremely rare outside of `console=`); the raw string is preserved
// on the resource for callers who need full fidelity.
func parseKernelCmdline(raw string) (map[string]any, []any) {
	params := map[string]any{}
	var flags []any
	for _, tok := range strings.Fields(raw) {
		if idx := strings.IndexByte(tok, '='); idx > 0 {
			params[tok[:idx]] = tok[idx+1:]
			continue
		}
		flags = append(flags, tok)
	}
	return params, flags
}

// =============================================================================
// kernel.taint — /proc/sys/kernel/tainted
// =============================================================================

func (k *mqlKernel) taint() (*mqlKernelTaint, error) {
	raw, ok, err := readKernelHardeningFile(k.MqlRuntime, "/proc/sys/kernel/tainted")
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(k.MqlRuntime, "kernel.taint", kernelTaintArgs(raw, ok))
	if err != nil {
		return nil, err
	}
	return resource.(*mqlKernelTaint), nil
}

// kernelTaintArgs turns the contents of /proc/sys/kernel/tainted into the
// resource fields. ok reports whether the file was read at all.
//
// Every field is null when the taint word could not be read. A bitmask of 0
// with no reasons is exactly what a genuinely clean kernel reports, so filling
// those values in for an unread kernel would make the two indistinguishable,
// and `tainted: false` is the answer a compliance check passes on. Zero is a
// real measurement here and must not be forged.
func kernelTaintArgs(raw string, ok bool) map[string]*llx.RawData {
	if ok {
		if bitmask, perr := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); perr == nil {
			return map[string]*llx.RawData{
				"bitmask": llx.IntData(bitmask),
				"tainted": llx.BoolData(bitmask != 0),
				"reasons": llx.ArrayData(stringsAsAnySlice(taintReasons(bitmask)), types.String),
			}
		}
	}

	return map[string]*llx.RawData{
		"bitmask": llx.NilData,
		"tainted": llx.NilData,
		"reasons": llx.NilData,
	}
}

func (t *mqlKernelTaint) id() (string, error) {
	return "kernel.taint", nil
}

// taintBits maps bit positions to the human-readable reasons documented
// in Documentation/admin-guide/tainted-kernels.rst. The list is bit-
// ordered; new bits append at the end.
var taintBits = []string{
	"proprietary module loaded",    // 0  G/P
	"module force-loaded",          // 1  F
	"SMP with CPU mismatch",        // 2  S
	"module force-unloaded",        // 3  R
	"machine check exception",      // 4  M
	"bad page",                     // 5  B
	"taint requested by userspace", // 6  U
	"kernel oops or BUG",           // 7  D
	"ACPI table overridden",        // 8  A
	"kernel issued warning",        // 9  W
	"staging driver loaded",        // 10 C
	"firmware workaround applied",  // 11 I
	"out-of-tree module loaded",    // 12 O
	"unsigned module loaded",       // 13 E
	"soft lockup occurred",         // 14 L
	"kernel was live-patched",      // 15 K
	"auxiliary taint",              // 16 X
	"struct randomization plugin",  // 17 T
	"in-kernel test",               // 18
}

func taintReasons(bitmask int64) []string {
	if bitmask == 0 {
		return []string{}
	}
	out := []string{}
	for i, reason := range taintBits {
		if bitmask&(1<<uint(i)) != 0 {
			out = append(out, reason)
		}
	}
	return out
}

// =============================================================================
// kernel.lockdown — /sys/kernel/security/lockdown
// =============================================================================

func (k *mqlKernel) lockdown() (*mqlKernelLockdown, error) {
	raw, ok, err := readKernelHardeningFile(k.MqlRuntime, "/sys/kernel/security/lockdown")
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(k.MqlRuntime, "kernel.lockdown", kernelLockdownArgs(raw, ok))
	if err != nil {
		return nil, err
	}
	return resource.(*mqlKernelLockdown), nil
}

// kernelLockdownArgs turns the contents of /sys/kernel/security/lockdown into
// the resource fields. ok reports whether the file was read at all.
//
// `mode` keeps its sentinel so the reason is visible, but `enabled` is null
// whenever no mode was actually observed: the lockdown LSM being unreadable is
// not evidence that lockdown is off.
func kernelLockdownArgs(raw string, ok bool) map[string]*llx.RawData {
	mode := "unavailable"
	if ok {
		mode = parseLockdownMode(raw)
	}

	args := map[string]*llx.RawData{
		"mode":    llx.StringData(mode),
		"enabled": llx.NilData,
	}
	if mode != "unavailable" && mode != "unknown" {
		args["enabled"] = llx.BoolData(mode == "integrity" || mode == "confidentiality")
	}
	return args
}

func (l *mqlKernelLockdown) id() (string, error) {
	return "kernel.lockdown", nil
}

// parseLockdownMode extracts the active mode from
// `/sys/kernel/security/lockdown`. The file lists every supported mode
// with the active one in square brackets, e.g. `[none] integrity
// confidentiality`. We return the bracketed token, or `unknown` if
// the file is malformed and no bracketed token is found.
func parseLockdownMode(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "unknown"
	}
	for _, tok := range strings.Fields(raw) {
		if len(tok) >= 2 && tok[0] == '[' && tok[len(tok)-1] == ']' {
			return tok[1 : len(tok)-1]
		}
	}
	return "unknown"
}

// =============================================================================
// kernel.aslr — /proc/sys/kernel/randomize_va_space
// =============================================================================

func (k *mqlKernel) aslr() (*mqlKernelAslr, error) {
	raw, ok, err := readKernelHardeningFile(k.MqlRuntime, "/proc/sys/kernel/randomize_va_space")
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(k.MqlRuntime, "kernel.aslr", kernelAslrArgs(raw, ok))
	if err != nil {
		return nil, err
	}
	return resource.(*mqlKernelAslr), nil
}

// kernelAslrArgs turns the contents of /proc/sys/kernel/randomize_va_space into
// the resource fields. ok reports whether the file was read at all.
//
// `mode` and `level` keep their sentinels so the reason is visible, but
// `enabled` is null whenever no value was actually observed. A container image
// or an extracted filesystem carries no /proc, and reporting ASLR as disabled
// there asserts a measurement that was never taken.
func kernelAslrArgs(raw string, ok bool) map[string]*llx.RawData {
	if ok {
		if mode, perr := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); perr == nil {
			return map[string]*llx.RawData{
				"mode":    llx.IntData(mode),
				"level":   llx.StringData(aslrLevel(mode)),
				"enabled": llx.BoolData(mode > 0),
			}
		}
	}

	return map[string]*llx.RawData{
		"mode":    llx.IntData(-1),
		"level":   llx.StringData("unknown"),
		"enabled": llx.NilData,
	}
}

func (a *mqlKernelAslr) id() (string, error) {
	return "kernel.aslr", nil
}

func aslrLevel(mode int64) string {
	switch mode {
	case 0:
		return "disabled"
	case 1:
		return "conservative"
	case 2:
		return "full"
	default:
		return "unknown"
	}
}

// =============================================================================
// shared helpers
// =============================================================================

// readKernelHardeningFile reads a file in /proc or /sys via the file
// resource, returning (content, true, nil) on success and ("", false, nil)
// when the file is simply not there: a missing kernel feature, a non-Linux
// host, or a container image / extracted filesystem that carries no /proc at
// all. That absence is a legitimate answer, not a failure, and callers must
// report the values it would have produced as null.
//
// A file that IS present but cannot be read is a different condition. The
// measurement failed for a reason the user should see, so that error is
// returned rather than folded into the absent case, where it would surface as
// an unexplained null. The file resource reports absence by leaving its
// content null with no error, so the two are distinguishable here.
func readKernelHardeningFile(runtime *plugin.Runtime, path string) (string, bool, error) {
	o, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return "", false, err
	}
	f := o.(*mqlFile)
	content := f.GetContent()
	if content.Error != nil {
		return "", false, content.Error
	}
	if content.IsNull() {
		return "", false, nil
	}
	return content.Data, true, nil
}

// stringsAsAnySlice converts a []string to []any so it can be wrapped
// in llx.ArrayData without colliding with the cgroup/firewalld helpers
// defined elsewhere in this package.
func stringsAsAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

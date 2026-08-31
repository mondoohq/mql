// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"errors"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/services"
	"go.mondoo.com/mql/types"
)

func (t *mqlSystemdTarget) id() (string, error) {
	return "systemd.target:" + t.Name.Data, nil
}

func (x *mqlSystemdTargets) id() (string, error) {
	return "systemd.targets", nil
}

func (x *mqlSystemdTargets) list() ([]any, error) {
	conn, ok := x.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("systemd.targets is not supported on this connection")
	}

	names, err := listSystemdTargetNames(x.MqlRuntime)
	if err != nil {
		return nil, err
	}
	// systemctl needs a running systemd to answer. Where it cannot, the unit
	// files are still on disk and are where systemctl would have read the
	// names from anyway.
	if len(names) == 0 {
		names = services.ListSystemdFSTargetNames(conn.FileSystem())
	}
	if len(names) == 0 {
		return []any{}, nil
	}

	// Batch every target's properties into a single `systemctl show`
	// invocation. systemctl emits one block per unit separated by a blank
	// line, in the same order we passed the unit names. This collapses
	// what was previously N round-trips through the command resource into
	// one — meaningful on remote/SSH connections where each command pays
	// a full connection round-trip.
	propsByName, err := showSystemdTargetPropertiesBatch(x.MqlRuntime, names)
	if err != nil {
		return nil, err
	}
	// `systemctl show` needs the bus even though listing did not, so it is the
	// step that fails first. Reporting every target with a blank description
	// and no dependencies is not a smaller answer, it is a wrong one: read the
	// unit files instead. The runtime fields (activeState, subState) stay empty
	// -- they exist only in a running systemd, and an empty string says we did
	// not read them rather than claiming the target is inactive.
	if len(propsByName) == 0 {
		propsByName = services.ReadSystemdFSTargetProperties(conn.FileSystem(), names)
	}

	res := make([]any, 0, len(names))
	for _, name := range names {
		props := propsByName[name]
		if props == nil {
			props = map[string]string{}
		}
		mqlTarget, err := CreateResource(x.MqlRuntime, "systemd.target", map[string]*llx.RawData{
			"name":          llx.StringData(name),
			"description":   llx.StringData(props["Description"]),
			"loadState":     llx.StringData(props["LoadState"]),
			"activeState":   llx.StringData(props["ActiveState"]),
			"subState":      llx.StringData(props["SubState"]),
			"unitFileState": llx.StringData(props["UnitFileState"]),
			"fragmentPath":  llx.StringData(props["FragmentPath"]),
			"wants":         llx.ArrayData(splitSystemdUnitList(props["Wants"]), types.String),
			"requires":      llx.ArrayData(splitSystemdUnitList(props["Requires"]), types.String),
			"after":         llx.ArrayData(splitSystemdUnitList(props["After"]), types.String),
			"before":        llx.ArrayData(splitSystemdUnitList(props["Before"]), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTarget)
	}
	return res, nil
}

// listSystemdTargetNames returns the de-duplicated set of every .target
// unit known to systemd — both installed unit files and any
// transient/active targets — without the .target suffix. Empty list is
// returned when systemctl isn't installed (e.g. on a non-systemd host).
func listSystemdTargetNames(runtime *plugin.Runtime) ([]string, error) {
	installed, ok, err := runSystemctl(runtime,
		"systemctl list-unit-files --type=target --no-legend --plain --no-pager")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	active, ok, err := runSystemctl(runtime,
		"systemctl list-units --type=target --all --no-legend --plain --no-pager")
	if err != nil {
		return nil, err
	}
	if !ok {
		active = ""
	}

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
	return names, nil
}

// showSystemdTargetPropertiesBatch runs a single `systemctl show` for
// every target name in `names` and returns the per-target property maps,
// keyed by the input name (no `.target` suffix). systemctl prints unit
// blocks separated by a blank line in the same order the units were
// passed, so we split on the blank line and zip blocks back to names.
// On a system without systemctl we return an empty map and let the
// caller render bare target shells.
func showSystemdTargetPropertiesBatch(runtime *plugin.Runtime, names []string) (map[string]map[string]string, error) {
	if len(names) == 0 {
		return map[string]map[string]string{}, nil
	}

	// Build `systemctl show --no-pager -- a.target b.target ...`.
	var b strings.Builder
	b.WriteString("systemctl show --no-pager --")
	for _, name := range names {
		b.WriteByte(' ')
		b.WriteString(shellQuoteUnit(name + ".target"))
	}

	stdout, ok, err := runSystemctl(runtime, b.String())
	if err != nil {
		return nil, err
	}
	if !ok {
		return map[string]map[string]string{}, nil
	}

	blocks := splitSystemctlShowBlocks(stdout)
	out := make(map[string]map[string]string, len(names))
	for i, name := range names {
		if i >= len(blocks) {
			break
		}
		out[name] = parseSystemdShowOutput(blocks[i])
	}
	return out, nil
}

// splitSystemctlShowBlocks splits `systemctl show` output for multiple
// units into the per-unit blocks. Blocks are separated by a single blank
// line; trailing blank lines are dropped.
func splitSystemctlShowBlocks(stdout string) []string {
	// Normalize line endings so we don't accidentally trip over CRLF that
	// may leak in over some SSH channels.
	stdout = strings.ReplaceAll(stdout, "\r\n", "\n")

	var blocks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		blocks = append(blocks, cur.String())
		cur.Reset()
	}
	for _, line := range strings.Split(stdout, "\n") {
		if line == "" {
			flush()
			continue
		}
		cur.WriteString(line)
		cur.WriteByte('\n')
	}
	flush()
	return blocks
}

// parseSystemdShowOutput consumes the `Key=Value` lines emitted by
// `systemctl show`. Values may themselves contain `=` (e.g.
// `Environment=FOO=bar`) so we split on the first `=` only.
func parseSystemdShowOutput(stdout string) map[string]string {
	out := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	// Some unit properties (e.g. ExecStart) can be very long; raise the
	// per-line cap so we don't drop them.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		out[line[:idx]] = line[idx+1:]
	}
	return out
}

// splitSystemdUnitList splits the space-separated unit list that systemd
// emits in Wants=/Requires=/After=/Before= fields, returning []any for
// llx.ArrayData.
func splitSystemdUnitList(s string) []any {
	if s == "" {
		return []any{}
	}
	parts := strings.Fields(s)
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		out = append(out, p)
	}
	return out
}

// runSystemctl executes a systemctl/resolvectl/timedatectl invocation via
// the command resource. Returns (stdout, true, nil) on success; (empty,
// false, nil) when the binary is missing or the command exits non-zero.
// Reusing this from systemd_resolved.go and systemd_timesyncd.go too.
func runSystemctl(runtime *plugin.Runtime, cmdline string) (string, bool, error) {
	o, err := CreateResource(runtime, "command", map[string]*llx.RawData{
		"command": llx.StringData(cmdline),
	})
	if err != nil {
		return "", false, err
	}
	cmd := o.(*mqlCommand)
	run, err := commandResult(cmd)
	if err != nil {
		return "", false, err
	}
	if run.exitcode != 0 {
		return "", false, nil
	}
	return run.stdout, true, nil
}

// shellQuoteUnit single-quotes a unit name for safe inclusion in a shell
// command line. systemd unit names normally contain only alnum + `-._@:\`
// (no whitespace or shell metacharacters), so the fast path returns the
// string unchanged. Defense-in-depth in case a future unit name carries
// something unexpected.
func shellQuoteUnit(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n'\"\\$`") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

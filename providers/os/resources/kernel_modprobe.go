// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// modprobeRule captures the "module must not load" intent expressed by a
// modprobe configuration file. It is the union of every directive observed
// across the files modprobe reads: if any of them blacklists the module the
// rule is blacklisted, and if any install rule short-circuits to a no-op
// binary like /bin/true or /bin/false the rule has installBypass set.
type modprobeRule struct {
	blacklisted   bool
	installBypass bool
}

// modprobeSearchPaths is the directory search order libkmod uses for
// modprobe.d configuration (default_config_paths in libkmod.c). When the
// same file name exists in more than one directory, the copy in the earlier
// directory wins and the later ones are ignored, so an /etc/modprobe.d file
// overrides a package-shipped file of the same name in /usr/lib or /lib.
//
// kmod 29 added /usr/local/lib/modprobe.d and kmod 30 added
// /usr/lib/modprobe.d. Older kmod releases skip those directories, but on
// those releases they don't exist or, on merged-/usr systems, alias
// /lib/modprobe.d, so walking the full list matches every release.
var modprobeSearchPaths = []string{
	"/etc/modprobe.d",
	"/run/modprobe.d",
	"/usr/local/lib/modprobe.d",
	"/usr/lib/modprobe.d",
	"/lib/modprobe.d",
}

// isModprobeConfigName reports whether libkmod reads a directory entry with
// this name: hidden files are skipped and only `*.conf` files count.
func isModprobeConfigName(name string) bool {
	return !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".conf")
}

// selectModprobeConfigFiles applies libkmod's file selection to the entries
// found in each search directory. listings[i] holds the names of the
// non-directory entries of dirs[i]. The first directory that holds a given
// name wins, and the winners are returned as full paths ordered by file name
// (strcmp order), which is the order modprobe applies them in.
func selectModprobeConfigFiles(dirs []string, listings [][]string) []string {
	winners := map[string]string{}
	for i, dir := range dirs {
		if i >= len(listings) {
			break
		}
		for _, name := range listings[i] {
			if !isModprobeConfigName(name) {
				continue
			}
			if _, ok := winners[name]; ok {
				continue
			}
			winners[name] = path.Join(dir, name)
		}
	}

	names := make([]string, 0, len(winners))
	for name := range winners {
		names = append(names, name)
	}
	sort.Strings(names)

	res := make([]string, len(names))
	for i, name := range names {
		res[i] = winners[name]
	}
	return res
}

// listModprobeConfigFiles returns the modprobe.d configuration files modprobe
// reads, in the order it applies them. Each search directory is listed one
// level deep (libkmod ignores subdirectories), symlinked files are followed,
// and missing directories are skipped. A directory that exists but can't be
// checked or listed doesn't stop the walk: the files from the other
// directories are still returned, together with the joined errors.
func listModprobeConfigFiles(runtime *plugin.Runtime) ([]string, error) {
	conn := runtime.Connection.(shared.Connection)
	fs := conn.FileSystem()

	var errs []error
	listings := make([][]string, len(modprobeSearchPaths))
	for i, dir := range modprobeSearchPaths {
		raw, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(dir),
		})
		if err != nil {
			return nil, err
		}
		exists := raw.(*mqlFile).GetExists()
		if exists.Error != nil {
			errs = append(errs, exists.Error)
			continue
		}
		if !exists.Data {
			continue
		}

		entries, err := afero.ReadDir(fs, dir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if entry.Mode()&os.ModeSymlink != 0 {
				// libkmod stats through the link: a link to a directory is
				// skipped and a dangling link has nothing to read.
				target, err := fs.Stat(path.Join(dir, entry.Name()))
				if err != nil || target.IsDir() {
					continue
				}
			}
			listings[i] = append(listings[i], entry.Name())
		}
	}

	return selectModprobeConfigFiles(modprobeSearchPaths, listings), errors.Join(errs...)
}

// installBypassBins are the executable paths whose presence as the command
// of an `install <mod> ...` line means the load is short-circuited rather
// than actually invoking modprobe / insmod. /bin/true and /bin/false appear
// in CIS guidance and in the wild — admins use them interchangeably (false
// is more semantically honest because it reports an error, true is silent).
// The /usr/bin variants are equivalent on modern distros where /bin is a
// symlink to /usr/bin, and admins write either form.
var installBypassBins = map[string]bool{
	"/bin/true":      true,
	"/bin/false":     true,
	"/usr/bin/true":  true,
	"/usr/bin/false": true,
}

// parseModprobeConfig parses a single modprobe configuration blob and
// returns the per-module rules it declares. Lines are interpreted per
// modprobe.d(5):
//
//   - `#` introduces a comment to end-of-line.
//   - `blacklist <name>` marks <name> as blacklisted.
//   - `install <name> <cmd>...` records installBypass when <cmd> resolves
//     to a no-op binary — /bin/true, /bin/false, or their /usr/bin
//     equivalents. A leading `exec` is stripped because modprobe accepts
//     `install foo exec /bin/false` and treats it the same as
//     `install foo /bin/false`.
//   - alias, options, softdep, remove and anything else are ignored — they
//     don't express "must not load" intent.
//
// Module names are normalized with normalizeModuleName, because modprobe
// treats '-' and '_' as interchangeable: `blacklist firewire-core` and
// `blacklist firewire_core` express the same rule, and CIS remediations
// write the dashed spelling while lsmod reports the underscore one. Keying
// on the underscore form lets either spelling resolve.
//
// The same module can appear in multiple files; the returned rule is the
// per-field OR across every occurrence.
func parseModprobeConfig(content string) map[string]modprobeRule {
	out := map[string]modprobeRule{}

	for _, raw := range strings.Split(content, "\n") {
		line := stripModprobeComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "blacklist":
			name := normalizeModuleName(fields[1])
			rule := out[name]
			rule.blacklisted = true
			out[name] = rule
		case "install":
			if len(fields) < 3 {
				continue
			}
			name := normalizeModuleName(fields[1])
			// modprobe accepts an optional leading `exec` before the
			// command — `install foo exec /bin/false` is equivalent to
			// `install foo /bin/false`. Strip it so the bypass check
			// always inspects the actual binary path.
			cmd := fields[2]
			if cmd == "exec" && len(fields) >= 4 {
				cmd = fields[3]
			}
			if installBypassBins[cmd] {
				rule := out[name]
				rule.installBypass = true
				out[name] = rule
			}
		}
	}

	return out
}

// stripModprobeComment removes everything from the first `#` to end-of-line.
// modprobe's parser treats `#` as a comment introducer anywhere on a line
// (there is no quoting in modprobe.d syntax).
func stripModprobeComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

// loadModprobeRules reads the modprobe.d files modprobe itself reads (see
// listModprobeConfigFiles), parses each, and stores the merged per-module
// rule set on the kernel resource. A file in /etc/modprobe.d shadows a file
// of the same name in a later search directory, so its rules replace the
// shadowed file's instead of adding to them.
//
// Uses sync.Once with an explicit error capture so all three accessors
// (blacklisted, installBypass, disabled) share a single walk per query.
func (k *mqlKernel) loadModprobeRules() (map[string]modprobeRule, error) {
	k.modprobeOnce.Do(func() {
		rules := map[string]modprobeRule{}

		paths, err := listModprobeConfigFiles(k.MqlRuntime)
		if err != nil && plugin.StructuredErrors() {
			k.modprobeErr = err
			return
		}
		// v13 behavior: an unreadable search directory contributes no rules,
		// the readable ones still count.

		conn := k.MqlRuntime.Connection.(shared.Connection)
		for _, p := range paths {
			content, err := readFileContent(conn, p)
			if err != nil {
				if plugin.StructuredErrors() {
					k.modprobeErr = err
					return
				}
				continue
			}

			for name, rule := range parseModprobeConfig(content) {
				merged := rules[name]
				if rule.blacklisted {
					merged.blacklisted = true
				}
				if rule.installBypass {
					merged.installBypass = true
				}
				rules[name] = merged
			}
		}

		k.modprobeRules = rules
	})

	return k.modprobeRules, k.modprobeErr
}

// moduleRule resolves the parent kernel resource, triggers a one-shot
// modprobe walk, and returns the rule for this module's name. The name is
// normalized the same way the rule keys are, so `kernel.module("firewire-core")`
// and `kernel.module("firewire_core")` both find a rule written with either
// spelling. A module with no matching rule yields a zero-value modprobeRule
// (both fields false), which is exactly what the accessors want.
func (m *mqlKernelModule) moduleRule() (modprobeRule, error) {
	obj, err := CreateResource(m.MqlRuntime, "kernel", map[string]*llx.RawData{})
	if err != nil {
		return modprobeRule{}, err
	}
	kernel := obj.(*mqlKernel)
	rules, err := kernel.loadModprobeRules()
	if err != nil {
		return modprobeRule{}, err
	}
	return lookupModprobeRule(rules, m.Name.Data), nil
}

// lookupModprobeRule finds the rule for a module name in a parsed rule set.
// The name is normalized the same way parseModprobeConfig normalizes its
// keys, so a config written with dashes answers a query written with
// underscores and the other way round.
func lookupModprobeRule(rules map[string]modprobeRule, name string) modprobeRule {
	return rules[normalizeModuleName(name)]
}

func (m *mqlKernelModule) blacklisted() (bool, error) {
	rule, err := m.moduleRule()
	if err != nil {
		return false, err
	}
	return rule.blacklisted, nil
}

func (m *mqlKernelModule) installBypass() (bool, error) {
	rule, err := m.moduleRule()
	if err != nil {
		return false, err
	}
	return rule.installBypass, nil
}

func (m *mqlKernelModule) disabled() (bool, error) {
	rule, err := m.moduleRule()
	if err != nil {
		return false, err
	}
	return rule.blacklisted || rule.installBypass, nil
}

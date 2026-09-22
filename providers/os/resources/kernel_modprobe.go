// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

// modprobeRule captures the "module must not load" intent expressed by a
// modprobe configuration file. It is the union of every directive observed
// across every config path — i.e. if any file blacklists the module the
// rule is blacklisted, and if any install rule short-circuits to a no-op
// binary like /bin/true or /bin/false the rule has installBypass set.
type modprobeRule struct {
	blacklisted   bool
	installBypass bool
}

// modprobeSearchPaths is the search order used by libkmod when resolving
// modprobe.d configuration. The first path that contains a given file name
// wins for that file name, but for our union-of-intent semantics we just
// walk every path that exists. Order is documented in modprobe.d(5).
var modprobeSearchPaths = []string{
	"/etc/modprobe.d",
	"/run/modprobe.d",
	"/usr/lib/modprobe.d",
	"/lib/modprobe.d",
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

// loadModprobeRules walks modprobeSearchPaths for *.conf files, parses each,
// and stores the merged per-module rule set on the kernel resource. Missing
// directories are best-effort — they're a normal state on stripped-down
// container images and stock minimal installs, and absent files just
// contribute zero rules.
//
// Uses sync.Once with an explicit error capture so all three accessors
// (blacklisted, installBypass, disabled) share a single walk per query.
func (k *mqlKernel) loadModprobeRules() (map[string]modprobeRule, error) {
	k.modprobeOnce.Do(func() {
		rules := map[string]modprobeRule{}

		for _, dir := range modprobeSearchPaths {
			files, err := k.modprobeFilesIn(dir)
			if err != nil {
				// Treat any per-directory failure as "directory absent"
				// for our purposes — modprobe itself silently ignores
				// missing search paths.
				continue
			}

			for _, f := range files {
				mf, ok := f.(*mqlFile)
				if !ok {
					continue
				}
				path := mf.Path.Data
				if !strings.HasSuffix(path, ".conf") {
					continue
				}

				content := mf.GetContent()
				if content.Error != nil {
					if errors.Is(content.Error, resources.NotFoundError{}) {
						continue
					}
					// Permission / IO errors on a single file shouldn't
					// abort the whole walk — surface what we can.
					continue
				}

				for name, rule := range parseModprobeConfig(content.Data) {
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
		}

		k.modprobeRules = rules
	})

	return k.modprobeRules, k.modprobeErr
}

// modprobeFilesIn lists every regular file in dir using files.find. The
// directory's presence is checked up front so missing search paths are
// silently skipped rather than producing a noisy error from files.find.
func (k *mqlKernel) modprobeFilesIn(dir string) ([]any, error) {
	dirFile, err := CreateResource(k.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(dir),
	})
	if err != nil {
		return nil, err
	}
	exists := dirFile.(*mqlFile).GetExists()
	if exists.Error != nil {
		return nil, exists.Error
	}
	if !exists.Data {
		return nil, nil
	}

	files, err := CreateResource(k.MqlRuntime, "files.find", map[string]*llx.RawData{
		"from": llx.StringData(dir),
		"type": llx.StringData("file"),
	})
	if err != nil {
		return nil, err
	}

	list := files.(*mqlFilesFind).GetList()
	if list.Error != nil {
		return nil, list.Error
	}
	return list.Data, nil
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

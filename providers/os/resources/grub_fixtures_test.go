// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests run against boot loader configuration copied verbatim from real
// hosts. See testdata/grub/README.md for how each fixture was collected and
// what layout it represents. The oracle files beside each fixture record what
// the host actually booted with, so the expectations here are checked against
// the host rather than against this parser.

const fixtureRoot = "testdata/grub"

func fixtureNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(fixtureRoot)
	require.NoError(t, err)

	names := []string{}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		names = append(names, e.Name())
	}
	require.NotEmpty(t, names)
	return names
}

// fixtureFS roots a filesystem at a fixture, so path resolution is exercised
// rather than only line parsing.
func fixtureFS(name string) afero.Fs {
	return afero.NewBasePathFs(afero.NewOsFs(), filepath.Join(fixtureRoot, name, "files"))
}

func loadFixtureEntries(t *testing.T, name string) []GrubEntry {
	t.Helper()
	fs := fixtureFS(name)

	cfgPath := findGrubCfg(fs, grubCfgPaths)
	var content []byte
	if cfgPath != "" {
		var err error
		content, err = afero.ReadFile(fs, cfgPath)
		require.NoError(t, err)
	}

	entries, err := LoadGrubEntries(fs, cfgPath, content)
	require.NoError(t, err)
	return entries
}

func readOracle(t *testing.T, name, file string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureRoot, name, "oracle", file))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// TestFixtureEveryHostYieldsEntries is the regression that matters most: on the
// Red Hat family the authoritative grub.cfg holds no kernel command line at
// all, so reading it alone returned nothing and any assertion made over the
// entries passed without testing anything.
func TestFixtureEveryHostYieldsEntries(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			entries := loadFixtureEntries(t, name)
			require.NotEmpty(t, entries, "no boot entries found")

			bootable := 0
			for _, e := range entries {
				if e.Kind != GrubEntryNormal && e.Kind != GrubEntryRecovery {
					continue
				}
				bootable++
				assert.NotEmpty(t, e.Kernel, "%q boots no kernel", e.Title)
				assert.NotEmpty(t, e.Parameters, "%q has no kernel parameters", e.Title)
				assert.Contains(t, e.Parameters, "root", "%q has no root parameter", e.Title)
				assert.NotEmpty(t, e.Source, "%q names no source file", e.Title)
			}
			assert.NotZero(t, bootable, "no entry boots a kernel")
		})
	}
}

// TestFixtureParametersMatchProcCmdline checks the parsed parameters against
// what the host actually booted with. /proc/cmdline is what the boot loader
// handed the kernel, so an entry that boots this kernel has to agree with it.
func TestFixtureParametersMatchProcCmdline(t *testing.T) {
	// GRUB prepends the image it loaded, which is not a kernel parameter.
	ignore := map[string]bool{"BOOT_IMAGE": true}

	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			raw := readOracle(t, name, "proc-cmdline.txt")
			require.NotEmpty(t, raw, "fixture has no /proc/cmdline oracle")

			booted, bootedFlags := ParseCmdline(raw)
			for k := range ignore {
				delete(booted, k)
			}

			entries := loadFixtureEntries(t, name)
			matched := false
			for _, e := range entries {
				if e.Kind != GrubEntryNormal {
					continue
				}
				if !parametersAgree(e.Parameters, booted) {
					continue
				}
				if !flagsAgree(e.Flags, bootedFlags) {
					continue
				}
				matched = true
				break
			}

			assert.True(t, matched,
				"no normal entry matches the booted command line\n  booted: %v %v\n  entries: %s",
				booted, bootedFlags, describeEntries(entries))
		})
	}
}

func parametersAgree(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

func flagsAgree(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, f := range got {
		seen[f]++
	}
	for _, f := range want {
		seen[f]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func describeEntries(entries []GrubEntry) string {
	out := []string{}
	for _, e := range entries {
		out = append(out, "\n    ["+e.Kind+"] "+e.Title+" | "+e.Cmdline)
	}
	return strings.Join(out, "")
}

// TestFixtureKernelsAreInstalled checks the entries against the kernel each
// host reports running, so a parser that picked up the wrong field would be
// caught rather than merely producing a plausible-looking string.
func TestFixtureKernelsAreInstalled(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			release := readOracle(t, name, "kernel-release.txt")
			require.NotEmpty(t, release)

			entries := loadFixtureEntries(t, name)
			found := false
			for _, e := range entries {
				if e.Kind == GrubEntryNormal && strings.Contains(e.Kernel, release) {
					found = true
					break
				}
			}

			if !found {
				// NixOS names the image by its store path rather than by the
				// kernel release, so the release string cannot appear in it.
				if name == "nixos2605" {
					t.Skip("NixOS names the kernel image by store path")
				}
				t.Errorf("no normal entry boots the running kernel %q: %s", release, describeEntries(entries))
			}
		})
	}
}

// TestFixtureBootableMatchesEntryRole states, independently of the
// implementation, which roles boot an operating system, and checks every entry
// of all 22 hosts against it. The corpus is required to contain each role, so
// the negative half cannot quietly stop being exercised: proxmox-nas
// contributes the memory tests, the Debian and SUSE families the submenus, and
// the firmware entries are the ones that boot no kernel.
func TestFixtureBootableMatchesEntryRole(t *testing.T) {
	bootsAnOS := map[string]bool{
		GrubEntryNormal:   true,
		GrubEntryRecovery: true,
		GrubEntryMemtest:  false,
		GrubEntrySubmenu:  false,
		GrubEntryOther:    false,
	}

	seen := map[string]int{}
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			for _, e := range loadFixtureEntries(t, name) {
				want, known := bootsAnOS[e.Kind]
				require.True(t, known, "%q has unknown kind %q", e.Title, e.Kind)
				seen[e.Kind]++

				assert.Equal(t, want, e.Bootable, "%q is a %s entry", e.Title, e.Kind)
				if e.Bootable {
					// An entry with no kernel to hand parameters to cannot be
					// the subject of a control over boot parameters.
					assert.NotEmpty(t, e.Kernel, "%q is bootable but boots no kernel", e.Title)
				}
			}
		})
	}

	for kind := range bootsAnOS {
		assert.NotZero(t, seen[kind], "no fixture contributes a %q entry", kind)
	}
}

// TestFixtureBootedEntryIsBootable checks the flag against the host rather than
// against the parser: the entry whose command line matches what the boot loader
// handed the kernel is by definition one that boots an operating system.
func TestFixtureBootedEntryIsBootable(t *testing.T) {
	ignore := map[string]bool{"BOOT_IMAGE": true}

	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			raw := readOracle(t, name, "proc-cmdline.txt")
			require.NotEmpty(t, raw, "fixture has no /proc/cmdline oracle")

			booted, bootedFlags := ParseCmdline(raw)
			for k := range ignore {
				delete(booted, k)
			}

			entries := loadFixtureEntries(t, name)
			matched := 0
			for _, e := range entries {
				if !parametersAgree(e.Parameters, booted) || !flagsAgree(e.Flags, bootedFlags) {
					continue
				}
				matched++
				assert.True(t, e.Bootable,
					"%q carries the command line the host booted with but is not bootable", e.Title)
			}
			require.NotZero(t, matched, "no entry matches the booted command line: %s", describeEntries(entries))
		})
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/utils/versionx"
)

// NixOS has no kernel package to enumerate. It builds a whole system
// generation at a time and keeps the previous ones, each with the kernel it
// boots, so the kernels a NixOS host has installed are the kernels of the
// generations it can still boot into -- which is what kernel.installed means
// everywhere else, reached by a different road.
const (
	nixosSystemProfilesDir = "/nix/var/nix/profiles"
	nixosBootedSystemDir   = "/run/booted-system"
	nixosBootJSONName      = "boot.json"

	// nixosBootspecV1Key is the namespace a generation records its boot
	// details under (NixOS RFC 125).
	nixosBootspecV1Key = "org.nixos.bootspec.v1"
)

// nixosGenerationLink matches a generation symlink in the system profile
// directory: system-1-link, system-42-link. The directory also holds `system`
// (the current generation) and `per-user`, neither of which is a generation of
// its own.
var nixosGenerationLink = regexp.MustCompile(`^system-(\d+)-link$`)

// nixosStoreEntry pulls the entry name out of a store path, the part after the
// hash: /nix/store/<32 chars>-linux-6.18.50/bzImage yields linux-6.18.50.
var nixosStoreEntry = regexp.MustCompile(`^/nix/store/[a-z0-9]{32}-([^/]+)`)

// nixosBootJSON is a generation's boot.json, keyed by bootspec namespace.
// reboot.NixosReboot reads the same file for a different question; the two
// stay separate because a shared reader would couple the kernel resource to
// the reboot one for two fields.
type nixosBootJSON struct {
	V1 *struct {
		Kernel string `json:"kernel"`
	} `json:"org.nixos.bootspec.v1"`
}

// nixosInstalledKernels lists the kernel of every system generation, marking
// the one the host booted.
//
// runningVersion is the fallback for deciding which is running. The kernel's
// own store path is the better answer where /run/booted-system can be read,
// because it is an exact identity rather than a version string: a hardened or
// realtime kernel reports a `uname -r` that its derivation version does not
// contain, and matching on the string alone would mark none of them running.
func nixosInstalledKernels(fs afero.Fs, runningVersion string) ([]KernelVersion, error) {
	entries, err := afero.ReadDir(fs, nixosSystemProfilesDir)
	if err != nil {
		return nil, fmt.Errorf("could not read the NixOS system profiles at %s: %w", nixosSystemProfilesDir, err)
	}

	bootedKernel := nixosBootedKernelPath(fs)

	// Generations share a kernel far more often than not -- a configuration
	// change rebuilds the system without touching it -- so the same kernel is
	// one installed kernel however many generations reference it.
	seen := map[string]struct{}{}
	res := []KernelVersion{}
	for _, entry := range entries {
		if !nixosGenerationLink.MatchString(entry.Name()) {
			continue
		}

		kernelPath, ok := nixosGenerationKernel(fs, path.Join(nixosSystemProfilesDir, entry.Name()))
		if !ok {
			continue
		}

		name, version, ok := parseNixosKernelStorePath(kernelPath)
		if !ok {
			continue
		}

		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		running := version == runningVersion
		if bootedKernel != "" {
			running = kernelPath == bootedKernel
		}

		res = append(res, KernelVersion{
			Name:    name,
			Version: version,
			Running: running,
		})
	}

	// Newest version first, so the list reads like the boot menu rather than
	// like a directory listing.
	//
	// Compared segment by segment rather than as strings: "6.9.1" sorts above
	// "6.18.50" lexically, because "9" beats "1" before either is read as a
	// number. A host whose generations span a minor bump carries exactly that
	// pair, and a policy taking the first entry as the newest installed kernel
	// would get the older one.
	sort.Slice(res, func(i, j int) bool {
		if res[i].Name != res[j].Name {
			return res[i].Name < res[j].Name
		}
		return versionx.Compare(res[i].Version, res[j].Version) > 0
	})

	return res, nil
}

// nixosBootedKernelPath returns the store path of the kernel the host booted,
// or "" when /run holds nothing to read -- an offline scan of a NixOS disk,
// where /run is an empty tmpfs.
func nixosBootedKernelPath(fs afero.Fs) string {
	kernelPath, ok := nixosGenerationKernel(fs, nixosBootedSystemDir)
	if !ok {
		return ""
	}
	return kernelPath
}

// nixosGenerationKernel reads the kernel a generation boots out of its
// boot.json. The file is a plain file inside the generation, so this works on
// a connection that cannot run a command and cannot resolve a symlink.
func nixosGenerationKernel(fs afero.Fs, generationDir string) (string, bool) {
	data, err := afero.ReadFile(fs, path.Join(generationDir, nixosBootJSONName))
	if err != nil {
		return "", false
	}

	var doc nixosBootJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", false
	}
	if doc.V1 == nil || doc.V1.Kernel == "" {
		return "", false
	}

	return doc.V1.Kernel, true
}

// parseNixosKernelStorePath splits a kernel's store path into the derivation
// name and version:
//
//	/nix/store/dvab2dg1czm40gp5si151sj86rfjwnfm-linux-6.18.50/bzImage
//	-> ("linux", "6.18.50")
//
// The split is nix's own: the version begins at the first hyphen that is not
// followed by a letter, which keeps linux-hardened and linux-rt whole.
func parseNixosKernelStorePath(storePath string) (name string, version string, ok bool) {
	m := nixosStoreEntry.FindStringSubmatch(storePath)
	if m == nil {
		return "", "", false
	}

	entry := m[1]
	for i := 0; i+1 < len(entry); i++ {
		if entry[i] != '-' {
			continue
		}
		c := entry[i+1]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			continue
		}
		name, version = entry[:i], entry[i+1:]
		break
	}

	// A kernel derivation is always <name>-<version>; an entry with no version
	// is not one, and reporting it as an installed kernel with no version would
	// put a nameless row in a list a policy compares versions across.
	if name == "" || version == "" {
		return "", "", false
	}

	// The initrd lives beside the kernel in the same shape. Only the kernel is
	// asked for here, but guard the name so a future caller cannot mistake one.
	if strings.HasPrefix(name, "initrd") {
		return "", "", false
	}

	return name, version, true
}

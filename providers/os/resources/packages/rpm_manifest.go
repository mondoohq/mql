// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// rpmManifestPath is the package manifest Azure Linux and CBL-Mariner
// distroless images carry in place of an rpm database. The image build writes
// it with
//
//	rpm -qa --qf "%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t%{EPOCH}\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}\n"
//
// container-manifest-1 next to it lists only name-version-release.arch.
const rpmManifestPath = "/var/lib/rpmmanifest/container-manifest-2"

const rpmManifestFields = 10

// parseRpmManifest reads container-manifest-2. A line that doesn't have the
// ten columns is skipped; a manifest that yields no package at all, empty or
// unreadable, is an error, not an image without packages.
func parseRpmManifest(pf *inventory.Platform, r io.Reader) ([]Package, error) {
	pkgs := []Package{}
	skipped := 0
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < rpmManifestFields || fields[0] == "" || fields[1] == "" {
			skipped++
			continue
		}
		name, versionRelease, arch := fields[0], fields[1], fields[7]
		epoch := normalizeRpmEpoch(fields[8])
		version := versionRelease
		if epoch != "" {
			version = epoch + ":" + versionRelease
		}
		installTime, _ := strconv.ParseInt(fields[2], 10, 64)

		pkg := newRpmPackage(pf, name, version, arch, epoch, cleanupVendorName(fields[4]), "", "", "", installTime)
		pkg.FilesAvailable = PkgFilesIncluded
		pkg.Files = []FileRecord{{Path: rpmManifestPath}}
		pkgs = append(pkgs, pkg)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	// The image build writes every installed package here, so an empty
	// manifest is a broken one, never an image without packages.
	if len(pkgs) == 0 {
		return nil, errors.New("could not parse any package in " + rpmManifestPath)
	}
	if skipped > 0 {
		log.Warn().Int("skipped", skipped).Str("path", rpmManifestPath).Msg("mql[packages]> skipped malformed rpm manifest lines")
	}
	return pkgs, nil
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/purl"
	"gopkg.in/yaml.v3"
)

const (
	SnapPkgFormat = "snap"
)

type SnapPkgManager struct {
	conn     shared.Connection
	platform *inventory.Platform
}

type snapListEntry struct {
	name    string
	version string
	rev     string
}

func (spm *SnapPkgManager) Name() string {
	return "Snap Package Manager"
}

func (spm *SnapPkgManager) Format() string {
	return SnapPkgFormat
}

func (spm *SnapPkgManager) List() ([]Package, error) {
	if spm.conn.Capabilities().Has(shared.Capability_RunCommand) {
		packages, err := spm.listFromCLI()
		if err == nil {
			return packages, nil
		}

		log.Debug().Err(err).Msg("mql[snap]> could not enumerate snaps via cli, falling back to filesystem")
	}

	return spm.listFromFS()
}

func (spm *SnapPkgManager) listFromCLI() ([]Package, error) {
	cmdResult, err := spm.conn.RunCommand("snap list")
	if err != nil {
		return nil, err
	}

	if cmdResult.ExitStatus != 0 {
		stderr := "unknown error"
		if cmdResult.Stderr != nil {
			stderrBytes, readErr := io.ReadAll(cmdResult.Stderr)
			if readErr == nil {
				stderr = strings.TrimSpace(string(stderrBytes))
				if stderr == "" {
					stderr = "unknown error"
				}
			}
		}

		return nil, fmt.Errorf("snap list failed: %s", stderr)
	}

	if cmdResult.Stdout == nil {
		return []Package{}, nil
	}

	entries, err := parseSnapListOutput(cmdResult.Stdout)
	if err != nil {
		return nil, err
	}

	afs := &afero.Afero{Fs: spm.conn.FileSystem()}
	pkgList := make([]Package, 0, len(entries))

	for _, entry := range entries {
		manifestPath := path.Join("/snap", entry.name, entry.rev, "meta", "snap.yaml")
		manifest, err := afs.Open(manifestPath)
		if err != nil {
			log.Debug().Err(err).Str("path", manifestPath).Msg("mql[snap]> could not open snap manifest from cli revision")
			continue
		}

		pkg, err := spm.parseSnapManifest(manifest)
		manifest.Close()
		if err != nil {
			log.Debug().Err(err).Str("path", manifestPath).Msg("mql[snap]> could not parse snap manifest from cli revision")
			continue
		}

		pkgList = append(pkgList, pkg)
	}

	return pkgList, nil
}

func parseSnapListOutput(input io.Reader) ([]snapListEntry, error) {
	scanner := bufio.NewScanner(input)
	entries := []snapListEntry{}
	firstNonEmptyLine := true

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		if firstNonEmptyLine {
			firstNonEmptyLine = false
			if len(fields) >= 3 && fields[0] == "Name" && fields[2] == "Rev" {
				continue
			}
		}

		if len(fields) < 3 {
			continue
		}

		entries = append(entries, snapListEntry{
			name:    fields[0],
			version: fields[1],
			rev:     fields[2],
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func (spm *SnapPkgManager) listFromFS() ([]Package, error) {
	afs := &afero.Afero{Fs: spm.conn.FileSystem()}
	const snapDir = "/snap"

	dirEntries, err := afs.ReadDir(snapDir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debug().Str("path", snapDir).Msg("cannot find snap dir")
			return []Package{}, nil
		}

		return nil, err
	}

	pkgList := []Package{}
	for _, entry := range dirEntries {
		name := entry.Name()
		currentManifestPath := path.Join(snapDir, name, "current", "meta", "snap.yaml")
		manifest, err := afs.Open(currentManifestPath)
		if err == nil {
			pkg, err := spm.parseSnapManifest(manifest)
			manifest.Close()
			if err != nil {
				log.Debug().Err(err).Str("path", currentManifestPath).Msg("mql[snap]> could not parse current snap manifest")
				continue
			}

			pkgList = append(pkgList, pkg)
			continue
		}

		if !os.IsNotExist(err) {
			log.Debug().Err(err).Str("path", currentManifestPath).Msg("mql[snap]> could not open current snap manifest")
			continue
		}

		revisionDir := path.Join(snapDir, name)
		revisionEntries, err := afs.ReadDir(revisionDir)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Debug().Err(err).Str("path", revisionDir).Msg("mql[snap]> could not inspect snap revisions")
			}
			continue
		}

		revisions := make([]int, 0, len(revisionEntries))
		for _, revisionEntry := range revisionEntries {
			if !revisionEntry.IsDir() {
				continue
			}

			revision, err := strconv.Atoi(revisionEntry.Name())
			if err != nil {
				continue
			}

			revisions = append(revisions, revision)
		}

		sort.Sort(sort.Reverse(sort.IntSlice(revisions)))
		for _, revision := range revisions {
			manifestPath := path.Join(snapDir, name, strconv.Itoa(revision), "meta", "snap.yaml")
			manifest, err := afs.Open(manifestPath)
			if err != nil {
				if !os.IsNotExist(err) {
					log.Debug().Err(err).Str("path", manifestPath).Msg("mql[snap]> could not open snap manifest from revision fallback")
				}
				continue
			}

			pkg, err := spm.parseSnapManifest(manifest)
			manifest.Close()
			if err != nil {
				log.Debug().Err(err).Str("path", manifestPath).Msg("mql[snap]> could not parse snap manifest from revision fallback")
				continue
			}

			pkgList = append(pkgList, pkg)
			break
		}
	}

	return pkgList, nil
}

// snapRefreshListCmd asks snapd which installed snaps the store has a newer
// revision of. snapd contacts the store for it; no root is needed.
const snapRefreshListCmd = "LC_ALL=C snap refresh --list"

// Available reports the snaps `snap refresh --list` would refresh.
//
// A host without the snap command has no update check, as before. A snap
// command that cannot answer, because snapd is down or the store is out of
// reach, is a failed check: nothing is known about the snaps' updates, which
// is not the same as all of them being current.
func (spm *SnapPkgManager) Available() (map[string]PackageUpdate, error) {
	if !spm.conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil, nil
	}

	cmd, err := spm.conn.RunCommand(snapRefreshListCmd)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrUpdateCheckFailed, snapRefreshListCmd, err)
	}
	if cmd.ExitStatus == 127 {
		return nil, nil
	}
	if cmd.ExitStatus != 0 {
		return nil, fmt.Errorf("%w: %s exited with status %d%s", ErrUpdateCheckFailed, snapRefreshListCmd, cmd.ExitStatus, aptStderr(cmd))
	}
	if cmd.Stdout == nil {
		return map[string]PackageUpdate{}, nil
	}
	updates, err := ParseSnapRefreshList(cmd.Stdout)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUpdateCheckFailed, err)
	}

	// An update is matched to the installed package by name and
	// architecture. snap does not print the architecture, so it comes from
	// the installed snap's manifest, as it does for List.
	afs := &afero.Afero{Fs: spm.conn.FileSystem()}
	for name, u := range updates {
		u.Arch = spm.installedArch(afs, name)
		updates[name] = u
	}
	return updates, nil
}

// installedArch returns the architecture the current revision of a snap
// declares, "" when its manifest cannot be read.
func (spm *SnapPkgManager) installedArch(afs *afero.Afero, name string) string {
	manifestPath := path.Join("/snap", name, "current", "meta", "snap.yaml")
	f, err := afs.Open(manifestPath)
	if err != nil {
		log.Debug().Err(err).Str("path", manifestPath).Msg("mql[snap]> could not open snap manifest for update")
		return ""
	}
	defer f.Close()
	pkg, err := spm.parseSnapManifest(f)
	if err != nil {
		log.Debug().Err(err).Str("path", manifestPath).Msg("mql[snap]> could not parse snap manifest for update")
		return ""
	}
	return pkg.Arch
}

// ParseSnapRefreshList reads the table `snap refresh --list` prints:
//
//	Name              Version         Rev    Size  Publisher    Notes
//	core20            20260901        2922   66MB  canonical**  base
//	snapd             2.77.1          28254  46MB  canonical**  snapd
//
// Version is the version a refresh would install. With nothing to refresh,
// snap prints "All snaps up to date." on stderr and nothing on stdout.
func ParseSnapRefreshList(input io.Reader) (map[string]PackageUpdate, error) {
	res := map[string]PackageUpdate{}
	scanner := bufio.NewScanner(input)
	header := true
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if header {
			header = false
			if fields[0] == "Name" && len(fields) > 1 && fields[1] == "Version" {
				continue
			}
		}
		if len(fields) < 2 {
			continue
		}
		res[fields[0]] = PackageUpdate{
			Name:      fields[0],
			Available: fields[1],
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

func (spm *SnapPkgManager) Files(name string, version string, arch string) ([]FileRecord, error) {
	return nil, nil
}

// SnapManifest represents the structure of a meta/snap.yaml file
type SnapManifest struct {
	Name          string   `yaml:"name"`
	Version       string   `yaml:"version"`
	Summary       string   `yaml:"summary"`
	Description   string   `yaml:"description"`
	Architectures []string `yaml:"architectures"`
}

// parseSnapManifest parses a snap manifest file and returns a package
func (spm *SnapPkgManager) parseSnapManifest(manifest io.Reader) (Package, error) {
	manifestBytes, err := io.ReadAll(manifest)
	if err != nil {
		return Package{}, err
	}

	var snapManifest SnapManifest
	if err := yaml.Unmarshal(manifestBytes, &snapManifest); err != nil {
		return Package{}, fmt.Errorf("failed to parse snap manifest: %w", err)
	}

	arch := ""
	if len(snapManifest.Architectures) > 0 {
		arch = snapManifest.Architectures[0]
	}

	return Package{
		Name:        snapManifest.Name,
		Version:     snapManifest.Version,
		Format:      SnapPkgFormat,
		Description: snapManifest.Description,
		Arch:        arch,
		PUrl: purl.NewPackageURL(
			spm.platform,
			purl.TypeSnap,
			snapManifest.Name,
			snapManifest.Version,
			purl.WithArch(arch),
		).String(),
	}, nil
}

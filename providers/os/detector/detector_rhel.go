// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"bufio"
	"bytes"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/parsers"
)

const (
	modulesDir = "/etc/dnf/modules.d"
	// TODO: Is this the same on newer rhel versions? DNF?
	reposDir = "/etc/yum.repos.d"
)

type RhelModule struct {
	Name  string
	State string
}

func getActivatedRhelModules(conn shared.Connection) []string {
	afs := &afero.Afero{Fs: conn.FileSystem()}
	ok, err := afs.DirExists(modulesDir)
	if err != nil || !ok {
		return []string{}
	}

	files, err := afs.ReadDir(modulesDir)
	if err != nil {
		return []string{}
	}

	modules := []string{}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".module") {
			continue
		}

		content, err := afs.ReadFile(filepath.Join(modulesDir, file.Name()))
		if err != nil {
			continue
		}

		module := RhelModule{}
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			s := strings.Split(scanner.Text(), "=")
			if len(s) != 2 {
				continue
			}

			switch strings.ToLower(s[0]) {
			case "name":
				module.Name = strings.TrimSpace(s[1])
			case "state":
				module.State = strings.TrimSpace(s[1])
			}
		}

		// We are only interested in enabled modules
		if module.State != "enabled" {
			continue
		}

		modules = append(modules, module.Name)
	}

	return modules
}

// getActivatedRhelSupportLevels returns the support level of the currently activated rhel repositories
// It currently detects the following support levels:
//   - eus (Extended Update Support)
//   - e4s (Enhanced Extended Update Support)
//   - els (Extended Life Cycle Support)
func getActivatedRhelSupportLevels(conn shared.Connection) []string {
	afs := &afero.Afero{Fs: conn.FileSystem()}
	ok, err := afs.DirExists(reposDir)
	if err != nil || !ok {
		return []string{}
	}

	files, err := afs.ReadDir(reposDir)
	if err != nil {
		return []string{}
	}

	supportLevels := []string{}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".repo") {
			continue
		}

		content, err := afs.ReadFile(filepath.Join(reposDir, file.Name()))
		if err != nil {
			continue
		}

		repoIni := parsers.ParseIni(string(content), "=")
		if repoIni == nil {
			continue
		}

		for section, fields := range repoIni.Fields {
			supportLevel := ""
			switch {
			case strings.Contains(section, "baseos-e4s-"):
				supportLevel = "e4s"
			case strings.Contains(section, "baseos-eus-"):
				supportLevel = "eus"
			// ELS repo IDs differ by major version: RHEL 7 uses
			// rhel-7-server-els-rpms, RHEL 8+ uses rhel-8-for-x86_64-baseos-els-rpms.
			// Both share the "-els-" segment, as do their RHUI and debug/source
			// variants. The trailing dash keeps "els" a whole segment so repo IDs
			// that merely contain the letters (e.g. "-elsewhere-") don't match.
			case strings.Contains(section, "-els-"):
				supportLevel = "els"
			}
			if supportLevel == "" {
				continue
			}
			if subFieldsMap, ok := fields.(map[string]interface{}); ok {
				if enabled, ok := subFieldsMap["enabled"]; ok {
					if v, ok := enabled.(string); ok && v == "1" {
						supportLevels = append(supportLevels, supportLevel)
					}
				}
			}
		}
	}

	slices.Sort(supportLevels)
	supportLevels = slices.Compact(supportLevels)

	return supportLevels
}

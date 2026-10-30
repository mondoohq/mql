// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/parsers"
)

// hasOracleELSEnabled checks whether any Oracle Linux Extended Lifecycle Support (ELS)
// repository is enabled. Oracle ELS repos have section names with an _ELS suffix,
// e.g. ol7_latest_ELS, ol7_UEKR6_ELS.
func hasOracleELSEnabled(conn shared.Connection) bool {
	afs := &afero.Afero{Fs: conn.FileSystem()}
	ok, err := afs.DirExists(reposDir)
	if err != nil || !ok {
		return false
	}

	files, err := afs.ReadDir(reposDir)
	if err != nil {
		return false
	}

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
			if !strings.HasSuffix(section, "_ELS") {
				continue
			}
			if subFieldsMap, ok := fields.(map[string]any); ok {
				if enabled, ok := subFieldsMap["enabled"]; ok {
					if v, ok := enabled.(string); ok && v == "1" {
						return true
					}
				}
			}
		}
	}

	return false
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// firefoxAddonKey identifies one addon in one profile. The profile is named
// by its directory, not its name: every Linux profile root is called
// "Firefox", and a profile copied from one root to another (the deb to snap
// and rpm to flatpak migrations do this) keeps its directory name.
func firefoxAddonKey(user, browser, profileDir, addonID string) string {
	return user + "|" + browser + "|" + profileDir + "|" + addonID
}

// firefoxAbsoluteProfiles returns the profiles a profiles.ini registers with
// an absolute path (IsRelative=0), as `firefox -CreateProfile "name <dir>"`
// and the profile manager's "Choose Folder" write them. Those live outside
// the profile root, so a search of the root does not find them.
func firefoxAbsoluteProfiles(ini string) []string {
	var out []string
	inProfile, absolute := false, false
	profilePath := ""
	flush := func() {
		if inProfile && absolute && isAbsoluteProfilePath(profilePath) {
			out = append(out, profilePath)
		}
		inProfile, absolute, profilePath = false, false, ""
	}
	for _, line := range strings.Split(ini, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			flush()
			inProfile = strings.HasPrefix(line, "[Profile")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "IsRelative":
			absolute = strings.TrimSpace(value) == "0"
		case "Path":
			profilePath = strings.TrimSpace(value)
		}
	}
	flush()
	return out
}

// isAbsoluteProfilePath accepts a Unix path or a Windows drive or UNC path.
func isAbsoluteProfilePath(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

// firefoxAbsoluteProfileFiles returns the extensions.json of each profile
// that browserDir's profiles.ini registers with an absolute path, skipping
// those already found under browserDir.
func firefoxAbsoluteProfileFiles(runtime *plugin.Runtime, afs *afero.Afero, browserDir string, found []any) []any {
	data, err := afs.ReadFile(filepath.Join(browserDir, "profiles.ini"))
	if err != nil {
		return nil
	}
	known := map[string]bool{}
	for _, f := range found {
		if file, ok := f.(*mqlFile); ok {
			known[file.GetPath().Data] = true
		}
	}
	var out []any
	for _, dir := range firefoxAbsoluteProfiles(string(data)) {
		p := filepath.Join(dir, "extensions.json")
		if known[p] {
			continue
		}
		if ok, err := afs.Exists(p); err != nil || !ok {
			continue
		}
		file, err := CreateResource(runtime, "file", map[string]*llx.RawData{"path": llx.StringData(p)})
		if err != nil {
			log.Debug().Err(err).Str("path", p).Msg("could not read Firefox profile outside the profile root")
			continue
		}
		known[p] = true
		out = append(out, file)
	}
	return out
}

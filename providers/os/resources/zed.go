// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/tailscale/hujson"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"

	_ "github.com/glebarez/go-sqlite" // registers the "sqlite" database/sql driver
)

func initZed(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initOSConfigPath(runtime, args, "zed", zedConfigDir)
}

// zedConfigDir returns where Zed keeps settings.json, relative to the user's
// home. Zed's paths::config_dir() uses the roaming application-data directory
// on Windows and ~/.config/zed everywhere else, macOS included.
func zedConfigDir(osFamily string) string {
	if osFamily == "windows" {
		return filepath.Join("AppData", "Roaming", "Zed")
	}
	return filepath.Join(".config", "zed")
}

func (r *mqlZed) id() (string, error) {
	return "zed/" + r.ConfigPath.Data, nil
}

func (r *mqlZed) settings() (any, error) {
	afs := connectionAfs(r.MqlRuntime)
	data, err := afs.ReadFile(filepath.Join(r.ConfigPath.Data, "settings.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}

	// Zed's settings.json is JSONC (allows // and /* */ comments, trailing commas).
	// Use hujson to normalize to standard JSON before parsing.
	clean, err := hujson.Standardize(data)
	if err != nil {
		return nil, err
	}
	var settings map[string]any
	if err := json.Unmarshal(clean, &settings); err != nil {
		return nil, err
	}
	return redactSettings(settings), nil
}

// zedAgentSettings captures the default model configured for Zed's agent.
// Recent Zed versions store this under `agent`; older ones under `assistant`.
type zedAgentSettings struct {
	DefaultModel struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
	} `json:"default_model"`
}

// mqlZedInternal caches the parsed default-model settings so that model()
// and modelProvider() do not each re-read settings.json.
type mqlZedInternal struct {
	modelOnce      sync.Once
	cachedProvider string
	cachedModel    string
	cachedModelErr error
}

// defaultModel returns the configured default agent model and its provider,
// preferring the current `agent` key and falling back to the legacy
// `assistant` key. Empty strings when unset or when no settings file exists.
// The result is parsed once and cached for the resource's lifetime.
func (r *mqlZed) defaultModel() (provider string, model string, err error) {
	r.modelOnce.Do(func() {
		r.cachedProvider, r.cachedModel, r.cachedModelErr = r.readDefaultModel()
	})
	return r.cachedProvider, r.cachedModel, r.cachedModelErr
}

func (r *mqlZed) readDefaultModel() (provider string, model string, err error) {
	afs := connectionAfs(r.MqlRuntime)
	data, err := afs.ReadFile(filepath.Join(r.ConfigPath.Data, "settings.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", nil
		}
		return "", "", err
	}
	clean, err := hujson.Standardize(data)
	if err != nil {
		return "", "", err
	}
	var settings struct {
		Agent     zedAgentSettings `json:"agent"`
		Assistant zedAgentSettings `json:"assistant"`
	}
	if err := json.Unmarshal(clean, &settings); err != nil {
		return "", "", err
	}
	dm := settings.Agent.DefaultModel
	if dm.Model == "" && dm.Provider == "" {
		dm = settings.Assistant.DefaultModel
	}
	return dm.Provider, dm.Model, nil
}

func (r *mqlZed) model() (string, error) {
	_, model, err := r.defaultModel()
	return model, err
}

func (r *mqlZed) modelProvider() (string, error) {
	provider, _, err := r.defaultModel()
	return provider, err
}

func (r *mqlZed) extensions() ([]any, error) {
	afs := connectionAfs(r.MqlRuntime)
	extensionsDir := filepath.Join(r.ConfigPath.Data, "extensions")

	data, err := afs.ReadFile(filepath.Join(extensionsDir, "installed.json"))
	if err != nil {
		if os.IsNotExist(err) {
			// Fallback: scan extensions directory for subdirectories
			return zedExtensionsFromDir(afs, extensionsDir)
		}
		return nil, err
	}

	// installed.json contains extension names
	var installed map[string]json.RawMessage
	if err := json.Unmarshal(data, &installed); err != nil {
		return zedExtensionsFromDir(afs, extensionsDir)
	}

	var result []any
	for name := range installed {
		result = append(result, name)
	}
	return result, nil
}

// zedExtensionsFromDir lists extension names by scanning subdirectories.
func zedExtensionsFromDir(afs *afero.Afero, extensionsDir string) ([]any, error) {
	subdirs, err := listSubdirsAfero(afs, extensionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []any
	for _, dir := range subdirs {
		result = append(result, dir.name)
	}
	return result, nil
}

func (r *mqlZedRepo) id() (string, error) {
	return "zed.repo/" + r.Path.Data, nil
}

func (r *mqlZed) repos() ([]any, error) {
	paths, err := r.workspacePaths()
	if err != nil {
		return nil, err
	}
	return gitReposFromPaths(r.MqlRuntime, "zed.repo", paths)
}

// zedDataDir returns the platform-specific data directory Zed stores its
// workspace database under, given a user home. This is distinct from the
// configPath (see zedConfigDir) the resource resolves for settings.
func zedDataDir(home, osFamily string) string {
	switch osFamily {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Zed")
	case "windows":
		return filepath.Join(home, "AppData", "Local", "Zed")
	default: // linux and other unix-likes
		return filepath.Join(home, ".local", "share", "zed")
	}
}

// workspacePaths returns the deduplicated on-disk workspace paths recorded in
// Zed's workspace database(s), across every user on the target. Zed stores
// these in a SQLite DB at <dataDir>/db/<version>/db.sqlite; the paths live in
// the workspaces table as a binary blob, so they are recovered best-effort by
// extracting absolute-path substrings (see extractZedPaths). Unreadable or
// missing databases are skipped.
func (r *mqlZed) workspacePaths() ([]string, error) {
	conn := r.MqlRuntime.Connection.(shared.Connection)
	osFamily := targetOSFamily(conn)
	afs := connectionAfs(r.MqlRuntime)

	users, err := targetUserHomes(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var paths []string
	for _, u := range users {
		dbParent := filepath.Join(zedDataDir(u.home, osFamily), "db")
		dbDirs, err := listSubdirsAfero(afs, dbParent)
		if err != nil {
			continue
		}
		for _, d := range dbDirs {
			dbPath := filepath.Join(d.path, "db.sqlite")
			for _, p := range readZedWorkspacePaths(afs, dbPath) {
				if _, ok := seen[p]; ok {
					continue
				}
				seen[p] = struct{}{}
				paths = append(paths, p)
			}
		}
	}
	return paths, nil
}

// readZedWorkspacePaths copies the Zed SQLite database to a local temp file
// (the DB may live on a remote connection), reads every column of the
// workspaces table, and extracts absolute-path substrings from each value. The
// paths column is a version-specific binary blob, so extraction is heuristic;
// non-repository paths are filtered out later by resolving each against
// .git/config. Returns nil on any read/query failure.
func readZedWorkspacePaths(afs *afero.Afero, dbPath string) []string {
	data, err := afs.ReadFile(dbPath)
	if err != nil {
		return nil
	}

	tmp, err := os.CreateTemp("", "zed-*.sqlite")
	if err != nil {
		log.Debug().Err(err).Msg("cannot create temp file for zed db")
		return nil
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return nil
	}
	tmp.Close()

	db, err := sql.Open("sqlite", "file:"+tmp.Name()+"?mode=ro&immutable=1")
	if err != nil {
		log.Debug().Err(err).Msg("cannot open zed db")
		return nil
	}
	defer db.Close()

	rows, err := db.Query("SELECT * FROM workspaces")
	if err != nil {
		log.Debug().Err(err).Msg("cannot query zed workspaces table")
		return nil
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil
	}

	var out []string
	for rows.Next() {
		raw := make([]sql.RawBytes, len(cols))
		dest := make([]any, len(cols))
		for i := range raw {
			dest[i] = &raw[i]
		}
		if err := rows.Scan(dest...); err != nil {
			continue
		}
		for _, rb := range raw {
			out = append(out, extractZedPaths(rb)...)
		}
	}
	return out
}

// extractZedPaths pulls absolute-path substrings out of a raw column value.
// Zed serializes workspace paths as a binary blob rather than plain text, so
// this scans for maximal printable-ASCII runs and returns the absolute paths
// found within them. Over-extraction is harmless: callers resolve each path
// against .git/config and drop anything that is not a git working tree.
func extractZedPaths(blob []byte) []string {
	var out []string
	start := -1
	for i := 0; i <= len(blob); i++ {
		printable := i < len(blob) && blob[i] >= 0x20 && blob[i] < 0x7f
		if printable {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if p := zedCandidatePath(string(blob[start:i])); p != "" {
				out = append(out, p)
			}
			start = -1
		}
	}
	return out
}

// zedCandidatePath extracts a leading absolute path from a printable run,
// returning "" when the run contains none. It finds the first '/' or Windows
// drive prefix and trims trailing delimiter punctuation.
func zedCandidatePath(run string) string {
	idx := -1
	for i := 0; i < len(run); i++ {
		if run[i] == '/' {
			idx = i
			break
		}
		if i+2 < len(run) && run[i+1] == ':' && (run[i+2] == '/' || run[i+2] == '\\') &&
			((run[i] >= 'A' && run[i] <= 'Z') || (run[i] >= 'a' && run[i] <= 'z')) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ""
	}
	p := strings.TrimRight(run[idx:], "\"',]}> \t")
	if len(p) < 2 {
		return ""
	}
	return p
}

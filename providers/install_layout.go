// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/v13/cli/config"
	"go.mondoo.com/mql/v13/providers/core/resources/versions/semver"
)

// Robust provider layout
//
// Historically a provider lived flat in <providers>/<name>/, holding the
// binary and its two JSON files. Overwriting those files in place during an
// update is not atomic and leaves no way back if the new version is broken.
//
// The robust layout installs each version into its own directory and records
// the active one in a small pointer file:
//
//	<providers>/<name>/
//	  .current                     <- text file containing the active version
//	  13.4.1/                       <- one directory per installed version
//	    <name> <name>.json <name>.resources.json
//	  13.4.2/
//	    ...
//
// Activation is a single atomic rename of the pointer file, so a crash can
// never expose a half-installed version, and rollback is just re-pointing at
// the previous version directory (which is kept, not overwritten).
//
// The reader is backward compatible: a container without a .current pointer
// but with the flat files directly inside it is treated as a legacy install
// and used as-is, so existing installations keep working until their next
// update migrates them to the versioned layout.

const (
	// currentPointerFile names the active-version pointer inside a provider's
	// container directory. Leading dot keeps it out of the version-directory
	// listing and signals "not a provider payload".
	currentPointerFile = ".current"

	// stagingDirPrefix marks an in-progress version directory. A crash during
	// staging leaves a .staging-* directory that the reader ignores and the
	// next install cleans up.
	stagingDirPrefix = ".staging-"

	// defaultKeepVersions is how many installed versions we retain per provider
	// (the active one plus this many previous, for rollback). Older versions
	// are pruned after a successful activation.
	defaultKeepVersions = 2
)

// providerKeepVersions is the effective retention count applied when an
// InstallConf does not specify one. It lets a long-running host (e.g. serve)
// configure retention globally without threading InstallConf through every
// call site. Zero means "use defaultKeepVersions". It is atomic so a
// configure-at-startup goroutine and a concurrent install cannot race.
var providerKeepVersions atomic.Int32

// SetKeepVersions sets the global provider version retention count used when an
// install does not specify its own. Values below 1 are ignored.
func SetKeepVersions(n int) {
	if n >= 1 {
		providerKeepVersions.Store(int32(n))
	}
}

// providerContainerDir returns <dst>/<name>, the directory that holds all
// installed versions of a provider plus its pointer file.
func providerContainerDir(dst, name string) string {
	return filepath.Join(dst, name)
}

// readCurrentPointer returns the active version recorded in a container's
// pointer file, or ("", false) if there is no pointer.
func readCurrentPointer(containerDir string) (string, bool) {
	data, err := afero.ReadFile(config.AppFs, filepath.Join(containerDir, currentPointerFile))
	if err != nil {
		return "", false
	}
	v := strings.TrimSpace(string(data))
	if v == "" {
		return "", false
	}
	return v, true
}

// resolveActiveDir returns the directory to read a provider's payload from and
// whether that payload uses the legacy flat layout. Resolution order:
//
//  1. If a .current pointer names a version directory that actually contains
//     the provider's config JSON, use that directory.
//  2. Otherwise, if the container itself holds the flat <name>.json, treat it
//     as a legacy install and use the container directory.
//  3. Otherwise there is no usable provider; return ok=false.
//
// name is the provider name (the container's base name); the caller passes it
// explicitly because the resolved directory may be a version subdirectory
// whose own base name is the version, not the provider.
func resolveActiveDir(containerDir, name string) (dir string, legacy bool, ok bool) {
	confName := name + ".json"

	if version, has := readCurrentPointer(containerDir); has {
		vdir := filepath.Join(containerDir, version)
		if config.ProbeFile(filepath.Join(vdir, confName)) {
			return vdir, false, true
		}
		// A dangling pointer (version dir missing or incomplete) is a real
		// problem worth surfacing, but we still fall back to any legacy flat
		// payload so the provider keeps working.
		log.Warn().
			Str("provider", name).
			Str("version", version).
			Msg("provider .current pointer is dangling, falling back")
	}

	if config.ProbeFile(filepath.Join(containerDir, confName)) {
		return containerDir, true, true
	}

	return "", false, false
}

// writeCurrentPointerAtomic records version as the active version for the
// container. It writes a temporary file and renames it over the pointer, which
// is atomic on a single filesystem on every supported OS (Go's os.Rename maps
// to MoveFileEx with REPLACE_EXISTING on Windows).
func writeCurrentPointerAtomic(containerDir, version string) error {
	pointer := filepath.Join(containerDir, currentPointerFile)
	tmp := pointer + ".tmp"

	f, err := os.Create(tmp)
	if err != nil {
		return errors.Wrap(err, "failed to write provider pointer")
	}
	if _, err := f.WriteString(version + "\n"); err != nil {
		f.Close()
		os.Remove(tmp)
		return errors.Wrap(err, "failed to write provider pointer")
	}
	// Flush the pointer contents before the rename so a crash can't leave the
	// renamed pointer referencing unwritten (zeroed) bytes.
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return errors.Wrap(err, "failed to flush provider pointer")
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return errors.Wrap(err, "failed to close provider pointer")
	}

	if err := osRetry(func() error { return os.Rename(tmp, pointer) }, maxInstallConfRetries); err != nil {
		os.Remove(tmp)
		return errors.Wrap(err, "failed to activate provider pointer")
	}
	syncDir(containerDir)
	return nil
}

// listInstalledVersions returns the version directories inside a container
// (those holding the provider's config JSON), highest version first. Staging
// and pointer entries are skipped.
//
// Ordering is by semantic version, not modification time: install directories
// created in the same operation can share an mtime (and on fast filesystems
// often do), which would make an mtime-based order nondeterministic and let
// prune keep the wrong versions. Provider versions increase over time, so
// semver-descending is both deterministic and a faithful "newest first".
func listInstalledVersions(containerDir, name string) []string {
	entries, err := afero.ReadDir(config.AppFs, containerDir)
	if err != nil {
		return nil
	}
	confName := name + ".json"

	var versions []string
	for _, e := range entries {
		// Dot-prefixed entries (the .current pointer and .staging-* dirs) are
		// never versions.
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if !config.ProbeFile(filepath.Join(containerDir, e.Name(), confName)) {
			continue
		}
		versions = append(versions, e.Name())
	}

	sv := semver.Parser{}
	sort.Slice(versions, func(i, j int) bool {
		cmp, err := sv.Compare(versions[i], versions[j])
		if err != nil {
			// Unparseable versions fall back to a stable string order so the
			// result is still deterministic.
			return versions[i] > versions[j]
		}
		return cmp > 0
	})
	return versions
}

// pruneOldVersions removes installed version directories beyond the newest
// keep, never removing any version in protect (the active version and, during
// an update, the one being replaced). It is best-effort: a failure to remove
// an old directory is logged, not fatal, because the active version is already
// committed by the time we prune.
func pruneOldVersions(containerDir, name string, keep int, protect ...string) {
	if keep < 1 {
		keep = 1
	}
	protected := map[string]struct{}{}
	for _, p := range protect {
		if p != "" {
			protected[p] = struct{}{}
		}
	}

	// versions is newest-first. Keep the newest `keep` outright; beyond the
	// window remove anything that is not protected. Protected versions (the
	// active one and the one just replaced) are never removed even when they
	// fall outside the window, so rollback is always possible.
	versions := listInstalledVersions(containerDir, name)

	for i, v := range versions {
		if i < keep {
			continue
		}
		if _, isProtected := protected[v]; isProtected {
			continue
		}
		dir := filepath.Join(containerDir, v)
		if err := osRetry(func() error { return os.RemoveAll(dir) }, maxInstallConfRetries); err != nil {
			log.Warn().Err(err).Str("provider", name).Str("version", v).Msg("failed to prune old provider version")
		} else {
			log.Debug().Str("provider", name).Str("version", v).Msg("pruned old provider version")
		}
	}
}

// cleanupStagingDirs removes leftover staging directories from interrupted
// installs. Best-effort.
func cleanupStagingDirs(containerDir string) {
	entries, err := afero.ReadDir(config.AppFs, containerDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), stagingDirPrefix) {
			_ = os.RemoveAll(filepath.Join(containerDir, e.Name()))
		}
	}
}

// readProviderVersion reads the version string out of a staged provider config
// JSON. The version names the install directory, so it must be present.
func readProviderVersion(jsonPath string) (string, error) {
	data, err := afero.ReadFile(config.AppFs, jsonPath)
	if err != nil {
		return "", err
	}
	var meta struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", errors.Wrap(err, "failed to parse provider config")
	}
	version := strings.TrimSpace(meta.Version)
	if version == "" {
		return "", errors.New("provider config has no version")
	}
	return version, nil
}

// removeLegacyFlatFiles deletes the old flat-layout payload files from a
// container root after a versioned install has taken over. Once a .current
// pointer exists these files are shadowed; removing them keeps the container
// clean and avoids confusion. Best-effort.
func removeLegacyFlatFiles(containerDir, providerName, binName string) {
	for _, f := range []string{binName, providerName + ".json", providerName + ".resources.json"} {
		p := filepath.Join(containerDir, f)
		if config.ProbeFile(p) {
			if err := os.Remove(p); err != nil {
				log.Debug().Err(err).Str("path", p).Msg("failed to remove legacy flat provider file")
			}
		}
	}
}

// commitProviderVersion installs one provider from the unpacked staging tree
// (tmpdir) into its own version directory, health-checks the new binary, and
// atomically activates it by writing the .current pointer. On any failure
// before activation the previously active version is left completely
// untouched, so a bad download or a binary that will not start can never
// replace a working provider. It returns the provider's container directory,
// whose pointer now names the newly activated version.
//
// binName is the file name of the binary as it appears in the archive (with
// the .exe suffix on Windows); providerName is that name without the suffix.
func commitProviderVersion(tmpdir string, conf InstallConf, binName, providerName string) (string, error) {
	// The version names the install directory; read it from the staged config
	// before anything is moved.
	version, err := readProviderVersion(filepath.Join(tmpdir, providerName+".json"))
	if err != nil {
		return "", errors.Wrap(err, "failed to determine version for provider "+providerName)
	}

	containerDir := providerContainerDir(conf.Dst, providerName)
	if err := os.MkdirAll(containerDir, 0o755); err != nil {
		return "", err
	}
	cleanupStagingDirs(containerDir)

	// Remember what we are replacing so prune keeps the rollback target.
	previousVersion, _ := readCurrentPointer(containerDir)

	// Stage into a hidden directory first so a crash mid-move never presents a
	// complete-looking version directory to the reader.
	stagingDir := filepath.Join(containerDir, stagingDirPrefix+version)
	if err := os.RemoveAll(stagingDir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return "", err
	}

	// Move the binary and its two JSON files into the staging directory,
	// flushing each to disk as the original install did (the per-file Sync
	// happened during extraction; the directory sync happens below).
	moves := []struct{ src, dst string }{
		{filepath.Join(tmpdir, binName), filepath.Join(stagingDir, binName)},
		{filepath.Join(tmpdir, providerName+".json"), filepath.Join(stagingDir, providerName+".json")},
		{filepath.Join(tmpdir, providerName+".resources.json"), filepath.Join(stagingDir, providerName+".resources.json")},
	}
	// The binary move gets the long retry window (antivirus scans on Windows);
	// the small JSON files get the shorter one.
	maxRetry := maxInstallBinaryRetries
	for _, m := range moves {
		src, dst := m.src, m.dst
		if err := osRetry(func() error { return os.Rename(src, dst) }, maxRetry); err != nil {
			os.RemoveAll(stagingDir)
			return "", err
		}
		maxRetry = maxInstallConfRetries
	}

	stagedBin := filepath.Join(stagingDir, binName)
	if err := os.Chmod(stagedBin, 0o755); err != nil {
		os.RemoveAll(stagingDir)
		return "", err
	}
	syncDir(stagingDir)

	// Health-check gate: prove the freshly staged binary actually starts before
	// activating it. A version that fails to launch never becomes current.
	if !conf.SkipHealthCheck {
		if err := healthCheckProvider(stagedBin); err != nil {
			os.RemoveAll(stagingDir)
			return "", errors.Wrap(err, "provider "+providerName+"-"+version+" failed its health check")
		}
	}

	// Promote staging -> version directory. A reinstall of the same version
	// replaces the existing directory.
	versionDir := filepath.Join(containerDir, version)
	if err := os.RemoveAll(versionDir); err != nil {
		os.RemoveAll(stagingDir)
		return "", err
	}
	if err := osRetry(func() error { return os.Rename(stagingDir, versionDir) }, maxInstallConfRetries); err != nil {
		os.RemoveAll(stagingDir)
		return "", err
	}
	syncDir(containerDir)

	// Atomic activation: this single rename is the commit point.
	if err := writeCurrentPointerAtomic(containerDir, version); err != nil {
		// The new version is on disk but not active; the previous pointer (if
		// any) still governs, so nothing is broken. Surface the error.
		return "", err
	}

	// Migrate away from a legacy flat install now that the pointer governs.
	removeLegacyFlatFiles(containerDir, providerName, binName)

	keep := conf.KeepVersions
	if keep <= 0 {
		keep = int(providerKeepVersions.Load())
	}
	if keep <= 0 {
		keep = defaultKeepVersions
	}
	pruneOldVersions(containerDir, providerName, keep, version, previousVersion)

	return containerDir, nil
}

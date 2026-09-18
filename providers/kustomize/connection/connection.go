// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"sigs.k8s.io/kustomize/api/types"
	"sigs.k8s.io/kustomize/kyaml/filesys"
)

// ErrNoKustomization is the sentinel returned by loadSingleKustomization
// when the directory has none of the recognized kustomization filenames.
// Callers use errors.Is to distinguish "look elsewhere" from a real
// parse failure on a file that exists.
var ErrNoKustomization = errors.New("no kustomization file found")

var (
	_ plugin.Connection = (*KustomizeConnection)(nil)
	_ plugin.Closer     = (*KustomizeConnection)(nil)
)

type KustomizeConnection struct {
	plugin.Connection
	Conf           *inventory.Config
	asset          *inventory.Asset
	path           string
	kustomizations []*KustomizationEntry
	closer         func()
}

// KustomizationEntry holds a parsed kustomization and its directory path.
type KustomizationEntry struct {
	Path          string
	Kustomization *types.Kustomization
}

func NewKustomizeConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*KustomizeConnection, error) {
	if asset == nil || len(asset.Connections) == 0 {
		return nil, errors.New("kustomize provider requires an asset with at least one connection")
	}

	conn := &KustomizeConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	// If a git clone is performed below, clean up the temporary directory on any
	// error path. Close() is a no-op when nothing was cloned, and the guard is
	// disarmed once the connection is returned and takes ownership of cleanup.
	cleanupClone := true
	defer func() {
		if cleanupClone {
			conn.Close()
		}
	}()

	cc := asset.Connections[0]
	kustomizePath := cc.Options["path"]
	// When discovered from a git repository (e.g. by the GitHub provider) the
	// asset carries the repo URL plus a repo-relative path to the kustomization
	// directory. Clone the repo and resolve the directory within the checkout.
	// The path option is kept relative so the detector can name the asset from
	// the repo rather than the temporary clone directory.
	if _, ok := cc.Options["http-url"]; ok {
		clonePath, closer, err := plugin.NewGitClone(asset)
		if err != nil {
			return nil, err
		}
		conn.closer = closer
		kustomizePath = filepath.Join(clonePath, kustomizePath)
	}
	if kustomizePath == "" {
		return nil, errors.New("kustomize provider requires a 'path' option")
	}
	conn.path = filepath.Clean(kustomizePath)

	// Discover from the cleaned path so entry.Path matches conn.path and
	// downstream cache keys (kustomize.kustomization:<path>) are stable
	// across "./foo" vs "./foo/" inputs.
	entries, err := loadKustomizations(conn.path)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no kustomization file found at %s: %w", conn.path, plugin.ErrNoMatch)
	}
	conn.kustomizations = entries

	cleanupClone = false
	return conn, nil
}

// Close cleans up any temporary directory created by a git clone.
func (c *KustomizeConnection) Close() {
	if c.closer != nil {
		c.closer()
	}
}

func (c *KustomizeConnection) Name() string {
	return "kustomize"
}

func (c *KustomizeConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *KustomizeConnection) Kustomizations() []*KustomizationEntry {
	return c.kustomizations
}

func (c *KustomizeConnection) Path() string {
	return c.path
}

// kustomizationFilenames are the recognized filenames for kustomization files.
var kustomizationFilenames = []string{
	"kustomization.yaml",
	"kustomization.yml",
	"Kustomization",
}

// scanSkipDirs are subdir names that should not be scanned during
// kustomization discovery. Hidden dirs (starting with `.`) are also
// skipped — they're handled separately via the prefix check.
var scanSkipDirs = map[string]struct{}{
	"node_modules": {},
	"vendor":       {},
	"target":       {},
	"dist":         {},
	"build":        {},
}

// maxScanDepth bounds the recursive subdirectory scan so a path aimed at a
// large monorepo root (with no kustomization anywhere near the top) can't walk
// the entire tree. The canonical base/overlays/<env>[/<region>] layouts sit
// well within this depth.
const maxScanDepth = 10

// loadKustomizations finds and parses kustomization files from a path.
func loadKustomizations(kustomizePath string) ([]*KustomizationEntry, error) {
	fi, err := os.Stat(kustomizePath)
	if err != nil {
		return nil, err
	}

	if !fi.IsDir() {
		return nil, fmt.Errorf("kustomize path must be a directory: %s: %w", kustomizePath, plugin.ErrNoMatch)
	}

	// Check if this directory has a kustomization file.
	// "no kustomization file found" → fall through to subdir scan.
	// Any other error (malformed YAML, unreadable file) is a real
	// failure the caller should see, not silently swallow.
	entry, err := loadSingleKustomization(kustomizePath)
	if err == nil {
		return []*KustomizationEntry{entry}, nil
	}
	if !errors.Is(err, ErrNoKustomization) {
		return nil, err
	}

	// Otherwise scan subdirectories recursively. A one-level scan silently
	// missed the canonical Kustomize layout (base/ next to overlays/<env>/),
	// where the actual deployment overlays live two levels below the repo
	// root — the tool would find only the base and drop every overlay.
	var entries []*KustomizationEntry
	if err := scanForKustomizations(kustomizePath, 0, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// scanForKustomizations walks subdirectories of dir looking for kustomization
// files. A directory that itself contains a kustomization owns its whole
// subtree (its resources and overlays are its own concern), so the scan
// records it and does not descend into it; only kustomization-free glue
// directories (e.g. overlays/) are recursed through to reach nested overlays.
func scanForKustomizations(dir string, depth int, entries *[]*KustomizationEntry) error {
	if depth > maxScanDepth {
		return nil
	}

	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		// The root directory not being readable is a real failure the caller
		// should see; a single unreadable subdir deeper in the tree should
		// not abort discovery of everything else.
		if depth == 0 {
			return err
		}
		log.Warn().Err(err).Str("path", dir).Msg("failed to read directory during kustomization scan; skipping")
		return nil
	}

	for _, de := range dirEntries {
		if !de.IsDir() {
			continue
		}
		name := de.Name()
		// Skip hidden dirs (.git, .terraform, .idea, etc.) and a
		// short skip-list of well-known noise dirs. A misconfigured
		// path on a repo root would otherwise spend file handles on
		// directories that can't contain a kustomization.
		if strings.HasPrefix(name, ".") {
			continue
		}
		if _, skip := scanSkipDirs[name]; skip {
			continue
		}
		subPath := filepath.Join(dir, name)
		entry, err := loadSingleKustomization(subPath)
		switch {
		case err == nil:
			// Found a kustomization here; this directory owns its subtree,
			// so don't descend further into it.
			*entries = append(*entries, entry)
		case errors.Is(err, ErrNoKustomization):
			// No kustomization at this level; descend to find nested overlays.
			if err := scanForKustomizations(subPath, depth+1, entries); err != nil {
				return err
			}
		default:
			// A file exists but won't parse: loud warning, then skip.
			log.Warn().Err(err).Str("path", subPath).Msg("failed to load kustomization; skipping")
		}
	}

	return nil
}

func loadSingleKustomization(dir string) (*KustomizationEntry, error) {
	fSys := filesys.MakeFsOnDisk()

	// Count every recognized filename rather than taking the first that
	// reads. Kustomize's own loader (target.LoadKustFile) hard-errors on more
	// than one match, so a directory holding both kustomization.yaml and
	// Kustomization can never be built. Picking one of them reported that
	// file's static fields while the resources accessor failed with krusty's
	// error, presenting the directory as half-valid.
	var data []byte
	matched := make([]string, 0, len(kustomizationFilenames))
	for _, filename := range kustomizationFilenames {
		filePath := filepath.Join(dir, filename)
		content, err := fSys.ReadFile(filePath)
		if err != nil {
			continue
		}
		matched = append(matched, filename)
		data = content
	}

	switch len(matched) {
	case 0:
		return nil, ErrNoKustomization
	case 1:
		k := &types.Kustomization{}
		if err := k.Unmarshal(data); err != nil {
			return nil, err
		}
		// Unmarshal leaves deprecated field aliases in their legacy slots.
		// FixKustomization reconciles them into the modern fields: bases into
		// resources, imageTags into images, and the singular env into a
		// generator's envs. Without it the raw-field accessors (resourceRefs,
		// images, and a generator's envs) silently omit entries declared with
		// the older syntax. This only affects our in-memory view; rendering
		// runs krusty against the filesystem path independently.
		k.FixKustomization()
		return &KustomizationEntry{
			Path:          dir,
			Kustomization: k,
		}, nil
	default:
		return nil, fmt.Errorf("found multiple kustomization files under %s: %s",
			dir, strings.Join(matched, ", "))
	}
}

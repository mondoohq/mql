// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

var (
	_ plugin.Connection = (*BicepConnection)(nil)
	_ plugin.Closer     = (*BicepConnection)(nil)
)

type BicepConnection struct {
	plugin.Connection
	Conf            *inventory.Config
	asset           *inventory.Asset
	path            string
	bicepFiles      []*BicepFile
	bicepParamFiles []*BicepParamFile
	armTemplates    []*ARMTemplateFile
	closer          func()
}

// BicepFile holds a Bicep source file path and its raw content.
type BicepFile struct {
	Path    string
	Content string
}

// BicepParamFile holds a `.bicepparam` parameter file path and its raw content.
type BicepParamFile struct {
	Path    string
	Content string
}

// ARMTemplateFile pairs a parsed ARM template with the path it was read from.
// A scanned directory can hold several templates, and each needs its own path
// to build a stable, non-colliding resource id.
type ARMTemplateFile struct {
	Path     string
	Template *ARMTemplate
}

// ARMTemplate holds a parsed ARM template JSON.
//
// Resources is kept raw because ARM has two encodings for it: the classic
// array, and the object keyed by symbolic name that `bicep build` emits for
// any template declaring "languageVersion": "2.0". ResourceList decodes both.
type ARMTemplate struct {
	Schema          string                     `json:"$schema"`
	ContentVersion  string                     `json:"contentVersion"`
	LanguageVersion string                     `json:"languageVersion"`
	Parameters      map[string]json.RawMessage `json:"parameters"`
	Variables       map[string]json.RawMessage `json:"variables"`
	Resources       json.RawMessage            `json:"resources"`
	Outputs         map[string]json.RawMessage `json:"outputs"`
}

// ARMResource is one entry of a template's `resources`. SymbolicName is the
// object key for a symbolic-name (languageVersion 2.0) template and empty for
// the classic array form, where a resource has no name of its own in the
// template beyond its position.
type ARMResource struct {
	SymbolicName string
	Raw          json.RawMessage
}

// ResourceList decodes `resources` in whichever of the two ARM encodings the
// template uses. Object-form entries are returned in key-sorted order so the
// materialized resource list is deterministic.
func (t *ARMTemplate) ResourceList() []ARMResource {
	if len(t.Resources) == 0 {
		return nil
	}

	var arr []json.RawMessage
	if err := json.Unmarshal(t.Resources, &arr); err == nil {
		out := make([]ARMResource, 0, len(arr))
		for _, raw := range arr {
			out = append(out, ARMResource{Raw: raw})
		}
		return out
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(t.Resources, &obj); err != nil {
		log.Warn().Err(err).Msg("ARM template `resources` is neither an array nor a symbolic-name object")
		return nil
	}
	names := make([]string, 0, len(obj))
	for name := range obj {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]ARMResource, 0, len(names))
	for _, name := range names {
		out = append(out, ARMResource{SymbolicName: name, Raw: obj[name]})
	}
	return out
}

func NewBicepConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*BicepConnection, error) {
	if len(asset.Connections) == 0 {
		return nil, errors.New("no connections configured on asset")
	}

	conn := &BicepConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
	}

	// If a git clone is performed below, clean up the temporary directory on any
	// error path. Close() is a no-op when nothing was cloned, and the guard is
	// disarmed once the connection is returned and takes ownership of cleanup.
	cleanup := true
	defer func() {
		if cleanup {
			conn.Close()
		}
	}()

	cc := asset.Connections[0]
	bicepPath := cc.Options["path"]
	// When discovered from a git repository (e.g. by the GitHub provider) the
	// asset carries the repo URL instead of a local path. Clone the repo and
	// scan the resulting directory for Bicep/ARM files.
	if bicepPath == "" {
		if _, ok := cc.Options["http-url"]; ok {
			clonePath, closer, err := plugin.NewGitClone(asset)
			if err != nil {
				return nil, err
			}
			conn.closer = closer
			bicepPath = clonePath
			// Intentionally do NOT overwrite cc.Options["path"]: the detector
			// reads it to derive a platform ID, and a non-deterministic temp
			// clone path would produce a different ID on every scan. The
			// detector's git-discovered branch (ssh-url) handles naming for
			// this path.
		}
	}
	conn.path = bicepPath

	fi, err := os.Stat(bicepPath)
	if err != nil {
		return nil, err
	}

	if fi.IsDir() {
		files, err := loadBicepFiles(bicepPath)
		if err != nil {
			return nil, err
		}
		conn.bicepFiles = files
		paramFiles, err := loadBicepParamFiles(bicepPath)
		if err != nil {
			return nil, err
		}
		conn.bicepParamFiles = paramFiles
		// Check for ARM template JSON anywhere in the directory tree
		conn.armTemplates = findARMTemplates(bicepPath)
		if len(files) == 0 && len(paramFiles) == 0 && len(conn.armTemplates) == 0 {
			return nil, fmt.Errorf("no .bicep, .bicepparam, or ARM template JSON files found at %s: %w", bicepPath, plugin.ErrNoMatch)
		}
	} else if strings.HasSuffix(bicepPath, ".json") {
		// Direct ARM template JSON
		tmpl, err := loadARMTemplate(bicepPath)
		if err != nil {
			return nil, err
		}
		conn.armTemplates = []*ARMTemplateFile{{Path: bicepPath, Template: tmpl}}
	} else if strings.HasSuffix(bicepPath, ".bicepparam") {
		// Single .bicepparam parameter file
		content, err := os.ReadFile(bicepPath)
		if err != nil {
			return nil, err
		}
		conn.bicepParamFiles = []*BicepParamFile{{Path: bicepPath, Content: string(content)}}
	} else {
		// Single .bicep file
		content, err := os.ReadFile(bicepPath)
		if err != nil {
			return nil, err
		}
		conn.bicepFiles = []*BicepFile{{Path: bicepPath, Content: string(content)}}
	}

	cleanup = false
	return conn, nil
}

// Close cleans up any temporary directory created by a git clone.
func (c *BicepConnection) Close() {
	if c.closer != nil {
		c.closer()
	}
}

func (c *BicepConnection) Name() string {
	return "bicep"
}

func (c *BicepConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *BicepConnection) BicepFiles() []*BicepFile {
	return c.bicepFiles
}

func (c *BicepConnection) BicepParamFiles() []*BicepParamFile {
	return c.bicepParamFiles
}

// ARMTemplate returns the first discovered ARM template, or nil when the scan
// found none. It stays the right answer for a direct `bicep <file>.json`
// connection; use ARMTemplates to reach every template in a scanned tree.
func (c *BicepConnection) ARMTemplate() *ARMTemplate {
	if len(c.armTemplates) == 0 {
		return nil
	}
	return c.armTemplates[0].Template
}

// ARMTemplatePath returns the path the first discovered ARM template was read
// from, or "" when the scan found none.
func (c *BicepConnection) ARMTemplatePath() string {
	if len(c.armTemplates) == 0 {
		return ""
	}
	return c.armTemplates[0].Path
}

// ARMTemplates returns every ARM template the scan discovered, each with the
// path it came from, in path-sorted order.
func (c *BicepConnection) ARMTemplates() []*ARMTemplateFile {
	return c.armTemplates
}

func (c *BicepConnection) Path() string {
	return c.path
}

func loadBicepFiles(dir string) ([]*BicepFile, error) {
	var files []*BicepFile

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// An unreadable entry must not abort the whole scan; skip it the
			// same way an unreadable file is skipped below. info is nil on an
			// error, so fall back to SkipDir only when we can tell it's a dir.
			log.Warn().Err(err).Str("path", path).Msg("skipping unreadable path")
			if info != nil && info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".bicep") {
			content, err := os.ReadFile(path)
			if err != nil {
				log.Warn().Err(err).Str("path", path).Msg("failed to read bicep file")
				return nil
			}
			files = append(files, &BicepFile{Path: path, Content: string(content)})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

func loadBicepParamFiles(dir string) ([]*BicepParamFile, error) {
	var files []*BicepParamFile

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// An unreadable entry must not abort the whole scan; skip it the
			// same way an unreadable file is skipped below. info is nil on an
			// error, so fall back to SkipDir only when we can tell it's a dir.
			log.Warn().Err(err).Str("path", path).Msg("skipping unreadable path")
			if info != nil && info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".bicepparam") {
			content, err := os.ReadFile(path)
			if err != nil {
				log.Warn().Err(err).Str("path", path).Msg("failed to read bicepparam file")
				return nil
			}
			files = append(files, &BicepParamFile{Path: path, Content: string(content)})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

// findARMTemplates walks the tree for JSON files that parse as ARM deployment
// templates. Discovery is recursive and name-agnostic to match how `.bicep`
// and `.bicepparam` files are already found: an `infra/azuredeploy.json` or an
// `arm/storage.prod.json` is just as much a template as a root `main.json`.
// Every match is kept, each carrying its own path.
func findARMTemplates(dir string) []*ARMTemplateFile {
	var out []*ARMTemplateFile

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Warn().Err(err).Str("path", path).Msg("skipping unreadable path")
			if info != nil && info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}
		tmpl, err := loadARMTemplate(path)
		if err != nil {
			// Most JSON in a repo is not an ARM template (package.json,
			// settings, fixtures), so a failed schema check is unremarkable
			// and logged at debug. Only a read error is worth a warning.
			log.Debug().Err(err).Str("path", path).Msg("json file is not an ARM deployment template")
			return nil
		}
		out = append(out, &ARMTemplateFile{Path: path, Template: tmpl})
		return nil
	})
	if err != nil {
		log.Warn().Err(err).Str("dir", dir).Msg("failed to walk directory for ARM templates")
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func loadARMTemplate(path string) (*ARMTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var tmpl ARMTemplate
	if err := json.Unmarshal(data, &tmpl); err != nil {
		return nil, err
	}

	// Verify it looks like an ARM template
	if tmpl.Schema == "" || !strings.Contains(tmpl.Schema, "deploymentTemplate") {
		return nil, errors.New("not an ARM template: " + path)
	}

	return &tmpl, nil
}

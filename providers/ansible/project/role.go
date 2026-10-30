// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package project

import (
	"os"
	"path/filepath"
	"sort"

	"go.mondoo.com/mql/providers/ansible/play"
	"gopkg.in/yaml.v3"
)

// Role is a parsed roles/<name>/ tree.
type Role struct {
	Name            string
	Path            string
	Tasks           []*play.Task
	Handlers        []*play.Handler
	Defaults        map[string]any
	Vars            map[string]any
	Meta            *RoleMeta
	ArgumentSpecs   map[string]any // entrypoint argument specs from meta/argument_specs.yml
	Templates       []string
	Files           []string
	DependencyNames []string // role names from meta/main.yml, resolved to typed refs at the resource layer
}

// RoleMeta is the parsed meta/main.yml of a role.
type RoleMeta struct {
	MinAnsibleVersion string
	GalaxyInfo        map[string]any
	Dependencies      []string
}

// loadRoles loads every immediate subdirectory of rolesDir as a role.
func loadRoles(rolesDir string) ([]*Role, error) {
	entries, err := os.ReadDir(rolesDir)
	if err != nil {
		return []*Role{}, nil // no roles/ directory is normal
	}

	roles := []*Role{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		role, err := loadRole(e.Name(), filepath.Join(rolesDir, e.Name()))
		if err != nil {
			// A role with an unparseable file (e.g. YAML that yaml.v3 rejects
			// but Ansible tolerates) should not abort the whole project load;
			// skip it, matching loadPlaybooks.
			continue
		}
		roles = append(roles, role)
	}
	return roles, nil
}

func loadRole(name, path string) (*Role, error) {
	role := &Role{Name: name, Path: path}

	if data := readMainFile(path, "tasks"); data != nil {
		tasks, err := play.DecodeTaskList(data)
		if err != nil {
			return nil, err
		}
		role.Tasks = tasks
	}

	if data := readMainFile(path, "handlers"); data != nil {
		handlers, err := play.DecodeHandlerList(data)
		if err != nil {
			return nil, err
		}
		role.Handlers = handlers
	}

	if data := readMainFile(path, "defaults"); data != nil {
		if err := yaml.Unmarshal(data, &role.Defaults); err != nil {
			return nil, err
		}
	}

	if data := readMainFile(path, "vars"); data != nil {
		if err := yaml.Unmarshal(data, &role.Vars); err != nil {
			return nil, err
		}
	}

	if data := readMainFile(path, "meta"); data != nil {
		meta, err := decodeRoleMeta(data)
		if err != nil {
			return nil, err
		}
		role.Meta = meta
		role.DependencyNames = meta.Dependencies
	}

	if specs := readArgumentSpecs(path); specs != nil {
		role.ArgumentSpecs = specs
	}

	role.Templates = listDirFiles(filepath.Join(path, "templates"))
	role.Files = listDirFiles(filepath.Join(path, "files"))

	return role, nil
}

// readArgumentSpecs parses a role's meta/argument_specs.yml and returns the
// per-entrypoint specs (the value of the top-level `argument_specs` key).
func readArgumentSpecs(rolePath string) map[string]any {
	p := firstExisting(
		filepath.Join(rolePath, "meta", "argument_specs.yml"),
		filepath.Join(rolePath, "meta", "argument_specs.yaml"),
	)
	if p == "" {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var doc struct {
		ArgumentSpecs map[string]any `yaml:"argument_specs"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	return doc.ArgumentSpecs
}

// readMainFile reads <rolePath>/<subdir>/main.yml (or .yaml), returning nil when
// neither exists.
func readMainFile(rolePath, subdir string) []byte {
	p := firstExisting(
		filepath.Join(rolePath, subdir, "main.yml"),
		filepath.Join(rolePath, subdir, "main.yaml"),
	)
	if p == "" {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return data
}

type rawRoleMeta struct {
	GalaxyInfo        map[string]any `yaml:"galaxy_info"`
	MinAnsibleVersion string         `yaml:"min_ansible_version"`
	Dependencies      []any          `yaml:"dependencies"`
}

func decodeRoleMeta(data []byte) (*RoleMeta, error) {
	var raw rawRoleMeta
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	meta := &RoleMeta{
		GalaxyInfo:        raw.GalaxyInfo,
		MinAnsibleVersion: raw.MinAnsibleVersion,
	}
	// min_ansible_version historically lived under galaxy_info.
	if meta.MinAnsibleVersion == "" && raw.GalaxyInfo != nil {
		if v, ok := raw.GalaxyInfo["min_ansible_version"].(string); ok {
			meta.MinAnsibleVersion = v
		}
	}

	for _, dep := range raw.Dependencies {
		if name := roleRefName(dep); name != "" {
			meta.Dependencies = append(meta.Dependencies, name)
		}
	}
	return meta, nil
}

// roleRefName extracts the role name from a meta dependency entry, which can be
// a bare string or a mapping keyed by `role` or `name`.
func roleRefName(dep any) string {
	switch v := dep.(type) {
	case string:
		return v
	case map[string]any:
		if r, ok := v["role"].(string); ok {
			return r
		}
		if r, ok := v["name"].(string); ok {
			return r
		}
	}
	return ""
}

// listDirFiles returns the relative paths of all files under dir (recursively),
// sorted for stable output. Returns nil when dir does not exist.
func listDirFiles(dir string) []string {
	var files []string
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if rel, relErr := filepath.Rel(dir, p); relErr == nil {
			files = append(files, rel)
		}
		return nil
	})
	sort.Strings(files)
	return files
}

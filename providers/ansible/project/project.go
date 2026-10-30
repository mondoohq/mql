// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package project loads an Ansible project directory — playbooks, roles,
// inventory, Galaxy requirements, ansible.cfg, and vault-encrypted files — into
// a static model for analysis, without executing anything against an inventory.
package project

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"go.mondoo.com/mql/providers/ansible/play"
	"gopkg.in/yaml.v3"
)

// Project is the static model of an Ansible project directory.
type Project struct {
	Root              string
	Playbooks         []*PlaybookFile
	Roles             []*Role
	Inventory         *Inventory
	Requirements      *Requirements
	Config            *Config
	VaultFiles        []*VaultFile
	VaultVars         []*VaultVariable
	Plugins           []*Plugin
	Collections       []*VendoredCollection
	Manifest          *Manifest
	LintConfig        string
	MoleculeScenarios []string
}

// PlaybookFile pairs a playbook file path with its parsed plays.
type PlaybookFile struct {
	Path  string
	Plays play.Playbook
}

// Load walks an Ansible project directory and assembles its static model. A
// missing or unreadable artifact (no roles/, no inventory, etc.) is not an
// error — the corresponding field is simply left empty.
func Load(root string) (*Project, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}

	p := &Project{Root: abs}

	if cfg := loadConfig(filepath.Join(abs, "ansible.cfg")); cfg != nil {
		p.Config = cfg
	}

	roles, err := loadRoles(filepath.Join(abs, "roles"))
	if err != nil {
		return nil, err
	}
	p.Roles = roles

	inv, err := loadInventory(abs)
	if err != nil {
		return nil, err
	}
	p.Inventory = inv

	req, err := loadRequirements(abs)
	if err != nil {
		return nil, err
	}
	p.Requirements = req

	pbs, err := loadPlaybooks(abs)
	if err != nil {
		return nil, err
	}
	p.Playbooks = pbs

	vault, err := detectVaultFiles(abs)
	if err != nil {
		return nil, err
	}
	p.VaultFiles = vault

	vaultVars, err := detectInlineVaultVars(abs)
	if err != nil {
		return nil, err
	}
	p.VaultVars = vaultVars

	plugins, err := loadPlugins(abs)
	if err != nil {
		return nil, err
	}
	p.Plugins = plugins

	collections, err := loadVendoredCollections(abs)
	if err != nil {
		return nil, err
	}
	p.Collections = collections

	p.Manifest = loadManifest(abs)
	p.LintConfig = firstExisting(filepath.Join(abs, ".ansible-lint"), filepath.Join(abs, ".config", "ansible-lint.yml"))
	p.MoleculeScenarios = loadMoleculeScenarios(abs)

	return p, nil
}

// loadMoleculeScenarios returns the names of the scenarios under molecule/ —
// each subdirectory is a scenario — as a signal of test maturity.
func loadMoleculeScenarios(root string) []string {
	entries, err := os.ReadDir(filepath.Join(root, "molecule"))
	if err != nil {
		return nil
	}
	var scenarios []string
	for _, e := range entries {
		if e.IsDir() {
			scenarios = append(scenarios, e.Name())
		}
	}
	sort.Strings(scenarios)
	return scenarios
}

// RoleByName returns the role with the given name, or nil. Role references in
// plays and meta dependencies resolve through this.
func (p *Project) RoleByName(name string) *Role {
	for _, r := range p.Roles {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// loadPlaybooks collects playbook files from the project root and a top-level
// playbooks/ directory. A YAML file counts as a playbook when at least one
// top-level entry carries a `hosts:` or `import_playbook:` key, which keeps
// task files and var files from being mistaken for playbooks.
func loadPlaybooks(root string) ([]*PlaybookFile, error) {
	out := []*PlaybookFile{}
	seen := map[string]bool{}

	for _, dir := range []string{root, filepath.Join(root, "playbooks")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // directory may not exist; that's fine
		}
		for _, e := range entries {
			if e.IsDir() || !isYAMLFile(e.Name()) || isRequirementsFile(e.Name()) {
				continue
			}
			full := filepath.Join(dir, e.Name())
			if seen[full] {
				continue
			}
			data, err := os.ReadFile(full)
			if err != nil || isVaultEncrypted(data) || !LooksLikePlaybook(data) {
				continue
			}
			pb, err := play.DecodePlaybook(data)
			if err != nil {
				continue
			}
			seen[full] = true
			out = append(out, &PlaybookFile{Path: full, Plays: pb})
		}
	}
	return out, nil
}

// LooksLikePlaybook reports whether the YAML is a list whose entries look like
// plays (have a `hosts:` selector or an `import_playbook:` statement).
//
// Exported because the connection applies the same rule to a single playbook
// file it was handed directly. The two have to agree: a file this says no to
// must not become an asset on one path and be skipped on the other.
func LooksLikePlaybook(data []byte) bool {
	var items []map[string]any
	if err := yaml.Unmarshal(data, &items); err != nil {
		return false
	}
	for _, item := range items {
		if _, ok := item["hosts"]; ok {
			return true
		}
		if _, ok := item["import_playbook"]; ok {
			return true
		}
	}
	return false
}

func isYAMLFile(name string) bool {
	ext := filepath.Ext(name)
	return ext == ".yml" || ext == ".yaml"
}

func isRequirementsFile(name string) bool {
	return name == "requirements.yml" || name == "requirements.yaml"
}

// firstExisting returns the first path in candidates that exists, or "".
func firstExisting(candidates ...string) string {
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// withinRoot reports whether path, with symlinks resolved, stays inside root.
// It keeps inventory and variable files from reading targets outside the
// project tree via a symlink.
func withinRoot(root, path string) bool {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		realRoot = filepath.Clean(root)
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(realRoot, realPath)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

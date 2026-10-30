// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package project

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Inventory is the parsed static inventory of a project: which hosts and groups
// exist and the variables that apply to them (including group_vars/host_vars).
// Dynamic inventory plugins are out of scope.
type Inventory struct {
	Groups []*InventoryGroup
	Hosts  []*InventoryHost
}

// InventoryGroup is a named group of hosts.
type InventoryGroup struct {
	Name     string
	Hosts    []string
	Children []string
	Vars     map[string]any
}

// InventoryHost is a named host and the variables that apply to it.
type InventoryHost struct {
	Name   string
	Groups []string
	Vars   map[string]any
}

// inventoryBuilder accumulates groups and hosts as files are parsed, keeping
// each unique by name so INI, YAML, and group_vars/host_vars overlays merge.
type inventoryBuilder struct {
	groups map[string]*InventoryGroup
	hosts  map[string]*InventoryHost
}

func newInventoryBuilder() *inventoryBuilder {
	return &inventoryBuilder{
		groups: map[string]*InventoryGroup{},
		hosts:  map[string]*InventoryHost{},
	}
}

func (b *inventoryBuilder) group(name string) *InventoryGroup {
	g, ok := b.groups[name]
	if !ok {
		g = &InventoryGroup{Name: name, Vars: map[string]any{}}
		b.groups[name] = g
	}
	return g
}

func (b *inventoryBuilder) host(name string) *InventoryHost {
	h, ok := b.hosts[name]
	if !ok {
		h = &InventoryHost{Name: name, Vars: map[string]any{}}
		b.hosts[name] = h
	}
	return h
}

func (b *inventoryBuilder) addHostToGroup(group, host string) {
	g := b.group(group)
	if !slices.Contains(g.Hosts, host) {
		g.Hosts = append(g.Hosts, host)
	}
	h := b.host(host)
	if !slices.Contains(h.Groups, group) {
		h.Groups = append(h.Groups, group)
	}
}

func (b *inventoryBuilder) result() *Inventory {
	inv := &Inventory{}
	names := make([]string, 0, len(b.groups))
	for n := range b.groups {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		g := b.groups[n]
		sort.Strings(g.Hosts)
		sort.Strings(g.Children)
		inv.Groups = append(inv.Groups, g)
	}

	hostNames := make([]string, 0, len(b.hosts))
	for n := range b.hosts {
		hostNames = append(hostNames, n)
	}
	sort.Strings(hostNames)
	for _, n := range hostNames {
		h := b.hosts[n]
		sort.Strings(h.Groups)
		inv.Hosts = append(inv.Hosts, h)
	}
	return inv
}

// loadInventory discovers and parses the project's static inventory plus
// group_vars/ and host_vars/. Returns nil when nothing inventory-related exists.
func loadInventory(root string) (*Inventory, error) {
	b := newInventoryBuilder()
	found := false

	for _, src := range inventorySources(root) {
		data, err := os.ReadFile(src)
		if err != nil || isVaultEncrypted(data) {
			continue
		}
		if isINIInventory(data) {
			parseINIInventory(b, data)
		} else if err := parseYAMLInventory(b, data); err != nil {
			// A single unparseable inventory file (e.g. YAML that yaml.v3
			// rejects but Ansible tolerates) should not abort the whole
			// project load; skip it, matching loadPlaybooks.
			continue
		}
		found = true
	}

	// group_vars/ and host_vars/ live at the project root and, per Ansible's
	// rules, beside each inventory source. Collect both sets of base dirs.
	varBases := map[string]bool{root: true}
	for _, src := range inventorySources(root) {
		varBases[filepath.Dir(src)] = true
	}
	for base := range varBases {
		if applyVarsDir(root, filepath.Join(base, "group_vars"), b.groupVars) {
			found = true
		}
		if applyVarsDir(root, filepath.Join(base, "host_vars"), b.hostVars) {
			found = true
		}
	}

	if !found {
		return nil, nil
	}
	return b.result(), nil
}

// inventorySources returns candidate inventory files: conventional filenames at
// the root, plus every file inside an inventory/ directory. Files whose real
// path escapes the project root (via a symlink) are dropped.
func inventorySources(root string) []string {
	var sources []string
	add := func(p string) {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && withinRoot(root, p) {
			sources = append(sources, p)
		}
	}
	for _, name := range []string{
		"inventory", "inventory.ini", "inventory.yml", "inventory.yaml",
		"hosts", "hosts.ini", "hosts.yml", "hosts.yaml",
	} {
		add(filepath.Join(root, name))
	}
	invDir := filepath.Join(root, "inventory")
	if fi, err := os.Stat(invDir); err == nil && fi.IsDir() {
		entries, _ := os.ReadDir(invDir)
		for _, e := range entries {
			if !e.IsDir() {
				add(filepath.Join(invDir, e.Name()))
			}
		}
	}
	return sources
}

// isINIInventory heuristically distinguishes an INI inventory from a YAML one:
// INI inventories open with a `[section]` header or bare host lines, whereas
// YAML inventories use `key:` mappings.
func isINIInventory(data []byte) bool {
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// A YAML document marker (--- / ...) can only start a YAML inventory;
		// INI has no such construct. Skip it so classification keys off the
		// first real content line (e.g. an `all:` mapping) rather than
		// mistaking `---` for a bare INI host line.
		if line == "---" || line == "..." {
			return false
		}
		if strings.HasPrefix(line, "[") {
			return true
		}
		// A YAML inventory's first meaningful line is a `key:` mapping.
		if strings.HasSuffix(line, ":") || strings.Contains(line, ": ") {
			return false
		}
		return true // a bare host line — INI style
	}
	return false
}

// parseINIInventory parses Ansible's INI inventory format, including
// `[group:vars]` and `[group:children]` sections and inline `key=value` host
// variables.
func parseINIInventory(b *inventoryBuilder, data []byte) {
	section := "ungrouped"
	sectionType := "hosts"

	for raw := range strings.SplitSeq(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			section, sectionType = name, "hosts"
			if before, after, ok := strings.CutLast(name, ":"); ok {
				section, sectionType = before, after
			}
			b.group(section) // ensure empty groups still appear
			continue
		}

		switch sectionType {
		case "vars":
			if k, v, ok := splitKV(line, "="); ok {
				b.group(section).Vars[k] = v
			}
		case "children":
			child := strings.Fields(line)[0]
			g := b.group(section)
			if !slices.Contains(g.Children, child) {
				g.Children = append(g.Children, child)
			}
			b.group(child)
		default:
			parseINIHostLine(b, section, line)
		}
	}
}

// parseINIHostLine adds a host to a group, capturing any inline `key=value`
// host variables that follow the hostname.
func parseINIHostLine(b *inventoryBuilder, group, line string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return
	}
	host := fields[0]
	b.addHostToGroup(group, host)
	for _, f := range fields[1:] {
		if k, v, ok := splitKV(f, "="); ok {
			b.host(host).Vars[k] = v
		}
	}
}

// parseYAMLInventory parses Ansible's YAML inventory format, recursing through
// nested `children`.
func parseYAMLInventory(b *inventoryBuilder, data []byte) error {
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	for name, body := range root {
		walkYAMLGroup(b, name, body)
	}
	return nil
}

func walkYAMLGroup(b *inventoryBuilder, name string, body any) {
	g := b.group(name)
	m, ok := body.(map[string]any)
	if !ok {
		return
	}

	switch hosts := m["hosts"].(type) {
	case map[string]any:
		for host, hv := range hosts {
			b.addHostToGroup(name, host)
			if vars, ok := hv.(map[string]any); ok {
				maps.Copy(b.host(host).Vars, vars)
			}
		}
	case []any:
		// Ansible also accepts a `hosts:` list (each element a hostname with
		// no per-host vars); a map type-assertion alone silently dropped them.
		for _, hv := range hosts {
			if host, ok := hv.(string); ok && host != "" {
				b.addHostToGroup(name, host)
			}
		}
	}

	if vars, ok := m["vars"].(map[string]any); ok {
		maps.Copy(g.Vars, vars)
	}

	if children, ok := m["children"].(map[string]any); ok {
		for child, cbody := range children {
			if !slices.Contains(g.Children, child) {
				g.Children = append(g.Children, child)
			}
			walkYAMLGroup(b, child, cbody)
		}
	}
}

// applyVarsDir merges group_vars/ or host_vars/ overlays. Each entry may be a
// single <name>.yml file or a <name>/ directory of files; the leaf name selects
// the target group or host via the supplied resolver. Files whose real path
// escapes root (via a symlink) are skipped.
func applyVarsDir(root, dir string, resolveVars func(string) map[string]any) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	applied := false
	for _, e := range entries {
		name := strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".yaml"), ".yml")
		var files []string
		if e.IsDir() {
			sub, _ := os.ReadDir(filepath.Join(dir, e.Name()))
			for _, f := range sub {
				if !f.IsDir() {
					files = append(files, filepath.Join(dir, e.Name(), f.Name()))
				}
			}
		} else if isYAMLFile(e.Name()) {
			files = append(files, filepath.Join(dir, e.Name()))
		}

		for _, f := range files {
			if !withinRoot(root, f) {
				continue
			}
			data, err := os.ReadFile(f)
			if err != nil || isVaultEncrypted(data) {
				continue
			}
			var vars map[string]any
			if err := yaml.Unmarshal(data, &vars); err != nil {
				continue
			}
			maps.Copy(resolveVars(name), vars)
			applied = true
		}
	}
	return applied
}

// group/host resolvers used by applyVarsDir return the Vars map to merge into.
func (b *inventoryBuilder) groupVars(name string) map[string]any { return b.group(name).Vars }
func (b *inventoryBuilder) hostVars(name string) map[string]any  { return b.host(name).Vars }

func splitKV(s, sep string) (string, string, bool) {
	idx := strings.Index(s, sep)
	if idx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+1:]), true
}

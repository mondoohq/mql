// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package project

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Inventory-adjacent group_vars/host_vars (e.g. inventory/group_vars/) must be
// honored in addition to the project root.
func TestInventoryAdjacentVars(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	}

	write("inventory/hosts", "[web]\nhost1\n")
	write("inventory/group_vars/web.yml", "adjacent_var: from_inventory_dir\n")
	write("inventory/host_vars/host1.yml", "host_adjacent: true\n")
	write("group_vars/all.yml", "root_var: from_root\n")

	inv, err := loadInventory(root)
	require.NoError(t, err)
	require.NotNil(t, inv)

	groups := map[string]*InventoryGroup{}
	for _, g := range inv.Groups {
		groups[g.Name] = g
	}
	assert.Equal(t, "from_inventory_dir", groups["web"].Vars["adjacent_var"])
	assert.Equal(t, "from_root", groups["all"].Vars["root_var"])

	hosts := map[string]*InventoryHost{}
	for _, h := range inv.Hosts {
		hosts[h.Name] = h
	}
	assert.Equal(t, true, hosts["host1"].Vars["host_adjacent"])
	assert.Contains(t, hosts["host1"].Groups, "web")
}

// A symlinked var file whose target lies outside the project must not be read,
// so a crafted repo cannot exfiltrate host files into the inventory model.
func TestSymlinkVarsEscapeSkipped(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.yml"), []byte("leaked: true\n"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "group_vars"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "inventory"), []byte("[web]\nhost1\n"), 0o600))
	require.NoError(t, os.Symlink(filepath.Join(outside, "secret.yml"), filepath.Join(root, "group_vars", "web.yml")))

	inv, err := loadInventory(root)
	require.NoError(t, err)
	require.NotNil(t, inv)
	for _, g := range inv.Groups {
		if g.Name == "web" {
			_, leaked := g.Vars["leaked"]
			assert.False(t, leaked, "symlinked var file escaping the root must be skipped")
		}
	}
}

// isINIInventory must not mistake a YAML inventory that opens with a `---`
// document marker for an INI file — doing so parsed the whole inventory as
// garbage INI host lines.
func TestIsINIInventoryClassification(t *testing.T) {
	assert.True(t, isINIInventory([]byte("[web]\nhost1\n")), "bracket section is INI")
	assert.True(t, isINIInventory([]byte("host1\nhost2\n")), "bare host lines are INI")
	assert.False(t, isINIInventory([]byte("all:\n  hosts:\n    web1:\n")), "key mapping is YAML")
	assert.False(t, isINIInventory([]byte("---\nall:\n  hosts:\n    web1:\n")), "leading --- is YAML")
	assert.False(t, isINIInventory([]byte("# comment\n---\nall:\n")), "comment then --- is YAML")
}

// A YAML inventory that opens with a `---` document marker must be parsed as
// YAML, not misclassified as INI (which produced bogus "---"/"all:" hosts).
func TestInventoryYAMLWithDocumentMarker(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "inventory.yml"),
		[]byte("---\nweb:\n  hosts:\n    web1:\n    web2:\n"),
		0o600,
	))

	inv, err := loadInventory(root)
	require.NoError(t, err)
	require.NotNil(t, inv)

	groups := map[string]*InventoryGroup{}
	for _, g := range inv.Groups {
		groups[g.Name] = g
	}
	require.Contains(t, groups, "web")
	assert.ElementsMatch(t, []string{"web1", "web2"}, groups["web"].Hosts)
	assert.NotContains(t, groups, "---", "the document marker must not become a group")
}

// A role whose file fails to decode (e.g. duplicate mapping keys, which yaml.v3
// rejects but Ansible tolerates) must be skipped rather than aborting the whole
// project load, matching loadPlaybooks.
func TestLoadRolesSkipsUnparseableRole(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "roles", "good"), 0o755))
	badDefaults := filepath.Join(root, "roles", "bad", "defaults")
	require.NoError(t, os.MkdirAll(badDefaults, 0o755))
	// Duplicate mapping key -> yaml.v3 returns a decode error.
	require.NoError(t, os.WriteFile(filepath.Join(badDefaults, "main.yml"), []byte("foo: 1\nfoo: 2\n"), 0o600))

	roles, err := loadRoles(filepath.Join(root, "roles"))
	require.NoError(t, err, "one unparseable role must not fail the whole load")

	names := make([]string, 0, len(roles))
	for _, r := range roles {
		names = append(names, r.Name)
	}
	assert.Contains(t, names, "good")
	assert.NotContains(t, names, "bad")
}

// A YAML inventory written with `hosts:` as a list (each element a bare
// hostname, which Ansible accepts) must be honored, not silently dropped by a
// map-only type assertion.
func TestInventoryYAMLListHosts(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(root, "inventory.yml"),
		[]byte("web:\n  hosts:\n    - web1\n    - web2\n"),
		0o600,
	))

	inv, err := loadInventory(root)
	require.NoError(t, err)
	require.NotNil(t, inv)

	groups := map[string]*InventoryGroup{}
	for _, g := range inv.Groups {
		groups[g.Name] = g
	}
	require.Contains(t, groups, "web")
	assert.ElementsMatch(t, []string{"web1", "web2"}, groups["web"].Hosts)

	hosts := map[string]*InventoryHost{}
	for _, h := range inv.Hosts {
		hosts[h.Name] = h
	}
	assert.Contains(t, hosts, "web1")
	assert.Contains(t, hosts, "web2")
}

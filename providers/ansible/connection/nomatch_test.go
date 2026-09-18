// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func ansibleConnect(t *testing.T, path string) error {
	t.Helper()
	asset := &inventory.Asset{Connections: []*inventory.Config{{
		Options: map[string]string{"path": path},
	}}}
	_, err := NewAnsibleConnection(0, asset, &inventory.Config{})
	return err
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

// project.Load treats every missing artifact as empty rather than as an error,
// so without the gate it succeeds on any directory at all.
func TestAnsibleRejectsAFolderThatIsNotAProject(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "settings.yaml", "log_level: debug\n")
	write(t, dir, "README.md", "# docs\n")

	err := ansibleConnect(t, dir)
	require.Error(t, err)
	assert.True(t, plugin.IsNoMatchError(err), err)
}

func TestAnsibleAcceptsProjectFolders(t *testing.T) {
	tests := map[string]func(dir string){
		"with an ansible.cfg": func(dir string) { write(t, dir, "ansible.cfg", "[defaults]\n") },
		"with roles":          func(dir string) { write(t, dir, "roles/web/tasks/main.yml", "- name: x\n  ansible.builtin.ping:\n") },
		"with an inventory":   func(dir string) { write(t, dir, "inventory", "[web]\nhost1\n") },
		// A bare playbook folder is a project holding one playbook, which is
		// how a playbook reached by the iac walk arrives -- the walk offers
		// folders, never files.
		"with only a playbook": func(dir string) { write(t, dir, "site.yml", "- name: play\n  hosts: all\n  tasks: []\n") },
	}

	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			setup(dir)
			assert.NoError(t, ansibleConnect(t, dir))
		})
	}
}

func TestAnsibleRejectsForeignPlaybookFiles(t *testing.T) {
	tests := map[string]string{
		// A Playbook is a slice, so any YAML mapping fails to decode.
		"a kubernetes manifest": "apiVersion: apps/v1\nkind: Deployment\n",
		"a settings file":       "log_level: debug\n",
		// Decodes cleanly into plays that say nothing at all.
		"a list of unrelated dicts": "- name: one\n  value: 1\n- name: two\n  value: 2\n",
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "doc.yml")
			require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
			err := ansibleConnect(t, path)
			require.Error(t, err)
			assert.True(t, plugin.IsNoMatchError(err), err)
		})
	}
}

func TestAnsibleReportsAMalformedPlaybook(t *testing.T) {
	// Does not parse as YAML at all, so it is a file meant to be one of ours
	// and broken -- distinct from a file that parses and is somebody else's.
	path := filepath.Join(t.TempDir(), "broken.yml")
	require.NoError(t, os.WriteFile(path, []byte("---\n- name: x\n  hosts: [unterminated"), 0o600))

	err := ansibleConnect(t, path)
	require.Error(t, err)
	assert.False(t, plugin.IsNoMatchError(err), err)
}

func TestAnsibleAcceptsAnImportOnlyPlaybook(t *testing.T) {
	// import_playbook lives on Task rather than Play, so a gate written against
	// the decoded struct would drop this one.
	path := filepath.Join(t.TempDir(), "site.yml")
	require.NoError(t, os.WriteFile(path, []byte("- import_playbook: other.yml\n"), 0o600))
	assert.NoError(t, ansibleConnect(t, path))
}

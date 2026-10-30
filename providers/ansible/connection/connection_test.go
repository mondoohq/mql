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
)

func TestNewAnsibleConnection_Errors(t *testing.T) {
	t.Run("nil asset", func(t *testing.T) {
		_, err := NewAnsibleConnection(0, nil, &inventory.Config{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no connection options")
	})

	t.Run("no connections", func(t *testing.T) {
		_, err := NewAnsibleConnection(0, &inventory.Asset{}, &inventory.Config{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no connection options")
	})

	t.Run("nil options", func(t *testing.T) {
		asset := &inventory.Asset{Connections: []*inventory.Config{{}}}
		_, err := NewAnsibleConnection(0, asset, &inventory.Config{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no playbook path")
	})

	t.Run("empty path", func(t *testing.T) {
		asset := &inventory.Asset{Connections: []*inventory.Config{{
			Options: map[string]string{"path": ""},
		}}}
		_, err := NewAnsibleConnection(0, asset, &inventory.Config{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no playbook path")
	})

	t.Run("missing file", func(t *testing.T) {
		asset := &inventory.Asset{Connections: []*inventory.Config{{
			Options: map[string]string{"path": "/no/such/playbook.yml"},
		}}}
		_, err := NewAnsibleConnection(0, asset, &inventory.Config{})
		require.Error(t, err)
		// error should wrap the path so users can debug typos
		assert.Contains(t, err.Error(), "/no/such/playbook.yml")
	})

	t.Run("malformed yaml", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "broken.yml")
		// `- name:` followed by a key without a value is fine; use a clearly
		// invalid YAML structure (unclosed mapping with a tab + quote).
		require.NoError(t, os.WriteFile(path, []byte("---\n- name: x\n  hosts: [unterminated"), 0o600))

		asset := &inventory.Asset{Connections: []*inventory.Config{{
			Options: map[string]string{"path": path},
		}}}
		_, err := NewAnsibleConnection(0, asset, &inventory.Config{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode playbook")
		assert.Contains(t, err.Error(), path)
	})
}

func TestNewAnsibleConnection_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "playbook.yml")
	require.NoError(t, os.WriteFile(path, []byte("---\n- hosts: webservers\n  tasks:\n    - name: ping\n      ping:\n"), 0o600))

	asset := &inventory.Asset{Connections: []*inventory.Config{{
		Options: map[string]string{"path": path},
	}}}
	conn, err := NewAnsibleConnection(42, asset, &inventory.Config{})
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, "ansible", conn.Name())
	require.Len(t, conn.Playbook(), 1)
	assert.Equal(t, "webservers", conn.Playbook()[0].Hosts)
	require.Len(t, conn.Playbook()[0].Tasks, 1)
	assert.Equal(t, "ping", conn.Playbook()[0].Tasks[0].Name)
}

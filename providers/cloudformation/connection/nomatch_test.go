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

func connectTo(t *testing.T, name, body string) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	asset := &inventory.Asset{Connections: []*inventory.Config{{
		Options: map[string]string{"path": path},
	}}}
	_, err := NewCloudformationConnection(0, asset, &inventory.Config{})
	return err
}

// parse.Reader accepts any well-formed YAML or JSON, so every one of these
// would otherwise connect as an empty stack and pass every policy.
func TestCloudformationRejectsForeignDocuments(t *testing.T) {
	tests := map[string]string{
		"a kubernetes deployment": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
		"a plain settings file":   "log_level: debug\nregion: us-east-1\n",
		"an ansible playbook":     "- hosts: all\n  tasks: []\n",
		"an empty file":           "",
		"a comment-only file":     "# nothing here\n",
		"a package.json":          `{"name":"app","version":"1.0.0"}`,
		// Not valid YAML at all. The iac opt-in matches every *.yaml in a tree,
		// so a chart full of Go templating reaches this connection on any
		// repository that has one -- and reporting it as a broken template
		// would fill the scan with errors about somebody else's files.
		"a helm template": "kind: Deployment\nmetadata:\n  name: {{ .Release.Name }}-api\n",
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			err := connectTo(t, "doc.yaml", body)
			require.Error(t, err)
			assert.True(t, plugin.IsNoMatchError(err), err)
		})
	}
}

func TestCloudformationReportsABrokenTemplate(t *testing.T) {
	// It says AWSTemplateFormatVersion, so it is meant to be one of ours and is
	// simply broken. Reading this as a mismatch would drop it from the scan.
	err := connectTo(t, "stack.yaml", "AWSTemplateFormatVersion: '2010-09-09'\nResources: [unterminated\n")
	require.Error(t, err)
	assert.False(t, plugin.IsNoMatchError(err), err)
}

func TestCloudformationAcceptsTemplates(t *testing.T) {
	tests := map[string]string{
		"with both markers":   "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n",
		"with Resources only": "Resources:\n  B:\n    Type: AWS::S3::Bucket\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			assert.NoError(t, connectTo(t, "stack.yaml", body))
		})
	}
}

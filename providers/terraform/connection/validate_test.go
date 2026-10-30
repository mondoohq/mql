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

func TestClassifyDocument(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		want    documentKind
		wantErr bool
	}{
		{
			name: "terraform show -json output",
			doc:  `{"format_version":"1.0","terraform_version":"1.9.0","values":{}}`,
			want: documentShowJSON,
		},
		{
			name: "OpenTofu encrypted envelope",
			doc:  `{"encrypted_data":"AAAA","encryption_version":"v0","meta":{}}`,
			want: documentEncrypted,
		},
		{
			// An encrypted envelope must be recognised as encrypted even if a
			// future version also carries a format_version alongside it.
			name: "encryption wins over format_version",
			doc:  `{"format_version":"1.0","encrypted_data":"AAAA"}`,
			want: documentEncrypted,
		},
		{
			name: "raw terraform.tfstate",
			doc:  `{"version":4,"terraform_version":"1.9.0","serial":3,"resources":[]}`,
			want: documentNativeState,
		},
		{
			name: "empty JSON object",
			doc:  `{}`,
			want: documentUnrecognized,
		},
		{
			name:    "not JSON at all (binary plan file)",
			doc:     "\x00\x01binary",
			want:    documentUnrecognized,
			wantErr: true,
		},
		{
			name:    "JSON array rather than an object",
			doc:     `[]`,
			want:    documentUnrecognized,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := classifyDocument([]byte(tc.doc))
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestValidateStateDocument(t *testing.T) {
	t.Run("accepts show -json output", func(t *testing.T) {
		assert.NoError(t, validateStateDocument(
			[]byte(`{"format_version":"1.0","values":{"root_module":{}}}`)))
	})

	t.Run("rejects an encrypted state file", func(t *testing.T) {
		err := validateStateDocument([]byte(`{"encrypted_data":"AAAA","encryption_version":"v0"}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encrypted")
	})

	t.Run("rejects a raw state file", func(t *testing.T) {
		err := validateStateDocument([]byte(`{"version":4,"resources":[]}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "raw state file")
	})

	t.Run("rejects an object with no format_version", func(t *testing.T) {
		err := validateStateDocument([]byte(`{"something":"else"}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "format_version")
	})

	t.Run("rejects malformed JSON", func(t *testing.T) {
		assert.Error(t, validateStateDocument([]byte(`{not json`)))
	})
}

func TestValidatePlanDocument(t *testing.T) {
	t.Run("accepts show -json output", func(t *testing.T) {
		assert.NoError(t, validatePlanDocument(
			[]byte(`{"format_version":"1.1","resource_changes":[]}`)))
	})

	t.Run("rejects an encrypted plan file", func(t *testing.T) {
		err := validatePlanDocument([]byte(`{"encrypted_data":"AAAA"}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encrypted")
	})

	t.Run("rejects a binary plan file", func(t *testing.T) {
		// real binary plan files start with a zip header
		err := validatePlanDocument([]byte("PK\x03\x04binary plan"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "terraform show -json")
	})
}

// writeFiles creates a directory holding the given name -> content files.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	return dir
}

func hclConnectionFor(path string) (*Connection, error) {
	return NewHclConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{Options: map[string]string{"path": path}, Type: "hcl"},
		},
	})
}

// hclConnectionAs connects with the dialect a given connector would record.
func hclConnectionAs(path string, dialect Dialect) (*Connection, error) {
	return NewHclConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{Options: map[string]string{"path": path, OptionDialect: string(dialect)}, Type: "hcl"},
		},
	})
}

const validResource = `resource "aws_s3_bucket" "b" { bucket = "example" }`

func TestHclConnectionAcceptsTerraformFiles(t *testing.T) {
	// Guards the Terraform path against over-eager rejection: adding an
	// extension to tofuConfigExtensions that overlaps .tf would fail here.
	dir := writeFiles(t, map[string]string{
		"main.tf":      validResource,
		"prod.tfvars":  `region = "us-east-1"`,
		"sub/other.tf": `variable "x" { default = 1 }`,
		"README.md":    "not terraform",
		// test files must not trip the OpenTofu check
		"main.tofutest.hcl": `run "x" {}`,
	})

	conn, err := hclConnectionFor(dir)
	require.NoError(t, err)
	assert.Len(t, conn.Parser().Files(), 2)
	assert.Len(t, conn.TfVars(), 1)
}

func TestHclConnectionSurfacesParseErrors(t *testing.T) {
	// The WalkDir return value used to be discarded, so a malformed .tf file
	// was skipped silently and scanned as an empty configuration. Re-discarding
	// it would make this test fail.
	dir := writeFiles(t, map[string]string{
		"broken.tf": `resource "aws_s3_bucket" "b" {`,
	})

	_, err := hclConnectionFor(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not parse hcl file")
}

func TestStateConnectionRejectsUnreadableFiles(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantMessage string
	}{
		{
			name:        "encrypted state",
			content:     `{"encrypted_data":"AAAA","encryption_version":"v0"}`,
			wantMessage: "encrypted",
		},
		{
			name:        "raw state file",
			content:     `{"version":4,"terraform_version":"1.9.0","resources":[]}`,
			wantMessage: "raw state file",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFiles(t, map[string]string{"state.json": tc.content})

			_, err := NewStateConnection(0, &inventory.Asset{
				Connections: []*inventory.Config{
					{Options: map[string]string{"path": filepath.Join(dir, "state.json")}, Type: "state"},
				},
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMessage)
		})
	}
}

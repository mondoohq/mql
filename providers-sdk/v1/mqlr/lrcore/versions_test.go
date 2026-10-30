// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lrcore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

func TestGenerateVersions(t *testing.T) {
	lrFile, err := os.ReadFile("testdata/new.lr")
	require.NoError(t, err)

	existing, err := ReadVersions("testdata/existing.lr.versions")
	require.NoError(t, err)

	lr := parse(t, string(lrFile))
	versions := GenerateVersions(lr, "13.0.0", existing)
	require.NotNil(t, versions)

	// existing resources preserve their version
	assert.Equal(t, "11.0.0", versions["sshd"])
	assert.Equal(t, "11.0.0", versions["sshd.config"])

	// new resource gets currentVersion
	assert.Equal(t, "13.0.0", versions["auditd.config"])

	// new fields on existing resource get currentVersion
	assert.Equal(t, "13.0.0", versions["sshd.config.ciphers"])
	assert.Equal(t, "13.0.0", versions["sshd.config.file"])

	// new fields on new resource also get currentVersion (explicit, not scrubbed)
	assert.Equal(t, "13.0.0", versions["auditd.config.file"])
	assert.Equal(t, "13.0.0", versions["auditd.config.params"])
}

func TestGenerateVersions_PreservesExistingProviderVersion(t *testing.T) {
	lrFile, err := os.ReadFile("testdata/new.lr")
	require.NoError(t, err)

	existing := LrVersions{
		"sshd":                "12.0.0",
		"sshd.config":         "11.0.0",
		"sshd.config.ciphers": "11.5.0",
	}

	lr := parse(t, string(lrFile))
	versions := GenerateVersions(lr, "13.0.0", existing)

	// existing min_provider_version must not be overwritten
	assert.Equal(t, "12.0.0", versions["sshd"])
	assert.Equal(t, "11.0.0", versions["sshd.config"])

	// existing field-level version preserved
	assert.Equal(t, "11.5.0", versions["sshd.config.ciphers"])

	// new fields on existing resource get currentVersion
	assert.Equal(t, "13.0.0", versions["sshd.config.file"])
	assert.Equal(t, "13.0.0", versions["sshd.config.macs"])

	// new resource gets the current version
	assert.Equal(t, "13.0.0", versions["auditd.config"])
	// its fields too
	assert.Equal(t, "13.0.0", versions["auditd.config.file"])
}

func TestReadWriteVersions(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.lr.versions")

	original := LrVersions{
		"asset":             "9.0.0",
		"asset.annotations": "10.4.0",
		"asset.eol":         "9.1.1",
	}

	err := WriteVersions(path, original, nil)
	require.NoError(t, err)

	loaded, err := ReadVersions(path)
	require.NoError(t, err)
	assert.Equal(t, original, loaded)
}

func TestInjectVersions(t *testing.T) {
	schema := &resources.Schema{
		Resources: map[string]*resources.ResourceInfo{
			"asset": {
				Fields: map[string]*resources.Field{
					"annotations": {},
					"name":        {},
				},
			},
			"asset.eol": {
				Fields: map[string]*resources.Field{
					"date": {},
				},
			},
		},
	}

	versions := LrVersions{
		"asset":             "9.0.0",
		"asset.annotations": "10.4.0",
		"asset.name":        "9.0.0",
		"asset.eol":         "9.1.1",
		"asset.eol.date":    "9.1.1",
	}

	InjectVersions(schema, versions)

	assert.Equal(t, "9.0.0", schema.Resources["asset"].MinProviderVersion)
	// annotations (10.4.0) differs from asset (9.0.0) — set explicitly
	assert.Equal(t, "10.4.0", schema.Resources["asset"].Fields["annotations"].MinProviderVersion)
	// name (9.0.0) matches asset (9.0.0) — left empty (omitted from JSON)
	assert.Equal(t, "", schema.Resources["asset"].Fields["name"].MinProviderVersion)
	assert.Equal(t, "9.1.1", schema.Resources["asset.eol"].MinProviderVersion)
	// date (9.1.1) matches asset.eol (9.1.1) — left empty
	assert.Equal(t, "", schema.Resources["asset.eol"].Fields["date"].MinProviderVersion)
}

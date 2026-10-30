// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package wheelegg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDistInfoName(t *testing.T) {
	tests := []struct {
		entry       string
		wantName    string
		wantVersion string
	}{
		{"requests-2.32.3.dist-info", "requests", "2.32.3"},
		{"litellm-1.80.15.dist-info", "litellm", "1.80.15"},
		// installed metadata records the normalized name, underscores and all
		{"python_ftp_server-1.3.17.dist-info", "python_ftp_server", "1.3.17"},
		// hyphens are legal inside a project name; only the last part is a version
		{"typing-extensions-4.12.2.dist-info", "typing-extensions", "4.12.2"},
		// calendar versioning
		{"certifi-2026.7.22.dist-info", "certifi", "2026.7.22"},
		// egg-info carries an interpreter tag after the version
		{"python_dateutil-2.6.1-py3.6.egg-info", "python_dateutil", "2.6.1"},
		{"six-1.11.0-py2.7.egg-info", "six", "1.11.0"},
		// no version part at all
		{"mypackage.egg-info", "mypackage", ""},
		{"setuptools.dist-info", "setuptools", ""},
		// a hyphen with no version after it belongs to the name
		{"my-package.egg-info", "my-package", ""},
		// nothing usable
		{"", "", ""},
		{".dist-info", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.entry, func(t *testing.T) {
			name, version := ParseDistInfoName(tc.entry)
			assert.Equal(t, tc.wantName, name, "name")
			assert.Equal(t, tc.wantVersion, version, "version")
		})
	}
}

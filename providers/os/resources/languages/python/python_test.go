// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package python

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPurlAndCPE(t *testing.T) {
	tests := []struct {
		name         string
		version      string
		expectedPurl string
		expectedCpes []string
	}{
		{
			name:         "test",
			version:      "1.0.0",
			expectedPurl: "pkg:pypi/test@1.0.0",
			expectedCpes: []string{"cpe:2.3:a:test_project:test:1.0.0:*:*:*:*:*:*:*"},
		},
		{
			// dots are separators under PEP 503 just like hyphens and
			// underscores; a purl that keeps them does not resolve against
			// vulnerability data
			name:         "zope.interface",
			version:      "7.2",
			expectedPurl: "pkg:pypi/zope-interface@7.2",
			expectedCpes: []string{"cpe:2.3:a:zope.interface_project:zope.interface:7.2:*:*:*:*:*:*:*"},
		},
		{
			name:         "ruamel.yaml.clib",
			version:      "0.2.12",
			expectedPurl: "pkg:pypi/ruamel-yaml-clib@0.2.12",
			expectedCpes: []string{"cpe:2.3:a:ruamel.yaml.clib_project:ruamel.yaml.clib:0.2.12:*:*:*:*:*:*:*"},
		},
	}

	for i := range tests {
		test := tests[i]
		t.Run(test.name, func(t *testing.T) {
			purl := NewPackageUrl(test.name, test.version)
			assert.Equal(t, test.expectedPurl, purl)

			cpes := NewCpes(test.name, test.version)
			assert.Equal(t, test.expectedCpes, cpes)
		})
	}
}

// Names are spelled inconsistently across installed metadata, manifests and lock
// files. All the spellings of one project have to collapse to a single key, or
// the same project is reported twice and its purl fails to match.
func TestNormalizeName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"requests", "requests"},
		{"Flask", "flask"},
		{"zope.interface", "zope-interface"},
		{"zope_interface", "zope-interface"},
		{"Zope.Interface", "zope-interface"},
		{"ruamel.yaml.clib", "ruamel-yaml-clib"},
		{"typing-extensions", "typing-extensions"},
		{"typing_extensions", "typing-extensions"},
		// runs of separators collapse to one
		{"foo--bar", "foo-bar"},
		{"foo._-bar", "foo-bar"},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, NormalizeName(tc.in))
		})
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packagejson

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageJson(t *testing.T) {
	tests := []struct {
		Fixture  string
		Expected packageJson
	}{
		{
			Fixture: "./testdata/author.json",
			Expected: packageJson{
				Name: "author.js",
				Author: &packageJsonPeople{
					Name:  "Barney Rubble",
					Email: "b@rubble.com",
					URL:   "http://barnyrubble.tumblr.com/",
				},
			},
		},
		{
			Fixture: "./testdata/author_shorten.json",
			Expected: packageJson{
				Name: "author-shorten.js",
				Author: &packageJsonPeople{
					Name:  "Barney Rubble",
					Email: "b@rubble.com",
				},
			},
		},
		{
			Fixture: "./testdata/author_shorten_url.json",
			Expected: packageJson{
				Name: "author-shorten.js",
				Author: &packageJsonPeople{
					Name:  "Barney Rubble",
					Email: "b@rubble.com",
					URL:   "http://barnyrubble.tumblr.com/",
				},
			},
		},
		{
			Fixture: "./testdata/bugs.json",
			// we do not parse bugs, so it should be empty
			Expected: packageJson{},
		},
		{
			Fixture: "./testdata/bundle_dependencies.json",
			Expected: packageJson{
				Name:    "awesome-web-framework",
				Version: "1.0.0",
				// we do not parse bundle dependencies, so it should be empty
			},
		},
		{
			Fixture: "./testdata/contributors.json",
			Expected: packageJson{
				Contributors: []packageJsonPeople{
					{
						Name:  "Barney Rubble",
						Email: "b@rubble.com",
						URL:   "http://barnyrubble.tumblr.com/",
					},
				},
			},
		},
		{
			Fixture: "./testdata/contributors_shorten.json",
			Expected: packageJson{
				Contributors: []packageJsonPeople{
					{
						Name:  "Barney Rubble",
						Email: "b@rubble.com",
						URL:   "http://barnyrubble.tumblr.com/",
					},
				},
			},
		},
		{
			Fixture: "./testdata/cpu_exclude.json",
			Expected: packageJson{
				CPU: []string{"!arm", "!mips"},
			},
		},
		{
			Fixture: "./testdata/cpu_include.json",
			Expected: packageJson{
				CPU: []string{"x64", "ia32"},
			},
		},
		{
			Fixture: "./testdata/dependencies.json",
			Expected: packageJson{
				Dependencies: map[string]string{
					"foo": "1.0.0 - 2.9999.9999",
					"bar": ">=1.0.2 <2.1.2",
					"baz": ">1.0.2 <=2.3.4",
					"boo": "2.0.1",
					"qux": "<1.0.0 || >=2.3.1 <2.4.5 || >=2.5.2 <3.0.0",
					"asd": "http://asdf.com/asdf.tar.gz",
					"til": "~1.2",
					"elf": "~1.2.3",
					"two": "2.x",
					"thr": "3.3.x",
					"lat": "latest",
					"dyl": "file:../dyl",
				},
			},
		},
		{
			Fixture: "./testdata/dev_dependencies.json",
			Expected: packageJson{
				Name:        "ethopia-waza",
				Description: "a delightfully fruity coffee varietal",
				Version:     "1.2.3",
				DevDependencies: map[string]string{
					"coffee-script": "~1.6.3",
				},
			},
		},
		{
			Fixture: "./testdata/engines.json",
			Expected: packageJson{
				Engines: map[string]string{
					"node": ">=0.10.3 <15",
				},
			},
		},
		// https://github.com/mondoohq/mql/issues/5235
		{
			Fixture: "./testdata/engines-malformed-GH5235.json",
			Expected: packageJson{
				Engines: map[string]string{},
			},
		},
		{
			Fixture: "./testdata/homepage.json",
			Expected: packageJson{
				Homepage: "https://github.com/owner/project#readme",
			},
		},
		{
			// the deprecated object form of `license`: the `type` is the
			// license, the `url` only links its text
			Fixture: "./testdata/license_deprecated_01.json",
			Expected: packageJson{
				License: &packageJsonLicense{
					Value: "ISC",
				},
			},
		},
		{
			// the deprecated `licenses` array, which npm replaced with the
			// single `license` string
			Fixture: "./testdata/license_deprecated_02.json",
			Expected: packageJson{
				License: nil,
				Licenses: []packageJsonLicense{
					{Value: "MIT"},
					{Value: "Apache-2.0"},
				},
			},
		},
		{
			Fixture: "./testdata/license_spdx.json",
			Expected: packageJson{
				License: &packageJsonLicense{
					Value: "BSD-3-Clause",
				},
			},
		},
		{
			Fixture: "./testdata/license_spdx_expression.json",
			Expected: packageJson{
				License: &packageJsonLicense{
					Value: "(MIT OR Apache-2.0)",
				},
			},
		},
		{
			Fixture: "./testdata/os_exclude.json",
			Expected: packageJson{
				OS: []string{"!win32"},
			},
		},
		{
			Fixture: "./testdata/os_include.json",
			Expected: packageJson{
				OS: []string{"darwin", "linux"},
			},
		},
		{
			Fixture: "./testdata/peer_dependencies.json",
			Expected: packageJson{
				Name:    "tea-latte",
				Version: "1.3.5",
				// we do not parse peerDependencies so it should be empty
			},
		},
		{
			Fixture: "./testdata/peer_dependencies_meta.json",
			Expected: packageJson{
				Name:    "tea-latte",
				Version: "1.3.5",
				// we do not parse peerDependenciesMeta so it should be empty
			},
		},
		{
			Fixture: "./testdata/private.json",
			Expected: packageJson{
				Private: true,
			},
		},
		{
			Fixture: "./testdata/repository.json",
			Expected: packageJson{
				Repository: packageJsonRepository{
					Type: "git",
					URL:  "https://github.com/npm/cli.git",
				},
			},
		},
		{
			Fixture: "./testdata/repository_bitbucket.json",
			Expected: packageJson{
				Repository: packageJsonRepository{
					Type: "bitbucket",
					URL:  "user/repo",
				},
			},
		},
		{
			Fixture: "./testdata/repository_directory.json",
			Expected: packageJson{
				Repository: packageJsonRepository{
					Type:      "git",
					URL:       "https://github.com/facebook/react.git",
					Directory: "packages/react-dom",
				},
			},
		},
		{
			Fixture: "./testdata/repository_gh.json",
			Expected: packageJson{
				Repository: packageJsonRepository{
					Type: "github",
					URL:  "npm/npm",
				},
			},
		},
		{
			Fixture: "./testdata/workspaces.json",
			Expected: packageJson{
				Name: "workspace-example",
				// we do not parse workspaces so it should be empty
			},
		},
		{
			Fixture: "./testdata/private-string.json",
			Expected: packageJson{
				Name:    "example",
				Version: "0.0.1",
				Private: true,
				Dependencies: map[string]string{
					"express": "*",
				},
			},
		},
	}

	for i := range tests {
		test := tests[i]
		t.Run(test.Fixture, func(t *testing.T) {
			f, err := os.Open(tests[i].Fixture)
			require.NoError(t, err)

			pkg := packageJson{}
			err = json.NewDecoder(f).Decode(&pkg)
			require.NoError(t, err)
			assert.Equal(t, tests[i].Expected, pkg)
		})
	}
}

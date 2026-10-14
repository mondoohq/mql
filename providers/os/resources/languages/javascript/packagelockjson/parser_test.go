// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packagelockjson

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/languages"
)

func TestScopeOf(t *testing.T) {
	// strictly dev-only
	assert.Equal(t, languages.PackageScopeDev, scopeOf(packageLockPackage{Dev: true}))
	// plain production
	assert.Equal(t, languages.PackageScopeProd, scopeOf(packageLockPackage{}))
	// devOptional can appear in the prod tree → prod, even when dev is also set
	assert.Equal(t, languages.PackageScopeProd, scopeOf(packageLockPackage{Dev: true, DevOptional: true}))
	assert.Equal(t, languages.PackageScopeProd, scopeOf(packageLockPackage{DevOptional: true}))
}

func TestResolveDepPurlDepthCapped(t *testing.T) {
	pkgs := map[string]packageLockPackage{"node_modules/target": {Version: "1.0.0"}}
	idx := map[string]string{"node_modules/target": "pkg:npm/target@1.0.0"}

	// Within the cap, a dep that only resolves at the root still resolves.
	assert.Equal(t, "pkg:npm/target@1.0.0", resolveDepPurl(pkgs, idx, "node_modules/a", "target"))

	// A pathologically deep path (beyond the cap) short-circuits to "" rather than
	// walking unbounded — the DoS guard.
	deep := "node_modules/a"
	for i := 0; i < maxNodeModulesDepth+5; i++ {
		deep += "/node_modules/a"
	}
	assert.Equal(t, "", resolveDepPurl(pkgs, idx, deep, "target"))
}

func TestPackageLock(t *testing.T) {
	tests := []struct {
		Fixture  string
		Expected packageLock
	}{
		{
			Fixture: "testdata/lockfile-v0.json",
			Expected: packageLock{
				Name:            "react-build",
				Version:         "15.1.0",
				LockfileVersion: 0,
				Requires:        false,
				Packages:        nil,
				Dependencies: map[string]packageLockDependency{
					"art": {
						Version:  "0.10.1",
						Resolved: "https://registry.npmjs.org/art/-/art-0.10.1.tgz",
					},
					"babel-cli": {
						Version:  "6.10.1",
						Resolved: "https://registry.npmjs.org/babel-cli/-/babel-cli-6.10.1.tgz",
						Dependencies: map[string]packageLockDependency{
							"babel-register": {
								Version:  "6.9.0",
								Resolved: "https://registry.npmjs.org/babel-register/-/babel-register-6.9.0.tgz",
							},
						},
					},
				},
			},
		},
		{
			Fixture: "testdata/lockfile-v1.json",
			Expected: packageLock{
				Name:            "npm",
				Version:         "6.0.0",
				LockfileVersion: 1,
				Requires:        true,
				Dependencies: map[string]packageLockDependency{
					"JSONStream": {
						Version:   "1.3.2",
						Resolved:  "https://registry.npmjs.org/JSONStream/-/JSONStream-1.3.2.tgz",
						Integrity: "sha1-wQI3G27Dp887hHygDCC7D85Mbeo=",
						Dependencies: map[string]packageLockDependency{
							"jsonparse": {
								Version:   "1.3.1",
								Resolved:  "https://registry.npmjs.org/jsonparse/-/jsonparse-1.3.1.tgz",
								Integrity: "sha1-P02uSpH6wxX3EGL4UhzCOfE2YoA=",
							},
							"through": {
								Version:   "2.3.8",
								Resolved:  "https://registry.npmjs.org/through/-/through-2.3.8.tgz",
								Integrity: "sha1-DdTJ/6q8NXlgsbckEV1+Doai4fU=",
							},
						},
					},
				},
			},
		},
		{
			Fixture: "testdata/lockfile-v2.json",
			Expected: packageLock{
				Name:            "npm",
				Version:         "7.0.0",
				LockfileVersion: 2,
				Requires:        true,
				Packages: map[string]packageLockPackage{
					"": {
						Name:    "npm",
						Version: "7.0.0",
						License: packageLockLicense(
							[]string{"Artistic-2.0"},
						),
						Dependencies: map[string]string{
							"@npmcli/arborist":  "^1.0.0",
							"@npmcli/ci-detect": "^1.2.0",
						},
					},
					"node_modules/@babel/code-frame": {
						Version:   "7.10.4",
						Resolved:  "https://registry.npmjs.org/@babel/code-frame/-/code-frame-7.10.4.tgz",
						Integrity: "sha512-vG6SvB6oYEhvgisZNFRmRCUkLz11c7rp+tbNTynGqc6mS1d5ATd/sGyV6W0KZZnXRKMTzZDRgQT3Ou9jhpAfUg==",
						Dev:       true,
						Dependencies: map[string]string{
							"@babel/highlight": "^7.10.4",
						},
					},
				},
				Dependencies: map[string]packageLockDependency{
					"@babel/code-frame": {
						Version:   "7.10.4",
						Resolved:  "https://registry.npmjs.org/@babel/code-frame/-/code-frame-7.10.4.tgz",
						Integrity: "sha512-vG6SvB6oYEhvgisZNFRmRCUkLz11c7rp+tbNTynGqc6mS1d5ATd/sGyV6W0KZZnXRKMTzZDRgQT3Ou9jhpAfUg==",
						Dev:       true,
					},
				},
			},
		},
		{
			Fixture: "testdata/lockfile-v2-licenses.json",
			Expected: packageLock{
				Name:            "my-package",
				Version:         "1.0.0",
				LockfileVersion: 2,
				Requires:        true,
				Packages: map[string]packageLockPackage{
					"": {
						Name:    "my-package",
						Version: "1.0.0",
						License: packageLockLicense(
							[]string{"MIT", "Apache2"},
						),
					},
				},
			},
		},
		{
			Fixture: "testdata/lockfile-v3.json",
			Expected: packageLock{
				Name:            "npm",
				Version:         "10.4.0",
				LockfileVersion: 3,
				Requires:        true,
				Packages: map[string]packageLockPackage{
					"": {
						Name:    "npm",
						Version: "10.4.0",
						License: packageLockLicense(
							[]string{"Artistic-2.0"},
						),
						Dependencies: map[string]string{
							"@isaacs/string-locale-compare": "^1.1.0",
						},
					},
					"node_modules/@isaacs/string-locale-compare": {
						Version:   "1.1.0",
						Resolved:  "https://registry.npmjs.org/@isaacs/string-locale-compare/-/string-locale-compare-1.1.0.tgz",
						Integrity: "sha512-SQ7Kzhh9+D+ZW9MA0zkYv3VXhIDNx+LzM6EJ+/65I3QY+enU6Itte7E5XX7EWrqLW2FN4n06GWzBnPoC3th2aQ==",
					},
				},
			},
		},
		{
			Fixture: "testdata/simple-lock.json",
			Expected: packageLock{
				Name:            "simple",
				Version:         "1.0.0",
				LockfileVersion: 1,
				Requires:        true,
			},
		},
	}

	for i := range tests {
		test := tests[i]
		t.Run(test.Fixture, func(t *testing.T) {
			f, err := os.Open(tests[i].Fixture)
			require.NoError(t, err)

			pkg := packageLock{}
			err = json.NewDecoder(f).Decode(&pkg)
			require.NoError(t, err)
			assert.Equal(t, tests[i].Expected, pkg)
		})
	}
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/test"
)

var once sync.Once

// setup builds mql locally
func setup() {
	// build mql
	cmd := exec.Command("go", "build", "../../apps/mql/mql.go")
	cmd.Env = test.BuildEnv()
	if err := cmd.Run(); err != nil {
		log.Fatalf("building mql: %v", err)
	}

	// install local provider
	providerCmd := exec.Command("bash", "-c", "cd ../.. && make providers/build/os providers/install/os")
	providerCmd.Env = test.BuildEnv()
	providerCmd.Stdout = os.Stdout
	providerCmd.Stderr = os.Stderr
	if err := providerCmd.Run(); err != nil {
		log.Fatalf("building os provider: %v", err)
	}

	providersPATH := os.Getenv("PROVIDERS_PATH")
	if providersPATH != "" {

		// provider install places the provider in the "$(HOME)/.config/mondoo/providers/${$@_NAME}") but we
		// want to test it in isolation. Therefore, we copy the provider to the current directory .providers
		osProviderPath := filepath.Join(providersPATH, "os")
		if err := os.MkdirAll(osProviderPath, 0o755); err != nil {
			log.Fatalf("creating directory: %v", err)
		}

		if err := exec.Command("cp", "-r", os.ExpandEnv("../../providers/os/dist"), osProviderPath).Run(); err != nil {
			log.Fatalf("copying provider: %v", err)
		}
	}
}

const mqlPackagesQuery = "packages"

type mqlPackages []struct {
	Packages []struct {
		Name    string `json:"name,omitempty"`
		Version string `json:"version,omitempty"`
	} `json:"packages.list,omitempty"`
}

const mqlPlatformQuery = "asset.platform"

type mqlPlatform []struct {
	Platform string `json:"asset.platform,omitempty"`
}

type connections []struct {
	name   string
	binary string
	args   []string
	tests  []mqlTest
}

type mqlTest struct {
	query    string
	expected func(*testing.T, test.Runner)
}

func TestOsProviderSharedTests(t *testing.T) {
	once.Do(setup)

	connections := connections{
		{
			name:   "local",
			binary: "./mql",
			args:   []string{"run", "local"},
			tests: []mqlTest{
				{
					mqlPackagesQuery,
					func(t *testing.T, r test.Runner) {
						var c mqlPackages
						err := r.Json(&c)
						assert.NoError(t, err)

						x := c[0]
						assert.NotNil(t, x.Packages)
						assert.True(t, len(x.Packages) > 0)
					},
				},
				{
					mqlPlatformQuery,
					func(t *testing.T, r test.Runner) {
						var c mqlPlatform
						err := r.Json(&c)
						assert.NoError(t, err)

						x := c[0]
						assert.True(t, len(x.Platform) > 0)
					},
				},
			},
		},
		{
			name:   "fs",
			binary: "./mql",
			args:   []string{"run", "fs", "--path", "./testdata/fs"},
			tests: []mqlTest{
				{
					mqlPackagesQuery,
					func(t *testing.T, r test.Runner) {
						var c mqlPackages
						err := r.Json(&c)
						assert.NoError(t, err)

						x := c[0]
						assert.NotNil(t, x.Packages)
						assert.True(t, len(x.Packages) > 0)
					},
				},
				{
					mqlPlatformQuery,
					func(t *testing.T, r test.Runner) {
						var c mqlPlatform
						err := r.Json(&c)
						assert.NoError(t, err)

						x := c[0]
						assert.Equal(t, "debian", x.Platform)
					},
				},
			},
		},
		{
			name:   "docker",
			binary: "./mql",
			args:   []string{"run", "docker", "alpine:latest"},
			tests: []mqlTest{
				{
					mqlPackagesQuery,
					func(t *testing.T, r test.Runner) {
						var c mqlPackages
						err := r.Json(&c)
						assert.NoError(t, err)

						x := c[0]
						assert.NotNil(t, x.Packages)
						assert.True(t, len(x.Packages) > 0)
					},
				},
				{
					mqlPlatformQuery,
					func(t *testing.T, r test.Runner) {
						var c mqlPlatform
						err := r.Json(&c)
						assert.NoError(t, err)

						x := c[0]
						assert.Equal(t, "alpine", x.Platform)
					},
				},
			},
		},
	}

	// iterate over all tests for all connections
	for _, cc := range connections {
		for _, tt := range cc.tests {
			t.Run(cc.name+"/"+tt.query, func(t *testing.T) {
				r := test.NewCliTestRunner(cc.binary, append(cc.args, "-c", tt.query, "-j")...)
				err := r.Run()
				require.NoError(t, err)
				assert.Equal(t, 0, r.ExitCode())
				assert.NotNil(t, r.Stdout())
				assert.NotNil(t, r.Stderr())

				tt.expected(t, r)
			})
		}
	}
}

// TestDebPackageFields verifies that deb package fields beyond name/version
// (arch, format) parse correctly end to end against the deterministic debian
// testdata. It is the deb analogue of the rpm field-shape check in
// rpm_test.go. Unlike rpm, the deb listing path needs no dual-path container
// test: it reads /var/lib/dpkg/status directly via the filesystem for both
// running systems and images, with no self-constructed queryformat delimiter
// and no separate runtime/static code paths, so it lacks the fragility that
// caused the rpm delimiter incident.
func TestDebPackageFields(t *testing.T) {
	once.Do(setup)

	pkgs := queryPackages(t, "fs", "--path", "./testdata/fs")

	// fdisk is in the testdata with a normal architecture, so it proves field
	// splitting worked end to end.
	fdisk, ok := hasPackage(pkgs, "fdisk")
	require.True(t, ok, "fdisk package missing from debian testdata")
	assert.Equal(t, "amd64", fdisk.Arch)
	assert.Equal(t, "deb", fdisk.Format)
	assert.NotEmpty(t, fdisk.Version)
}

func TestProvidersEnvVarsLoading(t *testing.T) {
	t.Run("command WITHOUT path should report the missing path", func(t *testing.T) {
		r := test.NewCliTestRunner("./mql", "run", "fs", "-c", mqlPackagesQuery, "-j")
		err := r.Run()
		require.NoError(t, err)

		// Without MONDOO_PATH (and without --path) the fs asset cannot connect.
		// That is a misconfiguration, so it exits non-zero rather than
		// reporting an empty package list, which would read as "this
		// filesystem has no packages installed".
		assert.Equal(t, 1, r.ExitCode())
		assert.NotNil(t, r.Stderr())
		assert.Contains(t, string(r.Stderr()), "missing filesystem mount path")
	})
	t.Run("command WITH path should find packages", func(t *testing.T) {
		os.Setenv("MONDOO_PATH", "./testdata/fs")
		defer os.Unsetenv("MONDOO_PATH")
		// Note we are not passing the flag "--path ./testdata/fs"
		r := test.NewCliTestRunner("./mql", "run", "fs", "-c", mqlPackagesQuery, "-j")
		err := r.Run()
		require.NoError(t, err)
		assert.Equal(t, 0, r.ExitCode())
		assert.NotNil(t, r.Stdout())
		assert.NotNil(t, r.Stderr())

		var c mqlPackages
		err = r.Json(&c)
		assert.NoError(t, err)

		// Should have packages
		if assert.NotEmpty(t, c) {
			x := c[0]
			assert.NotNil(t, x.Packages)
			assert.True(t, len(x.Packages) > 0)
		}
	})

	t.Run("command with flags set to not bind to config (ConfigEntry=\"-\")", func(t *testing.T) {
		t.Run("should work via direct flag", func(t *testing.T) {
			r := test.NewCliTestRunner("./mql", "run", "ssh", "localhost", "-c", "ls", "-p", "test", "-v")
			err := r.Run()
			require.NoError(t, err)
			// The subject here is flag binding, which is observable in stderr.
			// Whether ssh://localhost actually connects depends on the machine
			// running the test, so the exit code is deliberately not asserted.
			assert.NotNil(t, r.Stdout())
			if assert.NotNil(t, r.Stderr()) {
				assert.Contains(t, string(r.Stderr()), "skipping config binding for password")
				assert.Contains(t, string(r.Stderr()), "enabled ssh password authentication")
			}
		})
		t.Run("should NOT work via config/env-vars", func(t *testing.T) {
			os.Setenv("MONDOO_PASSWORD", "test")
			defer os.Unsetenv("MONDOO_PASSWORD")
			r := test.NewCliTestRunner("./mql", "run", "ssh", "localhost", "-c", "ls", "-v")
			err := r.Run()
			require.NoError(t, err)
			// As above: the assertion is about config binding, not reachability.
			assert.NotNil(t, r.Stdout())
			if assert.NotNil(t, r.Stderr()) {
				assert.Contains(t, string(r.Stderr()), "skipping config binding for password")
				assert.NotContains(t, string(r.Stderr()), "enabled ssh password authentication")
			}
		})
	})
}

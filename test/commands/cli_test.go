// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package commands

import (
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-cmdtest"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/test"
)

var once sync.Once
var testDir string

func setup() {
	// build mql
	cmd := exec.Command("go", "build", "../../apps/mql/mql.go")
	cmd.Env = test.BuildEnv()
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
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

	// create a fake directory to use for testing purposes (providers, config, etc.)
	dir, err := os.MkdirTemp("", "mondoo")
	if err != nil {
		log.Fatalf("creating directory: %v", err)
	}
	testDir = dir

	// provider install places the provider in the "$(HOME)/.config/mondoo/providers/${$@_NAME}") but we
	// want to test it in isolation. Therefore, we copy the provider to the current directory .providers
	osProviderPath := filepath.Join(testDir, "os")
	if err := os.MkdirAll(osProviderPath, 0755); err != nil {
		log.Fatalf("creating directory: %v", err)
	}

	distPath, err := filepath.Abs("../../providers/os/dist")
	if err != nil {
		log.Fatalf("unable to expand dist path: %v", err)
	}

	if err := os.CopyFS(osProviderPath, os.DirFS(distPath)); err != nil {
		log.Fatalf("copying provider: %v", err)
	}
}

func TestMain(m *testing.M) {
	// When tests run with -cover, Go sets GOCOVERDIR which is inherited by
	// child processes. The mql binary spawned by cmdtest is not built with
	// -cover, so it fails at exit when trying to write coverage data.
	// BuildEnv() strips GOCOVERDIR for setup() child processes, but cmdtest
	// spawns the mql binary using the current process environment directly,
	// so we must also unset it here.
	os.Unsetenv("GOCOVERDIR")

	ret := m.Run()

	// setup() copies the full os provider dist (~100MB) into testDir; without
	// this the directory is left behind in /tmp on every test run.
	if testDir != "" {
		if err := os.RemoveAll(testDir); err != nil {
			log.Printf("removing test directory %s: %v", testDir, err)
		}
	}

	os.Exit(ret)
}

func TestCompare(t *testing.T) {
	once.Do(setup)
	ts, err := cmdtest.Read("testdata")
	require.NoError(t, err)

	// Set a fake config path to avoid loading the real configuration
	// file from the system running this tests
	os.Setenv("MONDOO_CONFIG_PATH", path.Join(testDir, "foo"))
	// Override providers path with the fake test directory
	os.Setenv("PROVIDERS_PATH", testDir)
	// Disable auto-update to avoid installing providers
	os.Setenv("MONDOO_AUTO_UPDATE", "false")

	ts.DisableLogging = true
	ts.Commands["mql"] = cmdtest.Program("mql")
	ts.Run(t, false) // set to true to update test files
}

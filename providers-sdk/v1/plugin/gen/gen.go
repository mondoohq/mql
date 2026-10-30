// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gen

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Masterminds/semver"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// This package contains shared components for plugin generation.
// You use this library in your own plugins under:
// <PLUGIN>/gen/main.go
// See our builtin plugins for examples.

// CLI starts and manages the CLI of the plugin generation code.
func CLI(conf *plugin.Provider) {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "You have to provide the path of the plugin")
		os.Exit(1)
	}

	if conf.Version == "" {
		fmt.Fprintln(os.Stderr, "You must specify a version for the '"+conf.Name+"' provider (semver required)")
		os.Exit(1)
	}

	_, err := semver.NewVersion(conf.Version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Version must be a semver for '"+conf.Name+"' provider (was: '"+conf.Version+"')")
		os.Exit(1)
	}

	pluginPath := os.Args[1]
	fmt.Println("--> looking for plugin in " + pluginPath)

	if ok, err := afero.IsDir(fs, pluginPath); err != nil || !ok {
		fmt.Fprintln(os.Stderr, "Looks like the plugin path you provided isn't correct: "+pluginPath)
		os.Exit(1)
	}

	distPath := filepath.Join(pluginPath, "dist")
	if err := ensureDir(distPath); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	data, err := json.Marshal(conf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to generate JSON: "+string(data))
		os.Exit(1)
	}

	dst := filepath.Join(distPath, conf.Name+".json")
	fmt.Println("--> writing plugin json to " + dst)
	if err = afero.WriteFile(fs, dst, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to write JSON to file "+dst+": "+string(data))
		os.Exit(1)
	}
}

var fs afero.Fs

func init() {
	fs = afero.NewOsFs()
}

func ensureDir(path string) error {
	exist, err := afero.DirExists(fs, path)
	if err != nil {
		return errors.New("failed to check if " + path + " exists: " + err.Error())
	}
	if exist {
		return nil
	}

	fmt.Println("--> creating " + path)
	if err := fs.MkdirAll(path, 0o755); err != nil {
		return errors.New("failed to create " + path + ": " + err.Error())
	}
	return nil
}

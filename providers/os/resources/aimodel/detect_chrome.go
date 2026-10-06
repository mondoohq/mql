// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"encoding/json"
	"path/filepath"
)

// ChromeDetector discovers the Gemini Nano model Google Chrome downloads for
// its built-in AI APIs. Chrome keeps it as the "Optimization Guide On Device
// Model" component in OptGuideOnDeviceModel/<component version>/ under the
// browser's user data directory, shared by every profile. The component's
// manifest.json names the base model and its version in BaseModelSpec, the
// same values chrome://on-device-internals shows. Each release channel has its
// own user data directory and downloads its own copy.
type ChromeDetector struct{}

type chromeModelManifest struct {
	Version       string `json:"version"`
	BaseModelSpec struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"BaseModelSpec"`
}

func (d *ChromeDetector) Detect(ctx DetectContext) []ModelInfo {
	var results []ModelInfo
	for _, userData := range chromeUserDataDirs(ctx.Home, ctx.OSFamily) {
		storeDir := filepath.Join(userData, "OptGuideOnDeviceModel")
		entries, err := ctx.Fs.ReadDir(storeDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			componentDir := filepath.Join(storeDir, e.Name())
			// Chrome writes the manifest before the weights finish downloading,
			// so a component without weights.bin is not a usable model yet.
			if ok, _ := ctx.Fs.Exists(filepath.Join(componentDir, "weights.bin")); !ok {
				continue
			}
			data, err := ctx.Fs.ReadFile(filepath.Join(componentDir, "manifest.json"))
			if err != nil {
				continue
			}
			var manifest chromeModelManifest
			if json.Unmarshal(data, &manifest) != nil {
				continue
			}

			// Older components carry no BaseModelSpec; the component version is
			// then the only version on disk.
			name := manifest.BaseModelSpec.Name
			if name == "" {
				name = "gemini-nano"
			}
			version := manifest.BaseModelSpec.Version
			if version == "" {
				version = manifest.Version
			}

			size, modTime := dirSizeRecursive(ctx.Fs, componentDir)
			results = append(results, ModelInfo{
				Name:       name,
				Source:     "chrome",
				Vendor:     "google",
				Family:     "gemini-nano",
				Path:       componentDir,
				Size:       size,
				ModifiedAt: modTime,
				Version:    version,
			})
		}
	}
	return results
}

// chromeUserDataDirs returns the user data directory of each Chrome release
// channel (stable, beta, dev, canary).
func chromeUserDataDirs(home string, osFamily string) []string {
	switch osFamily {
	case "darwin":
		base := filepath.Join(home, "Library", "Application Support", "Google")
		return []string{
			filepath.Join(base, "Chrome"),
			filepath.Join(base, "Chrome Beta"),
			filepath.Join(base, "Chrome Dev"),
			filepath.Join(base, "Chrome Canary"),
		}
	case "linux":
		base := filepath.Join(home, ".config")
		return []string{
			filepath.Join(base, "google-chrome"),
			filepath.Join(base, "google-chrome-beta"),
			filepath.Join(base, "google-chrome-unstable"),
		}
	case "windows":
		base := filepath.Join(home, "AppData", "Local", "Google")
		return []string{
			filepath.Join(base, "Chrome", "User Data"),
			filepath.Join(base, "Chrome Beta", "User Data"),
			filepath.Join(base, "Chrome Dev", "User Data"),
			filepath.Join(base, "Chrome SxS", "User Data"),
		}
	}
	return nil
}

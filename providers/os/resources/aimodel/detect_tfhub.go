// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

// TFHubDetector discovers TensorFlow Hub modules cached at
// ~/.cache/tfhub_modules. Each module directory must contain a
// saved_model.pb file to be recognized as a valid TF SavedModel.
type TFHubDetector struct{}

func (d *TFHubDetector) Detect(ctx DetectContext) []ModelInfo {
	modulesDir := joinPath(ctx.Home, ".cache", "tfhub_modules")
	entries, err := ctx.Fs.ReadDir(modulesDir)
	if err != nil {
		return nil
	}

	var results []ModelInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		moduleDir := joinPath(modulesDir, e.Name())

		// TF Hub modules contain saved_model.pb
		savedModel := joinPath(moduleDir, "saved_model.pb")
		if exists, _ := ctx.Fs.Exists(savedModel); !exists {
			continue
		}

		totalSize, modTime := dirSizeRecursive(ctx.Fs, moduleDir)

		results = append(results, ModelInfo{
			Name:       e.Name(),
			Source:     "tfhub",
			Path:       moduleDir,
			Size:       totalSize,
			ModifiedAt: modTime,
			Format:     "savedmodel",
		})
	}
	return results
}

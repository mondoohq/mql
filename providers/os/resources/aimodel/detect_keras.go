// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"strings"
)

// KerasDetector discovers models cached by Keras (~/.keras/models).
// Supports .h5 (HDF5) and .keras (native Keras v3) formats.
type KerasDetector struct{}

func (d *KerasDetector) Detect(ctx DetectContext) []ModelInfo {
	modelsDir := joinPath(ctx.Home, ".keras", "models")
	entries, err := ctx.Fs.ReadDir(modelsDir)
	if err != nil {
		return nil
	}

	var results []ModelInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		lower := strings.ToLower(e.Name())
		if !strings.HasSuffix(lower, ".h5") && !strings.HasSuffix(lower, ".keras") {
			continue
		}

		format := "h5"
		if strings.HasSuffix(lower, ".keras") {
			format = "keras"
		}

		name := strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".h5"), ".keras")

		results = append(results, ModelInfo{
			Name:       name,
			Source:     "keras",
			Path:       joinPath(modelsDir, e.Name()),
			Size:       e.Size(),
			ModifiedAt: e.ModTime(),
			Format:     format,
		})
	}
	return results
}

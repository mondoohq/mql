// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"strings"
	"time"

	"github.com/spf13/afero"
)

// LMStudioDetector discovers GGUF models cached by LM Studio. It checks both
// the legacy path (~/.lmstudio/models) and the newer cache path
// (~/.cache/lm-studio/models). Models are organized as publisher/repo/file.gguf.
// Quantization is extracted from filenames via regex. The parameter size is
// the GGUF general.size_label, falling back to a count the name states.
type LMStudioDetector struct{}

func (d *LMStudioDetector) Detect(ctx DetectContext) []ModelInfo {
	dirs := []string{
		joinPath(ctx.Home, ".lmstudio", "models"),
		joinPath(ctx.Home, ".cache", "lm-studio", "models"),
	}

	seen := map[string]bool{}
	var results []ModelInfo
	for _, modelsDir := range dirs {
		entries, err := ctx.Fs.ReadDir(modelsDir)
		if err != nil {
			continue
		}
		for _, publisher := range entries {
			if !publisher.IsDir() {
				continue
			}
			publisherDir := joinPath(modelsDir, publisher.Name())
			repos, err := ctx.Fs.ReadDir(publisherDir)
			if err != nil {
				continue
			}
			for _, repo := range repos {
				if !repo.IsDir() {
					continue
				}
				repoDir := joinPath(publisherDir, repo.Name())
				modelName := publisher.Name() + "/" + repo.Name()
				if seen[modelName] {
					continue
				}
				seen[modelName] = true

				ggufFiles := findGGUFFiles(ctx.Fs, repoDir)
				for _, m := range ggufFiles {
					filename := baseName(m.path)
					quant := ""
					if match := reQuantization.FindString(filename); match != "" {
						quant = strings.ToUpper(match)
					}
					paramSize := parameterSizeFromGGUF(ctx.Fs, []string{m.path}, modelName)

					results = append(results, ModelInfo{
						Name:          modelName + "/" + filename,
						Source:        "lmstudio",
						Vendor:        publisher.Name(),
						Path:          m.path,
						Size:          m.size,
						ModifiedAt:    m.modTime,
						Format:        "gguf",
						Quantization:  quant,
						ParameterSize: paramSize,
					})
				}
			}
		}
	}
	return results
}

type fileEntry struct {
	path    string
	size    int64
	modTime time.Time
}

func findGGUFFiles(afs *afero.Afero, dir string) []fileEntry {
	entries, err := afs.ReadDir(dir)
	if err != nil {
		return nil
	}
	var results []fileEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), ".gguf") {
			results = append(results, fileEntry{
				path:    joinPath(dir, e.Name()),
				size:    e.Size(),
				modTime: e.ModTime(),
			})
		}
	}
	return results
}

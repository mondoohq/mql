// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"strings"
)

// GPT4AllDetector discovers models cached by GPT4All. It checks the shared
// cache directory (~/.cache/gpt4all) and the platform-specific application data
// directory (e.g. ~/Library/Application Support/nomic.ai/GPT4All on macOS).
// Supports .gguf and .bin (legacy ggml) files. Quantization is extracted from
// filenames via regex. The parameter size is the GGUF general.size_label,
// falling back to a count the filename states.
type GPT4AllDetector struct{}

func (d *GPT4AllDetector) Detect(ctx DetectContext) []ModelInfo {
	dirs := gpt4allDirs(ctx.Home, ctx.OSFamily)
	seen := map[string]bool{}
	var results []ModelInfo

	for _, dir := range dirs {
		entries, err := ctx.Fs.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			lower := strings.ToLower(e.Name())
			if !strings.HasSuffix(lower, ".gguf") && !strings.HasSuffix(lower, ".bin") {
				continue
			}
			if seen[e.Name()] {
				continue
			}
			seen[e.Name()] = true

			format := "gguf"
			if strings.HasSuffix(lower, ".bin") {
				format = "ggml"
			}

			quant := ""
			if match := reQuantization.FindString(e.Name()); match != "" {
				quant = strings.ToUpper(match)
			}
			paramSize := parameterSizeFromName(e.Name())
			if format == "gguf" {
				paramSize = parameterSizeFromGGUF(ctx.Fs, []string{joinPath(dir, e.Name())}, e.Name())
			}

			results = append(results, ModelInfo{
				Name:          e.Name(),
				Source:        "gpt4all",
				Path:          joinPath(dir, e.Name()),
				Size:          e.Size(),
				ModifiedAt:    e.ModTime(),
				Format:        format,
				Quantization:  quant,
				ParameterSize: paramSize,
			})
		}
	}
	return results
}

func gpt4allDirs(home string, osFamily string) []string {
	dirs := []string{
		joinPath(home, ".cache", "gpt4all"),
	}
	switch osFamily {
	case "darwin":
		dirs = append(dirs, joinPath(home, "Library", "Application Support", "nomic.ai", "GPT4All"))
	case "linux":
		dirs = append(dirs, joinPath(home, ".local", "share", "nomic.ai", "GPT4All"))
	case "windows":
		dirs = append(dirs, joinPath(home, "AppData", "Local", "nomic.ai", "GPT4All"))
	}
	return dirs
}

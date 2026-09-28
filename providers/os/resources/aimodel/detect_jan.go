// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
)

// JanDetector discovers models managed by Jan (~/jan/models). Each model lives
// in its own subdirectory and optionally contains a model.json with rich
// metadata: name, version, description, license, tags, publisher, and format.
// Quantization is extracted from GGUF filenames in the directory. The
// parameter size is the general.size_label of the model's GGUF file, falling
// back to a count the model name states.
type JanDetector struct{}

type janModelMeta struct {
	Name        string            `json:"name"`
	ID          string            `json:"id"`
	Format      string            `json:"format"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	License     string            `json:"license"`
	Metadata    janModelMetadata  `json:"metadata"`
	Publisher   janModelPublisher `json:"publisher"`
}

type janModelMetadata struct {
	Author string   `json:"author"`
	Name   string   `json:"name"`
	Tags   []string `json:"tags"`
}

type janModelPublisher struct {
	Author string `json:"author"`
	Name   string `json:"name"`
}

func (d *JanDetector) Detect(ctx DetectContext) []ModelInfo {
	modelsDir := filepath.Join(ctx.Home, "jan", "models")
	entries, err := ctx.Fs.ReadDir(modelsDir)
	if err != nil {
		return nil
	}

	var results []ModelInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		modelDir := filepath.Join(modelsDir, e.Name())

		name := e.Name()
		format := "unknown"
		vendor := ""
		version := ""
		description := ""
		license := ""
		var tags []string

		metaPath := filepath.Join(modelDir, "model.json")
		if data, err := ctx.Fs.ReadFile(metaPath); err == nil {
			var meta janModelMeta
			if json.Unmarshal(data, &meta) == nil {
				if meta.Name != "" {
					name = meta.Name
				} else if meta.ID != "" {
					name = meta.ID
				}
				if meta.Format != "" {
					format = strings.ToLower(meta.Format)
				}
				if meta.Publisher.Name != "" {
					vendor = meta.Publisher.Name
				} else if meta.Publisher.Author != "" {
					vendor = meta.Publisher.Author
				} else if meta.Metadata.Author != "" {
					vendor = meta.Metadata.Author
				}
				version = meta.Version
				description = meta.Description
				license = meta.License
				tags = meta.Metadata.Tags
			}
		}

		if format == "unknown" {
			format = detectDirModelFormat(ctx.Fs, modelDir)
		}

		// Quantization from GGUF filenames in directory
		quant := ""
		dirEntries, _ := ctx.Fs.ReadDir(modelDir)
		for _, f := range dirEntries {
			if match := reQuantization.FindString(f.Name()); match != "" {
				quant = strings.ToUpper(match)
				break
			}
		}

		// The first GGUF file in the directory carries the size label.
		var gguf []string
		if files := findGGUFFiles(ctx.Fs, modelDir); len(files) > 0 {
			gguf = []string{files[0].path}
		}
		paramSize := parameterSizeFromGGUF(ctx.Fs, gguf, name)

		totalSize, modTime := dirSizeRecursive(ctx.Fs, modelDir)

		results = append(results, ModelInfo{
			Name:          name,
			Source:        "jan",
			Vendor:        vendor,
			Path:          modelDir,
			Size:          totalSize,
			ModifiedAt:    modTime,
			Format:        format,
			Version:       version,
			Quantization:  quant,
			ParameterSize: paramSize,
			License:       license,
			Tags:          tags,
			Description:   description,
		})
	}
	return results
}

func detectDirModelFormat(afs *afero.Afero, dir string) string {
	entries, err := afs.ReadDir(dir)
	if err != nil {
		return "unknown"
	}
	for _, f := range entries {
		switch strings.ToLower(filepath.Ext(f.Name())) {
		case ".gguf":
			return "gguf"
		case ".safetensors":
			return "safetensors"
		case ".onnx":
			return "onnx"
		}
	}
	return "unknown"
}

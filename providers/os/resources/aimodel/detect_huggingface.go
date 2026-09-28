// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
)

// HuggingFaceDetector discovers models cached by the Hugging Face Hub client
// (~/.cache/huggingface/hub/models--*). For each model directory it reads:
//   - config.json: model_type (family), architectures, quantization_config
//   - README.md YAML frontmatter: license, tags, pipeline_tag
//   - Snapshot directory name (first 12 chars of the revision hash) as version
//   - File extensions to detect format (safetensors, gguf, onnx, mlx, pytorch)
//
// Parameter size is extracted from the model name via regex when present
// (e.g. "meta-llama/Llama-2-7B" -> "7B").
type HuggingFaceDetector struct{}

type hfConfig struct {
	ModelType          string         `json:"model_type"`
	Architectures      []string       `json:"architectures"`
	QuantizationConfig map[string]any `json:"quantization_config"`
}

type hfReadmeMeta struct {
	License     string   `yaml:"license"`
	Tags        []string `yaml:"tags"`
	PipelineTag string   `yaml:"pipeline_tag"`
}

func (d *HuggingFaceDetector) Detect(ctx DetectContext) []ModelInfo {
	hubDir := filepath.Join(ctx.Home, ".cache", "huggingface", "hub")
	entries, err := ctx.Fs.ReadDir(hubDir)
	if err != nil {
		return nil
	}

	var results []ModelInfo
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "models--") {
			continue
		}

		// Parse name from directory: models--<org>--<repo>
		nameParts := strings.SplitN(entry.Name(), "--", 3)
		if len(nameParts) < 3 {
			continue
		}
		modelName := nameParts[1] + "/" + nameParts[2]

		modelDir := filepath.Join(hubDir, entry.Name())
		blobsDir := filepath.Join(modelDir, "blobs")

		totalSize, modTime := dirSizeAndLatestMtime(ctx.Fs, blobsDir)
		meta := extractHuggingFaceMetadata(ctx.Fs, modelDir)

		paramSize := parameterSizeFromName(modelName)

		results = append(results, ModelInfo{
			Name:          modelName,
			Source:        "huggingface",
			Vendor:        nameParts[1],
			Family:        meta.Family,
			Path:          modelDir,
			Size:          totalSize,
			ModifiedAt:    modTime,
			Format:        meta.Format,
			Version:       meta.Version,
			Quantization:  meta.Quantization,
			ParameterSize: paramSize,
			Architecture:  meta.Architecture,
			License:       meta.License,
			Tags:          meta.Tags,
			Description:   meta.Description,
		})
	}
	return results
}

type hfExtracted struct {
	Format       string
	Family       string
	Version      string
	Architecture string
	Quantization string
	License      string
	Tags         []string
	Description  string
}

func extractHuggingFaceMetadata(afs *afero.Afero, modelDir string) hfExtracted {
	var result hfExtracted
	snapshotsDir := filepath.Join(modelDir, "snapshots")
	snapshots, err := afs.ReadDir(snapshotsDir)
	if err != nil || len(snapshots) == 0 {
		result.Format = "unknown"
		return result
	}

	latest := snapshots[0]
	for _, s := range snapshots[1:] {
		if s.ModTime().After(latest.ModTime()) {
			latest = s
		}
	}
	latestSnapshot := filepath.Join(snapshotsDir, latest.Name())

	// Version = first 12 chars of snapshot dir name (revision hash)
	rev := latest.Name()
	if len(rev) > 12 {
		rev = rev[:12]
	}
	result.Version = rev

	// Read config.json
	configPath := filepath.Join(latestSnapshot, "config.json")
	if data, readErr := afs.ReadFile(configPath); readErr == nil {
		var cfg hfConfig
		if json.Unmarshal(data, &cfg) == nil {
			result.Family = cfg.ModelType
			if len(cfg.Architectures) > 0 {
				result.Architecture = cfg.Architectures[0]
			}
			if cfg.QuantizationConfig != nil {
				if qt, ok := cfg.QuantizationConfig["quant_method"].(string); ok && qt != "" {
					result.Quantization = qt
				}
			}
		}
	}

	// README frontmatter
	readme := parseHFReadmeFrontmatter(afs, latestSnapshot)
	result.License = readme.License
	result.Tags = readme.Tags
	if readme.PipelineTag != "" && len(result.Tags) == 0 {
		result.Tags = []string{readme.PipelineTag}
	}

	// Format detection
	if f := detectFormatInDir(afs, latestSnapshot); f != "" {
		result.Format = f
	} else {
		subdirs, _ := afs.ReadDir(latestSnapshot)
		for _, d := range subdirs {
			fullPath := filepath.Join(latestSnapshot, d.Name())
			info, err := afs.Stat(fullPath)
			if err != nil || !info.IsDir() {
				continue
			}
			if f := detectFormatInDir(afs, fullPath); f != "" {
				result.Format = f
				break
			}
		}
		if result.Format == "" {
			result.Format = "unknown"
		}
	}

	// Quantization fallback from filenames
	if result.Quantization == "" {
		files, _ := afs.ReadDir(latestSnapshot)
		for _, f := range files {
			if m := reQuantization.FindString(f.Name()); m != "" {
				result.Quantization = strings.ToUpper(m)
				break
			}
		}
	}

	return result
}

func parseHFReadmeFrontmatter(afs *afero.Afero, snapshotDir string) hfReadmeMeta {
	var meta hfReadmeMeta
	readmePath := filepath.Join(snapshotDir, "README.md")
	data, err := afs.ReadFile(readmePath)
	if err != nil {
		return meta
	}
	content := string(data)
	if !strings.HasPrefix(content, "---") {
		return meta
	}
	end := strings.Index(content[3:], "---")
	if end < 0 {
		return meta
	}
	frontmatter := content[3 : 3+end]
	_ = yaml.Unmarshal([]byte(frontmatter), &meta)
	return meta
}

func detectFormatInDir(afs *afero.Afero, dir string) string {
	files, err := afs.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, f := range files {
		switch strings.ToLower(filepath.Ext(f.Name())) {
		case ".safetensors":
			return "safetensors"
		case ".gguf":
			return "gguf"
		case ".onnx":
			return "onnx"
		case ".npz":
			return "mlx"
		}
	}
	for _, f := range files {
		if strings.ToLower(filepath.Ext(f.Name())) == ".bin" {
			return "pytorch"
		}
	}
	return ""
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/afero"
)

// OllamaDetector discovers locally cached Ollama models by walking the manifest
// directory (~/.ollama/models/manifests). Each manifest JSON references a
// config blob that contains the model family, quantization (file_type),
// parameter size (model_type), architecture, and license. The vendor is
// inferred from a prefix lookup table mapping model names to known publishers.
type OllamaDetector struct{}

type ollamaManifest struct {
	Config ollamaDescriptor `json:"config"`
	Layers []ollamaLayer    `json:"layers"`
}

type ollamaDescriptor struct {
	Digest string `json:"digest"`
}

type ollamaLayer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type ollamaExtracted struct {
	Family        string
	Architecture  string
	ParameterSize string
	License       string
	Quantization  string
}

// ollamaVendorPrefixes maps model name prefixes to vendor names.
// Lookup uses longest-prefix match so "deepseek-r1" matches "deepseek".
var ollamaVendorPrefixes = map[string]string{
	"llama":       "Meta",
	"codellama":   "Meta",
	"gemma":       "Google",
	"codegemma":   "Google",
	"shieldgemma": "Google",
	"medgemma":    "Google",
	"qwen":        "Alibaba",
	"qwq":         "Alibaba",
	"codeqwen":    "Alibaba",
	"marco-o1":    "Alibaba",
	"deepseek":    "DeepSeek",
	"mistral":     "Mistral AI",
	"mixtral":     "Mistral AI",
	"codestral":   "Mistral AI",
	"devstral":    "Mistral AI",
	"magistral":   "Mistral AI",
	"mathstral":   "Mistral AI",
	"ministral":   "Mistral AI",
	"phi":         "Microsoft",
	"wizardlm":    "Microsoft",
	"orca":        "Microsoft",
	"gpt-oss":     "OpenAI",
	"glm":         "Z.AI",
	"codegeex":    "Z.AI",
	"command-r":   "Cohere",
	"command-a":   "Cohere",
	"aya":         "Cohere",
	"grok":        "xAI",
	"yi":          "01.AI",
	"jamba":       "AI21 Labs",
	"granite":     "IBM",
	"falcon":      "TII",
	"nemotron":    "NVIDIA",
	"solar":       "Upstage",
	"dbrx":        "Databricks",
	"starcoder":   "BigCode",
	"stable":      "Stability AI",
	"olmo":        "Allen Institute for AI",
	"tulu":        "Allen Institute for AI",
	"smollm":      "Hugging Face",
	"nomic":       "Nomic",
	"snowflake":   "Snowflake",
	"internlm":    "Shanghai AI Lab",
	"minicpm":     "OpenBMB",
	"kimi":        "Moonshot AI",
	"minimax":     "MiniMax",
	"exaone":      "LG AI Research",
	"dolphin":     "Cognitive Computations",
	"tinydolphin": "Cognitive Computations",
	"hermes":      "Nous Research",
	"tinyllama":   "TinyLlama",
	"llava":       "LLaVA",
	"bakllava":    "LLaVA",
	"moondream":   "Moondream AI",
	"neural-chat": "Intel",
	"sailor":      "Sea AI Lab",
	"cogito":      "Deep Cogito",
	"lfm":         "Liquid AI",
	"reader-lm":   "Jina AI",
	"baichuan":    "Baichuan",
	"rwkv":        "RWKV Foundation",
}

func ollamaVendor(modelBase string) string {
	best := ""
	for prefix := range ollamaVendorPrefixes {
		if strings.HasPrefix(modelBase, prefix) && len(prefix) > len(best) {
			best = prefix
		}
	}
	if best != "" {
		return ollamaVendorPrefixes[best]
	}
	return ""
}

// Detect walks every model store the context names. Ollama's store is not
// reliably $HOME/.ollama/models: OLLAMA_MODELS relocates it, and the packaged
// Linux service sets it, so on a stock distribution install the default path
// does not exist and looking only there reports no models on a host that has
// them. The caller resolves the real locations and passes them in; the default
// is only the fallback for when nothing could be resolved.
func (d *OllamaDetector) Detect(ctx DetectContext) []ModelInfo {
	dirs := ctx.OllamaModelsDirs
	if len(dirs) == 0 {
		if ctx.Home == "" {
			return nil
		}
		dirs = []string{filepath.Join(ctx.Home, ".ollama", "models")}
	}

	var results []ModelInfo
	// A model reachable through two stores (a user's own and the daemon's) is
	// one model. ai.model keys on source and name, so emitting it twice would
	// collide in the resource cache rather than produce two entries.
	seen := map[string]struct{}{}
	for _, dir := range dirs {
		for _, m := range DetectOllamaModels(ctx.Fs, dir) {
			if _, ok := seen[m.Name]; ok {
				continue
			}
			seen[m.Name] = struct{}{}
			results = append(results, m)
		}
	}
	return results
}

// DetectOllamaModels reads the models cached in one Ollama model store, the
// directory OLLAMA_MODELS points at (or $HOME/.ollama/models by default), which
// holds the manifests and blobs subdirectories.
func DetectOllamaModels(afs *afero.Afero, modelsDir string) []ModelInfo {
	manifestsDir := filepath.Join(modelsDir, "manifests")

	// Ollama manifests follow a 4-level structure: registry/namespace/model/tag
	// (e.g. registry.ollama.ai/library/llama3/latest).
	// Walk each level explicitly to avoid unbounded traversal.
	registries, err := afs.ReadDir(manifestsDir)
	if err != nil {
		return nil
	}

	var results []ModelInfo
	for _, registry := range registries {
		if !registry.IsDir() {
			continue
		}
		registryDir := filepath.Join(manifestsDir, registry.Name())
		namespaces, err := afs.ReadDir(registryDir)
		if err != nil {
			continue
		}
		for _, ns := range namespaces {
			if !ns.IsDir() {
				continue
			}
			nsDir := filepath.Join(registryDir, ns.Name())
			models, err := afs.ReadDir(nsDir)
			if err != nil {
				continue
			}
			for _, model := range models {
				if !model.IsDir() {
					continue
				}
				modelBase := model.Name()
				modelDir := filepath.Join(nsDir, modelBase)
				tags, err := afs.ReadDir(modelDir)
				if err != nil {
					continue
				}
				for _, tag := range tags {
					if tag.IsDir() {
						continue
					}
					tagPath := filepath.Join(modelDir, tag.Name())
					data, err := afs.ReadFile(tagPath)
					if err != nil {
						continue
					}

					var manifest ollamaManifest
					if json.Unmarshal(data, &manifest) != nil || len(manifest.Layers) == 0 {
						continue
					}

					name := modelBase + ":" + tag.Name()

					var totalSize int64
					for _, l := range manifest.Layers {
						totalSize += l.Size
					}

					extracted := readOllamaConfig(afs, modelsDir, manifest.Config.Digest)

					if extracted.License == "" {
						extracted.License = readOllamaLicenseLayer(afs, modelsDir, manifest.Layers)
					}

					version := tag.Name()

					quant := extracted.Quantization
					if quant == "" {
						if m := reQuantization.FindString(tag.Name()); m != "" {
							quant = strings.ToUpper(m)
						}
					}

					paramSize := extracted.ParameterSize
					if paramSize == "" {
						if m := reParamSize.FindStringSubmatch(name); len(m) > 1 {
							paramSize = m[1] + "B"
						}
					}

					// Build tags from tag name parts (split on -)
					var modelTags []string
					for _, part := range strings.Split(tag.Name(), "-") {
						if part != "" && part != "latest" {
							modelTags = append(modelTags, part)
						}
					}

					results = append(results, ModelInfo{
						Name:          name,
						Source:        "ollama",
						Vendor:        ollamaVendor(modelBase),
						Family:        extracted.Family,
						Path:          tagPath,
						Size:          totalSize,
						ModifiedAt:    tag.ModTime(),
						Format:        "gguf",
						Version:       version,
						Quantization:  quant,
						ParameterSize: paramSize,
						Architecture:  extracted.Architecture,
						License:       extracted.License,
						Tags:          modelTags,
					})
				}
			}
		}
	}
	return results
}

const ollamaLicenseMediaType = "application/vnd.ollama.image.license"

// maxLicenseRead is the maximum bytes to read from a license blob.
// License headers are identifiable within the first few KB.
const maxLicenseRead = 8 * 1024

func readOllamaLicenseLayer(afs *afero.Afero, modelsDir string, layers []ollamaLayer) string {
	for _, l := range layers {
		if l.MediaType != ollamaLicenseMediaType || l.Digest == "" {
			continue
		}
		if l.Size > 1<<20 {
			continue
		}
		blobName := strings.Replace(l.Digest, ":", "-", 1)
		blobPath := filepath.Join(modelsDir, "blobs", blobName)
		f, err := afs.Open(blobPath)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxLicenseRead))
		f.Close()
		if err != nil {
			continue
		}
		if id := identifyLicense(string(data)); id != "" {
			return id
		}
	}
	return ""
}

var reCCVersion = regexp.MustCompile(`(?i)VERSION\s+(\d+\.\d+)`)

// identifyLicense extracts a short SPDX-like identifier from license text.
func identifyLicense(text string) string {
	prefix := text
	if len(prefix) > 4096 {
		prefix = prefix[:4096]
	}
	upper := strings.ToUpper(prefix)

	switch {
	case strings.Contains(upper, "APACHE LICENSE") && strings.Contains(upper, "VERSION 2.0"):
		return "Apache-2.0"
	case strings.Contains(upper, "MIT LICENSE"):
		return "MIT"
	case strings.Contains(upper, "BSD 2-CLAUSE"):
		return "BSD-2-Clause"
	case strings.Contains(upper, "BSD 3-CLAUSE"):
		return "BSD-3-Clause"
	case strings.Contains(upper, "GNU GENERAL PUBLIC LICENSE") && strings.Contains(upper, "VERSION 3"):
		return "GPL-3.0"
	case strings.Contains(upper, "GNU GENERAL PUBLIC LICENSE") && strings.Contains(upper, "VERSION 2"):
		return "GPL-2.0"
	case strings.Contains(upper, "LLAMA 3.1 COMMUNITY LICENSE"):
		return "Llama-3.1"
	case strings.Contains(upper, "LLAMA 3 COMMUNITY LICENSE"):
		return "Llama-3"
	case strings.Contains(upper, "LLAMA 2 COMMUNITY LICENSE"):
		return "Llama-2"
	case strings.Contains(upper, "GEMMA TERMS OF USE"):
		return "Gemma"
	case strings.Contains(upper, "DEEPSEEK"):
		return "DeepSeek"
	case strings.Contains(upper, "MICROSOFT RESEARCH LICENSE"):
		return "MS-Research"
	case strings.Contains(upper, "CREATIVECOMMONS.ORG") || strings.Contains(upper, "CREATIVE COMMONS"):
		return identifyCCLicense(prefix)
	}

	first := strings.TrimSpace(text)
	if i := strings.IndexByte(first, '\n'); i > 0 {
		first = strings.TrimSpace(first[:i])
	}
	if len(first) > 0 && len(first) <= 80 {
		return "LicenseRef-" + first
	}
	return ""
}

func identifyCCLicense(text string) string {
	upper := strings.ToUpper(text)
	var variant string
	switch {
	case strings.Contains(upper, "BY-NC-SA"):
		variant = "CC-BY-NC-SA"
	case strings.Contains(upper, "BY-NC-ND"):
		variant = "CC-BY-NC-ND"
	case strings.Contains(upper, "BY-NC"):
		variant = "CC-BY-NC"
	case strings.Contains(upper, "BY-SA"):
		variant = "CC-BY-SA"
	case strings.Contains(upper, "BY-ND"):
		variant = "CC-BY-ND"
	default:
		variant = "CC-BY"
	}
	if m := reCCVersion.FindStringSubmatch(text); len(m) > 1 {
		return variant + "-" + m[1]
	}
	return variant
}

func readOllamaConfig(afs *afero.Afero, modelsDir string, digest string) ollamaExtracted {
	var result ollamaExtracted
	if digest == "" {
		return result
	}
	blobName := strings.Replace(digest, ":", "-", 1)
	blobPath := filepath.Join(modelsDir, "blobs", blobName)
	data, err := afs.ReadFile(blobPath)
	if err != nil {
		return result
	}

	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil {
		return result
	}

	if v, ok := raw["model_family"].(string); ok {
		result.Family = v
	}
	// file_type holds quantization (e.g. "Q4_0", "Q8_0")
	if v, ok := raw["file_type"].(string); ok {
		result.Quantization = v
	}
	// model_type holds human-readable parameter size (e.g. "8.0B", "70B")
	if v, ok := raw["model_type"].(string); ok && v != "" {
		result.ParameterSize = v
	}
	if v, ok := raw["license"].(string); ok {
		result.License = v
	}
	// general.architecture is the model arch in some blobs
	if v, ok := raw["general.architecture"].(string); ok {
		result.Architecture = v
	}
	// Fallback: use model_family as architecture if general.architecture is absent
	// (don't use "architecture" — that's the platform arch like "amd64")
	if result.Architecture == "" {
		result.Architecture = result.Family
	}

	return result
}

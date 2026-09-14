// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAfs() (*afero.Afero, afero.Fs) {
	fs := afero.NewMemMapFs()
	return &afero.Afero{Fs: fs}, fs
}

func writeJSON(t *testing.T, fs afero.Fs, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, afero.WriteFile(fs, path, data, 0644))
}

func detectWith(d Detector, afs *afero.Afero, home string) []ModelInfo {
	return d.Detect(DetectContext{Fs: afs, Home: home})
}

func TestDetectOllama(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:abc123"},
		Layers: []ollamaLayer{
			{MediaType: "application/vnd.ollama.image.model", Digest: "sha256:model1", Size: 1000},
			{MediaType: "application/vnd.ollama.image.template", Digest: "sha256:tmpl1", Size: 200},
		},
	}
	manifestPath := filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library/llama3/latest")
	writeJSON(t, fs, manifestPath, manifest)

	configBlob := map[string]any{"model_family": "llama"}
	configPath := filepath.Join(home, ".ollama/models/blobs/sha256-abc123")
	writeJSON(t, fs, configPath, configBlob)

	results := detectWith(&OllamaDetector{}, afs, home)
	require.Len(t, results, 1)

	m := results[0]
	assert.Equal(t, "llama3:latest", m.Name)
	assert.Equal(t, "ollama", m.Source)
	assert.Equal(t, "Meta", m.Vendor)
	assert.Equal(t, "llama", m.Family)
	assert.Equal(t, int64(1200), m.Size)
	assert.Equal(t, "gguf", m.Format)
	assert.Equal(t, "latest", m.Version)
}

func TestDetectOllama_MultipleModels(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	for _, tc := range []struct {
		model, tag, family, vendor string
	}{
		{"gemma", "7b", "gemma", "Google"},
		{"deepseek-r1", "latest", "deepseek2", "DeepSeek"},
		{"qwen", "4b", "qwen2", "Alibaba"},
	} {
		manifest := ollamaManifest{
			Config: ollamaDescriptor{Digest: "sha256:" + tc.model},
			Layers: []ollamaLayer{{Size: 500}},
		}
		manifestPath := filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library", tc.model, tc.tag)
		writeJSON(t, fs, manifestPath, manifest)

		configPath := filepath.Join(home, ".ollama/models/blobs/sha256-"+tc.model)
		writeJSON(t, fs, configPath, map[string]any{"model_family": tc.family})
	}

	results := detectWith(&OllamaDetector{}, afs, home)
	require.Len(t, results, 3)

	vendors := map[string]string{}
	families := map[string]string{}
	for _, m := range results {
		vendors[m.Name] = m.Vendor
		families[m.Name] = m.Family
	}

	assert.Equal(t, "Google", vendors["gemma:7b"])
	assert.Equal(t, "DeepSeek", vendors["deepseek-r1:latest"])
	assert.Equal(t, "Alibaba", vendors["qwen:4b"])
	assert.Equal(t, "gemma", families["gemma:7b"])
	assert.Equal(t, "deepseek2", families["deepseek-r1:latest"])
	assert.Equal(t, "qwen2", families["qwen:4b"])
}

func TestDetectOllama_MalformedManifest(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	manifestPath := filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library/badmodel/latest")
	require.NoError(t, afero.WriteFile(fs, manifestPath, []byte("not json"), 0644))

	results := detectWith(&OllamaDetector{}, afs, home)
	assert.Empty(t, results)
}

func TestDetectOllama_EmptyLayers(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:abc"},
		Layers: []ollamaLayer{},
	}
	manifestPath := filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library/empty/latest")
	writeJSON(t, fs, manifestPath, manifest)

	results := detectWith(&OllamaDetector{}, afs, home)
	assert.Empty(t, results)
}

func TestDetectOllama_MissingConfigBlob(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:missing"},
		Layers: []ollamaLayer{{Size: 100}},
	}
	manifestPath := filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library/phi/latest")
	writeJSON(t, fs, manifestPath, manifest)

	results := detectWith(&OllamaDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "Microsoft", results[0].Vendor)
	assert.Equal(t, "", results[0].Family)
}

func TestDetectOllama_NoManifestsDir(t *testing.T) {
	afs, _ := newTestAfs()
	results := detectWith(&OllamaDetector{}, afs, "/nonexistent")
	assert.Nil(t, results)
}

func TestDetectOllama_ExtractsNewFields(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:fullcfg"},
		Layers: []ollamaLayer{{Size: 4000000000}},
	}
	manifestPath := filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library/llama3/8b-q4_0")
	writeJSON(t, fs, manifestPath, manifest)

	configBlob := map[string]any{
		"model_family": "llama",
		"model_type":   "8.0B",
		"file_type":    "Q4_0",
		"license":      "llama3",
	}
	configPath := filepath.Join(home, ".ollama/models/blobs/sha256-fullcfg")
	writeJSON(t, fs, configPath, configBlob)

	results := detectWith(&OllamaDetector{}, afs, home)
	require.Len(t, results, 1)

	m := results[0]
	assert.Equal(t, "llama3:8b-q4_0", m.Name)
	assert.Equal(t, "8b-q4_0", m.Version)
	assert.Equal(t, "Q4_0", m.Quantization)
	assert.Equal(t, "8.0B", m.ParameterSize)
	assert.Equal(t, "llama", m.Architecture)
	assert.Equal(t, "llama3", m.License)
	assert.Equal(t, []string{"8b", "q4_0"}, m.Tags)
}

func TestDetectOllama_LicenseFromLayer(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:cfg1"},
		Layers: []ollamaLayer{
			{MediaType: "application/vnd.ollama.image.model", Digest: "sha256:model1", Size: 1000},
			{MediaType: "application/vnd.ollama.image.license", Digest: "sha256:lic1", Size: 500},
		},
	}
	manifestPath := filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library/llama3.1/latest")
	writeJSON(t, fs, manifestPath, manifest)

	configPath := filepath.Join(home, ".ollama/models/blobs/sha256-cfg1")
	writeJSON(t, fs, configPath, map[string]any{"model_family": "llama"})

	licenseText := "LLAMA 3.1 COMMUNITY LICENSE AGREEMENT\nLlama 3.1 Version Release Date: July 23, 2024\n..."
	require.NoError(t, afero.WriteFile(fs, filepath.Join(home, ".ollama/models/blobs/sha256-lic1"), []byte(licenseText), 0644))

	results := detectWith(&OllamaDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "Llama-3.1", results[0].License)
}

func TestDetectOllama_LicenseApache(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:cfg2"},
		Layers: []ollamaLayer{
			{MediaType: "application/vnd.ollama.image.model", Digest: "sha256:model2", Size: 1000},
			{MediaType: "application/vnd.ollama.image.license", Digest: "sha256:lic2", Size: 500},
		},
	}
	manifestPath := filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library/gemma/latest")
	writeJSON(t, fs, manifestPath, manifest)

	configPath := filepath.Join(home, ".ollama/models/blobs/sha256-cfg2")
	writeJSON(t, fs, configPath, map[string]any{"model_family": "gemma"})

	licenseText := "\n                                 Apache License\n                           Version 2.0, January 2004\n"
	require.NoError(t, afero.WriteFile(fs, filepath.Join(home, ".ollama/models/blobs/sha256-lic2"), []byte(licenseText), 0644))

	results := detectWith(&OllamaDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "Apache-2.0", results[0].License)
}

func TestDetectOllama_LicenseMIT(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:cfg3"},
		Layers: []ollamaLayer{
			{MediaType: "application/vnd.ollama.image.model", Digest: "sha256:model3", Size: 1000},
			{MediaType: "application/vnd.ollama.image.license", Digest: "sha256:lic3", Size: 200},
		},
	}
	manifestPath := filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library/deepseek-r1/7b")
	writeJSON(t, fs, manifestPath, manifest)

	configPath := filepath.Join(home, ".ollama/models/blobs/sha256-cfg3")
	writeJSON(t, fs, configPath, map[string]any{"model_family": "deepseek2"})

	require.NoError(t, afero.WriteFile(fs, filepath.Join(home, ".ollama/models/blobs/sha256-lic3"), []byte("MIT License\n\nCopyright (c) 2024 DeepSeek"), 0644))

	results := detectWith(&OllamaDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "MIT", results[0].License)
}

func TestDetectOllama_ConfigLicenseTakesPrecedence(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:cfglic"},
		Layers: []ollamaLayer{
			{MediaType: "application/vnd.ollama.image.model", Digest: "sha256:model4", Size: 1000},
			{MediaType: "application/vnd.ollama.image.license", Digest: "sha256:lic4", Size: 200},
		},
	}
	manifestPath := filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library/custom/latest")
	writeJSON(t, fs, manifestPath, manifest)

	configPath := filepath.Join(home, ".ollama/models/blobs/sha256-cfglic")
	writeJSON(t, fs, configPath, map[string]any{"model_family": "custom", "license": "custom-license"})

	require.NoError(t, afero.WriteFile(fs, filepath.Join(home, ".ollama/models/blobs/sha256-lic4"), []byte("MIT License"), 0644))

	results := detectWith(&OllamaDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "custom-license", results[0].License)
}

func TestIdentifyLicense(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{"Apache-2.0", "\n                                 Apache License\n                           Version 2.0, January 2004\n", "Apache-2.0"},
		{"MIT", "MIT License\n\nCopyright (c) 2024", "MIT"},
		{"Llama-3.1", "LLAMA 3.1 COMMUNITY LICENSE AGREEMENT\nLlama 3.1 Version Release Date: July 23, 2024", "Llama-3.1"},
		{"Llama-3", "LLAMA 3 COMMUNITY LICENSE AGREEMENT\nMeta Llama 3 Version Release Date: April 18, 2024", "Llama-3"},
		{"Llama-2", "LLAMA 2 COMMUNITY LICENSE AGREEMENT\n", "Llama-2"},
		{"Gemma", "Gemma Terms of Use\nLast modified: February 21, 2024", "Gemma"},
		{"DeepSeek", "DeepSeek License Agreement\nVersion 1.0", "DeepSeek"},
		{"BSD-3-Clause", "BSD 3-Clause License\n\nCopyright", "BSD-3-Clause"},
		{"CC-BY-NC-SA-4.0", "Creative Commons Attribution-NonCommercial-ShareAlike\nVersion 4.0 (CC BY-NC-SA)", "CC-BY-NC-SA-4.0"},
		{"CC-BY-NC-3.0", "Creative Commons Attribution-NonCommercial (CC BY-NC)\nVersion 3.0", "CC-BY-NC-3.0"},
		{"CC-BY-no-version", "Creative Commons Attribution License\nSome text", "CC-BY"},
		{"short-first-line", "Custom Model License v1\nSome details...", "LicenseRef-Custom Model License v1"},
		{"empty", "", ""},
		{"long-no-match", strings.Repeat("x", 100) + "\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, identifyLicense(tt.text))
		})
	}
}

func TestDetectOllama_QuantizationFromTagFallback(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:noquant"},
		Layers: []ollamaLayer{{Size: 100}},
	}
	manifestPath := filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library/mistral/7b-Q4_K_M")
	writeJSON(t, fs, manifestPath, manifest)

	// Config blob without quantization
	configBlob := map[string]any{"model_family": "mistral"}
	configPath := filepath.Join(home, ".ollama/models/blobs/sha256-noquant")
	writeJSON(t, fs, configPath, configBlob)

	results := detectWith(&OllamaDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "Q4_K_M", results[0].Quantization)
}

func TestDetectOllama_ParameterSizeFromNameFallback(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:noparam"},
		Layers: []ollamaLayer{{Size: 100}},
	}
	manifestPath := filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library/llama3/70b")
	writeJSON(t, fs, manifestPath, manifest)

	configBlob := map[string]any{"model_family": "llama"}
	configPath := filepath.Join(home, ".ollama/models/blobs/sha256-noparam")
	writeJSON(t, fs, configPath, configBlob)

	results := detectWith(&OllamaDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "70B", results[0].ParameterSize)
}

func TestOllamaVendor(t *testing.T) {
	tests := []struct {
		modelBase string
		want      string
	}{
		{"llama3", "Meta"},
		{"codellama", "Meta"},
		{"gemma", "Google"},
		{"deepseek-r1", "DeepSeek"},
		{"qwen", "Alibaba"},
		{"phi", "Microsoft"},
		{"mistral", "Mistral AI"},
		{"mixtral", "Mistral AI"},
		{"glm", "Z.AI"},
		{"grok", "xAI"},
		{"jamba", "AI21 Labs"},
		{"baichuan", "Baichuan"},
		{"rwkv", "RWKV Foundation"},
		{"unknown-model", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.modelBase, func(t *testing.T) {
			assert.Equal(t, tt.want, ollamaVendor(tt.modelBase))
		})
	}
}

func TestDetectHuggingFace(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	modelDir := filepath.Join(home, ".cache/huggingface/hub/models--meta-llama--Llama-2-7b-hf")
	snapshotDir := filepath.Join(modelDir, "snapshots/abc123def456")

	require.NoError(t, afero.WriteFile(fs, filepath.Join(snapshotDir, "model.safetensors"), make([]byte, 5000), 0644))

	cfg := hfConfig{ModelType: "llama", Architectures: []string{"LlamaForCausalLM"}}
	writeJSON(t, fs, filepath.Join(snapshotDir, "config.json"), cfg)

	require.NoError(t, afero.WriteFile(fs, filepath.Join(modelDir, "blobs/sha256abc"), make([]byte, 4000), 0644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(modelDir, "blobs/sha256def"), make([]byte, 1000), 0644))

	results := detectWith(&HuggingFaceDetector{}, afs, home)
	require.Len(t, results, 1)

	m := results[0]
	assert.Equal(t, "meta-llama/Llama-2-7b-hf", m.Name)
	assert.Equal(t, "huggingface", m.Source)
	assert.Equal(t, "meta-llama", m.Vendor)
	assert.Equal(t, "llama", m.Family)
	assert.Equal(t, int64(5000), m.Size)
	assert.Equal(t, "safetensors", m.Format)
	assert.Equal(t, "abc123def456"[:12], m.Version)
	assert.Equal(t, "LlamaForCausalLM", m.Architecture)
	assert.Equal(t, "7B", m.ParameterSize)
}

func TestDetectHuggingFace_GGUFFormat(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	modelDir := filepath.Join(home, ".cache/huggingface/hub/models--TheBloke--Llama-2-7B-GGUF")
	snapshotDir := filepath.Join(modelDir, "snapshots/rev1")
	require.NoError(t, afero.WriteFile(fs, filepath.Join(snapshotDir, "llama-2-7b.Q4_K_M.gguf"), make([]byte, 3000), 0644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(modelDir, "blobs/b1"), make([]byte, 3000), 0644))

	results := detectWith(&HuggingFaceDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "gguf", results[0].Format)
	assert.Equal(t, "Q4_K_M", results[0].Quantization)
}

func TestDetectHuggingFace_QuantizationFromConfig(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	modelDir := filepath.Join(home, ".cache/huggingface/hub/models--org--model-gptq")
	snapshotDir := filepath.Join(modelDir, "snapshots/rev1")
	require.NoError(t, afero.WriteFile(fs, filepath.Join(snapshotDir, "model.safetensors"), make([]byte, 100), 0644))

	cfg := hfConfig{
		ModelType:          "llama",
		Architectures:      []string{"LlamaForCausalLM"},
		QuantizationConfig: map[string]any{"quant_method": "gptq", "bits": float64(4)},
	}
	writeJSON(t, fs, filepath.Join(snapshotDir, "config.json"), cfg)
	require.NoError(t, afero.WriteFile(fs, filepath.Join(modelDir, "blobs/b1"), make([]byte, 100), 0644))

	results := detectWith(&HuggingFaceDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "gptq", results[0].Quantization)
}

func TestDetectHuggingFace_ReadmeFrontmatter(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	modelDir := filepath.Join(home, ".cache/huggingface/hub/models--org--model-with-readme")
	snapshotDir := filepath.Join(modelDir, "snapshots/rev1")
	require.NoError(t, afero.WriteFile(fs, filepath.Join(snapshotDir, "model.safetensors"), make([]byte, 100), 0644))

	readme := `---
license: apache-2.0
tags:
  - text-generation
  - pytorch
pipeline_tag: text-generation
---
# Model Card
This is a great model.
`
	require.NoError(t, afero.WriteFile(fs, filepath.Join(snapshotDir, "README.md"), []byte(readme), 0644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(modelDir, "blobs/b1"), make([]byte, 100), 0644))

	results := detectWith(&HuggingFaceDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "apache-2.0", results[0].License)
	assert.Equal(t, []string{"text-generation", "pytorch"}, results[0].Tags)
}

func TestDetectHuggingFace_ONNXInSubdir(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	modelDir := filepath.Join(home, ".cache/huggingface/hub/models--sentence-transformers--all-MiniLM-L6-v2")
	snapshotDir := filepath.Join(modelDir, "snapshots/rev1")
	require.NoError(t, afero.WriteFile(fs, filepath.Join(snapshotDir, "onnx/model.onnx"), make([]byte, 2000), 0644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(modelDir, "blobs/b1"), make([]byte, 2000), 0644))

	results := detectWith(&HuggingFaceDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "onnx", results[0].Format)
}

func TestDetectHuggingFace_EmptySnapshotsDir(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	modelDir := filepath.Join(home, ".cache/huggingface/hub/models--org--repo")
	require.NoError(t, fs.MkdirAll(filepath.Join(modelDir, "snapshots"), 0755))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(modelDir, "blobs/b1"), make([]byte, 100), 0644))

	results := detectWith(&HuggingFaceDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "unknown", results[0].Format)
	assert.Equal(t, "", results[0].Family)
}

func TestDetectHuggingFace_LockFilesExcluded(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	modelDir := filepath.Join(home, ".cache/huggingface/hub/models--org--model")
	snapshotDir := filepath.Join(modelDir, "snapshots/rev1")
	require.NoError(t, afero.WriteFile(fs, filepath.Join(snapshotDir, "model.safetensors"), make([]byte, 100), 0644))

	require.NoError(t, afero.WriteFile(fs, filepath.Join(modelDir, "blobs/sha1"), make([]byte, 1000), 0644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(modelDir, "blobs/sha1.lock"), make([]byte, 500), 0644))

	results := detectWith(&HuggingFaceDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, int64(1000), results[0].Size)
}

func TestDetectHuggingFace_NoHubDir(t *testing.T) {
	afs, _ := newTestAfs()
	results := detectWith(&HuggingFaceDetector{}, afs, "/nonexistent")
	assert.Nil(t, results)
}

func TestDetectHuggingFace_SkipsNonModelDirs(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	hubDir := filepath.Join(home, ".cache/huggingface/hub")
	require.NoError(t, fs.MkdirAll(filepath.Join(hubDir, "datasets--org--data"), 0755))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(hubDir, ".locks"), []byte("lock"), 0644))

	results := detectWith(&HuggingFaceDetector{}, afs, home)
	assert.Empty(t, results)
}

func TestDetectJan_ExtractsNewFields(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	modelDir := filepath.Join(home, "jan/models/llama-7b")
	meta := janModelMeta{
		Name:        "Llama 7B",
		ID:          "llama-7b",
		Format:      "gguf",
		Version:     "1.0.0",
		Description: "A great language model",
		License:     "llama2",
		Metadata:    janModelMetadata{Author: "Meta", Tags: []string{"llm", "chat"}},
		Publisher:   janModelPublisher{Name: "Meta"},
	}
	writeJSON(t, fs, filepath.Join(modelDir, "model.json"), meta)
	require.NoError(t, afero.WriteFile(fs, filepath.Join(modelDir, "llama-7b-Q4_K_M.gguf"), make([]byte, 4000), 0644))

	results := detectWith(&JanDetector{}, afs, home)
	require.Len(t, results, 1)

	m := results[0]
	assert.Equal(t, "Llama 7B", m.Name)
	assert.Equal(t, "jan", m.Source)
	assert.Equal(t, "Meta", m.Vendor)
	assert.Equal(t, "1.0.0", m.Version)
	assert.Equal(t, "A great language model", m.Description)
	assert.Equal(t, "llama2", m.License)
	assert.Equal(t, []string{"llm", "chat"}, m.Tags)
	assert.Equal(t, "Q4_K_M", m.Quantization)
	assert.Equal(t, "7B", m.ParameterSize)
}

func TestDetectLMStudio_QuantizationFromFilename(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	modelsDir := filepath.Join(home, ".lmstudio/models/TheBloke/Llama-2-13B-GGUF")
	require.NoError(t, afero.WriteFile(fs, filepath.Join(modelsDir, "llama-2-13b.Q5_K_S.gguf"), make([]byte, 9000), 0644))

	results := detectWith(&LMStudioDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "Q5_K_S", results[0].Quantization)
	assert.Equal(t, "13B", results[0].ParameterSize)
}

func TestDetectGPT4All_QuantizationFromFilename(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	dir := filepath.Join(home, ".cache/gpt4all")
	require.NoError(t, afero.WriteFile(fs, filepath.Join(dir, "mistral-7b-instruct-v0.1.Q4_0.gguf"), make([]byte, 4000), 0644))

	results := (&GPT4AllDetector{}).Detect(DetectContext{Fs: afs, Home: home, OSFamily: "linux"})
	require.Len(t, results, 1)
	assert.Equal(t, "Q4_0", results[0].Quantization)
	assert.Equal(t, "7B", results[0].ParameterSize)
}

func TestDetectAll(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:cfg1"},
		Layers: []ollamaLayer{{Size: 100}},
	}
	writeJSON(t, fs, filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library/llama3/latest"), manifest)
	writeJSON(t, fs, filepath.Join(home, ".ollama/models/blobs/sha256-cfg1"), map[string]any{"model_family": "llama"})

	modelDir := filepath.Join(home, ".cache/huggingface/hub/models--google--bert-base")
	snapshotDir := filepath.Join(modelDir, "snapshots/rev1")
	require.NoError(t, afero.WriteFile(fs, filepath.Join(snapshotDir, "model.safetensors"), make([]byte, 200), 0644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(modelDir, "blobs/b1"), make([]byte, 200), 0644))

	results := DetectAll(afs, home, "linux", nil)
	assert.GreaterOrEqual(t, len(results), 2)

	sources := map[string]bool{}
	for _, m := range results {
		sources[m.Source] = true
	}
	assert.True(t, sources["ollama"])
	assert.True(t, sources["huggingface"])
}

func TestDetectFormatInDir(t *testing.T) {
	tests := []struct {
		name     string
		files    []string
		expected string
	}{
		{"safetensors", []string{"model.safetensors"}, "safetensors"},
		{"gguf", []string{"model.gguf"}, "gguf"},
		{"onnx", []string{"model.onnx"}, "onnx"},
		{"mlx", []string{"weights.npz"}, "mlx"},
		{"pytorch_bin", []string{"pytorch_model.bin"}, "pytorch"},
		{"safetensors_over_bin", []string{"model.safetensors", "model.bin"}, "safetensors"},
		{"empty", []string{}, ""},
		{"unknown_ext", []string{"readme.txt", "config.json"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			afs, fs := newTestAfs()
			dir := "/test"
			for _, f := range tt.files {
				require.NoError(t, afero.WriteFile(fs, filepath.Join(dir, f), []byte("data"), 0644))
			}
			assert.Equal(t, tt.expected, detectFormatInDir(afs, dir))
		})
	}
}

func TestQuantizationRegex(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"llama-2-7b.Q4_K_M.gguf", "Q4_K_M"},
		{"model-Q8_0.gguf", "Q8_0"},
		{"model-F16.gguf", "F16"},
		{"model-FP16.gguf", "FP16"},
		{"model-F32.safetensors", "F32"},
		{"model-Q5_K_S.gguf", "Q5_K_S"},
		{"model-q4_0.gguf", "q4_0"},
		{"no-quant-model.gguf", ""},
		{"readme.txt", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := reQuantization.FindString(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParamSizeRegex(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"llama3:70b", "70"},
		{"llama3-7b-instruct", "7"},
		{"Llama-2-13B-GGUF", "13"},
		{"mistral-7b-instruct-v0.1.Q4_0.gguf", "7"},
		{"model-0.5b-chat", "0.5"},
		{"no-params-here", ""},
		{"bert-base", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			m := reParamSize.FindStringSubmatch(tt.input)
			if tt.want == "" {
				assert.True(t, len(m) < 2, "expected no match for %q", tt.input)
			} else {
				require.True(t, len(m) >= 2, "expected match for %q", tt.input)
				assert.Equal(t, tt.want, m[1])
			}
		})
	}
}

// The packaged Linux service sets OLLAMA_MODELS, so the store is not under
// $HOME/.ollama/models and looking only there reports no models on a host that
// has them. This is the shape of a real Arch install: the daemon runs as the
// "ollama" account with its store at /var/lib/ollama.
func TestOllamaDetector_RelocatedStore(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}

	const store = "/var/lib/ollama"
	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:cfg1"},
		Layers: []ollamaLayer{{Size: 4096}},
	}
	writeJSON(t, fs, filepath.Join(store, "manifests/registry.ollama.ai/library/qwen3-coder/30b"), manifest)
	writeJSON(t, fs, filepath.Join(store, "blobs/sha256-cfg1"), map[string]any{"model_family": "qwen3moe"})

	// Looking in the default location finds nothing, which is the bug.
	assert.Empty(t, DetectAll(afs, "/home/zero", "linux", nil))

	results := DetectAll(afs, "/home/zero", "linux", []string{store})
	require.Len(t, results, 1)
	assert.Equal(t, "qwen3-coder:30b", results[0].Name)
	assert.Equal(t, "ollama", results[0].Source)
	assert.Equal(t, "Alibaba", results[0].Vendor)
	assert.Equal(t, "qwen3moe", results[0].Family)
	assert.Equal(t, int64(4096), results[0].Size)
}

// A model reachable through two stores is one model, not two: ai.model keys on
// source and name, so a duplicate would collide in the resource cache and the
// second entry would silently report the first one's values.
func TestOllamaDetector_DeduplicatesAcrossStores(t *testing.T) {
	fs := afero.NewMemMapFs()
	afs := &afero.Afero{Fs: fs}

	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:cfg1"},
		Layers: []ollamaLayer{{Size: 10}},
	}
	for _, store := range []string{"/var/lib/ollama", "/home/zero/.ollama/models"} {
		writeJSON(t, fs, filepath.Join(store, "manifests/registry.ollama.ai/library/llama3/latest"), manifest)
		writeJSON(t, fs, filepath.Join(store, "blobs/sha256-cfg1"), map[string]any{"model_family": "llama"})
	}

	results := DetectAll(afs, "/home/zero", "linux",
		[]string{"/var/lib/ollama", "/home/zero/.ollama/models"})
	require.Len(t, results, 1)
	assert.Equal(t, "llama3:latest", results[0].Name)
}

func TestOllamaDetector_NoStore(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	assert.Empty(t, DetectAll(afs, "/home/zero", "linux", []string{"/var/lib/ollama"}))
	assert.Empty(t, DetectAll(afs, "", "linux", nil))
}

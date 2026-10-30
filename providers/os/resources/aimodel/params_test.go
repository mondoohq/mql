// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParameterSizeFromName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"smollm:135m", "135M"},
		{"smollm2:360m-instruct-q8_0", "360M"},
		{"qwen2.5:0.5b", "0.5B"},
		{"llama3:7b", "7B"},
		{"llama3.1:8b-instruct-q4_K_M", "8B"},
		{"HuggingFaceTB/SmolLM2-135M-Instruct", "135M"},
		{"Qwen/Qwen2.5-0.5B-Instruct", "0.5B"},
		{"smollm2-135m-instruct-q8_0.gguf", "135M"},
		// A context length is not a parameter count.
		{"yarn-mistral:7b-128k", "7B"},
		{"llama3-gradient:1048k", ""},
		// Quantization suffixes and words are not counts either.
		{"llama3:latest-q4_K_M", ""},
		{"phi3:mini", ""},
		{"nomic-embed-text:latest", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parameterSizeFromName(tt.name))
		})
	}
}

// ggufBuilder writes GGUF v3 metadata in the layout of the specification:
// header, then key/value pairs. Tensor info and data are not needed to read
// metadata and are left out.
type ggufBuilder struct {
	kv    bytes.Buffer
	count uint64
}

func (b *ggufBuilder) str(s string) {
	_ = binary.Write(&b.kv, binary.LittleEndian, uint64(len(s)))
	b.kv.WriteString(s)
}

func (b *ggufBuilder) key(k string, typ uint32) {
	b.count++
	b.str(k)
	_ = binary.Write(&b.kv, binary.LittleEndian, typ)
}

func (b *ggufBuilder) String(k, v string) *ggufBuilder {
	b.key(k, ggufTypeString)
	b.str(v)
	return b
}

func (b *ggufBuilder) Uint32(k string, v uint32) *ggufBuilder {
	b.key(k, ggufTypeUint32)
	_ = binary.Write(&b.kv, binary.LittleEndian, v)
	return b
}

func (b *ggufBuilder) Float32(k string, v float32) *ggufBuilder {
	b.key(k, ggufTypeFloat32)
	_ = binary.Write(&b.kv, binary.LittleEndian, v)
	return b
}

func (b *ggufBuilder) Bool(k string, v bool) *ggufBuilder {
	b.key(k, ggufTypeBool)
	if v {
		b.kv.WriteByte(1)
	} else {
		b.kv.WriteByte(0)
	}
	return b
}

func (b *ggufBuilder) Strings(k string, vs ...string) *ggufBuilder {
	b.key(k, ggufTypeArray)
	_ = binary.Write(&b.kv, binary.LittleEndian, uint32(ggufTypeString))
	_ = binary.Write(&b.kv, binary.LittleEndian, uint64(len(vs)))
	for _, v := range vs {
		b.str(v)
	}
	return b
}

func (b *ggufBuilder) Int32s(k string, n int) *ggufBuilder {
	b.key(k, ggufTypeArray)
	_ = binary.Write(&b.kv, binary.LittleEndian, uint32(ggufTypeInt32))
	_ = binary.Write(&b.kv, binary.LittleEndian, uint64(n))
	b.kv.Write(make([]byte, 4*n))
	return b
}

func (b *ggufBuilder) Bytes() []byte {
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, uint32(ggufMagic))
	_ = binary.Write(&out, binary.LittleEndian, uint32(3))
	_ = binary.Write(&out, binary.LittleEndian, uint64(30)) // tensor count
	_ = binary.Write(&out, binary.LittleEndian, b.count)
	out.Write(b.kv.Bytes())
	// Stand-in for the tensor info and data that follow the metadata.
	out.Write(make([]byte, 1024))
	return out.Bytes()
}

// smolGGUF is metadata in the order llama.cpp's converter writes it for a
// small model: general.* keys first, then model parameters, then the
// tokenizer. The values are illustrative.
func smolGGUF() *ggufBuilder {
	return (&ggufBuilder{}).
		String("general.architecture", "llama").
		String("general.type", "model").
		String("general.name", "SmolLM2 135M Instruct").
		String("general.finetune", "Instruct").
		String("general.basename", "SmolLM2").
		String("general.size_label", "135M").
		String("general.license", "apache-2.0").
		Strings("general.tags", "safetensors", "onnx", "transformers.js").
		Uint32("llama.block_count", 30).
		Uint32("llama.context_length", 8192).
		Float32("llama.rope.freq_base", 100000).
		Bool("tokenizer.ggml.add_bos_token", false).
		Strings("tokenizer.ggml.tokens", "<|endoftext|>", "<|im_start|>", "<|im_end|>").
		Uint32("general.quantization_version", 2)
}

func TestReadGGUFSizeLabel(t *testing.T) {
	t.Run("label among general keys", func(t *testing.T) {
		got, err := readGGUFSizeLabel(bytes.NewReader(smolGGUF().Bytes()))
		require.NoError(t, err)
		assert.Equal(t, "135M", got)
	})

	t.Run("label after arrays and scalars of every width", func(t *testing.T) {
		b := (&ggufBuilder{}).
			String("general.architecture", "qwen2").
			Uint32("qwen2.block_count", 24).
			Float32("qwen2.attention.layer_norm_rms_epsilon", 1e-6).
			Bool("tokenizer.ggml.add_bos_token", false).
			Strings("tokenizer.ggml.merges", "Ġ Ġ", "ĠĠ ĠĠ", "i n").
			Int32s("tokenizer.ggml.token_type", 64).
			String("general.size_label", "0.5B")
		got, err := readGGUFSizeLabel(bytes.NewReader(b.Bytes()))
		require.NoError(t, err)
		assert.Equal(t, "0.5B", got)
	})

	t.Run("no label", func(t *testing.T) {
		b := (&ggufBuilder{}).
			String("general.architecture", "llama").
			String("general.name", "LLaMA v2").
			Uint32("general.quantization_version", 2)
		got, err := readGGUFSizeLabel(bytes.NewReader(b.Bytes()))
		require.NoError(t, err)
		assert.Equal(t, "", got)
	})

	t.Run("label beyond the read budget", func(t *testing.T) {
		b := (&ggufBuilder{}).
			String("general.architecture", "llama").
			Int32s("tokenizer.ggml.token_type", ggufHeaderBudget/4).
			String("general.size_label", "7B")
		got, err := readGGUFSizeLabel(bytes.NewReader(b.Bytes()))
		require.ErrorIs(t, err, errGGUFBudget)
		assert.Equal(t, "", got)
	})

	t.Run("not a gguf file", func(t *testing.T) {
		_, err := readGGUFSizeLabel(bytes.NewReader([]byte("PK\x03\x04 not a model")))
		assert.Error(t, err)
	})

	t.Run("truncated file", func(t *testing.T) {
		data := smolGGUF().Bytes()
		_, err := readGGUFSizeLabel(bytes.NewReader(data[:40]))
		assert.Error(t, err)
	})

	t.Run("version 1 is not read", func(t *testing.T) {
		data := smolGGUF().Bytes()
		binary.LittleEndian.PutUint32(data[4:], 1)
		_, err := readGGUFSizeLabel(bytes.NewReader(data))
		assert.Error(t, err)
	})
}

// A small model's size is in millions. The GGUF size label is preferred over
// the name, which need not state a size at all.
func TestDetectLMStudio_ParameterSizeFromGGUF(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	dir := filepath.Join(home, ".lmstudio/models/HuggingFaceTB/SmolLM2-Instruct-GGUF")
	require.NoError(t, afero.WriteFile(fs, filepath.Join(dir, "smollm2-instruct-q8_0.gguf"), smolGGUF().Bytes(), 0o644))

	results := detectWith(&LMStudioDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "135M", results[0].ParameterSize)
	assert.Equal(t, "Q8_0", results[0].Quantization)
}

func TestDetectGPT4All_ParameterSize(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"
	dir := filepath.Join(home, ".cache/gpt4all")

	// Label from the file's metadata.
	require.NoError(t, afero.WriteFile(fs, filepath.Join(dir, "SmolLM2-Instruct.Q8_0.gguf"), smolGGUF().Bytes(), 0o644))
	// No metadata: the count the filename states.
	require.NoError(t, afero.WriteFile(fs, filepath.Join(dir, "qwen2.5-0.5b-instruct-q4_0.gguf"), make([]byte, 4000), 0o644))

	results := (&GPT4AllDetector{}).Detect(DetectContext{Fs: afs, Home: home, OSFamily: "linux"})
	got := map[string]string{}
	for _, m := range results {
		got[m.Name] = m.ParameterSize
	}
	assert.Equal(t, map[string]string{
		"SmolLM2-Instruct.Q8_0.gguf":      "135M",
		"qwen2.5-0.5b-instruct-q4_0.gguf": "0.5B",
	}, got)
}

func TestDetectJan_ParameterSizeFromGGUF(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"

	modelDir := filepath.Join(home, "jan/models/smollm2-instruct")
	writeJSON(t, fs, filepath.Join(modelDir, "model.json"), janModelMeta{ID: "smollm2-instruct", Format: "gguf"})
	require.NoError(t, afero.WriteFile(fs, filepath.Join(modelDir, "model.gguf"), smolGGUF().Bytes(), 0o644))

	results := detectWith(&JanDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, "135M", results[0].ParameterSize)
}

// Ollama records the parameter size in the model's config blob as model_type,
// which its API reports as details.parameter_size. Without it, only a size the
// tag states is taken.
func TestDetectOllama_SmallModelParameterSize(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"
	models := filepath.Join(home, ".ollama/models")

	writeJSON(t, fs, filepath.Join(models, "manifests/registry.ollama.ai/library/smollm/135m"), ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:cfgsmol"},
		Layers: []ollamaLayer{{MediaType: "application/vnd.ollama.image.model", Digest: "sha256:m1", Size: 91728832}},
	})
	writeJSON(t, fs, filepath.Join(models, "blobs/sha256-cfgsmol"), map[string]any{
		"model_format":   "gguf",
		"model_family":   "llama",
		"model_families": []string{"llama"},
		"model_type":     "134.52M",
		"file_type":      "Q4_0",
		"architecture":   "amd64",
		"os":             "linux",
	})

	writeJSON(t, fs, filepath.Join(models, "manifests/registry.ollama.ai/library/smollm2/360m"), ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:cfgnotype"},
		Layers: []ollamaLayer{{MediaType: "application/vnd.ollama.image.model", Digest: "sha256:m2", Size: 229000000}},
	})
	writeJSON(t, fs, filepath.Join(models, "blobs/sha256-cfgnotype"), map[string]any{"model_family": "llama"})

	results := detectWith(&OllamaDetector{}, afs, home)
	got := map[string]string{}
	for _, m := range results {
		got[m.Name] = m.ParameterSize
	}
	assert.Equal(t, map[string]string{
		"smollm:135m":  "134.52M",
		"smollm2:360m": "360M",
	}, got)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Legacy torch.save output: pickle protocol 2 (PROTO 0x80 0x02) followed by
// the pickled magic number 0x1950a86a20f9469cfc6c as a LONG1.
var legacyTorchHeader = []byte{0x80, 0x02, 0x8a, 0x0a, 0x6c, 0xfc, 0x9c, 0x46, 0xf9, 0x20, 0x6a, 0xa8, 0x50, 0x19}

// zipHeader builds a zip local file header whose first entry is name, the
// shape torch.save (PyTorch 1.6+) writes with <archive>/data.pkl first.
func zipHeader(name string) []byte {
	h := make([]byte, 30, 30+len(name)+16)
	copy(h, "PK\x03\x04")
	binary.LittleEndian.PutUint16(h[26:28], uint16(len(name)))
	h = append(h, name...)
	return append(h, make([]byte, 16)...)
}

func TestHeaderSerialization(t *testing.T) {
	tru, fal := boolPtr(true), boolPtr(false)
	cases := []struct {
		name string
		head []byte
		want *bool
	}{
		// Synthetic: legacy torch.save header, built from the magic number in torch/serialization.py.
		{"legacy torch pickle", legacyTorchHeader, tru},
		// Synthetic: pickle protocol 5 stream.
		{"pickle protocol 5", []byte{0x80, 0x05, 0x95}, tru},
		// Synthetic: 0x80 followed by a protocol pickle doesn't have.
		{"not a pickle protocol", []byte{0x80, 0x09, 0x00}, nil},
		// Synthetic: torch.save zip archive, first record <archive>/data.pkl.
		{"torch zip", zipHeader("pytorch_model/data.pkl"), tru},
		// Synthetic: torch.save zip archive with a bare data.pkl record.
		{"torch zip bare name", zipHeader("data.pkl"), tru},
		// Synthetic: a zip archive that isn't a torch.save archive.
		{"other zip", zipHeader("metadata.json"), nil},
		// Synthetic: zip header whose name runs past the bytes read.
		{"truncated zip", zipHeader("archive/data.pkl")[:35], nil},
		// Synthetic: GGUF magic.
		{"gguf", []byte("GGUF\x03\x00\x00\x00"), fal},
		// Synthetic: GGJT magic 0x67676a74 as little-endian uint32.
		{"ggjt", []byte("tjgg\x03\x00\x00\x00"), fal},
		// Synthetic: GGML magic 0x67676d6c as little-endian uint32.
		{"ggml", []byte("lmgg"), fal},
		// Synthetic: an opaque vendor format.
		{"opaque", []byte{0x18, 0x00, 0x00, 0x00, 'T', 'F', 'L', '3'}, nil},
		// Synthetic: empty file.
		{"empty", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, headerSerialization(c.head))
		})
	}
}

func TestClassifyWeightFile(t *testing.T) {
	afs, fs := newTestAfs()
	dir := "/m"
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		require.NoError(t, afero.WriteFile(fs, p, data, 0o644))
		return p
	}

	cases := []struct {
		file   string
		data   []byte
		weight bool
		want   *bool
	}{
		// Synthetic: extensions whose loader is pickle, whatever the bytes.
		{"resnet50-0676ba61.pth", []byte("x"), true, boolPtr(true)},
		{"model.PT", []byte("x"), true, boolPtr(true)},
		{"sd-v1-5.ckpt", []byte("x"), true, boolPtr(true)},
		{"clf.joblib", []byte("x"), true, boolPtr(true)},
		// Synthetic: pure data formats.
		{"model.safetensors", []byte("x"), true, boolPtr(false)},
		{"model.gguf", []byte("x"), true, boolPtr(false)},
		{"model.onnx", []byte("x"), true, boolPtr(false)},
		{"weights.npz", []byte("x"), true, boolPtr(false)},
		// Synthetic: Keras files depend on whether a Lambda layer is inside.
		{"mymodel.h5", []byte("x"), true, nil},
		{"mymodel.keras", []byte("x"), true, nil},
		// Synthetic: .bin is decided by its header.
		{"pytorch_model.bin", zipHeader("archive/data.pkl"), true, boolPtr(true)},
		{"ggml-model-q4_0.bin", []byte("tjgg\x01\x00\x00\x00"), true, boolPtr(false)},
		{"weights.bin", []byte{0x01, 0x02, 0x03}, true, nil},
		// Synthetic: files that aren't weights.
		{"config.json", []byte("{}"), false, nil},
		{"README", []byte("x"), false, nil},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			weight, unsafe := classifyWeightFile(afs, write(c.file, c.data))
			assert.Equal(t, c.weight, weight)
			assert.Equal(t, c.want, unsafe)
		})
	}

	// Synthetic: a .bin that can't be opened is unknown, not safe.
	weight, unsafe := classifyWeightFile(afs, "/m/missing.bin")
	assert.True(t, weight)
	assert.Nil(t, unsafe)
}

func TestUnsafeSerialization(t *testing.T) {
	afs, fs := newTestAfs()
	for name, data := range map[string][]byte{
		"/m/a.safetensors": []byte("x"),
		"/m/b.gguf":        []byte("x"),
		"/m/c.pth":         []byte("x"),
		"/m/d.h5":          []byte("x"),
		"/m/config.json":   []byte("{}"),
	} {
		require.NoError(t, afero.WriteFile(fs, name, data, 0o644))
	}

	// Synthetic: only data formats.
	assert.Equal(t, boolPtr(false), unsafeSerialization(afs, []string{"/m/a.safetensors", "/m/b.gguf", "/m/config.json"}))
	// Synthetic: one pickle among data formats wins, even next to an unknown one.
	assert.Equal(t, boolPtr(true), unsafeSerialization(afs, []string{"/m/a.safetensors", "/m/d.h5", "/m/c.pth"}))
	// Synthetic: data next to an undecidable file can't be called safe.
	assert.Nil(t, unsafeSerialization(afs, []string{"/m/a.safetensors", "/m/d.h5"}))
	// Synthetic: no weight file at all.
	assert.Nil(t, unsafeSerialization(afs, []string{"/m/config.json"}))
	assert.Nil(t, unsafeSerialization(afs, nil))
}

const (
	digestA = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	digestB = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
)

func TestDetectHuggingFace_MixedSafetensorsAndPickle(t *testing.T) {
	// Synthetic: a snapshot that ships model.safetensors next to a pickled
	// pytorch_model.bin, plus config.json, which is not a weight file.
	afs, fs := newTestAfs()
	home := "/home/testuser"
	snapshotDir := filepath.Join(home, ".cache/huggingface/hub/models--org--mixed-7b/snapshots/0123456789abcdef0123456789abcdef01234567")
	require.NoError(t, afero.WriteFile(fs, filepath.Join(snapshotDir, "model.safetensors"), []byte("x"), 0o644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(snapshotDir, "pytorch_model.bin"), zipHeader("pytorch_model/data.pkl"), 0o644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(snapshotDir, "config.json"), []byte(`{"model_type":"llama"}`), 0o644))

	results := detectWith(&HuggingFaceDetector{}, afs, home)
	require.Len(t, results, 1)
	m := results[0]
	assert.Equal(t, "safetensors", m.Format, "format reports the preferred file")
	assert.Equal(t, boolPtr(true), m.UnsafeSerialization)
	// The cache names a Xet-backed file's blob by its Xet hash, which looks
	// like a SHA-256 but isn't one, so no digest is reported.
	assert.Nil(t, m.WeightDigests)
}

func TestDetectHuggingFace_OnnxInSubdir(t *testing.T) {
	// Measured: dslim/bert-base-NER revision d1a3e8f13f8c on macOS, 2026-10-28:
	// the snapshot root holds only JSON and vocab.txt; the weights are
	// onnx/model.onnx. The scan returned unsafeSerialization false.
	afs, fs := newTestAfs()
	home := "/home/testuser"
	snapshotDir := filepath.Join(home, ".cache/huggingface/hub/models--dslim--bert-base-NER/snapshots/d1a3e8f13f8c3566299d95fcfc9a8d2382a9affc")
	for _, name := range []string{"config.json", "special_tokens_map.json", "tokenizer_config.json", "vocab.txt",
		"onnx/config.json", "onnx/special_tokens_map.json", "onnx/tokenizer.json", "onnx/tokenizer_config.json", "onnx/vocab.txt"} {
		require.NoError(t, afero.WriteFile(fs, filepath.Join(snapshotDir, name), []byte("{}"), 0o644))
	}
	require.NoError(t, afero.WriteFile(fs, filepath.Join(snapshotDir, "onnx/model.onnx"), []byte{0x08, 0x06, 0x12, 0x07, 'p', 'y', 't', 'o', 'r', 'c', 'h'}, 0o644))

	results := detectWith(&HuggingFaceDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, boolPtr(false), results[0].UnsafeSerialization)
}

func TestDetectHuggingFace_UnknownSerializationIsNull(t *testing.T) {
	// Synthetic: the only weight file is a .bin in no format the header
	// identifies; and a snapshot with no weight file at all.
	afs, fs := newTestAfs()
	home := "/home/testuser"
	hub := filepath.Join(home, ".cache/huggingface/hub")
	require.NoError(t, afero.WriteFile(fs, filepath.Join(hub, "models--org--opaque/snapshots/rev/weights.bin"), []byte{0x01, 0x02, 0x03, 0x04}, 0o644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(hub, "models--org--configonly/snapshots/rev/config.json"), []byte("{}"), 0o644))

	results := detectWith(&HuggingFaceDetector{}, afs, home)
	require.Len(t, results, 2)
	for _, m := range results {
		assert.Nil(t, m.UnsafeSerialization, m.Name)
		assert.Nil(t, m.WeightDigests, m.Name)
	}
}

func TestDetectOllama_WeightDigests(t *testing.T) {
	// Synthetic: a vision model manifest with model and projector layers
	// besides template and params layers.
	afs, fs := newTestAfs()
	home := "/home/testuser"
	manifest := ollamaManifest{
		Config: ollamaDescriptor{Digest: "sha256:cfg"},
		Layers: []ollamaLayer{
			{MediaType: "application/vnd.ollama.image.model", Digest: "sha256:" + digestA, Size: 1000},
			{MediaType: "application/vnd.ollama.image.projector", Digest: "sha256:" + digestB, Size: 300},
			{MediaType: "application/vnd.ollama.image.template", Digest: "sha256:" + strings.Repeat("c", 64), Size: 20},
			{MediaType: "application/vnd.ollama.image.params", Digest: "sha256:" + strings.Repeat("d", 64), Size: 10},
		},
	}
	writeJSON(t, fs, filepath.Join(home, ".ollama/models/manifests/registry.ollama.ai/library/llava/7b"), manifest)

	results := detectWith(&OllamaDetector{}, afs, home)
	require.Len(t, results, 1)
	assert.Equal(t, []string{"sha256:" + digestA, "sha256:" + digestB}, results[0].WeightDigests)
	assert.Equal(t, boolPtr(false), results[0].UnsafeSerialization)
}

func TestOllamaWeightDigests(t *testing.T) {
	// Synthetic: no weight layer.
	assert.Nil(t, ollamaWeightDigests([]ollamaLayer{{MediaType: "application/vnd.ollama.image.template", Digest: "sha256:" + digestA}}))
	assert.False(t, hasOllamaWeightLayer([]ollamaLayer{{MediaType: "application/vnd.ollama.image.license"}}))
	// Synthetic: a weight layer whose digest isn't a SHA-256 drops the list.
	assert.Nil(t, ollamaWeightDigests([]ollamaLayer{
		{MediaType: "application/vnd.ollama.image.model", Digest: "sha256:" + digestA},
		{MediaType: "application/vnd.ollama.image.adapter", Digest: "sha256:short"},
	}))
	assert.True(t, hasOllamaWeightLayer([]ollamaLayer{{MediaType: "application/vnd.ollama.image.adapter"}}))
	// Synthetic: a bare hex digest without the algorithm prefix drops the list.
	assert.Nil(t, ollamaWeightDigests([]ollamaLayer{{MediaType: "application/vnd.ollama.image.model", Digest: digestA}}))
	// Synthetic: upper-case hex is reported lower-case.
	assert.Equal(t, []string{"sha256:" + digestA}, ollamaWeightDigests([]ollamaLayer{
		{MediaType: "application/vnd.ollama.image.model", Digest: "sha256:" + strings.ToUpper(digestA)},
	}))
}

func TestFileBasedDetectors_UnsafeSerialization(t *testing.T) {
	afs, fs := newTestAfs()
	home := "/home/testuser"
	// Synthetic: a torchvision checkpoint, a Keras weights file, and GPT4All
	// GGUF and legacy GGML files.
	require.NoError(t, afero.WriteFile(fs, filepath.Join(home, ".cache/torch/hub/checkpoints/resnet50-0676ba61.pth"), zipHeader("resnet50-0676ba61/data.pkl"), 0o644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(home, ".keras/models/vgg16.h5"), []byte("\x89HDF\r\n\x1a\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(home, ".cache/gpt4all/orca-mini-3b.Q4_0.gguf"), []byte("GGUF\x03\x00\x00\x00"), 0o644))
	require.NoError(t, afero.WriteFile(fs, filepath.Join(home, ".cache/gpt4all/ggml-gpt4all-j.bin"), []byte("tjgg\x01\x00\x00\x00"), 0o644))

	got := map[string]*bool{}
	for _, m := range DetectAll(afs, []string{home}, "linux", nil) {
		got[m.Name] = m.UnsafeSerialization
	}
	assert.Equal(t, boolPtr(true), got["resnet50"])
	assert.Nil(t, got["vgg16"])
	assert.Equal(t, boolPtr(false), got["orca-mini-3b.Q4_0.gguf"])
	assert.Equal(t, boolPtr(false), got["ggml-gpt4all-j.bin"])
}

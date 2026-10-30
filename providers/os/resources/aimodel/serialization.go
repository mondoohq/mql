// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"

	"github.com/spf13/afero"
)

// Weight file formats by what loading them does.
var (
	// Pure data: the loader parses tensors and metadata and runs no code
	// stored in the file.
	dataWeightExts = map[string]struct{}{
		".safetensors": {},
		".gguf":        {},
		".onnx":        {},
		".npz":         {}, // numpy refuses pickled object arrays unless allow_pickle is set
		".msgpack":     {}, // Flax
		".tflite":      {},
	}
	// Python pickle: unpickling runs whatever callables the file names.
	// torch.save writes pickle (wrapped in a zip archive since PyTorch 1.6),
	// and .ckpt is the PyTorch Lightning and Stable Diffusion checkpoint.
	pickleWeightExts = map[string]struct{}{
		".pt":     {},
		".pth":    {},
		".ckpt":   {},
		".pkl":    {},
		".pickle": {},
		".joblib": {},
	}
	// Whether these run code depends on the model inside (a Keras Lambda
	// layer), which the file name and header do not tell.
	undecidedWeightExts = map[string]struct{}{
		".h5":    {},
		".keras": {},
	}
)

// sniffLen is how much of a .bin file is read to identify its format: the
// pickle and GGUF/GGML magic, or a zip local file header and its file name.
const sniffLen = 512

// classifyWeightFile reports whether the file at p holds model weights and, if
// it does, whether loading it executes code from the file. unsafe is nil when
// the format can't be told. A .bin file is identified by its first bytes,
// since the extension is shared by PyTorch pickles, GGML files and opaque
// vendor formats.
func classifyWeightFile(afs *afero.Afero, p string) (weight bool, unsafe *bool) {
	ext := strings.ToLower(fileExt(baseName(p)))
	if _, ok := dataWeightExts[ext]; ok {
		return true, boolPtr(false)
	}
	if _, ok := pickleWeightExts[ext]; ok {
		return true, boolPtr(true)
	}
	if _, ok := undecidedWeightExts[ext]; ok {
		return true, nil
	}
	if ext == ".bin" {
		return true, sniffSerialization(afs, p)
	}
	return false, nil
}

// isWeightFile is whether the file at p is in a weight format, by its
// extension alone.
func isWeightFile(p string) bool {
	ext := strings.ToLower(fileExt(baseName(p)))
	if ext == ".bin" {
		return true
	}
	for _, set := range []map[string]struct{}{dataWeightExts, pickleWeightExts, undecidedWeightExts} {
		if _, ok := set[ext]; ok {
			return true
		}
	}
	return false
}

func fileExt(name string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i:]
	}
	return ""
}

// sniffSerialization identifies a weight file by its header:
//   - a pickle stream of protocol 2 to 5 starts with PROTO (0x80) and the
//     protocol number; legacy torch.save writes protocol 2
//   - torch.save since PyTorch 1.6 writes a zip archive whose first record is
//     <archive>/data.pkl, the pickle that references the tensor records
//   - GGUF and the older GGML, GGMF, GGJT and GGLA files start with their
//     magic, the GGML family's as a little-endian uint32
//
// Anything else, including a file that can't be read, is unknown. That
// includes a pickle of protocol 0 or 1, which has no PROTO opcode and starts
// with an arbitrary opcode; torch.save never writes those, and the .pkl and
// .pickle extensions are classified as pickle without reading the header.
func sniffSerialization(afs *afero.Afero, p string) *bool {
	f, err := afs.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	head := make([]byte, sniffLen)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil
	}
	return headerSerialization(head[:n])
}

var ggmlMagics = [][]byte{
	[]byte("GGUF"),
	[]byte("lmgg"), // 0x67676d6c ggml
	[]byte("fmgg"), // 0x67676d66 ggmf
	[]byte("tjgg"), // 0x67676a74 ggjt
	[]byte("algg"), // 0x67676c61 ggla (LoRA adapter)
}

func headerSerialization(head []byte) *bool {
	if len(head) >= 2 && head[0] == 0x80 && head[1] >= 2 && head[1] <= 5 {
		return boolPtr(true)
	}
	if len(head) >= 30 && bytes.HasPrefix(head, []byte("PK\x03\x04")) {
		nameLen := int(binary.LittleEndian.Uint16(head[26:28]))
		if 30+nameLen > len(head) {
			return nil
		}
		name := string(head[30 : 30+nameLen])
		if name == "data.pkl" || strings.HasSuffix(name, "/data.pkl") {
			return boolPtr(true)
		}
		return nil
	}
	for _, m := range ggmlMagics {
		if bytes.HasPrefix(head, m) {
			return boolPtr(false)
		}
	}
	return nil
}

// weightFiles lists the weight files under dir, descending at most maxDepth
// directory levels. On filesystems whose listings come from lstat, as the
// local one's do, a Hugging Face snapshot's links to its blobs are listed as
// files and a link to a directory is not followed. Where a listing follows
// links, a linked directory is descended like any other, still bounded by
// maxDepth, and the weight files found are the same.
func weightFiles(afs *afero.Afero, dir string, maxDepth int) []string {
	entries, err := afs.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []string
	for _, e := range entries {
		p := joinPath(dir, e.Name())
		if e.IsDir() {
			if maxDepth > 0 {
				files = append(files, weightFiles(afs, p, maxDepth-1)...)
			}
			continue
		}
		if isWeightFile(p) {
			files = append(files, p)
		}
	}
	return files
}

// unsafeSerialization combines the verdicts of a model's weight files: true
// when any of them executes code on load, false when every one of them is a
// pure data format, and nil when there are none or one can't be told.
func unsafeSerialization(afs *afero.Afero, files []string) *bool {
	saw, unknown := false, false
	for _, f := range files {
		weight, unsafe := classifyWeightFile(afs, f)
		if !weight {
			continue
		}
		saw = true
		if unsafe == nil {
			unknown = true
			continue
		}
		if *unsafe {
			return boolPtr(true)
		}
	}
	if !saw || unknown {
		return nil
	}
	return boolPtr(false)
}

// validSHA256Digest checks that digest is sha256:<64 hex characters> and
// returns it with the hex lowercased.
func validSHA256Digest(digest string) (string, bool) {
	hexDigest, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexDigest) != 64 || !isHex(hexDigest) {
		return "", false
	}
	return "sha256:" + strings.ToLower(hexDigest), true
}

// Media types of the Ollama manifest layers that hold weights: the model, a
// vision projector, and a LoRA adapter. All three are GGUF.
var ollamaWeightMediaTypes = map[string]struct{}{
	"application/vnd.ollama.image.model":     {},
	"application/vnd.ollama.image.projector": {},
	"application/vnd.ollama.image.adapter":   {},
}

// ollamaWeightDigests returns the digest of each weight layer as the manifest
// records it, nil when the manifest names no weight layer or a digest isn't a
// SHA-256.
func ollamaWeightDigests(layers []ollamaLayer) []string {
	var digests []string
	for _, l := range layers {
		if _, ok := ollamaWeightMediaTypes[l.MediaType]; !ok {
			continue
		}
		d, ok := validSHA256Digest(l.Digest)
		if !ok {
			return nil
		}
		digests = append(digests, d)
	}
	return digests
}

func hasOllamaWeightLayer(layers []ollamaLayer) bool {
	for _, l := range layers {
		if _, ok := ollamaWeightMediaTypes[l.MediaType]; ok {
			return true
		}
	}
	return false
}

func boolPtr(b bool) *bool { return &b }

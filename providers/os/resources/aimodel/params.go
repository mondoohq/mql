// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"strings"

	"github.com/spf13/afero"
)

// parameterSizeFromName returns the parameter count a model name states
// explicitly, such as "7B" for "llama3:7b" or "135M" for "smollm:135m", or ""
// when the name states none. Only a count in billions (b) or millions (m) is
// taken; other suffixes, such as the "128k" of a context length, are not
// parameter counts. The unit is reported in upper case.
func parameterSizeFromName(name string) string {
	m := reParamSize.FindStringSubmatch(name)
	if len(m) < 3 {
		return ""
	}
	return m[1] + strings.ToUpper(m[2])
}

// GGUF metadata, as specified in
// https://github.com/ggml-org/ggml/blob/master/docs/gguf.md
const (
	ggufMagic = 0x46554747 // "GGUF" read as a little-endian uint32

	ggufTypeUint8   = 0
	ggufTypeInt8    = 1
	ggufTypeUint16  = 2
	ggufTypeInt16   = 3
	ggufTypeUint32  = 4
	ggufTypeInt32   = 5
	ggufTypeFloat32 = 6
	ggufTypeBool    = 7
	ggufTypeString  = 8
	ggufTypeArray   = 9
	ggufTypeUint64  = 10
	ggufTypeInt64   = 11
	ggufTypeFloat64 = 12

	// ggufSizeLabelKey is the parameter weight class of the model, such as
	// "135M", "7B", or "8x7B".
	ggufSizeLabelKey = "general.size_label"

	// ggufHeaderBudget bounds how much of a model file is read looking for
	// the size label. Model files are gigabytes, and the general.* keys come
	// before the large tokenizer arrays in files written by llama.cpp, so a
	// label that is present is found well within this.
	ggufHeaderBudget = 256 * 1024
	// ggufMaxString bounds a single key or string value.
	ggufMaxString = 64 * 1024
)

var errGGUFBudget = errors.New("gguf metadata exceeds the read budget")

// ggufSizeLabel reads general.size_label from the metadata of a GGUF file, or
// returns "" when the file is not GGUF, has no size label, or the label is not
// within the first ggufHeaderBudget bytes. Only the header is read.
func ggufSizeLabel(afs *afero.Afero, path string) string {
	f, err := afs.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	label, err := readGGUFSizeLabel(f)
	if err != nil {
		return ""
	}
	return label
}

func readGGUFSizeLabel(r io.Reader) (string, error) {
	g := &ggufReader{r: bufio.NewReader(io.LimitReader(r, ggufHeaderBudget))}

	magic, err := g.u32()
	if err != nil {
		return "", err
	}
	if magic != ggufMagic {
		return "", errors.New("not a gguf file")
	}
	version, err := g.u32()
	if err != nil {
		return "", err
	}
	// Version 1 used 32-bit counts and lengths; big-endian files show up as
	// an implausible version. Neither is worth the extra decoding here.
	if version < 2 || version > 255 {
		return "", errors.New("unsupported gguf version")
	}
	if _, err := g.u64(); err != nil { // tensor count
		return "", err
	}
	kvCount, err := g.u64()
	if err != nil {
		return "", err
	}

	for i := uint64(0); i < kvCount; i++ {
		key, err := g.str()
		if err != nil {
			return "", err
		}
		typ, err := g.u32()
		if err != nil {
			return "", err
		}
		if key == ggufSizeLabelKey && typ == ggufTypeString {
			v, err := g.str()
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(v), nil
		}
		if err := g.skip(typ); err != nil {
			return "", err
		}
	}
	return "", nil
}

type ggufReader struct {
	r *bufio.Reader
}

func (g *ggufReader) u32() (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(g.r, b[:]); err != nil {
		return 0, budgetErr(err)
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func (g *ggufReader) u64() (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(g.r, b[:]); err != nil {
		return 0, budgetErr(err)
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

func (g *ggufReader) str() (string, error) {
	n, err := g.u64()
	if err != nil {
		return "", err
	}
	if n > ggufMaxString {
		return "", errGGUFBudget
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(g.r, b); err != nil {
		return "", budgetErr(err)
	}
	return string(b), nil
}

func (g *ggufReader) discard(n uint64) error {
	if n > ggufHeaderBudget {
		return errGGUFBudget
	}
	if _, err := g.r.Discard(int(n)); err != nil {
		return budgetErr(err)
	}
	return nil
}

// skip reads past a value of the given type.
func (g *ggufReader) skip(typ uint32) error {
	switch typ {
	case ggufTypeUint8, ggufTypeInt8, ggufTypeBool:
		return g.discard(1)
	case ggufTypeUint16, ggufTypeInt16:
		return g.discard(2)
	case ggufTypeUint32, ggufTypeInt32, ggufTypeFloat32:
		return g.discard(4)
	case ggufTypeUint64, ggufTypeInt64, ggufTypeFloat64:
		return g.discard(8)
	case ggufTypeString:
		n, err := g.u64()
		if err != nil {
			return err
		}
		return g.discard(n)
	case ggufTypeArray:
		elem, err := g.u32()
		if err != nil {
			return err
		}
		if elem == ggufTypeArray {
			return errors.New("nested gguf arrays are not supported")
		}
		n, err := g.u64()
		if err != nil {
			return err
		}
		if n > ggufHeaderBudget {
			return errGGUFBudget
		}
		for j := uint64(0); j < n; j++ {
			if err := g.skip(elem); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("unknown gguf metadata type")
	}
}

// budgetErr reports running into the read budget as such, rather than as a
// truncated file.
func budgetErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errGGUFBudget
	}
	return err
}

// parameterSizeFromGGUF returns the size label of the first of paths that
// carries one, falling back to the count stated in name.
func parameterSizeFromGGUF(afs *afero.Afero, paths []string, name string) string {
	for _, p := range paths {
		if label := ggufSizeLabel(afs, p); label != "" {
			return label
		}
	}
	return parameterSizeFromName(name)
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"encoding/base64"
	"encoding/binary"

	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/sortx"
	"golang.org/x/crypto/blake2b"
)

// Checksum computes the checksum of this chunk
func (c *Chunk) ChecksumV1(code *CodeV1) string {
	data := []byte(c.Id)

	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(c.Call))
	data = append(data, b...)

	if c.Primitive != nil {
		cs := c.Primitive.checksumV1(code)
		data = append(data, cs...)
	}

	if c.Function != nil {
		data = append(data, c.Function.checksumV1(code)...)
	}

	hash := blake2b.Sum512(data)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func (f *Function) checksumV1(code *CodeV1) []byte {
	res := []byte(f.Type)

	for i := range f.Args {
		cs := f.Args[i].checksumV1(code)
		res = append(res, cs...)
	}

	return res
}

func (p *Primitive) checksumV1(code *CodeV1) []byte {
	ref, ok := p.RefV1()
	if ok {
		typ := types.Type(p.Type)
		if typ == types.Ref {
			refChecksum, ok := code.Checksums[int32(ref)]
			if !ok {
				panic("llx> cannot compute checksum for primitive, it doesn't seem to reference a variable on the stack")
			}

			return []byte(refChecksum)
		}

		if typ.Underlying() == types.FunctionLike {
			refFunction := code.Functions[int32(ref)-1]
			if !ok {
				panic("llx> cannot compute checksum for primitive, it doesn't seem to reference a function on the stack")
			}

			return []byte(refFunction.Id)
		}

		panic("llx> received a reference of an unknown type in trying to calculate the checksum")
	}

	res := []byte(p.Type)
	res = append(res, p.Value...)

	for i := range p.Array {
		entry := p.Array[i]
		res = append(res, entry.checksumV1(code)...)
	}

	keys := sortx.Keys(p.Map)

	for _, k := range keys {
		v := p.Map[k]
		res = append(res, k...)
		res = append(res, v.checksumV1(code)...)
	}

	return res
}

// Checksum computes the checksum of this chunk
func (c *Chunk) ChecksumV2(blockRef uint64, code *CodeV2) string {
	data := []byte(c.Id)

	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(c.Call))
	data = append(data, b...)

	if c.Primitive != nil {
		cs := c.Primitive.checksumV2(code)
		data = append(data, cs...)
	}

	if c.Function != nil {
		data = append(data, c.Function.checksumV2(code)...)
	}

	hash := blake2b.Sum512(data)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func (f *Function) checksumV2(code *CodeV2) []byte {
	res := []byte(f.Type)

	if f.Binding != 0 {
		ref := code.Checksums[f.Binding]
		if ref == "" {
			panic("cannot compute checksum for chunk, it doesn't seem to reference a function on the stack")
		}
		res = append(res, ref...)
	}

	for i := range f.Args {
		cs := f.Args[i].checksumV2(code)
		res = append(res, cs...)
	}

	// Nullability has to reach the checksum: `a.b.c` and `a.b?.c` are the same
	// bytes everywhere else, so without this they collide in the code cache and
	// in any store keyed on chunk checksums while meaning different things.
	//
	// Mixed only when set, the same way Binding is above. A non-strict
	// compilation leaves this at NULLABILITY_UNSPECIFIED, so every checksum
	// predating strict mode stays byte-identical.
	if f.Nullability != Function_NULLABILITY_UNSPECIFIED {
		res = append(res, byte(f.Nullability))
	}

	return res
}

func (p *Primitive) checksumV2(code *CodeV2) []byte {
	ref, ok := p.RefV2()
	if ok {
		typ := types.Type(p.Type)
		if typ == types.Ref {
			refChecksum, ok := code.Checksums[ref]
			if !ok {
				panic("llx> cannot compute checksum for primitive, it doesn't seem to reference a variable on the stack")
			}

			return []byte(refChecksum)
		} else if typ.Underlying() == types.FunctionLike {
			refChecksum := code.Blocks[(ref>>32)-1].checksum(code)
			return []byte(refChecksum)

		}

		panic("llx> received a reference of an unknown type in trying to calculate the checksum")
	}

	res := []byte(p.Type)
	res = append(res, p.Value...)

	for i := range p.Array {
		entry := p.Array[i]
		res = append(res, entry.checksumV2(code)...)
	}

	keys := sortx.Keys(p.Map)
	for _, k := range keys {
		v := p.Map[k]
		res = append(res, k...)
		res = append(res, v.checksumV2(code)...)
	}

	return res
}

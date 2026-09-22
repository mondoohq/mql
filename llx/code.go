// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"bytes"
	"sort"

	"go.mondoo.com/mql/checksums"
	"go.mondoo.com/mql/types"
)

func (b *Block) ChunkIndex() uint32 {
	return uint32(len(b.Chunks))
}

func ChunkIndex(ref uint64) uint32 {
	return uint32(ref & 0xFFFFFFFF)
}

func absRef(blockRef uint64, relRef uint32) uint64 {
	return (blockRef & 0xFFFFFFFF00000000) | uint64(relRef)
}

// TailRef returns the reference to the last chunk of the block
func (b *Block) TailRef(blockRef uint64) uint64 {
	return absRef(blockRef, b.ChunkIndex())
}

// HeadRef returns the reference to the first chunk of the block
func (b *Block) HeadRef(blockRef uint64) uint64 {
	return absRef(blockRef, 1)
}

func (b *Block) ReplaceEntrypoint(old uint64, nu uint64) {
	for i := range b.Entrypoints {
		if b.Entrypoints[i] == old {
			b.Entrypoints[i] = nu
			return
		}
	}
}

// LastChunk is the last chunk in the list or nil
func (b *Block) LastChunk() *Chunk {
	max := len(b.Chunks)
	if max == 0 {
		return nil
	}
	return b.Chunks[max-1]
}

// AddChunk to the list of chunks
func (b *Block) AddChunk(code *CodeV2, blockRef uint64, c *Chunk) {
	nuRef := b.TailRef(blockRef) + 1
	code.Checksums[nuRef] = c.ChecksumV2(blockRef, code)
	b.Chunks = append(b.Chunks, c)
}

func (b *Block) AddArgumentPlaceholder(code *CodeV2, blockRef uint64, typ types.Type, checksum string) {
	b.AddChunk(code, blockRef, &Chunk{
		Call:      Chunk_PRIMITIVE,
		Primitive: &Primitive{Type: string(typ)}, // placeholder
	})
	code.Checksums[b.TailRef(blockRef)] = checksum
	b.Parameters++
}

// PopChunk removes the last chunk from the block and returns it
func (b *Block) PopChunk(code *CodeV2, blockRef uint64) (prev *Chunk, isEntrypoint bool, isDatapoint bool) {
	isEntrypoint = false
	isDatapoint = false

	if len(b.Chunks) == 0 {
		return nil, false, false
	}

	tailRef := b.TailRef(blockRef)
	delete(code.Checksums, tailRef)

	if len(b.Entrypoints) > 0 && b.Entrypoints[len(b.Entrypoints)-1] == tailRef {
		isEntrypoint = true
		b.Entrypoints = b.Entrypoints[:len(b.Entrypoints)-1]
	}

	if len(b.Datapoints) > 0 && b.Datapoints[len(b.Datapoints)-1] == tailRef {
		isDatapoint = true
		b.Datapoints = b.Datapoints[:len(b.Datapoints)-1]
	}

	max := len(b.Chunks)
	last := b.Chunks[max-1]
	b.Chunks = b.Chunks[:max-1]
	return last, isEntrypoint, isDatapoint
}

// ChunkIndex is the index of the last chunk that was added
func (l *CodeV2) TailRef(blockRef uint64) uint64 {
	return l.Block(blockRef).TailRef(blockRef)
}

// Retrieve a chunk for the given ref
func (l *CodeV2) Chunk(ref uint64) *Chunk {
	return l.Block(ref).Chunks[uint32(ref)-1]
}

// Retrieve a block for the given ref
func (l *CodeV2) Block(ref uint64) *Block {
	return l.Blocks[uint32(ref>>32)-1]
}

// LastBlockRef retrieves the ref for the last block in the code
func (l *CodeV2) LastBlockRef() uint64 {
	return uint64(len(l.Blocks)) << 32
}

// AddBlock adds a new block at the end of this code and returns its ref
func (l *CodeV2) AddBlock() (*Block, uint64) {
	block := &Block{}
	l.Blocks = append(l.Blocks, block)
	return block, uint64(len(l.Blocks)) << 32
}

func (c *CodeV2) Entrypoints() []uint64 {
	if len(c.Blocks) == 0 {
		return []uint64{}
	}

	return c.Blocks[0].Entrypoints
}

func (c *CodeV2) Datapoints() []uint64 {
	if len(c.Blocks) == 0 {
		return []uint64{}
	}

	return c.Blocks[0].Datapoints
}

// DereferencedBlockType returns the type of a block, which is a specific
// type if it is a single-value block
func (l *CodeV2) DereferencedBlockType(b *Block) types.Type {
	if len(b.Entrypoints) != 1 {
		return types.Block
	}

	ep := b.Entrypoints[0]
	chunk := b.Chunks[(ep-1)&0xFFFFFFFF]
	return chunk.DereferencedTypeV2(l)
}

func (block *Block) checksum(l *CodeV2) string {
	c := checksums.New
	for i := range block.Entrypoints {
		c = c.Add(l.Checksums[block.Entrypoints[i]])
	}
	return c.String()
}

// checksum from this code
func (l *CodeV2) checksum() string {
	checksum := checksums.New

	for i := range l.Blocks {
		checksum = checksum.Add(l.Blocks[i].checksum(l))
	}

	assertionRefs := make([]uint64, 0, len(l.Assertions))
	for k := range l.Assertions {
		assertionRefs = append(assertionRefs, k)
	}
	sort.Slice(assertionRefs, func(i, j int) bool { return assertionRefs[i] < assertionRefs[j] })
	for _, ref := range assertionRefs {
		checksum = checksum.Add(l.Checksums[ref])
	}

	// TODO: review this behavior
	// if len(l.Blocks) == 0 || len(l.Blocks[0].Entrypoints) == 0 {
	//   panic("received a code without any entrypoints")
	// }
	// Why do we even handle this case? Because at this point we still have
	// all raw entrypoints, which may get shuffled around in the step after this.
	// This also means entrypoints aren't sanitized. We may not have any.
	//
	// We may want to do the entrypoint handling earlier.

	return checksum.String()
}

// UpdateID of the piece of code
func (l *CodeV2) UpdateID() {
	l.Id = l.checksum()
}

// RefDatapoints returns the additional datapoints that inform a ref.
// Typically used when writing tests and providing additional data when the test fails.
func (l *CodeV2) RefDatapoints(ref uint64) []uint64 {
	if assertion, ok := l.Assertions[ref]; ok {
		return assertion.Refs
	}

	chunk := l.Chunk(ref)

	if chunk.Id == "if" && chunk.Function != nil && len(chunk.Function.Args) != 0 {
		var ok bool
		ref, ok = chunk.Function.Args[0].RefV2()
		if !ok {
			return nil
		}
		chunk = l.Chunk(ref)
	}

	if chunk.Id == "" {
		return nil
	}

	// nothing to do for primitives (unclear if we need to investigate refs here)
	if chunk.Call != Chunk_FUNCTION || chunk.Function == nil {
		return nil
	}

	switch chunk.Id {
	case "$all", "$one", "$any", "$none":
		return []uint64{ref - 1}
	}

	label, ok := ComparableLabel(chunk.Id)
	if !ok {
		return nil
	}

	// A short-circuiting operator does not inform anything: its right side only
	// runs when the left side fails to decide the result, and a datapoint runs
	// unconditionally. Collecting the operands would evaluate a right side the
	// guard exists to skip, which is what `x == null || x.someCall()` is written
	// to prevent. Neither operand is worth the guarantee: `a || b` has no
	// expected/actual to report, and the operands of the operands are not
	// collected either, so the expansion could not render them anyway.
	if isShortCircuit(label) {
		return nil
	}

	var res []uint64

	// at this point we have a comparable
	// so 2 jobs: check the left, check the right. if it's static, ignore. if not, add
	left := chunk.Function.Binding
	if left != 0 {
		leftChunk := l.Chunk(left)
		if leftChunk != nil && !leftChunk.isStatic() {
			res = append(res, left)
		}
	}

	if len(chunk.Function.Args) != 0 {
		rightPrim := chunk.Function.Args[0]
		if rightPrim != nil && types.Type(rightPrim.Type) == types.Ref {
			right, ok := rightPrim.RefV2()
			if ok {
				res = append(res, right)
			}
		}
	}

	return res
}

func (l *CodeV2) refValues(bundle *CodeBundle, ref uint64, lookup func(s string) (*RawResult, bool)) []*RawResult {
	checksum := l.Checksums[ref]
	checksumRes, ok := lookup(checksum)
	if ok {
		return []*RawResult{checksumRes}
	}

	chunk := l.Chunk(ref)

	if chunk.Id == "if" && chunk.Function != nil && len(chunk.Function.Args) != 0 {
		// FIXME: we should be checking for the result of the if-condition and then proceed
		// with whatever result is applicable; not poke at possible results

		// function arguments are functions refs to:
		// [1] = the first condition, [2] = the second condition
		fref, ok := chunk.Function.Args[1].RefV2()
		if ok {
			if part, ok := lookup(l.Checksums[fref]); ok {
				return []*RawResult{part}
			}
		}

		fref, ok = chunk.Function.Args[2].RefV2()
		if ok {
			if part, ok := lookup(l.Checksums[fref]); ok {
				return []*RawResult{part}
			}
		}
	}

	return nil
}

func (l *CodeV2) returnValues(bundle *CodeBundle, lookup func(s string) (*RawResult, bool)) []*RawResult {
	var res []*RawResult

	if len(l.Blocks) == 0 {
		return res
	}
	block := l.Blocks[0]

	for i := range block.Entrypoints {
		ep := block.Entrypoints[i]
		cur := l.refValues(bundle, ep, lookup)
		if cur != nil {
			res = append(res, cur...)
		}
	}

	return res
}

func (l *CodeV2) Entrypoint2Assessment(bundle *CodeBundle, ref uint64, lookup func(s string) (*RawResult, bool)) *AssessmentItem {
	code := bundle.CodeV2
	checksum := code.Checksums[ref]

	checksumRes, ok := lookup(checksum)
	if !ok {
		return nil
	}

	truthy, _ := checksumRes.Data.IsTruthy()

	res := AssessmentItem{
		Checksum:   checksum,
		Entrypoint: ref,
		Success:    truthy,
	}

	if checksumRes.Data.Error != nil {
		res.Error = checksumRes.Data.Error.Error()
	}

	// explicit assessments
	if assertion, ok := bundle.Assertions[checksum]; ok {
		res.IsAssertion = true

		if assertion.DecodeBlock {
			sum := assertion.Checksums[0]
			raw, ok := lookup(sum)
			if !ok {
				res.Error = "cannot find required data block for assessment"
				return &res
			}

			x := raw.Result().Data
			if x == nil {
				res.Error = "required data block for assessment is nil"
				return &res
			}

			dataMap := map[string]*Primitive(x.Map)

			cnt := len(assertion.Checksums) - 1
			res.Data = make([]*Primitive, cnt)
			for i := 0; i < cnt; i++ {
				sum = assertion.Checksums[i+1]
				res.Data[i], ok = dataMap[sum]
				if !ok {
					res.Error = "required data field is not in block for assessment"
				}
			}

			res.Template = assertion.Template
			return &res
		}

		data := make([]*Primitive, len(assertion.Checksums))
		for j := range assertion.Checksums {
			sum := assertion.Checksums[j]

			raw, ok := lookup(sum)
			if !ok {
				res.Error = "cannot find required data"
				return &res
			}

			data[j] = raw.Result().Data
		}

		res.Data = data
		res.Template = assertion.Template
		return &res
	}

	chunk := l.Chunk(ref)

	if chunk.Id == "if" {
		// Our current assessment structure cannot handle nesting very well
		// We return nil here for now. Our result printing has good enough
		// information to convey this nesting and what exactly went wrong
		return nil
	}

	if chunk.Call == Chunk_PRIMITIVE {
		res.Actual = chunk.Primitive
		return &res
	}

	if chunk.Call != Chunk_FUNCTION {
		res.Error = "unknown type of chunk"
		return &res
	}

	if chunk.Function == nil {
		// this only happens when we have a call chain that resembles a resource
		// which is used without any init arguments
		chunk.Function = &Function{Type: string(types.Resource(chunk.Id))}
	}

	if chunk.Id == "" {
		res.Error = "chunk has unknown identifier"
		return &res
	}

	switch chunk.Id {
	case "$one", "$all", "$none", "$any":
		res.IsAssertion = true
		res.Operation = chunk.Id[1:]

		if !truthy {
			listRef := chunk.Function.Binding
			// Find the datapoint linked to this listRef
			// For .all(...) queries and alike, all is bound to a list.
			// This list only has the resource ids as datapoints.
			// But earlier on, we also bound a datapoint for the default fields to the list.
			// We need to find this datapoint and use it as the listRef.
		OUTER:
			for i := range code.Blocks {
				refIsEntrypoint := false
				for j := range code.Blocks[i].Entrypoints {
					if code.Blocks[i].Entrypoints[j] == ref {
						refIsEntrypoint = true
						break
					}
				}
				if !refIsEntrypoint {
					continue
				}
				for j := len(code.Blocks[i].Datapoints) - 1; j >= 0; j-- {
					// skip the resource ids datapoint
					if code.Blocks[i].Datapoints[j] == listRef {
						continue
					}
					cc := code.Chunk(code.Blocks[i].Datapoints[j])
					// this contains the default values
					if cc.Function != nil && cc.Function.Binding == listRef {
						listRef = code.Blocks[i].Datapoints[j]
						break OUTER
					}
				}
			}
			listChecksum := code.Checksums[listRef]
			list, ok := lookup(listChecksum)
			if !ok {
				res.Error = "cannot find value for assessment (" + res.Operation + ")"
				return &res
			}

			res.Actual = list.Result().Data
		} else {
			res.Actual = BoolPrimitive(true)
		}

		return &res
	}

	// FIXME: support child operations inside of block calls "{}" / "${}"

	if label, found := ComparableLabel(chunk.Id); found {
		res.Operation = label

		// A boolean combinator has no pair of values to put on either side of the
		// operator. Its operands are whole statements, and the right one may never
		// have run, because that is what the short circuit is for. The statement's
		// own value is the only thing that was measured; the label says the rest.
		if isShortCircuit(label) {
			res.IsAssertion = true
			res.Actual = checksumRes.Result().Data
			return &res
		}
	} else {
		cRes := checksumRes.Result()

		if checksumRes.Data.Type != types.Bool {
			res.Actual = cRes.Data
		} else {
			res.Operation = "=="
			res.Expected = BoolPrimitive(true)
			res.Actual = cRes.Data
			res.IsAssertion = true
		}
		return &res
	}

	res.IsAssertion = true

	// at this point we have a comparable
	// so 2 jobs: check the left, check the right. if it's static, ignore. if not, add
	left := chunk.Function.Binding
	if left != 0 {
		leftChunk := l.Chunk(left)
		if leftChunk == nil {
			res.Actual = &Primitive{
				Type:  string(types.Any),
				Value: []byte("< unknown expected value >"),
			}
		}

		if leftChunk.isStatic() {
			res.Actual = leftChunk.Primitive
		} else {
			leftSum := code.Checksums[left]
			leftRes, ok := lookup(leftSum)
			if !ok {
				res.Actual = nil
			} else {
				res.Actual = leftRes.Result().Data
			}
		}
	}

	if len(chunk.Function.Args) == 0 {
		return &res
	}

	rightPrim := chunk.Function.Args[0]
	if rightPrim == nil {
		res.Expected = &Primitive{
			Type:  string(types.Any),
			Value: []byte("< unknown actual value >"),
		}
		return &res
	}

	if types.Type(rightPrim.Type) != types.Ref {
		res.Expected = rightPrim
	} else {
		right, ok := rightPrim.RefV2()
		if !ok {
			res.Expected = &Primitive{
				Type:  string(types.Any),
				Value: []byte("< unknown actual value >"),
			}
		} else {
			rightSum := code.Checksums[right]
			rightRes, ok := lookup(rightSum)
			if !ok {
				res.Expected = nil
			} else {
				res.Expected = rightRes.Result().Data
			}
		}
	}

	return &res
}

// ComparableLabel takes any arbitrary label and returns the
// operation as a printable string and true if it is a comparable, otherwise "" and false.
func ComparableLabel(label string) (string, bool) {
	if label == "" {
		return "", false
	}

	start := 0
	for bytes.IndexByte(comparableIndicators, label[start]) == -1 {
		start++
		if start >= len(label) {
			return "", false
		}
	}

	if len(label)-start >= 2 {
		x := label[start : start+2]
		if _, ok := comparableOperations[x]; ok {
			return x, true
		}
	}

	x := label[start : start+1]
	if _, ok := comparableOperations[x]; ok {
		return x, true
	}
	if len(label) == 1 {
		return "", false
	}

	return "", false
}

// isShortCircuit reports whether a comparable label is one of the boolean
// combinators, which evaluate their right side lazily.
func isShortCircuit(label string) bool {
	return label == "&&" || label == "||"
}

var comparableIndicators = []byte{'=', '!', '>', '<', '&', '|'}

var comparableOperations = map[string]struct{}{
	"==": {},
	"!=": {},
	">":  {},
	"<":  {},
	">=": {},
	"<=": {},
	"&&": {},
	"||": {},
}

func (c *Chunk) isStatic() bool {
	if c.Call != Chunk_PRIMITIVE {
		return false
	}

	if types.Type(c.Primitive.Type) == types.Ref {
		return false
	}

	return true
}

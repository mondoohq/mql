// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package regf

import (
	"encoding/binary"
	"math/bits"
)

// logSeed is the Marvin32 seed Windows uses for the hashes of transaction log
// entries. The specification lists its bytes as 82 EF 4D 88 7A 4E 55 C5, which
// is the big-endian spelling of the 64-bit constant 0x82EF4D887A4E55C5: the low
// state word is 0x7A4E55C5 and the high one 0x82EF4D88 (checked against the
// hashes of real log entries).
var logSeed = [2]uint32{0x7A4E55C5, 0x82EF4D88}

// marvin32 is the Marvin32 hash (the one .NET uses for string hashing), which
// the transaction log entries use as their integrity check.
type marvin32 struct {
	lo, hi uint32
	tail   [4]byte
	ntail  int
}

func newMarvin32(seed [2]uint32) *marvin32 {
	return &marvin32{lo: seed[0], hi: seed[1]}
}

func (m *marvin32) block() {
	m.hi ^= m.lo
	m.lo = bits.RotateLeft32(m.lo, 20)
	m.lo += m.hi
	m.hi = bits.RotateLeft32(m.hi, 9)
	m.hi ^= m.lo
	m.lo = bits.RotateLeft32(m.lo, 27)
	m.lo += m.hi
	m.hi = bits.RotateLeft32(m.hi, 19)
}

// Write adds data to the hash.
func (m *marvin32) Write(p []byte) {
	for len(p) > 0 {
		if m.ntail > 0 || len(p) < 4 {
			n := copy(m.tail[m.ntail:], p)
			m.ntail += n
			p = p[n:]
			if m.ntail == 4 {
				m.lo += binary.LittleEndian.Uint32(m.tail[:])
				m.block()
				m.ntail = 0
			}
			continue
		}
		m.lo += binary.LittleEndian.Uint32(p)
		m.block()
		p = p[4:]
	}
}

// Sum finishes the hash and returns the two 32-bit halves of its state.
func (m *marvin32) Sum() (lo, hi uint32) {
	var last uint32
	switch m.ntail {
	case 0:
		last = 0x80
	case 1:
		last = 0x8000 | uint32(m.tail[0])
	case 2:
		last = 0x800000 | uint32(binary.LittleEndian.Uint16(m.tail[:]))
	case 3:
		last = 0x80000000 | uint32(m.tail[2])<<16 | uint32(binary.LittleEndian.Uint16(m.tail[:]))
	}
	c := *m
	c.lo += last
	c.block()
	c.block()
	return c.lo, c.hi
}

// Sum64 finishes the hash as the 8 bytes a log entry stores: the low half
// first.
func (m *marvin32) Sum64() uint64 {
	lo, hi := m.Sum()
	return uint64(hi)<<32 | uint64(lo)
}

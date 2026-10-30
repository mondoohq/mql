// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package regf

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The header of a real log entry (from a Windows Server 2025 SYSTEM.LOG2) with
// its stored Hash-1 at bytes 24..32 and Hash-2 at bytes 32..40. Hash-2 is the
// Marvin32 of the first 32 bytes, so this pins the seed and the byte order of
// the stored hash against what Windows wrote.
const realEntryHeader = "48764c4500fe000001000000e10000000010fe00090000004497c6d70d786654eae717011f187812"

func TestMarvin32AgainstWindowsLogEntry(t *testing.T) {
	hdr, err := hex.DecodeString(realEntryHeader)
	require.NoError(t, err)
	require.Len(t, hdr, 40)
	h := newMarvin32(logSeed)
	h.Write(hdr[:32])
	assert.Equal(t, le64(hdr[32:]), h.Sum64())

	wrongSeed := newMarvin32([2]uint32{logSeed[1], logSeed[0]})
	wrongSeed.Write(hdr[:32])
	assert.NotEqual(t, le64(hdr[32:]), wrongSeed.Sum64())
}

func le64(b []byte) uint64 {
	return uint64(le32(b, 0)) | uint64(le32(b, 4))<<32
}

func TestMarvin32WriteIsChunkIndependent(t *testing.T) {
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i * 7)
	}
	for _, n := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 999, 1000} {
		whole := newMarvin32(logSeed)
		whole.Write(data[:n])
		for _, chunk := range []int{1, 2, 3, 5, 64} {
			parts := newMarvin32(logSeed)
			for off := 0; off < n; off += chunk {
				parts.Write(data[off:min(off+chunk, n)])
			}
			assert.Equal(t, whole.Sum64(), parts.Sum64(), "length %d chunk %d", n, chunk)
		}
	}
	// different lengths and tails give different hashes
	a, b, c := newMarvin32(logSeed), newMarvin32(logSeed), newMarvin32(logSeed)
	a.Write(data[:5])
	b.Write(data[:6])
	c.Write(data[:7])
	assert.NotEqual(t, a.Sum64(), b.Sum64())
	assert.NotEqual(t, b.Sum64(), c.Sum64())
}

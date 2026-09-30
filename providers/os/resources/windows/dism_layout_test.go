// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The packed layouts from dismapi.h (pack 4): no member is padded, so on
// 64-bit Windows DismFeature is 12 bytes, not the 16 a Go struct would take.
func TestDismLayouts(t *testing.T) {
	switch unsafe.Sizeof(uintptr(0)) {
	case 8:
		assert.Equal(t, []uintptr{0, 8}, dismFeatureLayout.offsets)
		assert.Equal(t, uintptr(12), dismFeatureLayout.size)
		assert.Equal(t, []uintptr{0, 8, 12, 20, 28, 32, 40}, dismFeatureInfoLayout.offsets)
		assert.Equal(t, uintptr(44), dismFeatureInfoLayout.size)
	case 4:
		assert.Equal(t, []uintptr{0, 4}, dismFeatureLayout.offsets)
		assert.Equal(t, uintptr(8), dismFeatureLayout.size)
		assert.Equal(t, []uintptr{0, 4, 8, 12, 16, 20, 24}, dismFeatureInfoLayout.offsets)
		assert.Equal(t, uintptr(28), dismFeatureInfoLayout.size)
	default:
		t.Fatalf("unexpected pointer size %d", unsafe.Sizeof(uintptr(0)))
	}
}

// Reading an array of packed DismFeature elements finds every element's
// state, not only the first one's.
func TestDismFeatureArrayReads(t *testing.T) {
	l := dismFeatureLayout
	states := []uint32{dismStateInstalled, dismStateStaged, dismStatePartiallyInstalled}
	// A pointer-aligned buffer, so the pointer-sized reads are aligned for the
	// first element; the packed elements after it are what DISM hands out.
	words := make([]uint64, (int(l.size)*len(states)+7)/8)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
	for i, s := range states {
		binary.LittleEndian.PutUint32(buf[uintptr(i)*l.size+l.offsets[dismFeatureState]:], s)
	}
	base := unsafe.Pointer(&words[0])
	for i, want := range states {
		assert.Equal(t, want, l.uint32(l.element(base, i), dismFeatureState), "element %d", i)
	}
}

func TestFeatureStateFromDism(t *testing.T) {
	for dism, want := range map[uint32]int64{
		dismStateStaged:             0,
		dismStateUninstallPending:   1,
		dismStateInstalled:          2,
		dismStateInstallPending:     3,
		dismStateSuperseded:         4,
		dismStatePartiallyInstalled: 5,
		dismStateNotPresent:         0,
		dismStateResolved:           6,
	} {
		got, err := featureStateFromDism(dism)
		require.NoError(t, err, "DISM state %d", dism)
		assert.Equal(t, want, got, "DISM state %d", dism)
	}
	_, err := featureStateFromDism(8)
	assert.Error(t, err, "a state outside the DISM enum means a misread structure")
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package regf

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type pg struct {
	off  uint32
	data []byte
}

// fixHashes recomputes the two hashes of the log entry e, so that a crafted
// entry is rejected for what is wrong with it and not for its hashes.
func fixHashes(e []byte) {
	end := len(e)
	if size := int(le32(e, 4)); size >= logEntryHdr && size < end {
		end = size
	}
	h1 := newMarvin32(logSeed)
	h1.Write(e[logEntryHdr:end])
	binary.LittleEndian.PutUint64(e[24:], h1.Sum64())
	h2 := newMarvin32(logSeed)
	h2.Write(e[:32])
	binary.LittleEndian.PutUint64(e[32:], h2.Sum64())
}

// entryOf builds a valid log entry.
func entryOf(seq, binsSize uint32, pages ...pg) []byte {
	var refs, data []byte
	for _, p := range pages {
		refs = binary.LittleEndian.AppendUint32(refs, p.off)
		refs = binary.LittleEndian.AppendUint32(refs, uint32(len(p.data)))
		data = append(data, p.data...)
	}
	size := (logEntryHdr + len(refs) + len(data) + 511) &^ 511
	e := make([]byte, size)
	copy(e, "HvLE")
	put32(e, 4, uint32(size))
	put32(e, 12, seq)
	put32(e, 16, binsSize)
	put32(e, 20, uint32(len(pages)))
	copy(e[logEntryHdr:], refs)
	copy(e[logEntryHdr+len(refs):], data)
	fixHashes(e)
	return e
}

// logOf builds a log file for hive: a copy of its base block with the
// sequence numbers seq, followed by the entries.
func logOf(hive []byte, seq uint32, entries ...[]byte) []byte {
	l := make([]byte, logSectorSize)
	copy(l, hive[:logSectorSize])
	put32(l, 4, seq)
	put32(l, 8, seq)
	put32(l, 28, 6)
	setChecksum(l)
	for _, e := range entries {
		l = append(l, e...)
	}
	return l
}

func asLog(name string, b []byte) Log {
	return Log{Name: name, R: bytes.NewReader(b), Size: int64(len(b))}
}

// dirtied returns a copy of the hive whose sequence numbers say a write was
// in progress when it was copied.
func dirtied(hive []byte, seq2 uint32) []byte {
	b := append([]byte(nil), hive...)
	put32(b, 4, seq2+1)
	put32(b, 8, seq2)
	return b
}

// pageOf returns the index of the page of the hive bins data that holds needle.
func pageOf(t testing.TB, hive, needle []byte) int {
	t.Helper()
	i := bytes.Index(hive, needle)
	require.GreaterOrEqual(t, i, baseBlockSize)
	return (i - baseBlockSize) / pageSize
}

// editedPage returns the page of the hive that holds old, with old replaced.
func editedPage(t testing.TB, hive []byte, old, repl string) pg {
	t.Helper()
	require.Equal(t, len(old), len(repl))
	idx := pageOf(t, hive, utf16le(old))
	start := baseBlockSize + idx*pageSize
	page := append([]byte(nil), hive[start:start+pageSize]...)
	require.Equal(t, 1, bytes.Count(page, utf16le(old)))
	page = bytes.Replace(page, utf16le(old), utf16le(repl), 1)
	return pg{off: uint32(idx * pageSize), data: page}
}

func szValue(t testing.TB, h *Hive, key, name string) string {
	t.Helper()
	d, err := valueNamed(t, keyAt(t, h, key), name).Data()
	require.NoError(t, err)
	return string(d)
}

func TestRecoverReplaysLogInMemory(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	fix := fixture(t)
	hive := dirtied(fix, 10)
	binsSize := le32(hive, 40)
	edit := editedPage(t, fix, "hello world", "HELLO WORLD")
	log := logOf(hive, 11, entryOf(11, binsSize, edit))
	before := append([]byte(nil), hive...)

	h, err := openBytes(hive, asLog("LOG1", log))
	require.NoError(t, err)
	assert.True(t, h.Dirty())
	assert.Equal(t, 1, h.Replayed())
	assert.Equal(t, string(append(utf16le("HELLO WORLD"), 0, 0)), szValue(t, h, "Values", "Sz"))
	// the rest of the hive is the primary file's
	assert.Equal(t, "über 日本", func() string {
		d, err := valueNamed(t, keyAt(t, h, "Values"), "SzUnicode").Data()
		require.NoError(t, err)
		return DecodeName(d[:len(d)-2], false)
	}())

	// the same hive without the log keeps its value: nothing was written
	h, err = openBytes(hive)
	require.NoError(t, err)
	assert.Zero(t, h.Replayed())
	assert.Equal(t, string(append(utf16le("hello world"), 0, 0)), szValue(t, h, "Values", "Sz"))
	assert.Equal(t, before, hive, "the primary file is never modified")
	left, err := os.ReadDir(tmp)
	require.NoError(t, err)
	assert.Empty(t, left, "recovery does not create files")

	t.Run("a clean hive ignores the log", func(t *testing.T) {
		h, err := openBytes(fix, asLog("LOG1", log))
		require.NoError(t, err)
		assert.Zero(t, h.Replayed())
		assert.Equal(t, string(append(utf16le("hello world"), 0, 0)), szValue(t, h, "Values", "Sz"))
	})
	t.Run("entries the hive already has are skipped", func(t *testing.T) {
		// the hive is at sequence 20, the log only has older entries
		h, err := openBytes(dirtied(fix, 20), asLog("LOG1", log))
		require.NoError(t, err)
		assert.Zero(t, h.Replayed())
	})
}

func TestRecoverChainsTheLogsBySequence(t *testing.T) {
	fix := fixture(t)
	hive := dirtied(fix, 10)
	binsSize := le32(hive, 40)
	first := editedPage(t, fix, "hello world", "HELLO WORLD")
	// the second entry edits the same page again, built on top of the first
	second := pg{off: first.off, data: bytes.Replace(first.data, utf16le("HELLO WORLD"), utf16le("Hello World"), 1)}
	third := editedPage(t, fix, "one", "ONE")
	_ = third

	logA := logOf(hive, 11, entryOf(11, binsSize, first), entryOf(12, binsSize, second))
	logB := logOf(hive, 13, entryOf(13, binsSize, pg{off: first.off, data: bytes.Replace(second.data, utf16le("Hello World"), utf16le("hELLO wORLD"), 1)}))

	for name, logs := range map[string][]Log{
		"in order":       {asLog("LOG1", logA), asLog("LOG2", logB)},
		"in reverse":     {asLog("LOG2", logB), asLog("LOG1", logA)},
		"only the first": {asLog("LOG1", logA)},
	} {
		t.Run(name, func(t *testing.T) {
			h, err := openBytes(hive, logs...)
			require.NoError(t, err)
			want, replayed := "hELLO wORLD", 3
			if len(logs) == 1 {
				want, replayed = "Hello World", 2
			}
			assert.Equal(t, replayed, h.Replayed())
			assert.Equal(t, string(append(utf16le(want), 0, 0)), szValue(t, h, "Values", "Sz"))
		})
	}
	t.Run("a gap in the sequence ends the replay", func(t *testing.T) {
		gap := logOf(hive, 11, entryOf(11, binsSize, first), entryOf(13, binsSize, second))
		h, err := openBytes(hive, asLog("LOG1", gap))
		require.NoError(t, err)
		assert.Equal(t, 1, h.Replayed())
		assert.Equal(t, string(append(utf16le("HELLO WORLD"), 0, 0)), szValue(t, h, "Values", "Sz"))
	})
	t.Run("a second log that does not follow is not applied", func(t *testing.T) {
		far := logOf(hive, 20, entryOf(20, binsSize, second))
		h, err := openBytes(hive, asLog("LOG1", logA), asLog("LOG2", far))
		require.NoError(t, err)
		assert.Equal(t, 2, h.Replayed())
	})
	t.Run("the first entry may be later than the hive's sequence", func(t *testing.T) {
		// Windows logs start well after the primary file's sequence number
		late := logOf(hive, 500, entryOf(500, binsSize, first))
		h, err := openBytes(hive, asLog("LOG1", late))
		require.NoError(t, err)
		assert.Equal(t, 1, h.Replayed())
	})
	t.Run("an entry followed by garbage is still applied", func(t *testing.T) {
		l := logOf(hive, 11, entryOf(11, binsSize, first))
		l = append(l, bytes.Repeat([]byte{0xAB}, 1024)...)
		h, err := openBytes(hive, asLog("LOG1", l))
		require.NoError(t, err)
		assert.Equal(t, 1, h.Replayed())
	})
}

func TestRecoverGrowsTheHive(t *testing.T) {
	fix := fixture(t)
	bl := fromHive(fix)
	extraOff := bl.add(nkCell("Late", 0, noOffset, 0, noOffset))
	grown := bl.bytes()
	newBins := le32(grown, 40)
	oldBins := newBins - 4096
	// a primary file that was cut off before the new bin was written, with the
	// new size in its base block (the write began, then the machine stopped)
	cut := append([]byte(nil), grown[:baseBlockSize+int(oldBins)]...)
	put32(cut, 40, newBins)
	cut = dirtied(cut, 5)
	newPage := grown[baseBlockSize+int(oldBins):]
	root, _ := mustOpen(t, fix).Root()
	listOff := bl // keep the builder alive for the offsets below
	_ = listOff

	// re-point the root key at the new key through the new page of the log
	_ = extraOff
	_ = root
	log := logOf(cut, 6, entryOf(6, newBins, pg{off: oldBins, data: newPage}))

	_, err := openBytes(cut)
	require.Error(t, err, "without the log the file is shorter than its base block says")

	h, err := openBytes(cut, asLog("LOG1", log))
	require.NoError(t, err)
	assert.Equal(t, 1, h.Replayed())
	k, err := h.key(extraOff)
	require.NoError(t, err)
	assert.Equal(t, "Late", k.Name)
}

// Crafted logs for the findings about regparser's log replay (R3 to R6), each
// with correct hashes so that the check under test is what rejects it. Under
// regparser: a dirty page count of 0xFFFFFFFF sized an allocation of 4G
// elements; a log entry size of 0 made the replay loop spin forever; a page
// size of 0xFFFFFFFF allocated 4 GiB; a page offset of 0x7FFFF000 grew a
// temporary copy of the hive by 2 GiB, which also leaked when the scan died.
func TestRecoverRejectsCraftedLogs(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	fix := fixture(t)
	hive := dirtied(fix, 10)
	binsSize := le32(hive, 40)
	good := editedPage(t, fix, "hello world", "HELLO WORLD")
	okEntry := func() []byte { return entryOf(11, binsSize, good) }

	// mutate builds the log from a valid entry changed by f, re-hashing it
	mutate := func(f func(e []byte) []byte) []byte {
		e := f(okEntry())
		fixHashes(e)
		return logOf(hive, 11, e)
	}
	refOff := logEntryHdr // the first dirty page reference
	logs := map[string][]byte{
		"entry size 0 (endless loop)":     mutate(func(e []byte) []byte { put32(e, 4, 0); return e }),
		"entry size 40":                   mutate(func(e []byte) []byte { put32(e, 4, 40); return e }),
		"entry size not a multiple":       mutate(func(e []byte) []byte { put32(e, 4, uint32(len(e))-1); return e }),
		"entry size beyond the log":       mutate(func(e []byte) []byte { put32(e, 4, uint32(len(e))+512); return e }),
		"entry size 0xFFFFFE00":           mutate(func(e []byte) []byte { put32(e, 4, 0xFFFFFE00); return e }),
		"dirty page count 0xFFFFFFFF":     mutate(func(e []byte) []byte { put32(e, 20, 0xFFFFFFFF); return e }),
		"dirty page count 0x10000000":     mutate(func(e []byte) []byte { put32(e, 20, 0x10000000); return e }),
		"dirty page count one too many":   mutate(func(e []byte) []byte { put32(e, 20, 2); return e }),
		"page size 0xFFFFFFFF":            mutate(func(e []byte) []byte { put32(e, refOff+4, 0xFFFFFFFF); return e }),
		"page size 0xFFFFF000":            mutate(func(e []byte) []byte { put32(e, refOff+4, 0xFFFFF000); return e }),
		"page size 1 GiB":                 mutate(func(e []byte) []byte { put32(e, refOff+4, 1<<30); return e }),
		"page size 0":                     mutate(func(e []byte) []byte { put32(e, refOff+4, 0); return e }),
		"page size not a multiple":        mutate(func(e []byte) []byte { put32(e, refOff+4, 4000); return e }),
		"page offset 0x7FFFF000":          mutate(func(e []byte) []byte { put32(e, refOff, 0x7FFFF000); return e }),
		"page offset 0xFFFFF000":          mutate(func(e []byte) []byte { put32(e, refOff, 0xFFFFF000); return e }),
		"page offset at the end of bins":  mutate(func(e []byte) []byte { put32(e, refOff, binsSize); return e }),
		"page offset not a multiple":      mutate(func(e []byte) []byte { put32(e, refOff, le32(e, refOff)+512); return e }),
		"bins size not a multiple":        mutate(func(e []byte) []byte { put32(e, 16, binsSize+1); return e }),
		"bins size 0xFFFFF000":            mutate(func(e []byte) []byte { put32(e, 16, 0xFFFFF000); return e }),
		"bins size smaller than the page": mutate(func(e []byte) []byte { put32(e, 16, 4096); return e }),
		"hash-1 wrong": func() []byte {
			e := okEntry()
			e[len(e)-1] ^= 0xFF
			return logOf(hive, 11, e)
		}(),
		"hash-2 wrong": func() []byte {
			e := okEntry()
			e[33] ^= 0xFF
			return logOf(hive, 11, e)
		}(),
		"signature wrong": mutate(func(e []byte) []byte { e[0] = 'X'; return e }),
		"old format log": func() []byte {
			l := logOf(hive, 11, okEntry())
			copy(l[logSectorSize:], "DIRT")
			return l
		}(),
		"log checksum wrong": func() []byte {
			l := logOf(hive, 11, okEntry())
			l[100] ^= 1
			return l
		}(),
		"log signature wrong": func() []byte {
			l := logOf(hive, 11, okEntry())
			copy(l, "regX")
			return l
		}(),
		"log base block mid-update": func() []byte {
			l := logOf(hive, 11, okEntry())
			put32(l, 4, 12)
			setChecksum(l)
			return l
		}(),
		"first entry earlier than the hive": func() []byte {
			return logOf(hive, 3, entryOf(3, binsSize, good))
		}(),
		"log with only a base block":    logOf(hive, 11),
		"log shorter than a base block": logOf(hive, 11)[:300],
		"empty log":                     {},
		"zeros":                         make([]byte, 8192),
	}
	for name, l := range logs {
		t.Run(name, func(t *testing.T) {
			var h *Hive
			var err error
			cost := allocated(func() {
				within(t, 10*time.Second, func() {
					h, err = openBytes(hive, asLog("LOG1", l))
				})
			})
			require.NoError(t, err, "the hive is read as it is")
			assert.Zero(t, h.Replayed())
			assert.Equal(t, string(append(utf16le("hello world"), 0, 0)), szValue(t, h, "Values", "Sz"))
			assert.Less(t, cost, uint64(32<<20), "memory used while rejecting the log")
		})
	}
	left, err := os.ReadDir(tmp)
	require.NoError(t, err)
	assert.Empty(t, left)

	t.Run("a valid entry before a bad one is kept", func(t *testing.T) {
		bad := entryOf(12, binsSize, good)
		put32(bad, 4, 0)
		fixHashes(bad)
		h, err := openBytes(hive, asLog("LOG1", logOf(hive, 11, okEntry(), bad)))
		require.NoError(t, err)
		assert.Equal(t, 1, h.Replayed())
		assert.Equal(t, string(append(utf16le("HELLO WORLD"), 0, 0)), szValue(t, h, "Values", "Sz"))
	})
}

func TestRecoverOverlayReads(t *testing.T) {
	fix := fixture(t)
	hive := dirtied(fix, 10)
	binsSize := le32(hive, 40)
	page := bytes.Repeat([]byte{0xAA}, pageSize)
	log := logOf(hive, 11, entryOf(11, binsSize+2*pageSize, pg{off: 2 * pageSize, data: page}, pg{off: binsSize, data: page}))
	l := asLog("LOG1", log)
	o, err := planRecovery(bytes.NewReader(hive), int64(len(hive)), 10, []Log{l})
	require.NoError(t, err)
	require.Equal(t, int64(baseBlockSize+binsSize+2*pageSize), o.size())

	read := func(off int64, n int) ([]byte, error) {
		b := make([]byte, n)
		n, err := o.ReadAt(b, off)
		return b[:n], err
	}
	// a read that spans the primary file and a dirty page
	got, err := read(baseBlockSize+2*pageSize-4, 8)
	require.NoError(t, err)
	assert.Equal(t, append(hive[baseBlockSize+2*pageSize-4:baseBlockSize+2*pageSize], 0xAA, 0xAA, 0xAA, 0xAA), got)
	// the base block is the primary file's
	got, err = read(0, 8)
	require.NoError(t, err)
	assert.Equal(t, hive[:8], got)
	// the grown area: the dirty page, then zeros
	got, err = read(int64(baseBlockSize+binsSize), pageSize)
	require.NoError(t, err)
	assert.Equal(t, page, got)
	got, err = read(int64(baseBlockSize+binsSize+pageSize), 16)
	require.NoError(t, err)
	assert.Equal(t, make([]byte, 16), got)
	// reads past the end
	got, err = read(o.size()-4, 16)
	assert.ErrorIs(t, err, io.EOF)
	assert.Len(t, got, 4)
	_, err = read(o.size(), 1)
	assert.ErrorIs(t, err, io.EOF)
	_, err = o.ReadAt(make([]byte, 1), -1)
	assert.Error(t, err)
}

func gunzipFile(t testing.TB, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	zr, err := gzip.NewReader(f)
	require.NoError(t, err)
	b, err := io.ReadAll(zr)
	require.NoError(t, err)
	return b
}

// regressionInputs returns the hive (and log, if any) pairs of
// testdata/regression, found by fuzzing and hand-crafting regparser's inputs.
// Each pair made regparser panic, overflow the stack, hang or allocate GBs.
func regressionInputs(t testing.TB) map[string][2][]byte {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "regression", "*.hiv.gz"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	res := map[string][2][]byte{}
	for _, f := range files {
		var logBytes []byte
		if _, err := os.Stat(strings.TrimSuffix(f, ".gz") + ".LOG1.gz"); err == nil {
			logBytes = gunzipFile(t, strings.TrimSuffix(f, ".gz")+".LOG1.gz")
		}
		name := strings.TrimSuffix(filepath.Base(f), ".hiv.gz")
		res[name] = [2][]byte{gunzipFile(t, f), logBytes}
	}
	return res
}

// walkBounded opens and walks the hive like the registry package does, and
// reads every value, within fixed bounds.
func walkBounded(h *Hive) (keys int) {
	_ = h.Walk(20000, func(k Key) error {
		keys++
		vals, _ := k.Values()
		for i, v := range vals {
			if i == 64 {
				break
			}
			_, _ = v.Data()
		}
		return nil
	})
	return keys
}

func TestRegressionInputs(t *testing.T) {
	noRecover = true
	defer func() { noRecover = false }()
	for name, in := range regressionInputs(t) {
		t.Run(name, func(t *testing.T) {
			var logs []Log
			if in[1] != nil {
				logs = append(logs, asLog("LOG1", in[1]))
			}
			start := time.Now()
			keys, replayed := 0, 0
			var openErr error
			cost := allocated(func() {
				within(t, 20*time.Second, func() {
					h, err := openBytes(in[0], logs...)
					if err != nil {
						openErr = err
						return
					}
					replayed = h.Replayed()
					keys = walkBounded(h)
				})
			})
			t.Logf("%s: %s, %d KiB allocated, %d keys, %d log entries replayed, open error: %v", name, time.Since(start).Round(time.Millisecond), cost>>10, keys, replayed, openErr)
			assert.Zero(t, replayed)
			assert.Less(t, time.Since(start), 5*time.Second)
			assert.Less(t, cost, uint64(256<<20))
		})
	}
}

// repairLog makes a mutated log pass its integrity checks where its structure
// still allows it, so that the fuzzer reaches the code behind them.
func repairLog(l []byte) {
	if len(l) < logSectorSize {
		return
	}
	copy(l, "regf")
	put32(l, 8, le32(l, 4))
	setChecksum(l)
	for pos := logSectorSize; pos+logEntryHdr <= len(l); {
		size := int(le32(l, pos+4))
		if size < logSectorSize || size%logSectorSize != 0 || size > len(l)-pos {
			return
		}
		copy(l[pos:], "HvLE")
		fixHashes(l[pos : pos+size])
		pos += size
	}
}

func FuzzRecover(f *testing.F) {
	noRecover = true // the fuzzer must see a panic, not an error
	defer func() { noRecover = false }()
	bl, _, _ := attackHive()
	small := bl.bytes()
	smallBins := le32(small, 40)
	dirtySmall := dirtied(small, 10)
	page := append([]byte(nil), small[baseBlockSize:baseBlockSize+pageSize]...)
	f.Add(dirtySmall, logOf(dirtySmall, 11, entryOf(11, smallBins, pg{off: 0, data: page})))
	f.Add(dirtySmall, logOf(dirtySmall, 11, entryOf(11, smallBins+pageSize, pg{off: 0, data: page}, pg{off: smallBins, data: page}), entryOf(12, smallBins, pg{off: 0, data: page})))
	f.Add(dirtySmall, logOf(dirtySmall, 11, entryOf(11, smallBins, pg{off: 0xFFFFF000, data: page})))
	f.Fuzz(func(t *testing.T, hive, logBytes []byte) {
		if len(hive) > 4<<20 || len(logBytes) > 4<<20 {
			return
		}
		repairLog(logBytes)
		h, err := Open(bytes.NewReader(hive), int64(len(hive)), asLog("LOG1", logBytes), asLog("LOG2", logBytes))
		if err != nil {
			return
		}
		walkBounded(h)
	})
}

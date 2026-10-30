// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package regf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/rs/zerolog/log"
)

// Transaction log recovery, new format (Windows 8.1 and later). A dirty hive
// is recovered in memory: the dirty pages of the log entries that follow the
// hive's state are laid over the primary file by an io.ReaderAt, nothing is
// written anywhere. Everything is validated before it is applied; the first
// entry that fails ends the replay of its log.

const (
	pageSize = 4096
	// logSectorSize is the size of the base block copy that starts a log and
	// the alignment of its entries.
	logSectorSize = 512
	logEntryHdr   = 40
	// maxOverlayBytes bounds the dirty pages applied over a hive.
	maxOverlayBytes = 512 << 20
	// maxLogs bounds the number of log files that are considered.
	maxLogs = 4
)

// Log is a transaction log file next to a hive (<hive>.LOG1, <hive>.LOG2).
type Log struct {
	Name string
	R    io.ReaderAt
	Size int64
}

type pageDesc struct {
	hiveOff uint32 // relative to the start of the hive bins data
	size    uint32
	logOff  int64 // where the page data is in the log
}

type logEntry struct {
	seq      uint32
	binsSize uint32
	pages    []pageDesc
	bytes    uint64
}

// logRun is the chain of valid, consecutive entries of one log.
type logRun struct {
	log     int
	entries []logEntry
}

// parseLog validates the log and returns its entries up to the first one that
// is invalid. It reads the log once.
func parseLog(l Log) ([]logEntry, error) {
	if l.Size < logSectorSize+logEntryHdr {
		return nil, errors.New("log is too small to hold an entry")
	}
	hdr := make([]byte, logSectorSize)
	if err := readFull(l.R, hdr, 0); err != nil {
		return nil, err
	}
	if string(hdr[0:4]) != "regf" {
		return nil, errors.New("log base block has a bad signature")
	}
	var sum uint32
	for i := 0; i < 508; i += 4 {
		sum ^= binary.LittleEndian.Uint32(hdr[i:])
	}
	switch sum {
	case 0xFFFFFFFF:
		sum = 0xFFFFFFFE
	case 0:
		sum = 1
	}
	if sum != binary.LittleEndian.Uint32(hdr[508:]) {
		return nil, errors.New("log base block has a bad checksum")
	}
	if binary.LittleEndian.Uint32(hdr[4:]) != binary.LittleEndian.Uint32(hdr[8:]) {
		return nil, errors.New("log base block is mid-update (sequence numbers differ)")
	}
	var sig [4]byte
	if err := readFull(l.R, sig[:], logSectorSize); err != nil {
		return nil, err
	}
	switch string(sig[:]) {
	case "HvLE":
	case "DIRT":
		return nil, errors.New("old-format (DIRT) transaction logs are not supported")
	default:
		return nil, fmt.Errorf("unrecognised log content %q", sig[:])
	}

	var entries []logEntry
	var total uint64
	pos := int64(logSectorSize)
	for l.Size-pos >= logEntryHdr {
		e, size, err := parseLogEntry(l, pos)
		if err != nil {
			log.Debug().Err(err).Str("log", l.Name).Int64("offset", pos).Msg("transaction log replay ends at an invalid entry")
			break
		}
		if len(entries) > 0 && e.seq != entries[len(entries)-1].seq+1 {
			break
		}
		if total += e.bytes; total > maxOverlayBytes {
			log.Debug().Str("log", l.Name).Msg("transaction log holds more dirty pages than the limit, replay ends")
			break
		}
		entries = append(entries, e)
		pos += size
	}
	return entries, nil
}

// parseLogEntry validates the entry at pos, including both hashes. It
// returns the entry and its size in the log.
func parseLogEntry(l Log, pos int64) (logEntry, int64, error) {
	var e logEntry
	hdr := make([]byte, logEntryHdr)
	if err := readFull(l.R, hdr, pos); err != nil {
		return e, 0, err
	}
	if string(hdr[0:4]) != "HvLE" {
		return e, 0, errors.New("bad entry signature")
	}
	size := int64(binary.LittleEndian.Uint32(hdr[4:]))
	if size < logSectorSize || size%logSectorSize != 0 {
		return e, 0, fmt.Errorf("entry size %d is not a multiple of %d", size, logSectorSize)
	}
	if size > l.Size-pos {
		return e, 0, fmt.Errorf("entry size %d exceeds the %d bytes left in the log", size, l.Size-pos)
	}
	e.seq = binary.LittleEndian.Uint32(hdr[12:])
	e.binsSize = binary.LittleEndian.Uint32(hdr[16:])
	count := uint64(binary.LittleEndian.Uint32(hdr[20:]))
	if e.binsSize%pageSize != 0 || e.binsSize > maxBinsSize {
		return e, 0, fmt.Errorf("invalid hive bins data size %d", e.binsSize)
	}
	refsEnd := logEntryHdr + count*8
	if refsEnd > uint64(size) {
		return e, 0, fmt.Errorf("%d dirty page references do not fit the entry", count)
	}

	// Hash-1 covers everything after the entry header. It is computed in
	// chunks, the entry is not held in memory as a whole.
	h1 := newMarvin32(logSeed)
	buf := make([]byte, 64<<10)
	for off, end := pos+logEntryHdr, pos+size; off < end; {
		n := int(min(int64(len(buf)), end-off))
		if err := readFull(l.R, buf[:n], off); err != nil {
			return e, 0, err
		}
		h1.Write(buf[:n])
		off += int64(n)
	}
	if h1.Sum64() != binary.LittleEndian.Uint64(hdr[24:]) {
		return e, 0, errors.New("entry hash-1 does not match")
	}
	h2 := newMarvin32(logSeed)
	h2.Write(hdr[:32])
	if h2.Sum64() != binary.LittleEndian.Uint64(hdr[32:]) {
		return e, 0, errors.New("entry hash-2 does not match")
	}

	refs := make([]byte, count*8)
	if err := readFull(l.R, refs, pos+logEntryHdr); err != nil {
		return e, 0, err
	}
	e.pages = make([]pageDesc, 0, count)
	dataOff := pos + int64(refsEnd)
	room := uint64(size) - refsEnd
	for i := range count {
		off := binary.LittleEndian.Uint32(refs[8*i:])
		sz := binary.LittleEndian.Uint32(refs[8*i+4:])
		if sz == 0 || sz%pageSize != 0 || off%pageSize != 0 {
			return e, 0, fmt.Errorf("dirty page at %#x with size %#x is not page aligned", off, sz)
		}
		if uint64(off)+uint64(sz) > uint64(e.binsSize) {
			return e, 0, fmt.Errorf("dirty page at %#x with size %#x lies beyond the hive bins data", off, sz)
		}
		if e.bytes += uint64(sz); e.bytes > room {
			return e, 0, errors.New("dirty pages are larger than the entry")
		}
		e.pages = append(e.pages, pageDesc{hiveOff: off, size: sz, logOff: dataOff})
		dataOff += int64(sz)
	}
	return e, size, nil
}

// overlay is the recovered hive: the primary file with the dirty pages of the
// applied log entries laid over it.
type overlay struct {
	base     io.ReaderAt
	baseSize int64
	logs     []Log
	pages    map[uint32]pageRef // page index in the hive bins data
	binsSize int64
	entries  int
}

type pageRef struct {
	log int
	off int64
}

// planRecovery chooses the log entries that follow the state of the primary
// file (its secondary sequence number is seq2) and returns the overlay, or nil
// when there is nothing to apply.
//
// Per the format, each log holds consecutive entries, the entries of the
// two logs of a hive are chained in the order of their sequence numbers, and
// entries older than the hive's state are skipped.
func planRecovery(base io.ReaderAt, baseSize int64, seq2 uint32, logs []Log) (*overlay, error) {
	if len(logs) > maxLogs {
		logs = logs[:maxLogs]
	}
	var runs []logRun
	for i, l := range logs {
		if l.Size == 0 {
			continue // Windows leaves empty log files behind; they are no log
		}
		entries, err := parseLog(l)
		if err != nil {
			log.Debug().Err(err).Str("log", l.Name).Msg("skipping transaction log")
			continue
		}
		// leading entries the primary file already contains
		for len(entries) > 0 && entries[0].seq < seq2 {
			entries = entries[1:]
		}
		if len(entries) > 0 {
			runs = append(runs, logRun{log: i, entries: entries})
		}
	}
	if len(runs) == 0 {
		return nil, errors.New("no transaction log entry follows the hive")
	}
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].entries[0].seq < runs[j].entries[0].seq })

	o := &overlay{base: base, baseSize: baseSize, logs: logs, pages: map[uint32]pageRef{}}
	var applied uint64
	var last uint32
	for _, run := range runs {
		for _, e := range run.entries {
			if o.entries > 0 {
				if e.seq <= last {
					// entries of another log that this one already covers
					continue
				}
				if e.seq != last+1 {
					return o.finish()
				}
			}
			if applied += e.bytes; applied > maxOverlayBytes {
				return o.finish()
			}
			for _, p := range e.pages {
				for b := uint32(0); b < p.size/pageSize; b++ {
					o.pages[p.hiveOff/pageSize+b] = pageRef{log: run.log, off: p.logOff + int64(b)*pageSize}
				}
			}
			o.binsSize = int64(e.binsSize)
			o.entries++
			last = e.seq
		}
	}
	return o.finish()
}

func (o *overlay) finish() (*overlay, error) {
	if o.entries == 0 {
		return nil, errors.New("no transaction log entry applies")
	}
	return o, nil
}

// size is the length of the recovered file.
func (o *overlay) size() int64 { return baseBlockSize + o.binsSize }

// ReadAt implements io.ReaderAt over the recovered file. The base block comes
// from the primary file; hive bins data comes from the dirty pages where there
// are any, else from the primary file, with zeros where the hive has grown
// past the primary file.
func (o *overlay) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	size := o.size()
	if off >= size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > size-off {
		want = int(size - off)
	}
	done := 0
	for done < want {
		pos := off + int64(done)
		var chunk int
		var src io.ReaderAt
		var srcOff int64
		if pos < baseBlockSize {
			chunk = int(min(int64(want-done), baseBlockSize-pos))
			src, srcOff = o.base, pos
		} else {
			rel := pos - baseBlockSize
			within := rel % pageSize
			chunk = int(min(int64(want-done), pageSize-within))
			if ref, ok := o.pages[uint32(rel/pageSize)]; ok {
				src, srcOff = o.logs[ref.log].R, ref.off+within
			} else {
				src, srcOff = o.base, pos
			}
		}
		dst := p[done : done+chunk]
		if src == o.base && srcOff+int64(chunk) > o.baseSize {
			// past the end of the primary file: zeros
			have := int(max(0, min(int64(chunk), o.baseSize-srcOff)))
			if have > 0 {
				if err := readFull(src, dst[:have], srcOff); err != nil {
					return done, err
				}
			}
			clear(dst[have:])
		} else if err := readFull(src, dst, srcOff); err != nil {
			return done, err
		}
		done += chunk
	}
	if want < len(p) {
		return want, io.EOF
	}
	return want, nil
}

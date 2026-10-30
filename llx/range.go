// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/types"
)

// RangePrimitive creates a range primitive from the given
// range data. Use the helper functions to initialize and
// combine multiple sets of range data.
func RangePrimitive(data Range) *Primitive {
	return &Primitive{
		Type:  string(types.Range),
		Value: data,
	}
}

type Range []byte

const (
	// Byte indicators for ranges work like this:
	//
	// Byte1:    version + mode
	// xxxx xxxx
	// VVVV -------> version for the range
	//      MMMM --> 1 = single line
	//               2 = line range
	//               3 = line with column range
	//               4 = line + column range
	//
	// Byte2+:   length indicators
	// xxxx xxxx
	// NNNN -------> length of the first entry (up to 128bit)
	//      MMMM --> length of the second entry (up to 128bit)
	//               note: currently we only support up to 32bit
	//
	rangeVersion1 byte = 0x10
)

func NewRange() Range {
	return []byte{}
}

func (r Range) AddLine(line uint32) Range {
	r = append(r, rangeVersion1|0x01)
	bytes := int2bytes(int64(line))
	r = append(r, byte(len(bytes)<<4))
	r = append(r, bytes...)
	return r
}

func (r Range) AddLineRange(line1 uint32, line2 uint32) Range {
	r = append(r, rangeVersion1|0x02)
	bytes1 := int2bytes(int64(line1))
	bytes2 := int2bytes(int64(line2))
	r = append(r, byte(len(bytes1)<<4)|byte(len(bytes2)&0x0f))
	r = append(r, bytes1...)
	r = append(r, bytes2...)
	return r
}

func (r Range) AddColumnRange(line uint32, column1 uint32, column2 uint32) Range {
	r = append(r, rangeVersion1|0x03)
	bLine := int2bytes(int64(line))
	bCol1 := int2bytes(int64(column1))
	bCol2 := int2bytes(int64(column2))

	r = append(r, byte(len(bLine)<<4))
	r = append(r, bLine...)

	r = append(r, byte(len(bCol1)<<4)|byte(len(bCol2)&0xf))
	r = append(r, bCol1...)
	r = append(r, bCol2...)
	return r
}

func (r Range) AddLineColumnRange(line1 uint32, line2 uint32, column1 uint32, column2 uint32) Range {
	r = append(r, rangeVersion1|0x04)
	b1 := int2bytes(int64(line1))
	b2 := int2bytes(int64(line2))
	r = append(r, byte(len(b1)<<4)|byte(len(b2)&0xf))
	r = append(r, b1...)
	r = append(r, b2...)

	b1 = int2bytes(int64(column1))
	b2 = int2bytes(int64(column2))
	r = append(r, byte(len(b1)<<4)|byte(len(b2)&0xf))
	r = append(r, b1...)
	r = append(r, b2...)

	return r
}

func (r Range) ExtractNext() ([]uint32, Range) {
	if len(r) == 0 {
		return nil, nil
	}

	version := r[0] & 0xf0
	if version != rangeVersion1 {
		log.Error().Msg("failed to extract range, version is unsupported")
		return nil, nil
	}

	entries := r[0] & 0x0f
	res := []uint32{}
	idx := 1
	switch entries {
	case 3, 4:
		l1 := int((r[idx] & 0xf0) >> 4)
		l2 := int(r[idx] & 0x0f)

		idx++
		if l1 != 0 {
			n := bytes2int(r[idx : idx+l1])
			idx += l1
			res = append(res, uint32(n))
		}
		if l2 != 0 {
			n := bytes2int(r[idx : idx+l2])
			idx += l2
			res = append(res, uint32(n))
		}

		fallthrough

	case 1, 2:
		l1 := int((r[idx] & 0xf0) >> 4)
		l2 := int(r[idx] & 0x0f)

		idx++
		if l1 != 0 {
			n := bytes2int(r[idx : idx+l1])
			idx += l1
			res = append(res, uint32(n))
		}
		if l2 != 0 {
			n := bytes2int(r[idx : idx+l2])
			idx += l2
			res = append(res, uint32(n))
		}

	default:
		log.Error().Msg("failed to extract range, wrong number of entries")
		return nil, nil
	}

	return res, r[idx:]
}

func (r Range) ExtractAll() [][]uint32 {
	res := [][]uint32{}
	for {
		cur, rest := r.ExtractNext()
		if len(cur) != 0 {
			res = append(res, cur)
		}
		if len(rest) == 0 {
			break
		}
		r = rest
	}

	return res
}

func (r Range) IsEmpty() bool {
	return len(r) == 0
}

// Bounds returns the 1-based start/end line and column of the range's first
// entry. hasCols is false for line-only ranges (no column information). ok is
// false if the range is empty or cannot be decoded. Consumers that need a
// numeric region (e.g. SARIF) should use this instead of re-decoding the
// byte format. For line-only ranges startCol/endCol are 0.
func (r Range) Bounds() (startLine, startCol, endLine, endCol uint32, hasCols, ok bool) {
	items := r.ExtractAll()
	if len(items) == 0 {
		return 0, 0, 0, 0, false, false
	}

	x := items[0]
	switch len(x) {
	case 1: // single line
		return x[0], 0, x[0], 0, false, true
	case 2: // line range
		return x[0], 0, x[1], 0, false, true
	case 3: // single line with column range
		return x[0], x[1], x[0], x[2], true, true
	case 4: // line range with column range: [startLine, endLine, startCol, endCol]
		return x[0], x[2], x[1], x[3], true, true
	default:
		return 0, 0, 0, 0, false, false
	}
}

func (r Range) String() string {
	var res strings.Builder

	items := r.ExtractAll()
	for i := range items {
		x := items[i]
		switch len(x) {
		case 1:
			res.WriteString(strconv.Itoa(int(x[0])))
		case 2:
			res.WriteString(strconv.Itoa(int(x[0])))
			res.WriteString("-")
			res.WriteString(strconv.Itoa(int(x[1])))
		case 3:
			res.WriteString(strconv.Itoa(int(x[0])))
			res.WriteString(":")
			res.WriteString(strconv.Itoa(int(x[1])))
			res.WriteString("-")
			res.WriteString(strconv.Itoa(int(x[2])))
		case 4:
			res.WriteString(strconv.Itoa(int(x[0])))
			res.WriteString(":")
			res.WriteString(strconv.Itoa(int(x[2])))
			res.WriteString("-")
			res.WriteString(strconv.Itoa(int(x[1])))
			res.WriteString(":")
			res.WriteString(strconv.Itoa(int(x[3])))
		}

		if i != len(items)-1 {
			res.WriteString(",")
		}
	}

	ret := res.String()
	if ret == "" {
		return "undefined"
	}
	return ret
}

type ExtractConfig struct {
	MaxLines          int
	MaxColumns        int
	ShowLineNumbers   bool
	LineNumberPadding int
	maxLineDigits     int
}

var DefaultExtractConfig = ExtractConfig{
	MaxLines:          5,
	MaxColumns:        100,
	ShowLineNumbers:   true,
	LineNumberPadding: 2,
}

func writeLine(lineNum int, line string, cfg *ExtractConfig, res *strings.Builder, hasNewline bool) {
	max := cfg.MaxColumns
	if hasNewline {
		max--
	}

	if cfg.ShowLineNumbers && lineNum >= 0 {
		if cfg.maxLineDigits > 0 {
			fmt.Fprintf(res, "%"+strconv.Itoa(cfg.maxLineDigits)+"d:", lineNum)
		} else {
			res.WriteString(strconv.Itoa(int(lineNum)) + ":")
		}
		for i := 0; i < cfg.LineNumberPadding; i++ {
			res.WriteByte(' ')
		}
	}

	if len(line) <= max {
		res.WriteString(line)
	} else {
		if max > 3 {
			res.WriteString(line[:max-3])
		}
		res.WriteString("...")
	}
	if hasNewline {
		res.WriteByte('\n')
	}
}

func extractLineRange(lines []string, lineIdx uint32, end uint32, maxLines int, cfg *ExtractConfig, res *strings.Builder) {
	maxAllLines := uint32(len(lines))

	if end < lineIdx {
		return
	}
	lineCnt := end - lineIdx

	if uint32(maxLines) >= lineCnt {
		for ; lineIdx <= end; lineIdx++ {
			writeLine(int(lineIdx+1), lines[lineIdx], cfg, res, lineIdx+1 != maxAllLines)
		}
		return
	}

	if maxLines < 1 {
		writeLine(-1, "...", cfg, res, true)
		return
	}

	half := maxLines >> 1
	scrapS := lineIdx + uint32(half)
	scrapE := end - uint32(maxLines-half-1) + 1
	for ; lineIdx < scrapS; lineIdx++ {
		writeLine(int(lineIdx+1), lines[lineIdx], cfg, res, lineIdx+1 != maxAllLines)
	}
	res.WriteString("...\n")
	for lineIdx = scrapE; lineIdx <= end; lineIdx++ {
		writeLine(int(lineIdx+1), lines[lineIdx], cfg, res, lineIdx+1 != maxAllLines)
	}
}

func (r Range) ExtractString(src string, cfg ExtractConfig) string {
	lines := strings.Split(src, "\n")
	maxLines := uint32(len(lines))
	items := r.ExtractAll()
	var res strings.Builder
	for i := range items {
		x := items[i]

		// turn the start line into an IDX (starts from 0)
		lineIdx := x[0]
		if lineIdx > 0 {
			lineIdx--
		}

		switch len(x) {
		case 1:
			// since we aren't dealing with ranges, if someone says line 0 we don't have it!
			if x[0] == 0 {
				continue
			}
			if lineIdx >= maxLines {
				continue
			}
			writeLine(int(lineIdx+1), lines[lineIdx], &cfg, &res, lineIdx+1 != maxLines)

		case 2:
			end := min(x[1]-1, maxLines-1)
			cfg.maxLineDigits = len(strconv.Itoa(int(end)))
			extractLineRange(lines, lineIdx, end, cfg.MaxLines, &cfg, &res)

		case 3:
			// since we aren't dealing with ranges, if someone says line 0 we don't have it!
			if x[0] == 0 {
				continue
			}
			if lineIdx >= maxLines {
				continue
			}

			line := lines[lineIdx]
			var col1idx uint32
			if x[1] != 0 {
				col1idx = x[1] - 1
			}
			colMax := uint32(len(line))
			col2idx := min(x[2], colMax)

			res.WriteString(line[col1idx:col2idx])
			if col2idx >= colMax && lineIdx+1 < maxLines {
				res.WriteByte('\n')
			}

		case 4:
			if lineIdx >= maxLines {
				continue
			}

			// Remember: line 0 ==> outside of line index
			// because lines start at 1
			// We set it to empty string because if we are at line idx 0
			// then the empty string won't create extraction content
			line := ""
			if x[0] != 0 {
				line = lines[lineIdx]
			}

			if x[1] == 0 {
				continue
			}
			end := min(x[1]-1, maxLines-1)

			var col1idx uint32
			if x[2] != 0 {
				col1idx = x[2] - 1
			}
			c2 := x[3]

			if x[0] == x[1] {
				cMax := uint32(len(line))
				addNewline := false
				if c2 > cMax {
					c2 = cMax
					addNewline = lineIdx < maxLines
				}
				if col1idx < cMax {
					writeLine(int(lineIdx+1), line[col1idx:c2], &cfg, &res, addNewline)
				} else if addNewline {
					res.WriteByte('\n')
				}
				continue
			}

			cfg.maxLineDigits = len(strconv.Itoa(int(end)))

			if col1idx <= uint32(len(line)) {
				addNewline := x[0] != 0 && x[0]+1 != maxLines
				var txt string
				if col1idx < uint32(len(line)) {
					txt = line[col1idx:]
				}
				writeLine(int(lineIdx+1), txt, &cfg, &res, addNewline)
			}
			if x[0] != 0 {
				lineIdx++
			}

			// we remove 2 from max content lines because we will always print the first and last line
			if end > 0 {
				extractLineRange(lines, lineIdx, end-1, cfg.MaxLines-2, &cfg, &res)
			}

			// if the specified end is over the maximum number of lines we have
			// just write the last line and be done here
			if x[1] > maxLines {
				writeLine(int(maxLines), lines[maxLines-1], &cfg, &res, false)
				continue
			}

			// otherwise this is the last line with some column range we need to respect
			line = lines[end]
			addNewline := false
			if c2 > uint32(len(line)) {
				c2 = uint32(len(line))
				addNewline = end+1 < maxLines
			}
			writeLine(int(end+1), line[:c2], &cfg, &res, addNewline)
		}
	}

	return res.String()
}

// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package iox

import (
	"bufio"
	"io"
)

// MaxLineBytes is the longest line NewLineScanner reads. It is far above any
// line a scanned system produces: Linux caps a process's whole argv and
// environment at 6 MiB, which bounds the longest ps line, and config files and
// /etc databases stay well below that. It also bounds the memory one scanner
// holds, so a target that serves a file with no newlines cannot exhaust the
// scanner's memory.
const MaxLineBytes = 16 << 20

// NewLineScanner returns a bufio.Scanner that splits r into lines like
// bufio.ScanLines, with lines up to MaxLineBytes instead of the default
// 64 KiB.
//
// A default scanner stops at the first longer line and Scan returns false as
// if the input had ended, so a parser that does not check Err reports the
// lines before it as the whole input. Callers must check Err after the loop:
// a line over MaxLineBytes ends Scan with bufio.ErrTooLong, and a read error
// ends it too, and either has to fail the parse rather than return the lines
// read so far.
func NewLineScanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 4096), MaxLineBytes)
	return s
}

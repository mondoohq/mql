// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package iox

import (
	"bufio"
	"io"
	"math"
)

// NewLineScanner returns a bufio.Scanner that splits r into lines like
// bufio.ScanLines, without the default 64 KiB limit on a line.
//
// A default scanner stops at the first longer line and Scan returns false as
// if the input had ended, so a parser that does not check Err reports the
// lines before it as the whole input. Config files, /etc databases and
// command output such as ps (a process's full command line) have no such
// limit. Callers must still check Err after the loop: a read error also ends
// Scan.
func NewLineScanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 4096), math.MaxInt)
	return s
}

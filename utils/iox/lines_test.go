// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package iox

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLineScannerReadsLinesOverDefaultLimit(t *testing.T) {
	long := strings.Repeat("x", 200*1024)
	s := NewLineScanner(strings.NewReader("first\r\n" + long + "\nlast"))
	var lines []string
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	require.NoError(t, s.Err())
	require.Len(t, lines, 3)
	assert.Equal(t, "first", lines[0])
	assert.Len(t, lines[1], 200*1024)
	assert.Equal(t, "last", lines[2])
}

func TestLineScannerReportsReadError(t *testing.T) {
	s := NewLineScanner(io.MultiReader(strings.NewReader("a\n"), iotest.ErrReader(errors.New("boom"))))
	for s.Scan() {
	}
	require.Error(t, s.Err())
}

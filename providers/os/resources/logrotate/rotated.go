// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package logrotate

import (
	"compress/gzip"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/afero"
)

// DefaultMaxRotations bounds how far back through logrotate's numbered copies a
// reader walks. Distributions ship a rotate count of 12 for the apt and dpkg
// logs, so twelve copies covers the retained history without probing paths that
// cannot exist.
const DefaultMaxRotations = 12

// Paths lists a log and its logrotate copies, newest first.
//
// Both the plain and the gzipped spelling of every rotation are listed because
// the two coexist: logrotate's `delaycompress` leaves the first rotation
// uncompressed while every older one is gzipped, and which of the two a given
// log uses is a per-distribution configuration choice rather than something
// worth guessing per file. A caller opens them in order and ignores the misses.
func Paths(base string, max int) []string {
	if max < 0 {
		max = 0
	}
	paths := make([]string, 0, 1+2*max)
	paths = append(paths, base)
	for i := 1; i <= max; i++ {
		n := strconv.Itoa(i)
		paths = append(paths, base+"."+n, base+"."+n+".gz")
	}
	return paths
}

// Open opens one rotated log, transparently decompressing a gzipped copy. The
// caller closes the result, which closes the file underneath it.
func Open(fs afero.Fs, path string) (io.ReadCloser, error) {
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(path, ".gz") {
		return f, nil
	}

	gz, err := gzip.NewReader(f)
	if err != nil {
		// A truncated or corrupt archive must not leak the descriptor. The
		// caller only sees the error and moves to the next rotation.
		f.Close()
		return nil, err
	}
	return &gzipReadCloser{gz: gz, f: f}, nil
}

// gzipReadCloser ties a gzip decompressor to the file it reads from so a single
// Close releases both.
type gzipReadCloser struct {
	gz *gzip.Reader
	f  afero.File
}

func (r *gzipReadCloser) Read(p []byte) (int, error) { return r.gz.Read(p) }

// Close closes the decompressor and the file beneath it. The file is closed
// even when the decompressor reports an error, so a corrupt archive cannot leak
// the descriptor; the decompressor's error is the one returned.
func (r *gzipReadCloser) Close() error {
	err := r.gz.Close()
	if ferr := r.f.Close(); err == nil {
		err = ferr
	}
	return err
}
